import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { SignJWT, createLocalJWKSet, importJWK, jwtVerify } from 'jose';
import { admitted, canonicalPath, digest, documents, ensure, httpsUrl, matches, normalise } from './config.mjs';
import { requestJson } from './network.mjs';

const SESSION = '__Host-soca_session';
const BROWSER = '__Host-soca_browser';
const TX = '__Host-soca_tx_';
const random = () => randomBytes(32).toString('base64url');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

function response(status, body = '', extra = {}, type = 'text/plain; charset=utf-8') {
  const headers = {
    'content-type': [{ value: type }], 'cache-control': [{ value: 'no-store' }],
    'referrer-policy': [{ value: 'no-referrer' }], 'x-content-type-options': [{ value: 'nosniff' }],
    'content-security-policy': [{ value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" }],
  };
  for (const [name, value] of Object.entries(extra)) headers[name] = Array.isArray(value) ? value.map(v => ({ value: v })) : [{ value }];
  return { status: String(status), headers, body };
}

function cookie(name, value, age) {
  ensure(value.length <= 3800, 'Cookie exceeds size limit');
  return `${name}=${value}; Path=/; Max-Age=${age}; Secure; HttpOnly; SameSite=Lax`;
}

function cookies(request) {
  const raw = (request.headers.cookie ?? []).map(h => h.value).join(';');
  ensure(raw.length <= 16384, 'Cookie headers too large');
  const result = Object.create(null);
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const name = part.slice(0, i).trim();
    if (!name.startsWith('__Host-soca_')) continue;
    ensure(!Object.hasOwn(result, name), 'Duplicate authentication cookie');
    result[name] = part.slice(i + 1).trim();
  }
  return result;
}

function params(query) {
  ensure(typeof query === 'string' && query.length <= 8192, 'Query too large');
  const p = new URLSearchParams(query);
  ensure([...p.keys()].every(k => p.getAll(k).length === 1), 'Duplicate query parameter');
  return p;
}

function safeReturn(value, c) {
  ensure(typeof value === 'string' && value.length <= 4096, 'Invalid return URL');
  const path = canonicalPath(value.split('?')[0]);
  ensure(!matches(path, c.auth_path), 'Cannot return to authentication endpoints');
  const url = new URL(value, c.origin);
  ensure(url.origin === c.origin && !url.hash, 'Invalid return URL');
  return value;
}

export function validateDiscovery(d, c) {
  ensure(d.issuer === c.issuer, 'Discovery issuer mismatch');
  for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) httpsUrl(d[k]);
  for (const [k, v] of Object.entries({
    response_types_supported: 'code', code_challenge_methods_supported: 'S256',
    token_endpoint_auth_methods_supported: 'private_key_jwt',
    token_endpoint_auth_signing_alg_values_supported: 'ES256', id_token_signing_alg_values_supported: 'ES256',
  })) ensure(Array.isArray(d[k]) && d[k].includes(v), `Provider lacks ${v}`);
  ensure(!Object.hasOwn(d, 'client_id_metadata_document_supported') || d.client_id_metadata_document_supported === true, 'Provider explicitly rejects CIMD');
  return d;
}

function validateJwks(data) {
  ensure(Array.isArray(data.keys) && data.keys.length > 0 && data.keys.length <= 50, 'Invalid provider JWKS');
  ensure(data.keys.every(k => !['d', 'p', 'q', 'k'].some(name => Object.hasOwn(k, name))), 'Provider returned private key material');
  const keys = data.keys.filter(k => k.kty === 'EC' && k.crv === 'P-256' && (!k.alg || k.alg === 'ES256') && (!k.use || k.use === 'sig') && (!k.key_ops || k.key_ops.includes('verify')));
  ensure(keys.length > 0, 'Provider has no ES256 verification key');
  return createLocalJWKSet({ keys });
}

export function createHandler(deployment, { fetchJson = requestJson, now = () => Math.floor(Date.now() / 1000) } = {}) {
  const c = normalise(deployment.config);
  const docs = documents(c, deployment.public_keys);
  const revision = digest({ config: c, public_keys: deployment.public_keys, session_ids: deployment.session_keys.map(k => k.kid) });
  ensure(revision === deployment.revision, 'Deployment revision mismatch');
  // Routine key overlap preserves cookies; configuration/security_epoch changes revoke them.
  const cookieRevision = digest({ config: c, client_id: docs.client_id });
  ensure(deployment.session_keys.length > 0 && deployment.session_keys.length <= 3, 'Invalid session keyring');
  const sessionKeys = new Map(deployment.session_keys.map(k => {
    ensure(/^[a-zA-Z0-9_-]{8,64}$/.test(k.kid) && /^[a-zA-Z0-9_-]{43}$/.test(k.key), 'Invalid session key');
    return [k.kid, Buffer.from(k.key, 'base64url')];
  }));
  const signer = importJWK(deployment.signing_key, 'ES256');
  let discovery;
  let keyCache;
  let keyRefreshAt = 0;
  let discoveryPending;
  let keysPending;

  function seal(value, purpose) {
    const { kid } = deployment.session_keys[0];
    const key = Buffer.from(hkdfSync('sha256', sessionKeys.get(kid), c.origin, purpose, 32));
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(`soca:v1:${c.origin}:${purpose}`));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return [kid, iv.toString('base64url'), encrypted.toString('base64url'), cipher.getAuthTag().toString('base64url')].join('.');
  }

  function open(value, purpose) {
    try {
      ensure(typeof value === 'string' && value.length <= 3800 && /^[a-zA-Z0-9_.-]+$/.test(value), 'Invalid cookie');
      const [kid, iv, encrypted, tag, extra] = value.split('.');
      ensure(!extra && sessionKeys.has(kid), 'Unknown cookie key');
      const key = Buffer.from(hkdfSync('sha256', sessionKeys.get(kid), c.origin, purpose, 32));
      ensure(Buffer.from(iv, 'base64url').length === 12 && Buffer.from(tag, 'base64url').length === 16, 'Invalid cookie encoding');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
      decipher.setAAD(Buffer.from(`soca:v1:${c.origin}:${purpose}`));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));
      const v = JSON.parse(Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64url')), decipher.final()]).toString('utf8'));
      ensure(Number.isSafeInteger(v.exp) && v.exp > now() && Number.isSafeInteger(v.iat) && v.iat <= now() + 30 && v.iat <= v.exp && v.revision === cookieRevision, 'Expired or obsolete cookie');
      ensure(v.exp - v.iat <= (purpose === 'session' ? c.session_ttl_seconds : c.transaction_ttl_seconds), 'Cookie lifetime exceeds policy');
      return v;
    } catch { return null; }
  }

  async function provider() {
    if (discovery?.exp > now()) return discovery.value;
    if (!discoveryPending) discoveryPending = (async () => {
      const value = validateDiscovery(await fetchJson(`${c.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`), c);
      discovery = { value, exp: now() + 300 };
      return value;
    })().finally(() => { discoveryPending = undefined; });
    return discoveryPending;
  }

  async function verificationKeys(d, refresh = false) {
    if (keyCache?.uri === d.jwks_uri && keyCache.exp > now() && !refresh) return keyCache.value;
    ensure(!refresh || now() >= keyRefreshAt, 'Provider key refresh rate exceeded');
    if (!keysPending) {
      keyRefreshAt = now() + 30;
      keysPending = (async () => {
        const value = validateJwks(await fetchJson(d.jwks_uri));
        keyCache = { value, uri: d.jwks_uri, exp: now() + 300 };
        return value;
      })().finally(() => { keysPending = undefined; });
    }
    return keysPending;
  }

  async function verifyIdentity(token, d, tx) {
    ensure(typeof token === 'string' && token.length <= 32768, 'Invalid ID token');
    const options = {
      issuer: c.issuer, audience: docs.client_id, algorithms: ['ES256'],
      requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp', 'nonce'],
      clockTolerance: 30, currentDate: new Date(now() * 1000), maxTokenAge: '10m',
    };
    let result;
    try { result = await jwtVerify(token, await verificationKeys(d), options); }
    catch (error) {
      if (!['ERR_JWKS_NO_MATCHING_KEY', 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'].includes(error.code)) throw error;
      result = await jwtVerify(token, await verificationKeys(d, true), options);
    }
    const p = result.payload;
    ensure(typeof p.sub === 'string' && p.sub.length > 0 && p.sub.length <= 255, 'Invalid subject');
    ensure(equal(p.nonce, tx.nonce), 'Nonce mismatch');
    ensure((!Array.isArray(p.aud) || p.aud.length === 1 || p.azp === docs.client_id) && (p.azp === undefined || p.azp === docs.client_id), 'Invalid authorised party');
    for (const k of ['iat', 'exp', 'nbf', 'auth_time']) if (p[k] !== undefined) ensure(Number.isSafeInteger(p[k]), 'Invalid token time');
    ensure(p.exp > p.iat && p.iat <= now() + 30, 'Invalid token lifetime');
    if (c.max_age_seconds !== null) ensure(Number.isSafeInteger(p.auth_time) && p.auth_time <= now() + 30 && now() - p.auth_time <= c.max_age_seconds + 30, 'Fresh authentication required');
    if (c.required_acr.length) ensure(c.required_acr.includes(p.acr), 'Required assurance missing');
    if (c.required_amr.length) ensure(Array.isArray(p.amr) && p.amr.every(v => typeof v === 'string') && c.required_amr.every(v => p.amr.includes(v)), 'Required authentication method missing');
    // No UserInfo fetch: admission uses only the validated ID token.
    ensure(admitted(c, p), 'Admission denied');
    return p;
  }

  function forward(request) {
    // Neither credentials nor callback query strings become S3/cache metadata.
    if (request.headers.cookie) {
      const kept = request.headers.cookie.flatMap(h => h.value.split(';')).filter(p => !p.trim().startsWith('__Host-soca_')).join(';');
      if (kept) request.headers.cookie = [{ key: 'Cookie', value: kept }];
      else delete request.headers.cookie;
    }
    delete request.headers.authorization;
    return request;
  }

  return async event => {
    let clear = [];
    try {
      const request = event.Records?.[0]?.cf?.request;
      ensure(request && event.Records[0].cf.config.eventType === 'viewer-request', 'Expected viewer-request event');
      ensure(request.headers.host?.length === 1 && request.headers.host[0].value === new URL(c.origin).host, 'Unexpected host');
      const path = canonicalPath(request.uri);
      const auth = matches(path, c.auth_path);
      const method = request.method;
      if (path === `${c.auth_path}/client.json` || path === `${c.auth_path}/jwks.json`) {
        if (!['GET', 'HEAD'].includes(method)) return response(405, 'Method not allowed');
        const body = path.endsWith('/client.json') ? docs.metadata : docs.jwks;
        return response(200, method === 'HEAD' ? '' : stableJson(body), { 'cache-control': 'public, max-age=60' }, 'application/json');
      }
      if (path === `${c.auth_path}/logout`) {
        if (method === 'GET') return response(200, '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign out</title><h1>Sign out</h1><form method="post"><button type="submit">Sign out of this site</button></form></html>', {}, 'text/html; charset=utf-8');
        if (method !== 'POST' || request.headers.origin?.length !== 1 || request.headers.origin[0].value !== c.origin) return response(403, 'Sign-out requires a same-origin form submission');
        const jar = cookies(request);
        const names = [SESSION, BROWSER, ...Object.keys(jar).filter(k => k.startsWith(TX))];
        return response(200, 'You have signed out. You may close this tab.', { 'set-cookie': names.map(k => cookie(k, '', 0)) });
      }
      if (auth && ![`${c.auth_path}/login`, `${c.auth_path}/callback`].includes(path)) return response(404, 'Not found');
      const protectedPath = auth || (c.protected_paths.some(p => matches(path, p)) && !c.public_paths.some(p => matches(path, p)));
      if (!protectedPath) return forward(request);
      if (!['GET', 'HEAD'].includes(method)) return response(405, 'Only GET and HEAD are supported');
      if (!c.enabled) return response(503, 'SOCA sign-in is disabled. Contact the site operator.');
      const jar = cookies(request);

      if (path === `${c.auth_path}/callback`) {
        ensure(method === 'GET', 'Callback must use GET');
        const q = params(request.querystring);
        const state = q.get('state');
        ensure(typeof state === 'string' && /^[A-Za-z0-9_-]{43}$/.test(state), 'Invalid state');
        const txName = `${TX}${state}`;
        clear = [cookie(txName, '', 0)];
        const tx = open(jar[txName], 'transaction');
        const binding = open(jar[BROWSER], 'browser');
        ensure(tx && binding && equal(tx.binding, binding.id) && equal(state, tx.state), 'Transaction/browser binding failed');
        ensure(tx.issuer === c.issuer && tx.client_id === docs.client_id && tx.callback === docs.metadata.redirect_uris[0], 'Transaction profile mismatch');
        ensure(!q.has('error') && typeof q.get('code') === 'string' && q.get('code').length > 0 && q.get('code').length <= 4096, 'Authorisation failed');
        const d = await provider();
        ensure((!q.has('iss') || q.get('iss') === c.issuer) && (d.authorization_response_iss_parameter_supported !== true || q.get('iss') === c.issuer), 'Response issuer mismatch');
        const at = now();
        const assertion = await new SignJWT({}).setProtectedHeader({ alg: 'ES256', kid: deployment.signing_key.kid, typ: 'JWT' })
          .setIssuer(docs.client_id).setSubject(docs.client_id).setAudience(d.token_endpoint)
          .setIssuedAt(at).setExpirationTime(at + 60).setJti(random()).sign(await signer);
        const token = await fetchJson(d.token_endpoint, { body: new URLSearchParams({
          grant_type: 'authorization_code', code: q.get('code'), redirect_uri: tx.callback,
          client_id: docs.client_id, code_verifier: tx.verifier,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
        }).toString() });
        ensure(!token.error, 'Token endpoint rejected authorisation');
        const identity = await verifyIdentity(token.id_token, d, tx);
        const session = seal({ iat: at, exp: at + c.session_ttl_seconds, revision: cookieRevision, sid: random(), iss: c.issuer, sub: identity.sub }, 'session');
        return response(303, '', { location: `${c.origin}${safeReturn(tx.return_to, c)}`, 'set-cookie': [...clear, cookie(SESSION, session, c.session_ttl_seconds)] });
      }

      if (!auth) {
        const session = open(jar[SESSION], 'session');
        if (session && session.iss === c.issuer && typeof session.sub === 'string' && typeof session.sid === 'string') return forward(request);
        if (method === 'HEAD') return response(401, 'Authentication required');
        const returnTo = safeReturn(request.uri + (request.querystring ? `?${request.querystring}` : ''), c);
        return response(303, '', { location: `${c.origin}${c.auth_path}/login?return_to=${encodeURIComponent(returnTo)}` });
      }

      ensure(method === 'GET', 'Login must use GET');
      const q = params(request.querystring);
      const returnTo = safeReturn(q.get('return_to') ?? '/', c);
      const active = Object.keys(jar).filter(k => k.startsWith(TX));
      const expired = active.filter(k => !open(jar[k], 'transaction'));
      ensure(active.length - expired.length < 4, 'Too many pending logins');
      const d = await provider();
      const state = random();
      const nonce = random();
      const verifier = random();
      const at = now();
      const binding = open(jar[BROWSER], 'browser')?.id ?? random();
      const tx = { iat: at, exp: at + c.transaction_ttl_seconds, revision: cookieRevision, state, nonce, verifier, binding,
        issuer: c.issuer, client_id: docs.client_id, callback: docs.metadata.redirect_uris[0], return_to: returnTo };
      const location = new URL(d.authorization_endpoint);
      for (const [k, v] of Object.entries({ response_type: 'code', client_id: docs.client_id, redirect_uri: tx.callback,
        scope: c.scopes.join(' '), state, nonce, code_challenge: digest(verifier), code_challenge_method: 'S256', response_mode: 'query' })) location.searchParams.set(k, v);
      if (c.max_age_seconds !== null) location.searchParams.set('max_age', String(c.max_age_seconds));
      if (c.required_acr.length) location.searchParams.set('acr_values', c.required_acr.join(' '));
      return response(303, '', { location: location.href, 'set-cookie': [
        ...expired.map(k => cookie(k, '', 0)), cookie(BROWSER, seal({ iat: at, exp: tx.exp, revision: cookieRevision, id: binding }, 'browser'), c.transaction_ttl_seconds),
        cookie(`${TX}${state}`, seal(tx, 'transaction'), c.transaction_ttl_seconds),
      ] });
    } catch {
      // Never log event objects, tokens, provider errors or callback URLs.
      return response(403, 'SOCA could not authorise this request. Start a fresh sign-in or contact the site operator.', clear.length ? { 'set-cookie': clear } : {});
    }
  };
}

function stableJson(value) { return JSON.stringify(value); }
