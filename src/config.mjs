import { createHash } from 'node:crypto';

export const DEFAULT_PROXY = 'https://dynamic-cimd.resoauth.cloud/cimd/%s';
export const DEFAULTS = Object.freeze({
  issuer: 'https://auth.resoauth.cloud', enabled: false, security_epoch: 0,
  session_ttl_seconds: 43200, transaction_ttl_seconds: 300,
  auth_path: '/_soca', protected_paths: ['/'], public_paths: [],
  allow_domains: [], deny_domains: [], allow_emails: [], deny_emails: [],
  metadata_mode: 'hosted', proxy_template: DEFAULT_PROXY,
  client_name: 'SOCA static content', scopes: ['openid', 'email'],
  max_age_seconds: null, required_acr: [], required_amr: [],
});

export class SocaError extends Error {}

export function ensure(condition, message) {
  if (!condition) throw new SocaError(message);
}

export function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

export function digest(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : stable(value)).digest('base64url');
}

export function httpsUrl(value) {
  ensure(typeof value === 'string' && value.length <= 4096, 'Invalid HTTPS URL');
  const u = new URL(value);
  ensure(u.protocol === 'https:' && !u.username && !u.password && !u.hash, 'HTTPS URL must not contain credentials or a fragment');
  ensure(!/[\u0000-\u0020\\]/u.test(value), 'Invalid URL characters');
  return u;
}

export function canonicalPath(value) {
  ensure(typeof value === 'string' && value.length <= 4096 && value.startsWith('/') && !value.startsWith('//'), 'Invalid path');
  // Reject ambiguous representations instead of guessing what S3 will serve.
  ensure(!/[\\?#\u0000-\u0020\u007f]/u.test(value) && !/%(?:2f|5c|25|00|3f|23)/i.test(value), 'Ambiguous path');
  const decoded = decodeURIComponent(value);
  ensure(!/[\\?#\u0000-\u0020\u007f]/u.test(decoded) && !decoded.includes('//'), 'Ambiguous path');
  ensure(!decoded.split('/').some(p => p === '.' || p === '..'), 'Dot segments are forbidden');
  return decoded;
}

export function matches(path, prefix) {
  return prefix === '/' || path === prefix || path.startsWith(`${prefix}/`);
}

function domain(value, wildcard = true) {
  ensure(typeof value === 'string', 'Domain rules must be strings');
  const d = value.toLowerCase();
  const plain = wildcard && d.startsWith('*.') ? d.slice(2) : d;
  ensure(plain.length <= 253 && plain.includes('.') && plain.split('.').every(l => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)), 'Invalid domain rule');
  return d;
}

function email(value) {
  ensure(typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(value), 'Invalid email');
  const [local, host] = value.split('@');
  return `${local.toLowerCase()}@${domain(host, false)}`;
}

export function normalise(input) {
  const extra = ['origin', 'client_uri', 'logo_uri', 'policy_uri', 'tos_uri'];
  ensure(input && typeof input === 'object' && !Array.isArray(input), 'Configuration must be an object');
  for (const k of Object.keys(input)) ensure(Object.hasOwn(DEFAULTS, k) || extra.includes(k), `Unknown setting: ${k}`);
  const c = { ...DEFAULTS, ...input };
  const origin = httpsUrl(c.origin);
  ensure(c.origin === origin.origin, 'origin must be a canonical HTTPS origin without a path or trailing slash');
  const issuer = httpsUrl(c.issuer);
  ensure(!issuer.search, 'Issuer cannot contain a query');
  ensure(typeof c.enabled === 'boolean', 'enabled must be boolean');
  ensure(Number.isSafeInteger(c.security_epoch) && c.security_epoch >= 0, 'Invalid security_epoch');
  for (const [k, max] of [['session_ttl_seconds', 604800], ['transaction_ttl_seconds', 600]]) ensure(Number.isSafeInteger(c[k]) && c[k] > 0 && c[k] <= max, `Invalid ${k}`);
  ensure(c.max_age_seconds === null || (Number.isSafeInteger(c.max_age_seconds) && c.max_age_seconds >= 0 && c.max_age_seconds <= 86400), 'Invalid max_age_seconds');
  ensure(canonicalPath(c.auth_path) === c.auth_path && c.auth_path !== '/' && !c.auth_path.endsWith('/') && /^[a-zA-Z0-9/_-]+$/.test(c.auth_path), 'Invalid auth_path');
  for (const k of ['protected_paths', 'public_paths']) {
    ensure(Array.isArray(c[k]) && c[k].length <= 100, `Invalid ${k}`);
    c[k] = c[k].map(p => { ensure(canonicalPath(p) === p && (p === '/' || !p.endsWith('/')), 'Use literal paths without trailing slashes'); return p; });
  }
  ensure(c.protected_paths.length > 0, 'At least one protected path is required');
  for (const k of ['allow_domains', 'deny_domains', 'allow_emails', 'deny_emails', 'required_acr', 'required_amr', 'scopes']) ensure(Array.isArray(c[k]) && c[k].length <= 100, `Invalid ${k}`);
  for (const k of ['allow_domains', 'deny_domains']) c[k] = c[k].map(v => domain(v));
  for (const k of ['allow_emails', 'deny_emails']) c[k] = c[k].map(email);
  for (const k of ['required_acr', 'required_amr', 'scopes']) ensure(c[k].every(v => typeof v === 'string' && v.length > 0 && v.length <= 100 && !/\s/.test(v)), `Invalid ${k}`);
  ensure(c.scopes.includes('openid') && c.scopes.every(v => ['openid', 'email', 'profile'].includes(v)), 'Only identity scopes are supported');
  ensure(typeof c.client_name === 'string' && c.client_name.length > 0 && c.client_name.length <= 128 && !/[\u0000-\u001f]/u.test(c.client_name), 'Invalid client_name');
  for (const k of extra.slice(1)) if (c[k] !== undefined) httpsUrl(c[k]);
  ensure(['hosted', 'proxy'].includes(c.metadata_mode), 'Invalid metadata_mode');
  ensure(typeof c.proxy_template === 'string' && c.proxy_template.split('%s').length === 2, 'Proxy template needs exactly one %s');
  const proxy = httpsUrl(c.proxy_template.replace('%s', 'payload'));
  ensure(!proxy.search && c.proxy_template.indexOf('%s') > c.proxy_template.indexOf('/', 8), 'Proxy placeholder must be in the HTTPS path');
  return c;
}

export function documents(config, publicKeys) {
  const base = `${config.origin}${config.auth_path}`;
  const body = {
    client_name: config.client_name, client_uri: config.client_uri ?? config.origin,
    redirect_uris: [`${base}/callback`], grant_types: ['authorization_code'], response_types: ['code'],
    token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'ES256',
    id_token_signed_response_alg: 'ES256', jwks_uri: `${base}/jwks.json`,
  };
  for (const k of ['logo_uri', 'policy_uri', 'tos_uri']) if (config[k]) body[k] = config[k];
  const clientId = config.metadata_mode === 'hosted' ? `${base}/client.json` : config.proxy_template.replace('%s', Buffer.from(stable(body)).toString('base64url'));
  ensure(clientId.length <= 4096, 'Client metadata URL exceeds 4096 bytes');
  return { client_id: clientId, metadata: { ...body, client_id: clientId }, jwks: { keys: publicKeys } };
}

export function admitted(c, claims) {
  if (claims.email_verified !== true || typeof claims.email !== 'string') return false;
  let e;
  try { e = email(claims.email); } catch { return false; }
  const host = e.split('@')[1];
  const match = rule => rule.startsWith('*.') ? host.endsWith(`.${rule.slice(2)}`) : host === rule;
  if (c.deny_emails.includes(e) || c.deny_domains.some(match)) return false;
  return c.allow_emails.includes(e) || c.allow_domains.some(match);
}
