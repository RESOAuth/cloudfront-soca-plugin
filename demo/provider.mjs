import { createPrivateKey, randomBytes } from 'node:crypto';
import { SignJWT, createLocalJWKSet, jwtVerify } from 'jose';
import { digest, ensure } from '../src/config.mjs';
import { newKeys } from '../generator/package.mjs';

// Deliberate protocol simulator for tests/demo only. Never part of deployment ZIPs.
export function simulatedProvider(deployment, clock = () => Math.floor(Date.now() / 1000)) {
  const issuer = deployment.config.issuer;
  const pair = newKeys();
  const signer = pair.signing_key;
  const codes = new Map();
  const calls = [];
  const discovery = {
    issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`,
    response_types_supported: ['code'], code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['private_key_jwt'], token_endpoint_auth_signing_alg_values_supported: ['ES256'],
    id_token_signing_alg_values_supported: ['ES256'], client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  };
  function authorise(url, claims = {}, headers = {}) {
    const p = new URL(url).searchParams;
    ensure(p.get('code_challenge_method') === 'S256' && p.get('response_type') === 'code', 'Invalid authorisation request');
    const code = randomBytes(24).toString('base64url');
    codes.set(code, { params: p, claims, headers });
    const callback = new URL(p.get('redirect_uri'));
    callback.searchParams.set('state', p.get('state'));
    callback.searchParams.set('code', code);
    callback.searchParams.set('iss', issuer);
    return callback;
  }
  async function fetchJson(url, options = {}) {
    calls.push(url);
    if (url.endsWith('/.well-known/openid-configuration')) return discovery;
    if (url === discovery.jwks_uri) return { keys: pair.public_keys };
    ensure(url === discovery.token_endpoint, 'Unexpected simulator endpoint');
    const p = new URLSearchParams(options.body);
    const code = codes.get(p.get('code'));
    ensure(code, 'Code was already consumed or unknown');
    codes.delete(p.get('code'));
    ensure(p.get('grant_type') === 'authorization_code' && p.get('client_assertion_type') === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'Invalid token request');
    ensure(p.get('redirect_uri') === code.params.get('redirect_uri') && p.get('client_id') === code.params.get('client_id'), 'Client/callback mismatch');
    ensure(digest(p.get('code_verifier')) === code.params.get('code_challenge'), 'PKCE mismatch');
    const assertion = await jwtVerify(p.get('client_assertion'), createLocalJWKSet({ keys: deployment.public_keys }), {
      algorithms: ['ES256'], issuer: p.get('client_id'), audience: discovery.token_endpoint,
      subject: p.get('client_id'), requiredClaims: ['jti', 'iat', 'exp'], currentDate: new Date(clock() * 1000),
    });
    ensure(assertion.payload.exp - assertion.payload.iat <= 60, 'Assertion lifetime too long');
    const t = clock();
    const token = await new SignJWT({
      iss: issuer, sub: 'demo-user', aud: p.get('client_id'), iat: t, exp: t + 300,
      nonce: code.params.get('nonce'), email: 'reader@example.com', email_verified: true, ...code.claims,
    }).setProtectedHeader({ alg: 'ES256', kid: signer.kid, ...code.headers })
      .sign(createPrivateKey({ key: signer, format: 'jwk' }));
    return { id_token: token, access_token: 'discarded-simulator-access-token', token_type: 'Bearer' };
  }
  return { authorise, fetchJson, calls, discovery, pair };
}
