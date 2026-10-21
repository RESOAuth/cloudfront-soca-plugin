import test from 'node:test';
import assert from 'node:assert/strict';
import { createHandler } from '../src/runtime.mjs';
import { prepare } from '../generator/package.mjs';
import { event, fixture, login, cookieJar } from './helpers.mjs';

test('complete code + PKCE + private_key_jwt flow, local asset checks and absolute 12-hour expiry', async () => {
  const f = fixture();
  const l = await login(f);
  assert.equal(l.finish.status, '303');
  assert.equal(l.finish.headers.location[0].value, 'https://static.example.com/private/file.txt');
  assert.match(l.finish.headers['set-cookie'][1].value, /Max-Age=43200; Secure; HttpOnly; SameSite=Lax$/);
  assert.equal(f.provider.calls.length, 3);
  const asset = await f.handler(event('/private/file.txt', { cookies: l.jar }));
  assert.equal(asset.uri, '/private/file.txt');
  assert.equal(asset.headers.cookie, undefined);
  assert.equal(f.provider.calls.length, 3);
  f.advance(43200);
  assert.equal((await f.handler(event('/private/file.txt', { cookies: l.jar }))).status, '303');
});

test('head requests do not redirect to the provider, unsupported protected methods fail', async () => {
  const f = fixture();
  assert.equal((await f.handler(event('/private', { method: 'HEAD' }))).status, '401');
  assert.equal((await f.handler(event('/private', { method: 'POST' }))).status, '405');
  assert.equal(f.provider.calls.length, 0);
});

test('closed default still serves public documents without leaking keys, rules or session material', async () => {
  const f = fixture({ enabled: false });
  assert.equal((await f.handler(event('/'))).status, '503');
  const jwks = await f.handler(event('/_soca/jwks.json'));
  const metadata = await f.handler(event('/_soca/client.json'));
  assert.equal(jwks.status, '200');
  assert.equal(metadata.status, '200');
  for (const value of [jwks.body, metadata.body]) {
    assert.ok(!value.includes(f.deployment.signing_key.d));
    assert.ok(!value.includes(f.deployment.session_keys[0].key));
    assert.ok(!value.includes('allow_domains'));
    assert.ok(!value.includes('reader@example.com'));
  }
  assert.equal(JSON.parse(metadata.body).id_token_signed_response_alg, 'ES256');
});

test('path boundary matching, explicitly public paths, unknown auth routes and host pinning', async () => {
  const f = fixture({ protected_paths: ['/private'], public_paths: ['/private/public'] });
  assert.equal((await f.handler(event('/private'))).status, '303');
  assert.equal((await f.handler(event('/private/file'))).status, '303');
  assert.equal((await f.handler(event('/private-public'))).uri, '/private-public');
  assert.equal((await f.handler(event('/private/public/file'))).uri, '/private/public/file');
  assert.equal((await f.handler(event('/_soca/anything'))).status, '404');
  assert.equal((await f.handler(event('/private', { headers: { host: [{ value: 'attacker.example' }] } }))).status, '403');
});

for (const raw of ['/private%2F..%2Fpublic', '/private/%252e%252e/public', '/private//file', '/private/%2e%2e/public', '/private\\file', '/private/%00file']) {
  test(`ambiguous raw path rejected: ${raw}`, async () => {
    const e = event('/');
    e.Records[0].cf.request.uri = raw;
    assert.equal((await fixture().handler(e)).status, '403');
  });
}

test('encrypted transaction secrets are absent from URLs and cookie plaintext; browser binding is mandatory', async () => {
  const f = fixture();
  const start = await f.handler(event('/_soca/login'));
  const jar = cookieJar(start);
  const url = new URL(start.headers.location[0].value);
  assert.equal(url.searchParams.get('code_verifier'), null);
  const callback = f.provider.authorise(url);
  const unbound = jar.split('; ').filter(s => !s.startsWith('__Host-soca_browser=')).join('; ');
  assert.equal((await f.handler(event(callback.href, { cookies: unbound }))).status, '403');
  const token = jar.split('; ').find(s => s.startsWith('__Host-soca_tx_')).split('=')[1];
  assert.ok(!Buffer.from(token.split('.')[2], 'base64url').toString().includes('verifier'));
});

test('tampered cookies, duplicate cookies, foreign callback issuer, duplicate state and expired transactions fail closed', async () => {
  for (const kind of ['cookie', 'duplicate-cookie', 'issuer', 'duplicate-state', 'expired']) {
    const f = fixture();
    const start = await f.handler(event('/_soca/login'));
    let jar = cookieJar(start);
    const callback = f.provider.authorise(start.headers.location[0].value);
    if (kind === 'cookie') jar = jar.replace(/(__Host-soca_tx_[^=]+=)(.)/, (_, prefix, ch) => prefix + (ch === 'A' ? 'B' : 'A'));
    if (kind === 'duplicate-cookie') jar += `; ${jar.split('; ')[0]}`;
    if (kind === 'issuer') callback.searchParams.set('iss', 'https://evil.example');
    if (kind === 'duplicate-state') callback.searchParams.append('state', callback.searchParams.get('state'));
    if (kind === 'expired') f.advance(301);
    assert.equal((await f.handler(event(callback.href, { cookies: jar }))).status, '403', kind);
  }
});

for (const [name, claims] of Object.entries({
  nonce: { nonce: 'wrong' }, issuer: { iss: 'https://evil.example' }, audience: { aud: 'wrong' },
  subject: { sub: '' }, unverified: { email_verified: false }, stringVerified: { email_verified: 'true' },
  missingEmail: { email: null }, domain: { email: 'reader@badexample.com' },
  authorisedParty: { aud: ['https://static.example.com/_soca/client.json', 'other'], azp: 'other' },
  expired: { exp: 1 }, future: { iat: 9999999999 }, fractionTime: { iat: 1.5 },
})) {
  test(`ID token/admission rejection: ${name}`, async () => {
    const l = await login(fixture(), { claims });
    assert.equal(l.finish.status, '403');
    assert.ok(!l.finish.headers['set-cookie'].some(c => c.value.startsWith('__Host-soca_session=')));
  });
}

test('provider auth codes are single-use, even if a captured transaction cookie is replayed', async () => {
  const f = fixture();
  const l = await login(f);
  assert.equal(l.finish.status, '303');
  assert.equal((await f.handler(event(l.callback.href, { cookies: l.transactionJar }))).status, '403');
});

test('session tamper, configuration change and disable invalidate access', async () => {
  const f = fixture();
  const l = await login(f);
  const tampered = l.jar.replace(/(__Host-soca_session=[^.]+\.[^.]+\.)(.)/, (_, prefix, ch) => prefix + (ch === 'A' ? 'B' : 'A'));
  assert.equal((await f.handler(event('/private', { cookies: tampered }))).status, '303');
  for (const config of [{ deny_domains: ['example.com'] }, { enabled: false }]) {
    const changed = prepare({ ...f.deployment.config, ...config }, f.deployment);
    const handler = createHandler(changed, { fetchJson: () => { throw new Error('No network'); } });
    assert.notEqual((await handler(event('/private', { cookies: l.jar }))).uri, '/private');
  }
});

test('parallel logins after browser binding use independent cookies and respect the pending cap', async () => {
  const f = fixture();
  let jar = '';
  const starts = [];
  for (let i = 0; i < 4; i++) {
    const s = await f.handler(event('/_soca/login', { cookies: jar }));
    assert.equal(s.status, '303');
    starts.push(s);
    jar = cookieJar(s, jar);
  }
  assert.equal((await f.handler(event('/_soca/login', { cookies: jar }))).status, '403');
  for (const s of starts) {
    const callback = f.provider.authorise(s.headers.location[0].value);
    const finish = await f.handler(event(callback.href, { cookies: jar }));
    assert.equal(finish.status, '303');
    jar = cookieJar(finish, jar);
  }
});

test('safe return URLs and CSRF-protected local logout survive provider failure', async () => {
  const f = fixture();
  for (const value of ['https://evil.example', '//evil.example', '/_soca/login', '/%2f%2fevil.example', '/private#fragment']) {
    assert.equal((await f.handler(event(`/_soca/login?return_to=${encodeURIComponent(value)}`))).status, '403');
  }
  const l = await login(f, { returnTo: '/private?tab=1' });
  assert.equal(l.finish.headers.location[0].value, 'https://static.example.com/private?tab=1');
  assert.equal((await f.handler(event('/_soca/logout', { method: 'POST', cookies: l.jar }))).status, '403');
  const result = await f.handler(event('/_soca/logout', { method: 'POST', cookies: l.jar, headers: { origin: [{ value: 'https://static.example.com' }] } }));
  assert.equal(result.status, '200');
  assert.ok(result.headers['set-cookie'].every(h => h.value.includes('Max-Age=0')));
  assert.ok(result.body.includes('signed out'));
});

test('freshness and explicit assurance policy use validated auth_time/acr/amr', async () => {
  const f = fixture({ max_age_seconds: 60, required_acr: ['urn:example:mfa'], required_amr: ['otp'] });
  const failed = await login(f);
  assert.equal(failed.finish.status, '403');
  const passed = await login(f, { claims: { auth_time: Math.floor(Date.now() / 1000), acr: 'urn:example:mfa', amr: ['pwd', 'otp'] } });
  assert.equal(passed.finish.status, '303');
});

test('provider metadata incompatibility and expired trust fail closed', async () => {
  const f = fixture();
  f.provider.discovery.client_id_metadata_document_supported = false;
  assert.equal((await f.handler(event('/_soca/login'))).status, '403');
  const g = fixture();
  const l = await login(g);
  assert.equal(l.finish.status, '303');
  g.advance(301);
  g.provider.discovery.issuer = 'https://evil.example';
  assert.equal((await g.handler(event('/_soca/login'))).status, '403');
});
