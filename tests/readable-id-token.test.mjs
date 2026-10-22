import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { createHandler } from '../src/runtime.mjs';
import { cookieJar, event, fixture, login } from './helpers.mjs';

const NAME = '__Host-soca_id_token';
const header = response => response.headers['set-cookie']?.find(h => h.value.startsWith(`${NAME}=`))?.value;
const value = response => header(response)?.split(';')[0].slice(NAME.length + 1);

test('readable ID-token cookie is absent by default', async () => {
  const l = await login(fixture());
  assert.equal(l.finish.status, '303');
  assert.equal(header(l.finish), undefined);
});

test('opt-in publishes the complete original provider JWT for JavaScript, keeping the session HttpOnly', async () => {
  const f = fixture({ enable_readable_id_token_cookie: true });
  let original;
  f.handler = createHandler(f.deployment, {
    now: f.now,
    fetchJson: async (...args) => {
      const result = await f.provider.fetchJson(...args);
      if (result.id_token) original = result.id_token;
      return result;
    },
  });
  const l = await login(f, { claims: { name: 'A Reader', custom_claim: { department: 'Research' } } });
  assert.equal(l.finish.status, '303');
  assert.equal(value(l.finish), original);
  assert.match(header(l.finish), /; Path=\/; Max-Age=300; Secure; SameSite=Lax$/);
  assert.ok(!header(l.finish).includes('HttpOnly'));
  assert.ok(!header(l.finish).includes('Domain='));
  const session = l.finish.headers['set-cookie'].find(h => h.value.startsWith('__Host-soca_session='));
  assert.match(session.value, /; Secure; HttpOnly; SameSite=Lax$/);
  assert.ok(!session.value.includes(original));
  const { payload } = await jwtVerify(value(l.finish), createLocalJWKSet({ keys: f.provider.pair.public_keys }), {
    issuer: f.deployment.config.issuer, audience: 'https://static.example.com/_soca/client.json', algorithms: ['ES256'],
  });
  assert.equal(payload.name, 'A Reader');
  assert.deepEqual(payload.custom_claim, { department: 'Research' });
  await assert.rejects(jwtVerify(value(l.finish), createLocalJWKSet({ keys: f.deployment.public_keys }), { algorithms: ['ES256'] }));
});

test('readable lifetime is bounded by both token expiry and the configured session lifetime', async () => {
  for (const ttl of [60, 43200]) {
    const f = fixture({ enable_readable_id_token_cookie: true, session_ttl_seconds: ttl });
    const l = await login(f);
    assert.equal(l.finish.status, '303');
    assert.ok(header(l.finish).includes(`Max-Age=${Math.min(ttl, 300)};`));
  }
  const f = fixture({ enable_readable_id_token_cookie: true });
  const l = await login(f, { claims: { iat: f.now() - 10, exp: f.now() - 1 } });
  assert.equal(l.finish.status, '403');
  assert.equal(header(l.finish), undefined);
});

test('invalid or unadmitted ID tokens never publish a readable cookie or new session', async () => {
  for (const claims of [{ nonce: 'wrong' }, { email: 'reader@evil.example' }, { email_verified: false }]) {
    const l = await login(fixture({ enable_readable_id_token_cookie: true }), { claims });
    assert.equal(l.finish.status, '403');
    assert.equal(header(l.finish), undefined);
    assert.ok(!l.finish.headers['set-cookie'].some(h => h.value.startsWith('__Host-soca_session=')));
  }
});

test('token exchange time cannot extend the readable cookie beyond the encrypted session expiry', async () => {
  const f = fixture({ enable_readable_id_token_cookie: true, session_ttl_seconds: 60 });
  f.handler = createHandler(f.deployment, {
    now: f.now,
    fetchJson: async (url, options) => {
      if (options?.body) f.advance(10);
      return f.provider.fetchJson(url, options);
    },
  });
  const l = await login(f);
  assert.equal(l.finish.status, '303');
  assert.match(header(l.finish), /; Max-Age=50;/);
});

test('oversized full JWT fails opted-in login without truncation or a partial session', async () => {
  const claims = { large_claim: 'x'.repeat(3000) };
  const on = await login(fixture({ enable_readable_id_token_cookie: true }), { claims });
  assert.equal(on.finish.status, '403');
  assert.equal(header(on.finish), undefined);
  assert.ok(!on.finish.headers['set-cookie'].some(h => h.value.startsWith('__Host-soca_session=')));
  assert.equal((await login(fixture(), { claims })).finish.status, '303');
});

test('readable cookie grants no access and is stripped from both protected and public origin requests', async () => {
  const f = fixture({ enable_readable_id_token_cookie: true, public_paths: ['/public'] });
  const l = await login(f);
  const raw = `${NAME}=${value(l.finish)}`;
  assert.equal((await f.handler(event('/private', { cookies: raw }))).status, '303');
  const tampered = l.jar.replace(raw, `${NAME}=client-modified`);
  const asset = await f.handler(event('/private', { cookies: `${tampered}; preference=dark` }));
  assert.equal(asset.uri, '/private');
  assert.equal(asset.headers.cookie[0].value, ' preference=dark');
  const publicAsset = await f.handler(event('/public', { cookies: raw }));
  assert.equal(publicAsset.uri, '/public');
  assert.equal(publicAsset.headers.cookie, undefined);
  assert.equal(f.provider.calls.length, 3);
});

test('logout and successful sign-in with the option off remove an existing readable cookie', async () => {
  const f = fixture({ enable_readable_id_token_cookie: true });
  const l = await login(f);
  const signedOut = await f.handler(event('/_soca/logout', {
    method: 'POST', cookies: l.jar, headers: { origin: [{ value: f.deployment.config.origin }] },
  }));
  assert.equal(signedOut.status, '200');
  assert.equal(header(signedOut), `${NAME}=; Path=/; Max-Age=0; Secure; SameSite=Lax`);
  assert.ok(!cookieJar(signedOut, l.jar).includes(`${NAME}=`));
  const off = await login(fixture(), { jar: `${NAME}=${value(l.finish)}` });
  assert.equal(off.finish.status, '303');
  assert.equal(header(off.finish), `${NAME}=; Path=/; Max-Age=0; Secure; SameSite=Lax`);
});
