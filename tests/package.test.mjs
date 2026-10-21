import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { unzipSync } from 'fflate';
import { DEFAULT_PROXY, admitted, documents, normalise } from '../src/config.mjs';
import { newKeys, packageZip, prepare, saveNewKeys } from '../generator/package.mjs';
import { createHandler } from '../src/runtime.mjs';
import { event, fixture, login } from './helpers.mjs';

const config = { origin: 'https://static.example.com' };

test('generator defaults, seconds override, stable key reuse and secret file permissions', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'soca-keys-'));
  try {
    const path = join(dir, 'keys.json');
    await saveNewKeys(path);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    await assert.rejects(saveNewKeys(path));
    const keys = JSON.parse(await readFile(path));
    const a = prepare(config, keys);
    assert.equal(a.config.enabled, false);
    assert.equal(a.config.session_ttl_seconds, 43200);
    assert.deepEqual(a, prepare(config, keys));
    assert.equal(prepare(config, keys, { SOCA_SESSION_TTL_SECONDS: '120' }).config.session_ttl_seconds, 120);
    for (const value of ['0', '-1', 'abc', '1.5', '604801']) assert.throws(() => prepare(config, keys, { SOCA_SESSION_TTL_SECONDS: value }));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('generated ZIP is reproducible, private and independently executable without node_modules', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'soca-zip-'));
  try {
    const f = fixture();
    const l = await login(f);
    const first = join(dir, 'one.zip');
    const result = await packageZip(f.deployment, first);
    assert.ok(result.bytes < 150000);
    assert.equal((await stat(first)).mode & 0o777, 0o600);
    await packageZip(f.deployment, join(dir, 'two.zip'));
    assert.deepEqual(await readFile(first), await readFile(join(dir, 'two.zip')));
    await assert.rejects(packageZip(f.deployment, first));
    const files = unzipSync(await readFile(first));
    assert.deepEqual(Object.keys(files).sort(), ['LICENSE', 'deployment.json', 'index.mjs']);
    for (const [name, bytes] of Object.entries(files)) await writeFile(join(dir, name), bytes, { mode: 0o600 });
    const bundle = await import(pathToFileURL(join(dir, 'index.mjs')).href);
    assert.equal((await bundle.handler(event('/_soca/jwks.json'))).status, '200');
    assert.equal((await bundle.handler(event('/private', { cookies: l.jar }))).uri, '/private');
    const text = Buffer.from(files['index.mjs']).toString();
    assert.ok(!text.includes('simulatedProvider'));
    assert.ok(!text.includes('aws-sdk'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('manual two-stage key overlap preserves old sessions and rejects removed/revoked keys', async () => {
  const f = fixture();
  const l = await login(f);
  const next = newKeys();
  const ring = { ...f.deployment, session_keys: [...next.session_keys, ...f.deployment.session_keys], public_keys: [...f.deployment.public_keys, ...next.public_keys] };
  const handler = createHandler(prepare(f.deployment.config, ring));
  assert.equal((await handler(event('/private', { cookies: l.jar }))).uri, '/private');
  const removed = createHandler(prepare(f.deployment.config, { ...ring, session_keys: next.session_keys }));
  assert.equal((await removed(event('/private', { cookies: l.jar }))).status, '303');
  const revoked = createHandler(prepare({ ...f.deployment.config, security_epoch: 1 }, ring));
  assert.equal((await revoked(event('/private', { cookies: l.jar }))).status, '303');
});

test('hosted and proxy documents are deterministic, stable through public-key overlap and public only', () => {
  const keys = newKeys();
  const c = normalise({ ...config, metadata_mode: 'proxy', allow_domains: ['private.example'] });
  const docs = documents(c, keys.public_keys);
  assert.ok(docs.client_id.startsWith(DEFAULT_PROXY.replace('%s', '')));
  const decoded = JSON.parse(Buffer.from(docs.client_id.split('/').at(-1), 'base64url'));
  assert.equal(decoded.client_id, undefined);
  assert.equal(decoded.jwks_uri, 'https://static.example.com/_soca/jwks.json');
  assert.equal(decoded.allow_domains, undefined);
  assert.deepEqual(documents(c, [...keys.public_keys, ...newKeys().public_keys]).client_id, docs.client_id);
  assert.equal(documents(normalise(config), keys.public_keys).client_id, 'https://static.example.com/_soca/client.json');
});

for (const changes of [
  { allow_domains: ['*example.com'] }, { allow_domains: ['localhost'] }, { allow_domains: ['a..example.com'] },
  { deny_domains: ['https://example.com'] }, { allow_emails: ['a@example.com@evil.example'] },
  { origin: 'https://example.com/' }, { origin: 'http://example.com' },
  { protected_paths: ['/private/'] }, { auth_path: '/' }, { enabled: 'true' },
  { unknown: true }, { proxy_template: 'https://%s.example.com/cimd' }, { proxy_template: 'https://example.com/cimd?x=%s' },
  { scopes: ['openid', 'offline_access'] }, { security_epoch: -1 },
]) test(`invalid configuration rejected: ${JSON.stringify(changes)}`, () => assert.throws(() => normalise({ ...config, ...changes })));

test('domain label matching, wildcard depth, case folding, deny precedence and default deny', () => {
  const c = normalise({ ...config, allow_domains: ['*.Example.com'], deny_domains: ['blocked.example.com'] });
  const claim = email => ({ email, email_verified: true });
  assert.equal(admitted(c, claim('A@a.b.EXAMPLE.com')), true);
  for (const e of ['a@example.com', 'a@badexample.com', 'a@blocked.example.com', 'a@a..example.com']) assert.equal(admitted(c, claim(e)), false);
  assert.equal(admitted(normalise(config), claim('a@example.com')), false);
});

test('private public-JWKS entries and duplicate/mismatched key IDs are rejected before packaging', () => {
  const keys = newKeys();
  for (const changed of [
    { ...keys, public_keys: [{ ...keys.public_keys[0], d: keys.signing_key.d }] },
    { ...keys, signing_key: { ...keys.signing_key, kid: 'wrong' } },
    { ...keys, session_keys: [keys.session_keys[0], keys.session_keys[0]] },
    { ...keys, public_keys: [keys.public_keys[0], keys.public_keys[0]] },
    { ...keys, session_keys: [{ kid: 'validkeyid', key: 'weak' }] },
  ]) assert.throws(() => prepare(config, changed));
});
