import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { strToU8, zipSync } from 'fflate';
import { digest, documents, ensure, normalise, stable } from '../src/config.mjs';

export function publicKey(jwk) {
  const key = createPublicKey(createPrivateKey({ key: jwk, format: 'jwk' })).export({ format: 'jwk' });
  ensure(key.kty === 'EC' && key.crv === 'P-256', 'Only P-256 signing keys are supported');
  return { kty: key.kty, crv: key.crv, x: key.x, y: key.y, kid: digest(key), use: 'sig', alg: 'ES256' };
}

export function newKeys() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const signing = pair.privateKey.export({ format: 'jwk' });
  const pub = publicKey(signing);
  return { signing_key: { ...signing, kid: pub.kid, alg: 'ES256' }, public_keys: [pub], session_keys: [{ kid: randomBytes(12).toString('base64url'), key: randomBytes(32).toString('base64url') }] };
}

export function prepare(config, keys, env = {}) {
  const override = env.SOCA_SESSION_TTL_SECONDS;
  const c = normalise({ ...config, ...(override === undefined ? {} : { session_ttl_seconds: Number(override) }) });
  const pub = publicKey(keys.signing_key);
  ensure(keys.signing_key.kid === pub.kid && keys.signing_key.alg === 'ES256', 'Signing key metadata does not match its material');
  ensure(Array.isArray(keys.public_keys) && keys.public_keys.length > 0 && keys.public_keys.length <= 3, 'Invalid public signing keyring');
  ensure(keys.public_keys.some(k => stable(k) === stable(pub)), 'Active signing key is missing from JWKS');
  for (const key of keys.public_keys) {
    ensure(Object.keys(key).every(k => ['kty', 'crv', 'x', 'y', 'kid', 'use', 'alg'].includes(k)), 'Public JWKS contains forbidden fields');
    ensure(key.kty === 'EC' && key.crv === 'P-256' && key.alg === 'ES256' && key.use === 'sig', 'Invalid public key');
    ensure(typeof key.kid === 'string' && key.kid.length <= 64, 'Invalid signing key ID');
    createPublicKey({ key, format: 'jwk' });
  }
  ensure(new Set(keys.public_keys.map(k => k.kid)).size === keys.public_keys.length, 'Duplicate signing key ID');
  ensure(Array.isArray(keys.session_keys) && keys.session_keys.length > 0 && keys.session_keys.length <= 3, 'Invalid session keyring');
  for (const k of keys.session_keys) ensure(/^[A-Za-z0-9_-]{8,64}$/.test(k.kid) && /^[A-Za-z0-9_-]{43}$/.test(k.key) && Buffer.from(k.key, 'base64url').length === 32, 'Session keys must be 32-byte base64url values');
  ensure(new Set(keys.session_keys.map(k => k.kid)).size === keys.session_keys.length, 'Duplicate session key ID');
  const deployment = { config: c, signing_key: keys.signing_key, public_keys: keys.public_keys, session_keys: keys.session_keys };
  deployment.revision = digest({ config: c, public_keys: keys.public_keys, session_ids: keys.session_keys.map(k => k.kid) });
  documents(c, keys.public_keys);
  return deployment;
}

export async function saveNewKeys(path) {
  await mkdir(dirname(resolve(path)), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(newKeys(), null, 2)}\n`, { mode: 0o600, flag: 'wx' });
}

export async function readDeployment(configPath, keyPath, env = {}) {
  return prepare(JSON.parse(await readFile(configPath, 'utf8')), JSON.parse(await readFile(keyPath, 'utf8')), env);
}

export async function packageZip(deployment, output) {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const result = await build({
    stdin: { contents: `import { readFileSync } from 'node:fs'; import { createHandler } from './src/runtime.mjs'; const deployment = JSON.parse(readFileSync(new URL('./deployment.json', import.meta.url), 'utf8')); export const handler = createHandler(deployment);`, resolveDir: root },
    bundle: true, platform: 'node', target: 'node24', format: 'esm', write: false, minify: true, legalComments: 'eof',
  });
  // Fixed timestamps make identical source/config/keys produce identical archives.
  const options = { mtime: new Date('2020-01-01T00:00:00Z'), os: 3, attrs: 0o100644 << 16 };
  const archive = zipSync({
    'index.mjs': [result.outputFiles[0].contents, options],
    'deployment.json': [strToU8(stable(deployment)), options],
    'LICENSE': [new Uint8Array(await readFile(new URL('../LICENSE', import.meta.url))), options],
  }, { level: 9 });
  ensure(archive.length < 5 * 1024 * 1024, 'Deployment ZIP exceeds the MVP size budget');
  await mkdir(dirname(resolve(output)), { recursive: true, mode: 0o700 });
  // Exclusive create prevents overwriting a symlink or weakening an existing file's mode.
  await writeFile(output, archive, { mode: 0o600, flag: 'wx' });
  return { bytes: archive.length, revision: deployment.revision };
}
