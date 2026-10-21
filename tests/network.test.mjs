import test from 'node:test';
import assert from 'node:assert/strict';
import { publicAddress, resolvePublic, requestJson } from '../src/network.mjs';
import { httpsUrl } from '../src/config.mjs';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request } from 'node:https';

test('network policy rejects private, loopback, link-local, mapped and reserved addresses', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.1.1.1', '::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1', '2001:db8::1']) assert.equal(publicAddress(ip), false, ip);
  for (const ip of ['8.8.8.8', '2606:4700:4700::1111']) assert.equal(publicAddress(ip), true, ip);
});

test('mixed DNS answers fail closed and selected public address is pinned', async () => {
  await assert.rejects(resolvePublic('example.com', async () => [{ address: '8.8.8.8', family: 4 }, { address: '::1', family: 6 }]));
  await assert.rejects(resolvePublic('example.com', async () => []));
  assert.deepEqual(await resolvePublic('example.com', async () => [{ address: '8.8.8.8', family: 4 }]), { address: '8.8.8.8', family: 4 });
});

test('HTTPS endpoint validation rejects redirects through credentials, ports and unsafe schemes', async () => {
  for (const value of ['http://example.com', 'https://user:pass@example.com', 'https://example.com/#x', 'file:///etc/passwd']) assert.throws(() => httpsUrl(value));
  await assert.rejects(requestJson('https://example.com:8443/'));
  await assert.rejects(requestJson('https://127.0.0.1/'));
});

test('real Node 24 TLS transport: pinned lookup, POST, redirects, invalid/oversized JSON and TLS verification', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'soca-tls-'));
  let server;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
    const cert = await readFile(join(dir, 'cert.pem'));
    server = createServer({ key: await readFile(join(dir, 'key.pem')), cert }, (req, res) => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/redirect') { res.writeHead(302, { location: '/ok' }); res.end('{}'); }
      else if (req.url === '/large') res.end(JSON.stringify({ a: 'x'.repeat(140000) }));
      else if (req.url === '/invalid') res.end('not JSON');
      else if (req.url === '/type') { res.setHeader('content-type', 'text/html'); res.end('{}'); }
      else { let data = ''; req.on('data', c => { data += c; }); req.on('end', () => res.end(JSON.stringify({ ok: true, method: req.method, data }))); }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const deps = {
      resolveEndpoint: async () => ({ address: '127.0.0.1', family: 4 }),
      send: (url, options, cb) => request(`https://localhost:${server.address().port}${url.pathname}`, { ...options, ca: cert }, cb),
    };
    assert.deepEqual(await requestJson('https://public.example/ok', {}, deps), { ok: true, method: 'GET', data: '' });
    assert.deepEqual(await requestJson('https://public.example/ok', { body: 'a=b' }, deps), { ok: true, method: 'POST', data: 'a=b' });
    for (const path of ['/redirect', '/large', '/invalid', '/type']) await assert.rejects(requestJson(`https://public.example${path}`, {}, deps));
    await assert.rejects(requestJson('https://public.example/ok', {}, { ...deps, send: (url, options, cb) => request(`https://localhost:${server.address().port}${url.pathname}`, options, cb) }));
  } finally { if (server) await new Promise(resolve => server.close(resolve)); await rm(dir, { recursive: true, force: true }); }
});
