import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { createHandler } from '../src/runtime.mjs';
import { newKeys, prepare } from '../generator/package.mjs';
import { simulatedProvider } from './provider.mjs';

export async function startDemo(port = 8443) {
  const directory = await mkdtemp(join(tmpdir(), 'soca-demo-'));
  let cert, key;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem')], { stdio: 'ignore' });
    cert = await readFile(join(directory, 'cert.pem'));
    key = await readFile(join(directory, 'key.pem'));
  } finally { await rm(directory, { recursive: true, force: true }); }
  const origin = `https://localhost:${port}`;
  const deployment = prepare({ origin, issuer: 'https://simulated-idp.example', enabled: true, allow_domains: ['example.com'], client_name: 'Local SOCA simulator' }, newKeys());
  const provider = simulatedProvider(deployment);
  const handler = createHandler(deployment, { fetchJson: provider.fetchJson });
  const server = createServer({ cert, key }, async (req, res) => {
    try {
      const url = new URL(req.url, origin);
      if (url.pathname === '/_demo/authorize') {
        const callback = provider.authorise(url.href);
        res.writeHead(303, { location: callback.href, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
        res.end();
        return;
      }
      const headers = Object.fromEntries(Object.entries(req.headers).map(([name, value]) => [name, [{ value: String(value) }]]));
      const result = await handler({ Records: [{ cf: { config: { eventType: 'viewer-request' }, request: { method: req.method, uri: url.pathname, querystring: url.search.slice(1), headers } } }] });
      if (result.status) {
        const out = Object.fromEntries(Object.entries(result.headers).map(([name, values]) => [name, values.map(v => v.value)]));
        if (out.location?.[0]?.startsWith(deployment.config.issuer)) {
          const location = new URL(out.location[0]);
          out.location = [`${origin}/_demo/authorize${location.search}`];
        }
        res.writeHead(Number(result.status), out);
        res.end(req.method === 'HEAD' ? '' : result.body);
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>SOCA local demo</title><h1>Protected static content</h1><p>The simulated identity provider admitted reader@example.com. This is a local protocol simulation, not an AWS or real-provider deployment.</p><a href="/_soca/logout">Sign out</a></html>');
    } catch { res.writeHead(500); res.end('Demo failed'); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '0.0.0.0', resolve); });
  return { server, cert, origin };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startDemo().then(({ origin }) => console.log(`Local simulation: ${origin} (ephemeral self-signed TLS certificate)`)).catch(() => { console.error('Cannot start demo; check port 8443 and openssl.'); process.exitCode = 1; });
}
