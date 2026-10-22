import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:https';
import { startDemo } from '../demo/server.mjs';

test('local HTTPS demo completes browser redirects, session gating and same-origin logout', async () => {
  const { server, cert, origin } = await startDemo(18443);
  const jar = new Map();
  const get = (url, method = 'GET') => new Promise((resolve, reject) => {
    const req = request(url, { method, ca: cert, headers: { cookie: [...jar].map(p => p.join('=')).join('; '), ...(method === 'POST' ? { origin } : {}) } }, res => {
      for (const c of res.headers['set-cookie'] ?? []) {
        const [name, value] = c.split(';')[0].split('=');
        if (value) jar.set(name, value); else jar.delete(name);
      }
      let body = '';
      res.on('data', b => { body += b; });
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location, body }));
    });
    req.on('error', reject); req.end();
  });
  try {
    let result = await get(`${origin}/private/file.html`);
    assert.equal(result.status, 303);
    for (let i = 0; i < 4; i++) { assert.ok(result.location.startsWith(origin)); result = await get(result.location); }
    assert.equal(result.status, 200);
    assert.match(result.body, /Protected static content/);
    assert.equal((await get(`${origin}/_soca/logout`, 'POST')).status, 200);
    assert.equal((await get(`${origin}/private/file.html`)).status, 303);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
