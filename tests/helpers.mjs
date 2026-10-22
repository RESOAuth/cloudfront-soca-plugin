import assert from 'node:assert/strict';
import { createHandler } from '../src/runtime.mjs';
import { prepare, newKeys } from '../generator/package.mjs';
import { simulatedProvider } from '../demo/provider.mjs';

export function event(path, { method = 'GET', cookies = '', headers = {} } = {}) {
  const u = new URL(path, 'https://static.example.com');
  return { Records: [{ cf: { config: { eventType: 'viewer-request' }, request: {
    uri: u.pathname, querystring: u.search.slice(1), method,
    headers: { host: [{ value: 'static.example.com' }], ...(cookies ? { cookie: [{ value: cookies }] } : {}), ...headers },
  } } }] };
}

export function cookieJar(response, previous = '') {
  const jar = new Map(previous.split('; ').filter(Boolean).map(p => p.split('=')));
  for (const h of response.headers?.['set-cookie'] ?? []) {
    const [name, value] = h.value.split(';')[0].split('=');
    if (!value) jar.delete(name); else jar.set(name, value);
  }
  return [...jar].map(p => p.join('=')).join('; ');
}

export function fixture(overrides = {}) {
  let time = Math.floor(Date.now() / 1000);
  const deployment = prepare({ origin: 'https://static.example.com', enabled: true, allow_domains: ['example.com'], ...overrides }, newKeys());
  const provider = simulatedProvider(deployment, () => time);
  const handler = createHandler(deployment, { fetchJson: provider.fetchJson, now: () => time });
  return { deployment, provider, handler, now: () => time, advance: seconds => { time += seconds; } };
}

export async function login(f, { claims, headers, jar = '', returnTo = '/private/file.txt' } = {}) {
  const start = await f.handler(event(`/_soca/login?return_to=${encodeURIComponent(returnTo)}`, { cookies: jar }));
  assert.equal(start.status, '303');
  jar = cookieJar(start, jar);
  const callback = f.provider.authorise(start.headers.location[0].value, claims, headers);
  const finish = await f.handler(event(callback.href, { cookies: jar }));
  return { start, finish, callback, transactionJar: jar, jar: cookieJar(finish, jar) };
}
