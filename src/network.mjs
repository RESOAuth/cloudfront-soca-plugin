import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import ipaddr from 'ipaddr.js';
import { ensure, httpsUrl } from './config.mjs';

export function publicAddress(address) {
  try { return ipaddr.process(address).range() === 'unicast'; } catch { return false; }
}

export async function resolvePublic(hostname, resolver = lookup) {
  const records = await resolver(hostname.replace(/^\[|\]$/g, ''), { all: true, verbatim: true });
  ensure(records.length > 0 && records.every(r => publicAddress(r.address)), 'Endpoint DNS must resolve only to public addresses');
  return records[0];
}

// No redirects, pooled sockets, proxy environment variables or unpinned DNS lookup.
export async function requestJson(value, { body } = {}, { resolveEndpoint = resolvePublic, send = request } = {}) {
  const url = httpsUrl(value);
  ensure(!url.port || url.port === '443', 'Outbound HTTPS uses port 443 only');
  const signal = AbortSignal.timeout(5000);
  const resolved = await Promise.race([
    resolveEndpoint(url.hostname),
    new Promise((_, reject) => signal.addEventListener('abort', () => reject(new Error('Network deadline')), { once: true })),
  ]);
  return new Promise((resolve, reject) => {
    const req = send(url, {
      method: body === undefined ? 'GET' : 'POST', agent: false, signal,
      lookup: (_host, options, cb) => options.all ? cb(null, [resolved]) : cb(null, resolved.address, resolved.family),
      headers: {
        accept: 'application/json', 'accept-encoding': 'identity',
        ...(body === undefined ? {} : { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) }),
      },
    }, res => {
      let size = 0;
      const chunks = [];
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 131072) res.destroy(new Error('Response too large'));
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        try {
          ensure(res.statusCode === 200, 'Remote endpoint did not return 200');
          ensure(/^application\/(?:[a-z0-9.+-]+\+)?json(?:;|$)/i.test(res.headers['content-type'] ?? ''), 'Expected JSON content type');
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          ensure(data && typeof data === 'object' && !Array.isArray(data), 'Expected JSON object');
          resolve(data);
        } catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}
