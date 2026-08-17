'use strict';

/**
 * Stage 4 Sec8 — dedicated end-to-end regression coverage for the client-IP
 * trust chain used by every per-IP rate limiter in api/_lib/security.js
 * (globalIpRateLimit, adminIpRateLimit, intentIpRateLimit,
 * submissionIpRateLimit — all four call the same getIp()).
 *
 * Two separate, ORIGINAL-CODE-UNCHANGED pieces have to compose correctly:
 *   1. workers/lib/node-compat.js#toNodeRequest() — Workers-only shim code,
 *      overwrites req.headers['x-forwarded-for'] with cf-connecting-ip when
 *      present (already covered in isolation by node-compat.test.js).
 *   2. api/_lib/security.js#getIp() — original, platform-independent code,
 *      unchanged for this migration, trusts req.headers['x-forwarded-for']
 *      first.
 *
 * node-compat.test.js already proves (1) in isolation. This file proves the
 * two compose correctly end-to-end: a Worker Request carrying a real
 * cf-connecting-ip and a spoofed x-forwarded-for produces the SAME final
 * getIp() value a rate limiter would actually bucket on -- not just that an
 * intermediate header got rewritten.
 *
 * IMPORTANT SCOPE LIMIT, confirmed empirically, not assumed: this file (and
 * node-compat.test.js) can only prove the CODE correctly prefers
 * cf-connecting-ip over a client-supplied x-forwarded-for once Cloudflare
 * has attached it. Neither this file nor any local `wrangler dev` request
 * can prove cf-connecting-ip itself is unspoofable -- a real local probe
 * (Stage 4 Sec8 audit, see SECURITY-MIGRATION-VALIDATION.md) confirmed that
 * `wrangler dev` does NOT protect this header the way Cloudflare's real
 * edge does: a plain curl request with a hand-set `CF-Connecting-IP` header
 * reached the Worker unchanged (no local edge to strip/overwrite it).
 * Production spoof-resistance rests entirely on Cloudflare's edge
 * infrastructure, exactly as it does for every Cloudflare-fronted
 * application -- not on anything testable in this repo.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { toNodeRequest } = require('./node-compat');
const { getIp } = require('../../api/_lib/security');

async function resolvedIp(headers) {
  const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=stats', { headers });
  const req = await toNodeRequest(request);
  return getIp(req);
}

describe('client-IP trust chain (toNodeRequest -> getIp, end-to-end)', () => {
  test('a genuine Cloudflare-supplied cf-connecting-ip is what rate limiting buckets on', async () => {
    const ip = await resolvedIp({ 'CF-Connecting-IP': '203.0.113.9' });
    assert.equal(ip, '203.0.113.9');
  });

  test('cf-connecting-ip wins over a spoofed x-forwarded-for the request also carried', async () => {
    // Simulates an attacker who adds their own X-Forwarded-For, trying to
    // get a rate limiter to bucket them under a different IP than the one
    // Cloudflare's edge actually saw them connect from.
    const ip = await resolvedIp({ 'CF-Connecting-IP': '203.0.113.9', 'X-Forwarded-For': '198.51.100.1' });
    assert.equal(ip, '203.0.113.9', 'spoofed x-forwarded-for must not win over cf-connecting-ip');
  });

  test('cf-connecting-ip wins even against a multi-hop spoofed x-forwarded-for chain', async () => {
    const ip = await resolvedIp({
      'CF-Connecting-IP': '203.0.113.9',
      'X-Forwarded-For': '198.51.100.1, 198.51.100.2, 198.51.100.3',
    });
    assert.equal(ip, '203.0.113.9');
  });

  test('with no cf-connecting-ip at all, falls through to getIp()\'s own x-forwarded-for handling unmodified', async () => {
    // Confirms toNodeRequest() only overwrites x-forwarded-for when
    // cf-connecting-ip is actually present -- it must not invent one, or
    // silently discard a legitimately-forwarded value from elsewhere.
    const ip = await resolvedIp({ 'X-Forwarded-For': '198.51.100.1, 198.51.100.2' });
    assert.equal(ip, '198.51.100.1', 'getIp() itself takes the leftmost XFF entry');
  });

  test('with no IP-bearing headers at all, resolves to the documented 0.0.0.0 fallback without throwing', async () => {
    // req has no .socket in the Workers shim (toNodeRequest builds a plain
    // object) -- confirms getIp()'s `req.socket?.remoteAddress` optional
    // chaining is actually exercised safely here, not just in Vercel's
    // real IncomingMessage case where req.socket does exist.
    const ip = await resolvedIp({});
    assert.equal(ip, '0.0.0.0');
  });

  test('an IPv6 cf-connecting-ip is preserved, not truncated (well under the 45-char cap)', async () => {
    const ip = await resolvedIp({ 'CF-Connecting-IP': '2001:db8::1' });
    assert.equal(ip, '2001:db8::1');
  });
});
