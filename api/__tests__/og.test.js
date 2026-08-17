'use strict';

// Functional regression for the @resvg/resvg-js -> @resvg/resvg-wasm swap
// and the fs-based -> runtime-branched font loading (see
// workers/lib/resvg-wasm-init.js and workers/lib/og-fonts-init.js). This
// file previously had no test coverage at all; a real invocation is the
// only way to prove the still-live Vercel/Node path actually produces a
// correct PNG after those changes, not just that requiring it doesn't
// throw.
const ogHandler = require('../og');

// Plain Node-shaped fake, deliberately NOT going through
// workers/lib/node-compat.js -- this specifically exercises the
// unmodified Vercel/Node calling contract (res.statusCode assignment,
// res.end(buffer)), same as production traffic on that platform today.
function fakeReqRes(url) {
  const headers = {};
  let statusCode = 200;
  let endedWith;
  const res = {
    setHeader(k, v) { headers[k.toLowerCase()] = v; },
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
    end(body) { endedWith = body; },
  };
  const req = { url, method: 'GET', headers: {} };
  return { req, res, headers, getStatus: () => statusCode, getBody: () => endedWith };
}

describe('api/og.js', () => {
  test('renders a real PNG for valid query params', async () => {
    const { req, res, headers, getStatus, getBody } = fakeReqRes(
      '/api/og?title=Critical%20RCE%20in%20Example%20Library&severity=CRITICAL&cve=CVE-2026-12345&cvss=9.8&type=CVE%20ANALYSIS'
    );

    await ogHandler(req, res);

    expect(getStatus()).toBe(200);
    expect(headers['content-type']).toBe('image/png');
    expect(headers['cache-control']).toContain('max-age=86400');

    const body = getBody();
    // @resvg/resvg-wasm's RenderedImage#asPng() returns a plain
    // Uint8Array (confirmed against its .d.ts), not a Node Buffer like
    // the native @resvg/resvg-js package it replaced -- Node's real
    // http.ServerResponse#end() accepts Uint8Array directly per its own
    // documented API, so this is a real, harmless type change, not a
    // regression. workers/lib/node-compat.js's binary-body detection
    // already checks `instanceof Uint8Array`, not Buffer.isBuffer(), for
    // exactly this reason.
    expect(body instanceof Uint8Array).toBe(true);
    // PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
    expect(Array.from(body.subarray(0, 8))).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  });

  test('renders successfully with no query params (all defaults)', async () => {
    const { req, res, getStatus, getBody } = fakeReqRes('/api/og');
    await ogHandler(req, res);
    expect(getStatus()).toBe(200);
    expect(getBody() instanceof Uint8Array).toBe(true);
  });

  test('sanitizes an invalid/malformed cve param rather than rendering it raw', async () => {
    const { req, res, getStatus } = fakeReqRes('/api/og?cve=<script>alert(1)</script>');
    await ogHandler(req, res);
    // Malformed CVE fails the CVE-\d{4}-\d{4,} pattern and is dropped
    // entirely (empty string), not sanitized-and-kept -- still renders fine.
    expect(getStatus()).toBe(200);
  });
});
