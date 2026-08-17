'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { toNodeRequest, createNodeResponse } = require('./node-compat');

describe('toNodeRequest', () => {
  test('GET request: method, url, lowercased headers, parsed query, no body', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=live&x=1', {
      method: 'GET',
      headers: { 'X-API-Key': 'sentinel_abc', Accept: 'application/json' },
    });
    const req = await toNodeRequest(request);
    assert.equal(req.method, 'GET');
    assert.equal(req.url, '/api/v1/intel?action=live&x=1');
    assert.equal(req.headers['x-api-key'], 'sentinel_abc');
    assert.equal(req.headers['accept'], 'application/json');
    assert.deepEqual(req.query, { action: 'live', x: '1' });
    assert.equal(req.body, undefined);
    assert.equal(req.__cfRequest, undefined);
  });

  test('cf-connecting-ip overrides a client-spoofed x-forwarded-for', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=stats', {
      headers: { 'CF-Connecting-IP': '203.0.113.9', 'X-Forwarded-For': '1.2.3.4' },
    });
    const req = await toNodeRequest(request);
    assert.equal(req.headers['x-forwarded-for'], '203.0.113.9');
  });

  test('cf-connecting-ip populates x-forwarded-for when absent', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=stats', {
      headers: { 'CF-Connecting-IP': '203.0.113.9' },
    });
    const req = await toNodeRequest(request);
    assert.equal(req.headers['x-forwarded-for'], '203.0.113.9');
  });

  test('no cf-connecting-ip: x-forwarded-for left untouched (absent stays absent)', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=stats');
    const req = await toNodeRequest(request);
    assert.equal('x-forwarded-for' in req.headers, false);
  });

  test('POST application/json body is parsed into req.body', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/auth?action=register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'a@b.com' }),
    });
    const req = await toNodeRequest(request);
    assert.deepEqual(req.body, { email: 'a@b.com' });
  });

  test('POST with empty JSON body does not throw and yields {}', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/auth?action=register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '',
    });
    const req = await toNodeRequest(request);
    assert.deepEqual(req.body, {});
  });

  test('POST application/x-www-form-urlencoded body is parsed into a plain object', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/billing?action=subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'plan=pro&email=a%40b.com',
    });
    const req = await toNodeRequest(request);
    assert.deepEqual(req.body, { plan: 'pro', email: 'a@b.com' });
  });

  test('bodyParser:false config defers to __cfRequest instead of parsing JSON', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/billing/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': 't=1,v1=abc' },
      body: JSON.stringify({ type: 'checkout.session.completed' }),
    });
    const req = await toNodeRequest(request, { api: { bodyParser: false } });
    assert.equal(req.body, undefined);
    assert.equal(req.__cfRequest, request);
  });

  test('GET/HEAD/OPTIONS never attempt body parsing even with a content-type header', async () => {
    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
      const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=stats', {
        method,
        headers: { 'Content-Type': 'application/json' },
      });
      const req = await toNodeRequest(request);
      assert.equal(req.body, undefined, `expected no body parsing for ${method}`);
      assert.equal(req.__cfRequest, undefined, `expected no __cfRequest for ${method}`);
    }
  });
});

describe('createNodeResponse', () => {
  test('res.status(200).json(x) resolves a matching Response', async () => {
    const { res, response } = createNodeResponse();
    res.status(200).json({ success: true });
    const r = await response;
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'application/json');
    assert.deepEqual(await r.json(), { success: true });
  });

  test('res.status(204).end() resolves a null-body Response without throwing', async () => {
    const { res, response } = createNodeResponse();
    res.status(204).end();
    const r = await response;
    assert.equal(r.status, 204);
    assert.equal(r.body, null);
  });

  test('res.setHeader accumulates multiple headers onto the final Response', async () => {
    const { res, response } = createNodeResponse();
    res.setHeader('X-RateLimit-Limit', '100');
    res.setHeader('X-RateLimit-Remaining', '99');
    res.status(200).json({ ok: true });
    const r = await response;
    assert.equal(r.headers.get('x-ratelimit-limit'), '100');
    assert.equal(r.headers.get('x-ratelimit-remaining'), '99');
  });

  test('res.send(string) does not clobber an already-set Content-Type', async () => {
    const { res, response } = createNodeResponse();
    res.setHeader('Content-Type', 'text/csv');
    res.status(200).send('a,b,c\n1,2,3');
    const r = await response;
    assert.equal(r.headers.get('content-type'), 'text/csv');
    assert.equal(await r.text(), 'a,b,c\n1,2,3');
  });

  test('res.send(object) delegates to res.json', async () => {
    const { res, response } = createNodeResponse();
    res.send({ hello: 'world' });
    const r = await response;
    assert.equal(r.headers.get('content-type'), 'application/json');
    assert.deepEqual(await r.json(), { hello: 'world' });
  });

  test('first resolution wins — a second res.end() after res.json() is a no-op', async () => {
    const { res, response } = createNodeResponse();
    res.status(200).json({ first: true });
    res.status(500).end('second');
    const r = await response;
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { first: true });
  });

  // api/og.js's success path: res.statusCode = 200 (raw property
  // assignment, not the res.status(200) method every other handler uses).
  test('res.statusCode = X (property assignment) is respected, not just res.status(X)', async () => {
    const { res, response } = createNodeResponse();
    res.statusCode = 302;
    res.setHeader('Location', '/og-image.png');
    res.end();
    const r = await response;
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), '/og-image.png');
  });

  test('res.statusCode getter reflects a prior res.status() call', () => {
    const { res } = createNodeResponse();
    res.status(404);
    assert.equal(res.statusCode, 404);
  });

  // api/og.js's success path: res.end(pngBuffer) with the raw Buffer
  // returned by @resvg/resvg-js's .asPng() — must reach the Response
  // byte-for-byte, not get String()-coerced (which would corrupt it).
  test('res.end(buffer) passes binary bodies through untouched', async () => {
    const { res, response } = createNodeResponse();
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]); // PNG magic bytes
    res.statusCode = 200;
    res.setHeader('Content-Type', 'image/png');
    res.end(png);
    const r = await response;
    const out = new Uint8Array(await r.arrayBuffer());
    assert.deepEqual(Array.from(out), Array.from(png));
  });

  test('res.send(buffer) also passes binary bodies through untouched', async () => {
    const { res, response } = createNodeResponse();
    const bytes = new Uint8Array([1, 2, 3, 4]);
    res.send(bytes);
    const r = await response;
    const out = new Uint8Array(await r.arrayBuffer());
    assert.deepEqual(Array.from(out), Array.from(bytes));
  });
});
