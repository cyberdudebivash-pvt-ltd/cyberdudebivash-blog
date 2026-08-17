'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { applyBaselineHeaders, BASELINE } = require('./security-headers');

describe('applyBaselineHeaders', () => {
  test('applies every baseline header to a response with none set', () => {
    const response = applyBaselineHeaders(new Response('ok', { status: 200 }));
    for (const [key, value] of Object.entries(BASELINE)) {
      assert.equal(response.headers.get(key), value, `expected ${key} to be set`);
    }
    assert.equal(response.headers.get('content-security-policy'), "default-src 'none'; frame-ancestors 'none'");
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
  });

  test('does not overwrite a header the handler already set (duplicate-header handling)', () => {
    const response = new Response('ok', {
      status: 200,
      headers: { 'Referrer-Policy': 'no-referrer' },
    });
    applyBaselineHeaders(response);
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  });

  test('does not add a second Content-Security-Policy if the handler set one, even without X-Frame-Options', () => {
    const response = new Response('ok', {
      status: 200,
      headers: { 'Content-Security-Policy': "default-src 'self'" },
    });
    applyBaselineHeaders(response);
    assert.equal(response.headers.get('content-security-policy'), "default-src 'self'");
    // X-Frame-Options is deliberately NOT added either -- the handler
    // setting CSP but not X-Frame-Options is treated as an intentional
    // choice this baseline shouldn't second-guess by adding one alone.
    assert.equal(response.headers.has('x-frame-options'), false);
  });

  test('preserves an existing CORS header set by the app-layer middleware', () => {
    const response = new Response('ok', {
      status: 200,
      headers: { 'Access-Control-Allow-Origin': '*' },
    });
    applyBaselineHeaders(response);
    assert.equal(response.headers.get('access-control-allow-origin'), '*');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  });

  test('works on a manually-constructed redirect response (Response.redirect() headers are spec-immutable)', () => {
    const response = applyBaselineHeaders(new Response(null, {
      status: 308,
      headers: { Location: 'https://example.com/target' },
    }));
    assert.equal(response.status, 308);
    assert.equal(response.headers.get('location'), 'https://example.com/target');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  });

  test('Response.redirect() headers really are immutable, confirming why router.js avoids it', () => {
    const redirect = Response.redirect('https://example.com/x', 308);
    assert.throws(() => redirect.headers.set('X-Content-Type-Options', 'nosniff'));
  });

  test('returns the same response instance (mutates in place)', () => {
    const response = new Response('ok');
    const result = applyBaselineHeaders(response);
    assert.equal(result, response);
  });

  // Regression guard: api/v1/customer/dashboard.js (returns purchase
  // history and API-key/tier status) does not call
  // api/_lib/security.js#applySecurityHeaders(), so on Vercel it relied
  // entirely on vercel.json's platform-level `/api/v1/(.*)` rule for
  // Cache-Control -- a safety net router.js has no equivalent of. Confirmed
  // via a real Workerd probe before this baseline included Cache-Control:
  // every other header was present, Cache-Control was not.
  test('applies Cache-Control: no-store even when the handler sets nothing itself', () => {
    const response = applyBaselineHeaders(new Response('{}', {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }));
    assert.equal(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
  });

  test('does not overwrite a handler-set Cache-Control (e.g. a deliberately public value)', () => {
    const response = applyBaselineHeaders(new Response('ok', {
      status: 200,
      headers: { 'Cache-Control': 'public, max-age=600' },
    }));
    assert.equal(response.headers.get('cache-control'), 'public, max-age=600');
  });
});
