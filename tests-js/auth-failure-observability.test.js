'use strict';
// Tests for recordAuthFailure (api/_lib/middleware.js) -- GEORP v1 Phase 5.
// authenticate() is this platform's single shared authentication
// chokepoint (used by every authenticated endpoint), and had zero
// visibility into any of its three failure paths (missing/malformed key,
// invalid/revoked key, rate limit exceeded) before this. Mirrors the exact
// analytics:registrations:* counter pattern already established in
// auth.js's handleRegister().
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const middleware = require(path.join(__dirname, '..', 'api', '_lib', 'middleware.js'));
const redis = require(path.join(__dirname, '..', 'api', '_lib', 'redis.js'));

function withMockedIncr(fn) {
  const calls = [];
  const original = redis.incr;
  redis.incr = async (key) => { calls.push(key); return 1; };
  return fn(calls).finally(() => { redis.incr = original; });
}

test('recordAuthFailure increments a total and a per-day counter for the given reason', async () => {
  await withMockedIncr(async (calls) => {
    middleware.recordAuthFailure('unauthorized');
    // incr() calls are fire-and-forget (not awaited by recordAuthFailure
    // itself) -- give the microtask queue a tick to let them land.
    await new Promise(resolve => setImmediate(resolve));

    assert.strictEqual(calls.length, 2);
    assert.ok(calls[0].startsWith('analytics:auth_failures:unauthorized:total'));
    assert.ok(/^analytics:auth_failures:unauthorized:\d{8}$/.test(calls[1]));
  });
});

test('recordAuthFailure scopes counters to the specific failure reason', async () => {
  await withMockedIncr(async (calls) => {
    middleware.recordAuthFailure('invalid_key');
    await new Promise(resolve => setImmediate(resolve));

    assert.ok(calls.every(k => k.includes('invalid_key')));
    assert.ok(!calls.some(k => k.includes('unauthorized')));
  });
});

test('recordAuthFailure never throws even if redis.incr rejects', async () => {
  const original = redis.incr;
  redis.incr = async () => { throw new Error('redis down'); };
  try {
    assert.doesNotThrow(() => middleware.recordAuthFailure('rate_limited'));
    // Let the rejected promises settle (caught internally) before restoring.
    await new Promise(resolve => setImmediate(resolve));
  } finally {
    redis.incr = original;
  }
});

test('all three real failure reasons used in authenticate() produce distinct counter families', async () => {
  await withMockedIncr(async (calls) => {
    middleware.recordAuthFailure('unauthorized');
    middleware.recordAuthFailure('invalid_key');
    middleware.recordAuthFailure('rate_limited');
    await new Promise(resolve => setImmediate(resolve));

    const families = new Set(calls.map(k => k.split(':')[2]));
    assert.deepStrictEqual(families, new Set(['unauthorized', 'invalid_key', 'rate_limited']));
  });
});
