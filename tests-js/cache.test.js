'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { getOrSet } = require('../api/_lib/cache');

function fakeRedis(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    get: async (key) => (store.has(key) ? store.get(key) : null),
    setex: async (key, ttl, val) => { store.set(key, val); },
    _store: store,
  };
}

test('getOrSet computes and caches on a miss', async () => {
  const redis = fakeRedis();
  let computeCalls = 0;
  const result = await getOrSet('k', 60, async () => { computeCalls += 1; return { x: 1 }; }, redis);
  assert.strictEqual(result.cacheHit, false);
  assert.deepStrictEqual(result.value, { x: 1 });
  assert.strictEqual(computeCalls, 1);
  assert.strictEqual(redis._store.get('k'), JSON.stringify({ x: 1 }));
});

test('getOrSet returns the cached value on a hit without recomputing', async () => {
  const redis = fakeRedis({ k: JSON.stringify({ x: 42 }) });
  let computeCalls = 0;
  const result = await getOrSet('k', 60, async () => { computeCalls += 1; return { x: 999 }; }, redis);
  assert.strictEqual(result.cacheHit, true);
  assert.deepStrictEqual(result.value, { x: 42 });
  assert.strictEqual(computeCalls, 0);
});

test('getOrSet computes fresh when redis.get throws (fail open)', async () => {
  const redis = { get: async () => { throw new Error('redis down'); }, setex: async () => {} };
  const result = await getOrSet('k', 60, async () => ({ ok: true }), redis);
  assert.strictEqual(result.cacheHit, false);
  assert.deepStrictEqual(result.value, { ok: true });
});

test('getOrSet still returns a fresh value when redis.setex throws (fail open on write)', async () => {
  const redis = { get: async () => null, setex: async () => { throw new Error('redis down'); } };
  const result = await getOrSet('k', 60, async () => ({ ok: true }), redis);
  assert.strictEqual(result.cacheHit, false);
  assert.deepStrictEqual(result.value, { ok: true });
});

test('getOrSet computes fresh when the cached entry is corrupt JSON', async () => {
  const redis = fakeRedis({ k: 'not valid json{{{' });
  const result = await getOrSet('k', 60, async () => ({ recomputed: true }), redis);
  assert.strictEqual(result.cacheHit, false);
  assert.deepStrictEqual(result.value, { recomputed: true });
});

test('getOrSet never throws even when both redis operations and compute could fail independently', async () => {
  const redis = { get: async () => { throw new Error('x'); }, setex: async () => { throw new Error('y'); } };
  await assert.doesNotReject(getOrSet('k', 60, async () => ({ ok: true }), redis));
});
