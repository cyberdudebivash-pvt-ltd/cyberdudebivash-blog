'use strict';

// redis.js reads UPSTASH_REDIS_REST_URL/TOKEN into module-level consts at
// require() time, so they must be set before the first require below.
// Jest gives each test file its own module registry, so this doesn't leak
// into other test files. Values are synthetic -- no real Upstash instance
// is ever contacted; global.fetch is mocked below.
process.env.UPSTASH_REDIS_REST_URL = 'https://synthetic-test.upstash.io';
process.env.UPSTASH_REDIS_REST_TOKEN = 'synthetic_test_token';

const redis = require('../redis');

// Regression coverage for a real, pre-existing production defect found via
// a live Workerd request to /api/v1/workbench/dashboard during Cloudflare
// migration certification: `TypeError: redis.zcard is not a function`.
// A full-codebase sweep of every `redis.X(`/`this.redis.X(` call site
// found SIX methods called across 15 files (graph-engine.js,
// evidence-manager.js, case-manager.js, investigation-manager.js,
// intelligence-manager.js, publishing-pipeline.js, product-management-
// api.js, and the workbench/products/approvals API routes) that this
// client never implemented: sadd, srem, smembers, scard (the entire Set
// command family), plus zcard and zrem. Every one of those call sites
// threw an uncaught TypeError unconditionally -- not a Cloudflare-specific
// issue, identical on unmodified Vercel/Node today. Not previously caught
// because this file had zero test coverage before this.
describe('redis.js Upstash REST client', () => {
  let calls;

  beforeEach(() => {
    calls = [];
    global.fetch = jest.fn(async (url, opts) => {
      calls.push({ url, opts });
      return { ok: true, json: async () => ({ result: 'mock-result' }) };
    });
  });

  afterEach(() => {
    delete global.fetch;
  });

  function lastPath() {
    // Strip the base URL + auth to isolate just the command path Upstash
    // received, e.g. "SADD/graph%3Aentities%3Aall/intel-1".
    return calls[calls.length - 1].url.replace(
      `${process.env.UPSTASH_REDIS_REST_URL}/`, ''
    );
  }

  test('sadd sends SADD with key and member(s)', async () => {
    await redis.sadd('graph:entities:all', 'intel-1');
    expect(decodeURIComponent(lastPath())).toBe('SADD/graph:entities:all/intel-1');
  });

  test('sadd supports multiple members (real Redis SADD signature)', async () => {
    await redis.sadd('tag:set', 'a', 'b', 'c');
    expect(decodeURIComponent(lastPath())).toBe('SADD/tag:set/a/b/c');
  });

  test('srem sends SREM with key and member', async () => {
    await redis.srem('graph:relationships:related', 'rel-1');
    expect(decodeURIComponent(lastPath())).toBe('SREM/graph:relationships:related/rel-1');
  });

  test('smembers sends SMEMBERS with just the key', async () => {
    await redis.smembers('graph:entities:all');
    expect(decodeURIComponent(lastPath())).toBe('SMEMBERS/graph:entities:all');
  });

  test('scard sends SCARD with just the key', async () => {
    await redis.scard('graph:entities:all');
    expect(decodeURIComponent(lastPath())).toBe('SCARD/graph:entities:all');
  });

  test('zcard sends ZCARD with just the key', async () => {
    await redis.zcard('investigations:all');
    expect(decodeURIComponent(lastPath())).toBe('ZCARD/investigations:all');
  });

  test('zrem sends ZREM with key and member', async () => {
    await redis.zrem('cases:by:status:open', 'case-1');
    expect(decodeURIComponent(lastPath())).toBe('ZREM/cases:by:status:open/case-1');
  });

  test('all six new methods resolve the mocked Upstash result, not undefined', async () => {
    await expect(redis.sadd('k', 'm')).resolves.toBe('mock-result');
    await expect(redis.srem('k', 'm')).resolves.toBe('mock-result');
    await expect(redis.smembers('k')).resolves.toBe('mock-result');
    await expect(redis.scard('k')).resolves.toBe('mock-result');
    await expect(redis.zcard('k')).resolves.toBe('mock-result');
    await expect(redis.zrem('k', 'm')).resolves.toBe('mock-result');
  });

  test('setnx sends SET key val NX', async () => {
    await redis.setnx('event:abc', '{"a":1}');
    expect(decodeURIComponent(lastPath())).toBe('SET/event:abc/{"a":1}/NX');
  });

  test('pre-existing methods are unaffected (baseline sanity check)', async () => {
    await redis.get('some-key');
    expect(decodeURIComponent(lastPath())).toBe('GET/some-key');
    await redis.zadd('leaderboard', 5, 'member-1');
    expect(decodeURIComponent(lastPath())).toBe('ZADD/leaderboard/5/member-1');
  });
});
