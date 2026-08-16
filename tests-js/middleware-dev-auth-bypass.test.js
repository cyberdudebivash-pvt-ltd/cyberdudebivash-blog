'use strict';
// Tests for the Redis-unavailable dev-auth bypass in
// api/_lib/middleware.js's authenticate(). Previously this fired on
// NODE_ENV=development alone; it now additionally requires
// ALLOW_DEV_AUTH_BYPASS=true so an accidental NODE_ENV=development in a
// real deployment (e.g. during Vercel account/project reconstruction)
// can never grant tier-'pro' access on its own.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const middleware = require(path.join(__dirname, '..', 'api', '_lib', 'middleware.js'));
const redis = require(path.join(__dirname, '..', 'api', '_lib', 'redis.js'));

function fakeReq() {
  return {
    method: 'GET',
    headers: { authorization: 'Bearer sentinel_' + 'a'.repeat(64) },
    query: {},
  };
}

function fakeRes() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

async function withRedisDown(fn) {
  const original = redis.hgetall;
  redis.hgetall = async () => { throw new Error('redis down'); };
  try {
    return await fn();
  } finally {
    redis.hgetall = original;
  }
}

async function withEnv(overrides, fn) {
  const originals = {};
  for (const key of Object.keys(overrides)) originals[key] = process.env[key];
  try {
    for (const [key, value] of Object.entries(overrides)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    // Must await here, not just `return fn()` — fn is async, and without
    // awaiting it, this function's `finally` (restoring env vars) would
    // run synchronously right after fn() is *invoked*, not after it
    // *resolves*, undoing the env override before authenticate() ever
    // gets to read it.
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(originals)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('NODE_ENV=development alone does not bypass auth when Redis is down', async () => {
  await withRedisDown(() =>
    withEnv({ NODE_ENV: 'development', ALLOW_DEV_AUTH_BYPASS: undefined }, async () => {
      const res = fakeRes();
      const result = await middleware.authenticate(fakeReq(), res);
      assert.strictEqual(result, null);
      assert.strictEqual(res.statusCode, 503);
    })
  );
});

test('ALLOW_DEV_AUTH_BYPASS=true alone (not development) does not bypass auth when Redis is down', async () => {
  await withRedisDown(() =>
    withEnv({ NODE_ENV: 'production', ALLOW_DEV_AUTH_BYPASS: 'true' }, async () => {
      const res = fakeRes();
      const result = await middleware.authenticate(fakeReq(), res);
      assert.strictEqual(result, null);
      assert.strictEqual(res.statusCode, 503);
    })
  );
});

test('both NODE_ENV=development AND ALLOW_DEV_AUTH_BYPASS=true together bypass auth when Redis is down', async () => {
  await withRedisDown(() =>
    withEnv({ NODE_ENV: 'development', ALLOW_DEV_AUTH_BYPASS: 'true' }, async () => {
      const result = await middleware.authenticate(fakeReq(), fakeRes());
      assert.ok(result);
      assert.strictEqual(result.tier, 'pro');
      assert.strictEqual(result.userId, 'dev');
    })
  );
});

test('when Redis is reachable, the bypass path is never reached regardless of env flags', async () => {
  const original = redis.hgetall;
  redis.hgetall = async () => ['tier', 'free', 'userId', 'real-user', 'email', 'real@example.com'];
  const originalIncr = redis.incr;
  redis.incr = async () => 1;
  const originalExpire = redis.expire;
  redis.expire = async () => 1;
  const originalHincrby = redis.hincrby;
  redis.hincrby = async () => 1;
  const originalHset = redis.hset;
  redis.hset = async () => 'OK';
  const originalZadd = redis.zadd;
  redis.zadd = async () => 1;
  try {
    await withEnv({ NODE_ENV: 'development', ALLOW_DEV_AUTH_BYPASS: 'true' }, async () => {
      const result = await middleware.authenticate(fakeReq(), fakeRes());
      assert.ok(result);
      assert.strictEqual(result.userId, 'real-user', 'must use the real Redis-backed user, not the dev bypass');
    });
  } finally {
    redis.hgetall = original;
    redis.incr = originalIncr;
    redis.expire = originalExpire;
    redis.hincrby = originalHincrby;
    redis.hset = originalHset;
    redis.zadd = originalZadd;
  }
});
