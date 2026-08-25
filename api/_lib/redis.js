/**
 * SENTINEL APEX — Upstash Redis REST Client
 * Zero npm dependencies. Pure HTTP fetch to Upstash REST API.
 * Required env vars: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
 */
'use strict';

const BASE = process.env.UPSTASH_REDIS_REST_URL || '';
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';

if (!BASE || !TOKEN) {
  console.warn('[REDIS] UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN not set — Redis unavailable.');
}

async function redisCmd(...args) {
  if (!BASE || !TOKEN) throw new Error('Redis not configured');
  const res = await fetch(`${BASE}/${args.map(encodeURIComponent).join('/')}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`Redis HTTP ${res.status}`);
  const json = await res.json();
  return json.result;
}

const redis = {
  // Strings
  get:    key           => redisCmd('GET', key),
  set:    (key, val)    => redisCmd('SET', key, val),
  setex:  (key, ttl, v) => redisCmd('SETEX', key, String(ttl), v),
  // SET key val NX -- Upstash returns "OK" if the key was newly set, null
  // if it already existed (no-op). Used for idempotent event creation
  // (watchlist change-detection): the caller does not need a prior EXISTS
  // check -- a truthy return means "this call created it", falsy means
  // "someone/something already had".
  setnx:  (key, val)    => redisCmd('SET', key, val, 'NX'),
  del:    key           => redisCmd('DEL', key),
  exists: key           => redisCmd('EXISTS', key),
  incr:   key           => redisCmd('INCR', key),
  expire: (key, ttl)    => redisCmd('EXPIRE', key, String(ttl)),
  ttl:    key           => redisCmd('TTL', key),
  // KEYS, not SCAN: simple and sufficient at this platform's current key
  // count (registered users, not millions of keys). Revisit with
  // cursor-based SCAN if the keyspace grows large enough for KEYS's
  // single-pass cost to matter -- not needed at today's scale.
  keys:   pattern       => redisCmd('KEYS', pattern),

  // Hashes
  hget:   (key, field)       => redisCmd('HGET', key, field),
  hset:   (key, field, val)  => redisCmd('HSET', key, field, val),
  hgetall: key               => redisCmd('HGETALL', key),
  hmset: async (key, obj) => {
    const pairs = Object.entries(obj).flat().map(String);
    return redisCmd('HMSET', key, ...pairs);
  },
  hincrby: (key, field, n)   => redisCmd('HINCRBY', key, field, String(n)),

  // Sets (entity/relationship indexes -- graph-engine.js, evidence-manager.js)
  sadd:     (key, ...members) => redisCmd('SADD', key, ...members),
  srem:     (key, ...members) => redisCmd('SREM', key, ...members),
  smembers: key                => redisCmd('SMEMBERS', key),
  scard:    key                => redisCmd('SCARD', key),

  // Sorted sets (for usage analytics)
  zadd:     (key, score, member) => redisCmd('ZADD', key, String(score), member),
  zrem:     (key, ...members)    => redisCmd('ZREM', key, ...members),
  zcard:    key                  => redisCmd('ZCARD', key),
  zrange:   (key, start, stop)   => redisCmd('ZRANGE', key, String(start), String(stop)),
  zrevrange:(key, start, stop, ws) => ws
    ? redisCmd('ZREVRANGE', key, String(start), String(stop), 'WITHSCORES')
    : redisCmd('ZREVRANGE', key, String(start), String(stop)),

  // Pipeline: execute multiple commands
  pipeline: async (commands) => {
    const res = await fetch(`${BASE}/pipeline`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(commands),
    });
    if (!res.ok) throw new Error(`Redis pipeline HTTP ${res.status}`);
    const json = await res.json();
    return json.map(r => r.result);
  },
};

module.exports = redis;
