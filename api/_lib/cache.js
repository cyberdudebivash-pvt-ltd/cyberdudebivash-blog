/**
 * SENTINEL APEX — Read-Through Response Cache
 *
 * Redis-backed cache for expensive computed API responses (graph/campaign
 * clustering reads real JSON files off disk on every request today). Fails
 * open on any Redis error — unconfigured, network blip, whatever — falling
 * back to computing fresh rather than ever blocking a response on cache
 * availability, matching this codebase's existing fail-open convention
 * (see api/_lib/security.js's rate limiting, api/_lib/campaign-engine.js's
 * own 120s in-process cache for the same underlying data).
 *
 * Callers are responsible for tier-scoping cache keys themselves (e.g.
 * `cache:graph:${tier}`) — this module has no opinion on tiering, but
 * getting that wrong would leak one tier's response shape to another.
 */
'use strict';
const defaultRedis = require('./redis');

async function getOrSet(key, ttlSeconds, computeFn, redis = defaultRedis) {
  try {
    const cached = await redis.get(key);
    if (cached != null) {
      return { value: JSON.parse(cached), cacheHit: true };
    }
  } catch (_) {
    // Redis unavailable or corrupt entry — fall through to compute fresh.
  }

  const value = await computeFn();

  try {
    await redis.setex(key, ttlSeconds, JSON.stringify(value));
  } catch (_) {
    // Best-effort write — a cache-population failure must never fail the request.
  }

  return { value, cacheHit: false };
}

module.exports = { getOrSet };
