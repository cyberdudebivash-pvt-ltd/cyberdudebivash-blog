'use strict';

// In-memory double implementing the same surface as api/_lib/redis.js, so
// multi-step watchlist and notification-delivery flows (create -> add-
// entity -> evaluate -> feed -> delete; enqueue -> due-query -> attempt ->
// reschedule/dead-letter) can be tested as real sequences of commands
// against real semantics (SADD idempotency, ZREVRANGE ordering,
// ZRANGEBYSCORE range filtering, ZREMRANGEBYRANK trimming, SET...NX)
// without a live Upstash instance. Every command this codebase actually
// calls is implemented; nothing beyond that surface.

function sliceInclusiveByRank(sortedAscending, start, stop) {
  const len = sortedAscending.length;
  let s = start < 0 ? Math.max(len + start, 0) : start;
  let e = stop < 0 ? len + stop : stop;
  e = Math.min(e, len - 1);
  if (s > e || len === 0) return [];
  return sortedAscending.slice(s, e + 1);
}

function createFakeRedis() {
  const strings = new Map();
  const hashes  = new Map(); // key -> Map(field -> value)
  const sets    = new Map(); // key -> Set(member)
  const zsets   = new Map(); // key -> Map(member -> score)
  const expirations = new Map(); // key -> epoch ms a setnxpx-created string key expires at

  // Only setnxpx tracks real expiry (notification-store.js's atomic
  // delivery claim/lease -- see redis.js's own setnxpx comment). The
  // pre-existing setex/expire/ttl stubs below are deliberately left
  // as-is: nothing in this codebase's test suite depends on real TTL
  // semantics for those, so simulating it there would be unused fixture
  // surface, not a fix for anything (see this file's header discipline:
  // "every command this codebase actually calls is implemented; nothing
  // beyond that surface").
  function expireIfDue(k) {
    const exp = expirations.get(k);
    if (exp !== undefined && Date.now() >= exp) {
      strings.delete(k);
      expirations.delete(k);
    }
  }

  function matchKeys(pattern) {
    const all = [...strings.keys(), ...hashes.keys(), ...sets.keys(), ...zsets.keys()];
    if (!pattern.endsWith('*')) return all.filter(k => k === pattern);
    const prefix = pattern.slice(0, -1);
    return all.filter(k => k.startsWith(prefix));
  }

  return {
    get: async k => { expireIfDue(k); return strings.has(k) ? strings.get(k) : null; },
    set: async (k, v) => { expirations.delete(k); strings.set(k, String(v)); return 'OK'; },
    setex: async (k, _ttl, v) => { strings.set(k, String(v)); return 'OK'; },
    setnx: async (k, v) => {
      expireIfDue(k);
      if (strings.has(k)) return null;
      strings.set(k, String(v));
      return 'OK';
    },
    // SET key val NX PX ttlMs -- real expiry, unlike the setex/expire/ttl
    // stubs above (see expireIfDue's comment for why those stay stubbed).
    // Mirrors notification-store.js's atomic claim/lease: fails (returns
    // null) if the key exists and hasn't yet expired; otherwise creates
    // it with a real expiry, so a test can prove lease recovery by
    // advancing past ttlMs (e.g. via jest.useFakeTimers or a real short
    // sleep) and re-claiming.
    setnxpx: async (k, v, ttlMs) => {
      expireIfDue(k);
      if (strings.has(k)) return null;
      strings.set(k, String(v));
      expirations.set(k, Date.now() + Number(ttlMs));
      return 'OK';
    },
    del: async k => {
      expirations.delete(k);
      const existed = strings.delete(k) || hashes.delete(k) || sets.delete(k) || zsets.delete(k);
      return existed ? 1 : 0;
    },
    exists: async k => { expireIfDue(k); return (strings.has(k) || hashes.has(k) || sets.has(k) || zsets.has(k) ? 1 : 0); },
    incr: async k => { const v = (parseInt(strings.get(k), 10) || 0) + 1; strings.set(k, String(v)); return v; },
    expire: async () => 1,
    ttl: async () => -1,
    keys: async pattern => matchKeys(pattern),

    hget: async (k, f) => { const h = hashes.get(k); return h && h.has(f) ? h.get(f) : null; },
    hset: async (k, f, v) => { if (!hashes.has(k)) hashes.set(k, new Map()); hashes.get(k).set(f, String(v)); return 1; },
    hgetall: async k => {
      const h = hashes.get(k);
      if (!h || h.size === 0) return null;
      const flat = [];
      for (const [f, v] of h) flat.push(f, v);
      return flat;
    },
    hmset: async (k, obj) => {
      if (!hashes.has(k)) hashes.set(k, new Map());
      const h = hashes.get(k);
      for (const [f, v] of Object.entries(obj)) h.set(f, v === null || v === undefined ? '' : String(v));
      return 'OK';
    },
    hincrby: async (k, f, n) => {
      if (!hashes.has(k)) hashes.set(k, new Map());
      const h = hashes.get(k);
      const v = (parseInt(h.get(f), 10) || 0) + Number(n);
      h.set(f, String(v));
      return v;
    },

    sadd: async (k, ...members) => {
      if (!sets.has(k)) sets.set(k, new Set());
      const s = sets.get(k);
      let added = 0;
      for (const m of members) if (!s.has(m)) { s.add(m); added++; }
      return added;
    },
    srem: async (k, ...members) => {
      const s = sets.get(k);
      if (!s) return 0;
      let removed = 0;
      for (const m of members) if (s.delete(m)) removed++;
      if (s.size === 0) sets.delete(k);
      return removed;
    },
    smembers: async k => { const s = sets.get(k); return s ? [...s] : []; },
    scard: async k => { const s = sets.get(k); return s ? s.size : 0; },

    zadd: async (k, score, member) => {
      if (!zsets.has(k)) zsets.set(k, new Map());
      zsets.get(k).set(member, Number(score));
      return 1;
    },
    zrem: async (k, ...members) => {
      const z = zsets.get(k);
      if (!z) return 0;
      let removed = 0;
      for (const m of members) if (z.delete(m)) removed++;
      return removed;
    },
    zcard: async k => { const z = zsets.get(k); return z ? z.size : 0; },
    zrange: async (k, start, stop, withScores) => {
      const z = zsets.get(k);
      if (!z) return [];
      const asc = [...z.entries()].sort((a, b) => a[1] - b[1]);
      const sliced = sliceInclusiveByRank(asc, Number(start), Number(stop));
      return withScores ? sliced.flatMap(([m, s]) => [m, String(s)]) : sliced.map(([m]) => m);
    },
    zrangebyscore: async (k, min, max) => {
      const z = zsets.get(k);
      if (!z) return [];
      const lo = Number(min), hi = Number(max);
      return [...z.entries()]
        .filter(([, score]) => score >= lo && score <= hi)
        .sort((a, b) => a[1] - b[1])
        .map(([m]) => m);
    },
    zrevrange: async (k, start, stop, withScores) => {
      const z = zsets.get(k);
      if (!z) return [];
      const desc = [...z.entries()].sort((a, b) => b[1] - a[1]);
      const indices = sliceInclusiveByRank(desc.map((_, i) => i), Number(start), Number(stop));
      const sliced = indices.map(i => desc[i]);
      return withScores ? sliced.flatMap(([m, s]) => [m, String(s)]) : sliced.map(([m]) => m);
    },

    pipeline: async commands => {
      const results = [];
      for (const cmd of commands) {
        const [name, ...args] = cmd;
        if (name === 'ZREMRANGEBYRANK') {
          const [k, startStr, stopStr] = args;
          const z = zsets.get(k);
          if (z) {
            const asc = [...z.entries()].sort((a, b) => a[1] - b[1]);
            const toRemove = sliceInclusiveByRank(asc, parseInt(startStr, 10), parseInt(stopStr, 10)).map(([m]) => m);
            for (const m of toRemove) z.delete(m);
          }
          results.push(null);
        } else {
          results.push(null);
        }
      }
      return results;
    },

    _dump: () => ({ strings, hashes, sets, zsets }),
    _reset: () => { strings.clear(); hashes.clear(); sets.clear(); zsets.clear(); expirations.clear(); },
  };
}

module.exports = { createFakeRedis };
