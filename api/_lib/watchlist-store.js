/**
 * SENTINEL APEX — Watchlist Persistence
 *
 * Customer-owned watchlists, their tracked entities, the reverse index
 * used to match a changed entity back to its watchers, and each
 * customer's monitoring feed. Backed by Upstash Redis via the existing
 * api/_lib/redis.js REST client -- the same, already-production, already
 * Worker-compatible datastore this platform's customer/auth/billing code
 * already uses (api/_lib/middleware.js, api/_lib/payment-utils.js).
 *
 * Deliberately NOT built on Cloudflare D1/KV/Durable Objects/Queues: this
 * repository's own wrangler.jsonc documents zero production bindings of
 * any kind today ("kv_namespaces -- no blog-owned namespace exists yet",
 * "d1_databases -- none needed; the blog has no relational data
 * dependency"), and CLOUDFLARE-ACCOUNT-INVENTORY.md /
 * COMPLETE-CLOUDFLARE-INVENTORY.md independently confirm the account's
 * existing D1/KV resources all belong to sibling platforms and were
 * explicitly classified DEFER/DO_NOT_REUSE for this blog. Provisioning
 * new Cloudflare storage infrastructure is exactly the kind of
 * architectural event this platform's own governance requires separate,
 * explicit authorization for -- Redis is the evidenced, already-reused,
 * zero-new-infrastructure choice. See the certification doc's
 * Persistence/Cloudflare Runtime sections for the full evidence trail.
 *
 * Key schema (all under existing Redis conventions -- `user:*`,
 * `audit:*`, `ratelimit:*` already established by middleware.js/
 * payment-utils.js):
 *
 *   watchlist:{id}                    HASH  identity/metadata (owner is
 *                                            never exposed in API output)
 *   watchlist:{id}:entities           SET   members "{type}:{id}"
 *   owner:{ownerId}:watchlists        SET   members watchlistId
 *   entity_watchers:{type}:{id}       SET   members watchlistId (reverse
 *                                            index -- Phase 37/67: lets
 *                                            the change engine match one
 *                                            global event to N watchers
 *                                            without diffing N times, and
 *                                            lets the scheduled evaluator
 *                                            enumerate only entities that
 *                                            are actually watched instead
 *                                            of scanning the full corpus)
 *   events:for_owner:{ownerId}        ZSET  member=event_id, score=ts
 *   audit:watchlist:log               ZSET  same shape/trim policy as
 *                                            payment-utils.js's
 *                                            audit:payment:log, kept as
 *                                            its own key rather than
 *                                            reusing that one directly --
 *                                            auditLog() there is hardcoded
 *                                            to the payment domain's key,
 *                                            and mixing "WATCHLIST_*"
 *                                            entries into a "payment" log
 *                                            would confuse anyone
 *                                            auditing payments. Same
 *                                            pattern, deliberately
 *                                            separate key.
 *
 * Ownership: every read/write of a specific watchlist ID re-derives
 * ownership from the caller's authenticate()-issued userId and compares
 * it against the stored `owner` field -- never trusted from the request
 * body. A missing watchlist and someone else's watchlist return the
 * identical 404, mirroring api/v1/billing.js's handleManageSubscription
 * ownership-check precedent exactly, so a valid watchlist ID can't be
 * enumerated by comparing error responses.
 */
'use strict';

const crypto = require('crypto');
const redis  = require('./redis');
const { sanitize } = require('./payment-utils');

const WATCHLIST_SCHEMA_VERSION = '1.0';
const SUPPORTED_ENTITY_TYPES = new Set(['cve', 'campaign']);
const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/i;

// Phase 12: technical hard caps, abuse-prevention only. Not tier-
// differentiated in v1 -- api/_lib/payment-utils.js's PLANS carries no
// feature flags today (confirmed via direct read), and this mandate
// explicitly prohibits inventing pricing. Every authenticated tier gets
// the same limits; differentiating them by tier is documented as a real,
// deliberate gap in platform/open-issues.md for a future commercial
// decision, not silently decided here.
const MAX_WATCHLISTS_PER_OWNER    = 20;
const MAX_ENTITIES_PER_WATCHLIST  = 100;
const MAX_NAME_LENGTH             = 100;
const MAX_DESCRIPTION_LENGTH      = 500;
const FEED_MAX_PER_OWNER          = 500; // bounded retention (Phase 54)
const AUDIT_LOG_MAX_ENTRIES       = 10000; // matches payment-utils.js's own bound

function generateWatchlistId() {
  return 'wl_' + crypto.randomBytes(12).toString('hex');
}

async function auditWatchlistAction(action, data = {}) {
  try {
    const entry = JSON.stringify({ action, ts: new Date().toISOString(), ...data });
    await redis.zadd('audit:watchlist:log', Date.now(), entry);
    await redis.pipeline([
      ['ZREMRANGEBYRANK', 'audit:watchlist:log', '0', String(-(AUDIT_LOG_MAX_ENTRIES + 1))],
    ]).catch(() => {});
  } catch (_) {
    // Audit failure must never break the main flow (matches
    // payment-utils.js's auditLog() behavior exactly).
  }
}

function hashToObject(flatArray) {
  if (!flatArray || !Array.isArray(flatArray) || flatArray.length === 0) return null;
  const obj = {};
  for (let i = 0; i < flatArray.length; i += 2) obj[flatArray[i]] = flatArray[i + 1];
  return obj;
}

/* ───────────────────────── validation ───────────────────────── */

function validateName(name) {
  const clean = sanitize(name, MAX_NAME_LENGTH).trim();
  if (!clean) return { error: true, message: 'name is required (1-' + MAX_NAME_LENGTH + ' characters).' };
  return { value: clean };
}

function validateDescription(description) {
  if (description === undefined || description === null || description === '') return { value: '' };
  return { value: sanitize(description, MAX_DESCRIPTION_LENGTH).trim() };
}

// Phase 11: reject prototype-pollution keys, unsupported entity types, and
// malformed IDs before anything touches Redis. Campaign IDs have no fixed
// regex in this codebase (see api/v1/intel.js's own free-form handling),
// so they are bounded by length and character class only; genuine
// existence is verified by the caller against campaigns.json before
// persisting (api/v1/watchlists.js), not re-derived here.
function validateEntityRef(entityType, entityId) {
  const type = String(entityType || '').toLowerCase().trim();
  if (type === '__proto__' || type === 'constructor' || type === 'prototype') {
    return { error: 'UNSUPPORTED_ENTITY_TYPE', message: 'Unsupported watchlist entity type.' };
  }
  if (!SUPPORTED_ENTITY_TYPES.has(type)) {
    return { error: 'UNSUPPORTED_ENTITY_TYPE', message: `Unsupported watchlist entity type: "${entityType}". Supported: cve, campaign.` };
  }
  if (type === 'cve') {
    const id = String(entityId || '').toUpperCase().trim();
    if (!CVE_ID_RE.test(id)) {
      return { error: 'INVALID_ENTITY_ID', message: `Invalid CVE ID format: "${entityId}". Expected: CVE-YYYY-NNNNN` };
    }
    return { type, id };
  }
  const id = String(entityId || '').trim();
  if (!id || id.length > 200 || !/^[a-zA-Z0-9:_.\-]+$/.test(id)) {
    return { error: 'INVALID_ENTITY_ID', message: `Invalid campaign ID: "${entityId}".` };
  }
  return { type, id };
}

/* ───────────────────────── serialization ───────────────────────── */

function toPublicWatchlist(record, entityCount) {
  return {
    schema_version: record.schema_version || WATCHLIST_SCHEMA_VERSION,
    id: record.id,
    name: record.name,
    description: record.description || '',
    status: record.status || 'active',
    entity_count: entityCount,
    created_at: record.created_at,
    updated_at: record.updated_at,
    last_evaluated_at: record.last_evaluated_at || null,
  };
}

/* ───────────────────────── entitlements (Phase 9) ─────────────────────────
   Deliberately a single function other code calls, not `if (tier===...)`
   scattered across handlers -- the "smallest consistent extension" this
   mandate calls for given no centralized entitlement layer exists
   platform-wide (confirmed via the reuse audit: tier checks are inline
   per-route in api/v1/intel.js, not centralized). Flat across tiers in v1;
   see the module header for why. */
function getWatchlistEntitlements(tier) {
  return {
    enabled: true,
    max_watchlists: MAX_WATCHLISTS_PER_OWNER,
    max_entities_per_watchlist: MAX_ENTITIES_PER_WATCHLIST,
    feed_max_entries: FEED_MAX_PER_OWNER,
    // Same flat-across-tiers posture as every limit above (a documented
    // gap, not a decision — see platform/open-issues.md): no centralized
    // entitlement layer exists yet to gate this by tier, and inventing a
    // tier restriction here would be pricing this codebase has no
    // authority to set.
    email_notifications_enabled: true,
    webhook_notifications_enabled: true,
  };
}

/* ───────────────────────── watchlist CRUD ───────────────────────── */

async function getWatchlistRaw(watchlistId) {
  const flat = await redis.hgetall(`watchlist:${watchlistId}`);
  return hashToObject(flat);
}

// Ownership check: identical NOT_FOUND for "doesn't exist" and "exists but
// belongs to someone else" -- mirrors api/v1/billing.js's
// handleManageSubscription precedent so a valid watchlist ID can't be
// enumerated via a different error for "not yours".
async function getOwnedWatchlist(watchlistId, ownerId) {
  const record = await getWatchlistRaw(watchlistId);
  if (!record || record.owner !== ownerId) return null;
  return record;
}

async function createWatchlist({ ownerId, name, description }) {
  const nameResult = validateName(name);
  if (nameResult.error) return { error: 'INVALID_NAME', message: nameResult.message };
  const descResult = validateDescription(description);

  const existingIds = (await redis.smembers(`owner:${ownerId}:watchlists`)) || [];
  if (existingIds.length >= MAX_WATCHLISTS_PER_OWNER) {
    return { error: 'LIMIT_REACHED', message: `Maximum of ${MAX_WATCHLISTS_PER_OWNER} watchlists per account reached.` };
  }

  const id = generateWatchlistId();
  const nowIso = new Date().toISOString();
  const record = {
    schema_version: WATCHLIST_SCHEMA_VERSION,
    id, owner: ownerId,
    name: nameResult.value,
    description: descResult.value,
    status: 'active',
    created_at: nowIso, updated_at: nowIso, last_evaluated_at: '',
  };
  await redis.hmset(`watchlist:${id}`, record);
  await redis.sadd(`owner:${ownerId}:watchlists`, id);
  auditWatchlistAction('WATCHLIST_CREATED', { owner: ownerId, watchlistId: id }).catch(() => {});
  return { watchlist: toPublicWatchlist(record, 0) };
}

async function listWatchlists(ownerId) {
  const ids = (await redis.smembers(`owner:${ownerId}:watchlists`)) || [];
  const out = [];
  for (const id of ids) {
    const record = await getWatchlistRaw(id);
    if (!record) continue; // tolerate a dangling index entry
    const entityCount = (await redis.scard(`watchlist:${id}:entities`)) || 0;
    out.push(toPublicWatchlist(record, entityCount));
  }
  out.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  return out;
}

async function getWatchlist(watchlistId, ownerId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const entityCount = (await redis.scard(`watchlist:${watchlistId}:entities`)) || 0;
  return { watchlist: toPublicWatchlist(record, entityCount) };
}

async function updateWatchlist(watchlistId, ownerId, updates) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };

  const patch = { updated_at: new Date().toISOString() };
  if (updates.name !== undefined) {
    const r = validateName(updates.name);
    if (r.error) return { error: 'INVALID_NAME', message: r.message };
    patch.name = r.value;
  }
  if (updates.description !== undefined) {
    patch.description = validateDescription(updates.description).value;
  }
  if (updates.status !== undefined) {
    const s = String(updates.status).toLowerCase().trim();
    if (!['active', 'paused'].includes(s)) {
      return { error: 'INVALID_STATUS', message: 'status must be "active" or "paused".' };
    }
    patch.status = s;
  }

  await redis.hmset(`watchlist:${watchlistId}`, patch);
  auditWatchlistAction('WATCHLIST_UPDATED', { owner: ownerId, watchlistId, fields: Object.keys(patch) }).catch(() => {});
  const entityCount = (await redis.scard(`watchlist:${watchlistId}:entities`)) || 0;
  return { watchlist: toPublicWatchlist({ ...record, ...patch }, entityCount) };
}

// Phase 41/42: deletes membership and the reverse-index entries pointing
// at it. Never touches global change events (event:*, events:for_owner
// history already delivered stays visible) and never touches canonical
// intelligence -- only this watchlist's own subscription state.
async function deleteWatchlist(watchlistId, ownerId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };

  const members = (await redis.smembers(`watchlist:${watchlistId}:entities`)) || [];
  for (const member of members) {
    await redis.srem(`entity_watchers:${member}`, watchlistId).catch(() => {});
  }
  await redis.del(`watchlist:${watchlistId}:entities`).catch(() => {});
  await redis.del(`watchlist:${watchlistId}`).catch(() => {});
  await redis.srem(`owner:${ownerId}:watchlists`, watchlistId).catch(() => {});
  auditWatchlistAction('WATCHLIST_DELETED', { owner: ownerId, watchlistId }).catch(() => {});
  return { deleted: true };
}

/* ───────────────────────── entity membership ───────────────────────── */

async function listEntities(watchlistId, ownerId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const members = (await redis.smembers(`watchlist:${watchlistId}:entities`)) || [];
  const entities = members.map(m => {
    const idx = m.indexOf(':');
    return { type: m.slice(0, idx), id: m.slice(idx + 1) };
  }).sort((a, b) => (a.type + a.id).localeCompare(b.type + b.id));
  return { entities };
}

// Adding an already-present entity is a no-op success (Phase 11: "prevent
// duplicate membership"), even at the cap -- SADD is naturally idempotent.
// A genuinely new addition once at the cap is rolled back and rejected
// rather than silently exceeding the documented limit. This is not fully
// atomic under two concurrent add requests for the *same* watchlist (no
// Upstash-side transaction is used), so a customer racing themselves
// could transiently land 1 entity over the cap before the next add is
// rejected -- a low-severity, self-only race (never cross-customer),
// documented here rather than solved with added complexity this mandate
// doesn't require.
async function addEntity(watchlistId, ownerId, entityType, entityId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const ref = validateEntityRef(entityType, entityId);
  if (ref.error) return ref;

  const member = `${ref.type}:${ref.id}`;
  const entitiesKey = `watchlist:${watchlistId}:entities`;
  const beforeCount = (await redis.scard(entitiesKey)) || 0;
  await redis.sadd(entitiesKey, member);
  const afterCount = (await redis.scard(entitiesKey)) || 0;
  const wasNew = afterCount > beforeCount;

  if (wasNew && afterCount > MAX_ENTITIES_PER_WATCHLIST) {
    await redis.srem(entitiesKey, member).catch(() => {});
    return { error: 'LIMIT_REACHED', message: `Maximum of ${MAX_ENTITIES_PER_WATCHLIST} entities per watchlist reached.` };
  }

  await redis.sadd(`entity_watchers:${member}`, watchlistId);
  await redis.hset(`watchlist:${watchlistId}`, 'updated_at', new Date().toISOString());
  if (wasNew) {
    auditWatchlistAction('WATCHLIST_ENTITY_ADDED', { owner: ownerId, watchlistId, entityType: ref.type, entityId: ref.id }).catch(() => {});
  }
  return { added: true, duplicate: !wasNew, entity: { type: ref.type, id: ref.id } };
}

async function removeEntity(watchlistId, ownerId, entityType, entityId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const ref = validateEntityRef(entityType, entityId);
  if (ref.error) return ref;

  const member = `${ref.type}:${ref.id}`;
  await redis.srem(`watchlist:${watchlistId}:entities`, member);
  await redis.srem(`entity_watchers:${member}`, watchlistId);
  await redis.hset(`watchlist:${watchlistId}`, 'updated_at', new Date().toISOString());
  auditWatchlistAction('WATCHLIST_ENTITY_REMOVED', { owner: ownerId, watchlistId, entityType: ref.type, entityId: ref.id }).catch(() => {});
  return { removed: true };
}

/* ───────────────────────── change-engine support ─────────────────────────
   Consumed by api/_lib/change-engine.js, not by the customer-facing
   router directly. */

// Phase 48/67: enumerate only entities that are actually watched by at
// least one customer -- KEYS is used here deliberately, the same
// documented choice api/_lib/redis.js itself already makes ("simple and
// sufficient at this platform's current key count, not millions of
// keys"); the watched-entity set is bounded by total watchlist
// membership, never by total corpus size.
async function getAllWatchedEntityKeys() {
  const keys = (await redis.keys('entity_watchers:*')) || [];
  return keys.map(k => {
    const rest = k.slice('entity_watchers:'.length);
    const idx = rest.indexOf(':');
    return { entityType: rest.slice(0, idx), entityId: rest.slice(idx + 1) };
  });
}

// Phase 37/69: global event -> customer match. Returns only watchlists
// whose status is not 'paused' -- pausing a watchlist stops new matches
// without deleting membership or history. Never reveals one customer's
// watch to another (only the caller-supplied entity is resolved, and the
// result is consumed internally by the change engine, never echoed back
// to a customer-facing response).
async function getWatchersForEntity(entityType, entityId) {
  const member = `${entityType}:${entityId}`;
  const watchlistIds = (await redis.smembers(`entity_watchers:${member}`)) || [];
  const watchers = [];
  for (const watchlistId of watchlistIds) {
    const record = await getWatchlistRaw(watchlistId);
    if (record && record.status !== 'paused') {
      watchers.push({ watchlistId, ownerId: record.owner });
    }
  }
  return watchers;
}

async function markEvaluated(entityType, entityId, whenIso) {
  // No-op placeholder key today (per-entity last-evaluated tracking lives
  // in the snapshot record itself, api/_lib/change-engine.js) -- kept as
  // a named function so callers don't need to know that storage detail.
  return true;
}

// Phase 38/55/56: append one event_id to each matched owner's feed,
// newest-first, bounded (ZREMRANGEBYRANK keeps only the newest
// FEED_MAX_PER_OWNER entries per owner -- Phase 54 retention).
async function appendToOwnerFeed(ownerId, eventId, observedAtMs) {
  await redis.zadd(`events:for_owner:${ownerId}`, observedAtMs, eventId);
  await redis.pipeline([
    ['ZREMRANGEBYRANK', `events:for_owner:${ownerId}`, '0', String(-(FEED_MAX_PER_OWNER + 1))],
  ]).catch(() => {});
}

// Phase 55/56: paginated, newest-first, stable ordering (ZREVRANGE by
// insertion score). `cursor` is a 0-based offset -- simple and correct at
// this feature's bounded-per-owner scale (max FEED_MAX_PER_OWNER entries).
async function getOwnerFeedPage(ownerId, { limit = 20, cursor = 0 } = {}) {
  const boundedLimit = Math.max(1, Math.min(limit, 100));
  const start = Math.max(0, cursor);
  const end = start + boundedLimit - 1;
  const ids = (await redis.zrevrange(`events:for_owner:${ownerId}`, start, end)) || [];
  const total = (await redis.zcard(`events:for_owner:${ownerId}`)) || 0;
  return { eventIds: ids, total, nextCursor: end + 1 < total ? end + 1 : null };
}

module.exports = {
  WATCHLIST_SCHEMA_VERSION,
  SUPPORTED_ENTITY_TYPES,
  MAX_WATCHLISTS_PER_OWNER,
  MAX_ENTITIES_PER_WATCHLIST,
  getWatchlistEntitlements,
  createWatchlist,
  listWatchlists,
  getWatchlist,
  updateWatchlist,
  deleteWatchlist,
  listEntities,
  addEntity,
  removeEntity,
  getAllWatchedEntityKeys,
  getWatchersForEntity,
  markEvaluated,
  appendToOwnerFeed,
  getOwnerFeedPage,
  auditWatchlistAction,
  validateEntityRef,
};
