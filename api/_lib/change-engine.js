/**
 * SENTINEL APEX — Watchlist Change-Detection Engine
 *
 * Orchestrates one evaluation cycle: for each entity at least one
 * customer watches (api/_lib/watchlist-store.js's reverse index), loads
 * its CURRENT canonical state via the same functions api/v1/intel.js's
 * dossier action already uses (getCVEDetail/getCampaignDetail/loadGraph,
 * called at tier='enterprise' to see the full untiered facts -- this is
 * an internal system read, never returned to a customer directly; any
 * tier-gating a customer sees happens at feed-read time, mirroring
 * intelligence-dossier.js's own tier_info pattern), normalizes it
 * (api/_lib/watchable-state.js), compares its fingerprint against the
 * last-stored snapshot, and on a real semantic change runs the
 * deterministic detector (api/_lib/change-detector.js) to produce typed
 * events, persists each one idempotently, and matches it to watchers.
 *
 * GLOBAL EVENT vs CUSTOMER MATCH (Phase 67/68): one event is computed and
 * persisted once per entity change, then fanned out by reference
 * (event_id appended to each watcher's feed ZSET) -- not recomputed or
 * duplicated per watching customer. If 100 customers watch the same CVE,
 * the diff runs once.
 *
 * Trigger (Phase 48-51): this module exposes a pure, bounded, cursor-
 * resumable batch function. It is invoked manually today via
 * scripts/evaluate-watchlist-changes.js -- not from a Cloudflare Cron
 * Trigger. wrangler.jsonc's own header explicitly defers
 * "triggers.crons -- scheduling authority is undecided" pending separate
 * authorization, the same posture already applied to D1/KV in this
 * tranche; wiring a live cron is out of scope here and tracked in
 * platform/open-issues.md. Event-driven evaluation from the Intel
 * Factory's own publication pipeline (Python) was evaluated and deferred
 * for the same reason PR crossing the JS/Python boundary was avoided in
 * every prior tranche -- see the certification doc.
 */
'use strict';

const redis = require('./redis');
const store = require('./watchlist-store');
const {
  buildCveWatchableState, buildCampaignWatchableState,
  fingerprintState, WATCHABLE_STATE_SCHEMA_VERSION,
} = require('./watchable-state');
const { detectChanges } = require('./change-detector');

const CURSOR_KEY = 'watchlist_eval:cursor';
const DEFAULT_BATCH_LIMIT = 200;

function loadIntelLib() {
  // Lazy require: avoids a require-cycle at module-load time (intel.js
  // requires intelligence-dossier.js, which watchable-state.js also
  // requires) and lets tests inject a fake via jest.mock('./intel')
  // without touching the real data-file-backed module cache.
  return require('./intel');
}

/* ───────────────────────── event persistence ───────────────────────── */

// Phase 31: SET...NX makes "already exists" and "just created" a single
// atomic round trip -- no separate EXISTS check, no race between two
// evaluator runs processing the same change.
async function persistEventIfNew(event) {
  const created = await redis.setnx(`event:${event.event_id}`, JSON.stringify(event));
  if (!created) return { created: false };
  const scoreMs = Date.parse(event.observed_at) || Date.now();
  await redis.zadd(`events:by_entity:${event.entity_type}:${event.entity_id}`, scoreMs, event.event_id);
  return { created: true };
}

async function getEventById(eventId) {
  const raw = await redis.get(`event:${eventId}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function getEventsByIds(eventIds) {
  const events = [];
  for (const id of eventIds) {
    const e = await getEventById(id);
    if (e) events.push(e);
  }
  return events;
}

/* ───────────────────────── snapshots ───────────────────────── */

function snapshotKey(entityType, entityId) {
  return `snapshot:${entityType}:${entityId}`;
}

async function loadSnapshot(entityType, entityId) {
  const raw = await redis.get(snapshotKey(entityType, entityId));
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function saveSnapshot(entityType, entityId, state, fingerprint) {
  const record = {
    schema_version: WATCHABLE_STATE_SCHEMA_VERSION,
    fingerprint,
    state,
    snapshotted_at: new Date().toISOString(),
  };
  await redis.set(snapshotKey(entityType, entityId), JSON.stringify(record));
}

/* ───────────────────────── single-entity evaluation ───────────────────────── */

// Phase 72 (catastrophic data-loss protection): a canonical-load failure
// (found: false) is reported as 'load_failed' and the function returns
// immediately -- the stored snapshot is left untouched and no event is
// emitted. This is deliberate: overwriting the snapshot with an "empty"
// state derived from a failed load would make the *next* successful load
// look like every relationship just disappeared, or (worse, once this
// entity is re-found) like everything just reappeared as "new".
async function evaluateEntity({ entityType, entityId, intel, graph, reportsIndexData }) {
  let currentState = null;

  if (entityType === 'cve') {
    const { found, item } = intel.getCVEDetail(entityId, 'enterprise');
    if (!found) return { status: 'load_failed', entityType, entityId, events: [] };
    currentState = buildCveWatchableState({ graph, cveId: entityId, cveItem: item, reportsIndexData });
  } else if (entityType === 'campaign') {
    const { found, campaign } = intel.getCampaignDetail(entityId, 'enterprise');
    if (!found) return { status: 'load_failed', entityType, entityId, events: [] };
    currentState = buildCampaignWatchableState({ campaign, reportsIndexData });
  } else {
    return { status: 'unsupported_type', entityType, entityId, events: [] };
  }

  const fingerprint = fingerprintState(currentState);
  const prior = await loadSnapshot(entityType, entityId);

  // Phase 52: first observation ever -- establish baseline, zero events.
  // Phase 30: a stored snapshot from an older WATCHABLE_STATE_SCHEMA_VERSION
  // is treated identically -- its shape cannot be safely diffed against
  // the current one (a schema change can rename/add/remove fields), and
  // comparing incompatible shapes would either crash or, worse, produce a
  // false mass-change event for every watched entity purely because the
  // *schema* changed, not the intelligence. Re-baseline silently instead.
  if (!prior || prior.schema_version !== WATCHABLE_STATE_SCHEMA_VERSION) {
    await saveSnapshot(entityType, entityId, currentState, fingerprint);
    return { status: 'baseline_established', entityType, entityId, events: [] };
  }

  // Phase 29: fingerprint-identical -- skip the detailed diff entirely.
  if (prior.fingerprint === fingerprint) {
    return { status: 'unchanged', entityType, entityId, events: [] };
  }

  const { events } = detectChanges({ entityType, before: prior.state, after: currentState });

  const created = [];
  for (const event of events) {
    const result = await persistEventIfNew(event);
    if (!result.created) continue; // Phase 31/32: replay-safe, no duplicate fan-out
    const watchers = await store.getWatchersForEntity(entityType, entityId);
    for (const w of watchers) {
      await store.appendToOwnerFeed(w.ownerId, event.event_id, Date.parse(event.observed_at) || Date.now());
    }
    created.push(event);
  }

  await saveSnapshot(entityType, entityId, currentState, fingerprint);
  return { status: created.length ? 'changed' : 'unchanged', entityType, entityId, events: created };
}

/* ───────────────────────── bounded batch driver ───────────────────────── */

// Phase 48/51/67: enumerates ONLY watched entities (never the full
// corpus), processes a bounded slice, and persists a cursor so repeated
// runs sweep the full watched set over time rather than starving
// alphabetically-later entities. The cursor advances before processing
// completes (not after) so one entity that reliably throws can never
// permanently wedge the sweep -- safe because every step here is
// independently idempotent and cheap to simply skip and revisit next run.
async function evaluateWatchedEntities({ batchLimit = DEFAULT_BATCH_LIMIT } = {}) {
  const intel = loadIntelLib();
  const graph = intel.loadGraph();
  const reportsIndexData = intel.loadJSON(intel.PATHS.reportsIndex);

  const watched = (await store.getAllWatchedEntityKeys())
    .sort((a, b) => (a.entityType + a.entityId).localeCompare(b.entityType + b.entityId));

  const results = {
    watched_entities_total: watched.length,
    evaluated: 0, changed: 0, baseline: 0, unchanged: 0, load_failed: 0, unsupported: 0,
    events_created: 0, watchlists_touched: 0,
  };
  if (watched.length === 0) return results;

  const cursorRaw = await redis.get(CURSOR_KEY);
  let cursor = parseInt(cursorRaw, 10);
  if (!Number.isFinite(cursor) || cursor < 0) cursor = 0;
  cursor = cursor % watched.length;

  const batchSize = Math.min(batchLimit, watched.length);
  const batch = [];
  for (let i = 0; i < batchSize; i++) batch.push(watched[(cursor + i) % watched.length]);

  const nextCursor = (cursor + batchSize) % watched.length;
  await redis.set(CURSOR_KEY, String(nextCursor));

  const touchedWatchlists = new Set();

  for (const { entityType, entityId } of batch) {
    const outcome = await evaluateEntity({ entityType, entityId, intel, graph, reportsIndexData });
    results.evaluated++;
    if (outcome.status === 'load_failed') { results.load_failed++; continue; }
    if (outcome.status === 'unsupported_type') { results.unsupported++; continue; }
    if (outcome.status === 'baseline_established') results.baseline++;
    else if (outcome.status === 'changed') { results.changed++; results.events_created += outcome.events.length; }
    else results.unchanged++;

    const watchers = await store.getWatchersForEntity(entityType, entityId);
    for (const w of watchers) touchedWatchlists.add(w.watchlistId);
  }

  const nowIso = new Date().toISOString();
  for (const watchlistId of touchedWatchlists) {
    await redis.hset(`watchlist:${watchlistId}`, 'last_evaluated_at', nowIso).catch(() => {});
  }
  results.watchlists_touched = touchedWatchlists.size;

  return results;
}

module.exports = {
  evaluateEntity,
  evaluateWatchedEntities,
  persistEventIfNew,
  getEventById,
  getEventsByIds,
  loadSnapshot,
  saveSnapshot,
};
