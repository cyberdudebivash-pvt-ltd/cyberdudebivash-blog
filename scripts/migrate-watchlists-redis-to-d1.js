#!/usr/bin/env node
/**
 * SENTINEL APEX — Redis → D1 Watchlist & Change-Detection State Migration
 *
 * One-time backfill tool for the Cloudflare-Only Runtime Completion v2
 * tranche: copies any EXISTING watchlists / tracked entities / owner
 * feeds / entity snapshots / change events / eval cursor / audit log from
 * the pre-migration Redis keyspace (watchlist:*, owner:*:watchlists,
 * entity_watchers:*, events:for_owner:*, event:*, snapshot:*,
 * watchlist_eval:cursor, audit:watchlist:log) into the new D1 tables
 * (see migrations/0002_watchlists_change_detection.sql). Dry-run by
 * default — requires --apply to actually write anything to D1. Never
 * deletes or modifies the source Redis data — this tool only ever READS
 * from Redis; retiring the old keys is a separate, later, explicitly-
 * authorized step, not something this tool does.
 *
 * Idempotent for watchlists, entities, snapshots, and the eval cursor:
 * reuses the same D1 INSERT/UPSERT primitives watchlist-store.js and
 * change-engine.js themselves use. Idempotent for events too (event_id
 * is a natural, stable unique key already). owner_feed migration is
 * idempotent per (owner_id, event_id) via the same ON CONFLICT DO
 * NOTHING watchlist-store.js's appendToOwnerFeed() uses. Only the audit
 * log is NOT idempotency-checked (no natural shared unique key across
 * the two stores for a single historical entry) — same disclosed,
 * accepted limitation as migrate-notifications-redis-to-d1.js's own
 * audit-log migration; run --apply exactly once per environment.
 *
 * Usage:
 *   UPSTASH_REDIS_REST_URL=... UPSTASH_REDIS_REST_TOKEN=... \
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_D1_DATABASE_ID=... CLOUDFLARE_API_TOKEN=... \
 *     node scripts/migrate-watchlists-redis-to-d1.js [--apply] [--verbose]
 *
 * Without --apply: reports counts of what would be migrated, writes
 * nothing to D1 (Redis is never written to by this tool regardless).
 */
'use strict';

const redis = require('../api/_lib/redis');
const d1 = require('../api/_lib/d1');

function parseJsonSafe(raw) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function migrateWatchlists({ apply, verbose, counts }) {
  const keys = (await redis.keys('watchlist:*')).filter(k => !k.endsWith(':entities'));
  for (const key of keys) {
    const watchlistId = key.slice('watchlist:'.length);
    const flat = await redis.hgetall(key);
    if (!flat || flat.length === 0) continue;
    const record = {};
    for (let i = 0; i < flat.length; i += 2) record[flat[i]] = flat[i + 1];
    counts.watchlists_found++;
    if (verbose) console.log(`[MIGRATE] watchlist: ${watchlistId}`);
    if (!apply) continue;

    await d1.run(
      `INSERT INTO watchlists (id, owner_id, name, description, status, schema_version, created_at, updated_at, last_evaluated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         owner_id = excluded.owner_id, name = excluded.name, description = excluded.description,
         status = excluded.status, updated_at = excluded.updated_at, last_evaluated_at = excluded.last_evaluated_at`,
      [
        watchlistId, record.owner, record.name || '', record.description || '',
        record.status || 'active', record.schema_version || '1.0',
        record.created_at || new Date().toISOString(), record.updated_at || new Date().toISOString(),
        record.last_evaluated_at || null,
      ]
    );
    counts.watchlists_migrated++;

    const members = await redis.smembers(`${key}:entities`);
    for (const member of members || []) {
      const idx = member.indexOf(':');
      const entityType = member.slice(0, idx);
      const entityId = member.slice(idx + 1);
      counts.entities_found++;
      if (verbose) console.log(`[MIGRATE] entity: ${watchlistId} -> ${member}`);
      const affected = await d1.runMutationWithChanges(
        `INSERT INTO watchlist_entities (watchlist_id, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(watchlist_id, entity_type, entity_id) DO NOTHING`,
        [watchlistId, entityType, entityId, new Date().toISOString()]
      );
      if (affected > 0) counts.entities_migrated++;
    }
  }
}

async function migrateOwnerFeeds({ apply, verbose, counts }) {
  const keys = await redis.keys('events:for_owner:*');
  for (const key of keys) {
    const ownerId = key.slice('events:for_owner:'.length);
    const raw = await redis.zrange(key, 0, -1, true); // [member, score, member, score, ...]
    for (let i = 0; i < raw.length; i += 2) {
      const eventId = raw[i];
      const score = Number(raw[i + 1]) || Date.now();
      counts.feed_entries_found++;
      if (verbose) console.log(`[MIGRATE] owner_feed: ${ownerId} -> ${eventId}`);
      if (!apply) continue;
      const affected = await d1.runMutationWithChanges(
        `INSERT INTO owner_feed (owner_id, event_id, observed_at_ms) VALUES (?, ?, ?)
         ON CONFLICT(owner_id, event_id) DO NOTHING`,
        [ownerId, eventId, score]
      );
      if (affected > 0) counts.feed_entries_migrated++;
    }
  }
}

async function migrateSnapshots({ apply, verbose, counts }) {
  const keys = await redis.keys('snapshot:*');
  for (const key of keys) {
    const rest = key.slice('snapshot:'.length);
    const idx = rest.indexOf(':');
    const entityType = rest.slice(0, idx);
    const entityId = rest.slice(idx + 1);
    const record = parseJsonSafe(await redis.get(key));
    if (!record) continue;
    counts.snapshots_found++;
    if (verbose) console.log(`[MIGRATE] snapshot: ${entityType}:${entityId}`);
    if (!apply) continue;
    await d1.run(
      `INSERT INTO entity_snapshots (entity_type, entity_id, schema_version, fingerprint, state, snapshotted_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(entity_type, entity_id) DO UPDATE SET
         schema_version = excluded.schema_version, fingerprint = excluded.fingerprint,
         state = excluded.state, snapshotted_at = excluded.snapshotted_at`,
      [entityType, entityId, record.schema_version || '1.0', record.fingerprint || '', JSON.stringify(record.state || {}), record.snapshotted_at || new Date().toISOString()]
    );
    counts.snapshots_migrated++;
  }
}

async function migrateEvents({ apply, verbose, counts }) {
  const keys = (await redis.keys('event:*')).filter(k => !k.startsWith('events:'));
  for (const key of keys) {
    const eventId = key.slice('event:'.length);
    const event = parseJsonSafe(await redis.get(key));
    if (!event) continue;
    counts.events_found++;
    if (verbose) console.log(`[MIGRATE] event: ${eventId}`);
    if (!apply) continue;
    const affected = await d1.runMutationWithChanges(
      `INSERT INTO change_events (event_id, entity_type, entity_id, observed_at, payload, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(event_id) DO NOTHING`,
      [eventId, event.entity_type, event.entity_id, event.observed_at, JSON.stringify(event), new Date().toISOString()]
    );
    if (affected > 0) counts.events_migrated++;
  }
}

async function migrateCursor({ apply, verbose, counts }) {
  const raw = await redis.get('watchlist_eval:cursor');
  const cursor = parseInt(raw, 10);
  if (!Number.isFinite(cursor)) return;
  counts.cursor_found = 1;
  if (verbose) console.log(`[MIGRATE] eval cursor: ${cursor}`);
  if (!apply) return;
  await d1.run(
    `INSERT INTO watchlist_eval_state (id, cursor) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET cursor = excluded.cursor`,
    [cursor]
  );
  counts.cursor_migrated = 1;
}

async function migrateAuditLog({ apply, verbose, counts }) {
  const raw = await redis.zrevrange('audit:watchlist:log', 0, -1);
  for (const entryRaw of raw || []) {
    const entry = parseJsonSafe(entryRaw);
    if (!entry) continue;
    counts.audit_found++;
    if (verbose) console.log('[MIGRATE] audit entry');
    if (!apply) continue;
    const { action, ts, ...data } = entry;
    await d1.run(
      'INSERT INTO watchlist_audit_log (action, data, ts) VALUES (?, ?, ?)',
      [action || 'UNKNOWN', JSON.stringify(data), ts || new Date().toISOString()]
    );
    counts.audit_migrated++;
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const apply = argv.includes('--apply');
  const verbose = argv.includes('--verbose');

  if (!d1.isConfigured()) {
    console.error('[MIGRATE] CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_D1_DATABASE_ID / CLOUDFLARE_API_TOKEN must be set.');
    process.exit(1);
    return;
  }
  if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
    console.error('[MIGRATE] UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN must be set (this tool only reads from Redis; the source data lives there).');
    process.exit(1);
    return;
  }

  console.log(`[MIGRATE] Mode: ${apply ? 'APPLY (writing to D1)' : 'DRY RUN (no D1 writes — pass --apply to write)'}`);

  const counts = {
    watchlists_found: 0, watchlists_migrated: 0,
    entities_found: 0, entities_migrated: 0,
    feed_entries_found: 0, feed_entries_migrated: 0,
    snapshots_found: 0, snapshots_migrated: 0,
    events_found: 0, events_migrated: 0,
    cursor_found: 0, cursor_migrated: 0,
    audit_found: 0, audit_migrated: 0,
  };

  await migrateWatchlists({ apply, verbose, counts });
  await migrateOwnerFeeds({ apply, verbose, counts });
  await migrateSnapshots({ apply, verbose, counts });
  await migrateEvents({ apply, verbose, counts });
  await migrateCursor({ apply, verbose, counts });
  await migrateAuditLog({ apply, verbose, counts });

  console.log('[MIGRATE] Summary:', JSON.stringify(counts));
  if (!apply) console.log('[MIGRATE] Dry run only — re-run with --apply to write these rows to D1.');
}

if (require.main === module) {
  main().catch(err => {
    console.error('[MIGRATE] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { migrateWatchlists, migrateOwnerFeeds, migrateSnapshots, migrateEvents, migrateCursor, migrateAuditLog };
