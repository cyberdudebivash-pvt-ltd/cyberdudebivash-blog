#!/usr/bin/env node
/**
 * SENTINEL APEX — Redis → D1 Notification-Delivery-State Migration
 *
 * One-time backfill tool for the Cloudflare-Only Alert Runtime tranche:
 * copies any EXISTING notification preferences / pending deliveries /
 * delivery log / dead letters / audit log entries from the pre-migration
 * Redis keyspace (notify:*, audit:notify:log) into the new D1 tables (see
 * migrations/0001_notification_delivery.sql). Dry-run by default —
 * requires --apply to actually write anything to D1. Never deletes or
 * modifies the source Redis data (the migration mandate is explicit: "Do
 * NOT destroy external Redis data before reconciliation") — this tool
 * only ever READS from Redis; retiring the old Redis keys is a separate,
 * later, explicitly-authorized step, not something this tool does.
 *
 * Idempotent for preferences and pending deliveries: reuses the exact
 * same D1 INSERT ... ON CONFLICT primitives notification-store.js itself
 * uses (Principle 3/4 — one implementation of "how to write a
 * preferences row" / "how to enqueue a delivery job", not a second one
 * reinvented here), so re-running --apply is safe and will not duplicate
 * a preference row or a pending job. Delivery-log / dead-letter / audit-
 * log HISTORY entries are NOT idempotency-checked — neither the old
 * Redis sorted sets nor the new D1 autoincrement tables have a natural
 * shared unique key for a single historical entry. This is a disclosed,
 * low-risk limitation: these are audit/observability trails, not
 * authoritative delivery state (the authoritative state — preferences,
 * pending jobs — is fully idempotent either way) — run --apply exactly
 * once per environment, verify with a dry-run first, and treat a second
 * --apply run as a real risk of duplicated (not lost, not corrupted)
 * history rows.
 *
 * Usage:
 *   UPSTASH_REDIS_REST_URL=... UPSTASH_REDIS_REST_TOKEN=... \
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_D1_DATABASE_ID=... CLOUDFLARE_API_TOKEN=... \
 *     node scripts/migrate-notifications-redis-to-d1.js [--apply] [--verbose]
 *
 * Without --apply: reports counts of what would be migrated, writes
 * nothing to D1 (Redis is never written to by this tool regardless).
 */
'use strict';

const redis = require('../api/_lib/redis');
const d1 = require('../api/_lib/d1');
const notify = require('../api/_lib/notification-store');

function hashToObject(flatArray) {
  if (!flatArray || !Array.isArray(flatArray) || flatArray.length === 0) return null;
  const obj = {};
  for (let i = 0; i < flatArray.length; i += 2) obj[flatArray[i]] = flatArray[i + 1];
  return obj;
}

function parseJsonSafe(raw) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function migratePreferences({ apply, verbose, counts }) {
  const keys = await redis.keys('notify:prefs:*');
  for (const key of keys) {
    const ownerId = key.slice('notify:prefs:'.length);
    const stored = hashToObject(await redis.hgetall(key)) || {};
    counts.preferences_found++;
    if (verbose) console.log(`[MIGRATE] preferences: ${ownerId}`);
    if (!apply) continue;

    const now = new Date().toISOString();
    const cols = ['owner_id', 'updated_at'];
    const vals = [ownerId, stored.updated_at || now];
    const setClauses = ['updated_at = excluded.updated_at'];
    const maybe = (col, val) => { cols.push(col); vals.push(val); setClauses.push(`${col} = excluded.${col}`); };
    if (stored.email_enabled !== undefined) maybe('email_enabled', stored.email_enabled === 'true' ? 1 : 0);
    if (stored.email_override !== undefined) maybe('email_override', stored.email_override);
    if (stored.webhook_enabled !== undefined) maybe('webhook_enabled', stored.webhook_enabled === 'true' ? 1 : 0);
    if (stored.webhook_url !== undefined) maybe('webhook_url', stored.webhook_url);
    if (stored.webhook_secret !== undefined) maybe('webhook_secret', stored.webhook_secret);
    if (stored.webhook_configured_at !== undefined) maybe('webhook_configured_at', stored.webhook_configured_at);

    const placeholders = cols.map(() => '?').join(', ');
    await d1.run(
      `INSERT INTO notification_preferences (${cols.join(', ')}) VALUES (${placeholders})
       ON CONFLICT(owner_id) DO UPDATE SET ${setClauses.join(', ')}`,
      vals
    );
    counts.preferences_migrated++;
  }
}

async function migratePendingDeliveries({ apply, verbose, counts }) {
  const keys = await redis.keys('notify:pending:*');
  for (const key of keys) {
    const record = parseJsonSafe(await redis.get(key));
    if (!record) continue;
    for (const channel of record.channels_pending || []) {
      counts.pending_jobs_found++;
      const deliveryId = notify.buildDeliveryId(record.owner_id, record.event_id, channel);
      if (verbose) console.log(`[MIGRATE] pending job: ${deliveryId}`);
      if (!apply) continue;

      const attempt = record.attempts && record.attempts[channel];
      const nowIso = new Date().toISOString();
      const affected = await d1.runMutationWithChanges(
        `INSERT INTO notification_delivery_jobs
           (delivery_id, event_id, owner_id, watchlist_id, channel, state, attempt_count, next_attempt_at, schema_version, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
         ON CONFLICT(delivery_id) DO NOTHING`,
        [
          deliveryId, record.event_id, record.owner_id, record.watchlist_id || null, channel,
          (attempt && attempt.count) || 0, (attempt && attempt.next_attempt_at) || Date.now(),
          record.schema_version || notify.NOTIFICATION_SCHEMA_VERSION, record.created_at || nowIso, nowIso,
        ]
      );
      if (affected > 0) counts.pending_jobs_migrated++;
    }
  }
}

// Shared shape for the three append-only Redis sorted-set logs (delivery
// log, dead letters, audit log) -- one scan-and-insert implementation
// parameterized by each table's own INSERT SQL and field mapping, not
// three near-identical copies of the same Redis-scan loop.
async function migrateLogEntries({ label, keyPattern, keyPrefix, insertSql, buildParams, apply, verbose, counts }) {
  const keys = await redis.keys(keyPattern);
  for (const key of keys) {
    const ownerId = key.slice(keyPrefix.length);
    const raw = await redis.zrevrange(key, 0, -1);
    for (const entryRaw of raw || []) {
      const entry = parseJsonSafe(entryRaw);
      if (!entry) continue;
      counts[`${label}_found`] = (counts[`${label}_found`] || 0) + 1;
      if (verbose) console.log(`[MIGRATE] ${label}: ${ownerId}`);
      if (!apply) continue;
      await d1.run(insertSql, buildParams(ownerId, entry));
      counts[`${label}_migrated`] = (counts[`${label}_migrated`] || 0) + 1;
    }
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

  const counts = { preferences_found: 0, preferences_migrated: 0, pending_jobs_found: 0, pending_jobs_migrated: 0 };

  await migratePreferences({ apply, verbose, counts });
  await migratePendingDeliveries({ apply, verbose, counts });
  await migrateLogEntries({
    label: 'delivery_log', keyPattern: 'notify:delivery_log:*', keyPrefix: 'notify:delivery_log:',
    insertSql: `INSERT INTO notification_delivery_log (owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    buildParams: (ownerId, e) => [ownerId, e.channel, e.event_id, e.watchlist_id || null, e.status, e.error || null, e.attempt || 0, e.attempted_at || new Date().toISOString()],
    apply, verbose, counts,
  });
  await migrateLogEntries({
    label: 'dead_letters', keyPattern: 'notify:dead_letter:*', keyPrefix: 'notify:dead_letter:',
    insertSql: `INSERT INTO notification_dead_letters (owner_id, event_id, watchlist_id, channel, attempts, reason, dead_lettered_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    buildParams: (ownerId, e) => [ownerId, e.event_id, e.watchlist_id || null, e.channel, e.attempts || 0, e.reason || 'UNKNOWN', e.dead_lettered_at || new Date().toISOString()],
    apply, verbose, counts,
  });
  await migrateLogEntries({
    label: 'audit_log', keyPattern: 'audit:notify:log', keyPrefix: '',
    insertSql: `INSERT INTO notification_audit_log (owner_id, action, data, ts) VALUES (?, ?, ?, ?)`,
    buildParams: (_ownerId, e) => [e.owner_id || '', e.action || 'UNKNOWN', JSON.stringify(e), e.ts || new Date().toISOString()],
    apply, verbose, counts,
  });

  console.log('[MIGRATE] Summary:', JSON.stringify(counts));
  if (!apply) console.log('[MIGRATE] Dry run only — re-run with --apply to write these rows to D1.');
}

if (require.main === module) {
  main().catch(err => {
    console.error('[MIGRATE] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { migratePreferences, migratePendingDeliveries, migrateLogEntries };
