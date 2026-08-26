'use strict';

/**
 * In-memory double implementing the same PUBLIC surface as api/_lib/d1.js
 * (query/run/runMutationWithChanges/setD1Binding/isConfigured), so
 * notification-store.js and notification-dispatch.js can be tested as
 * real sequences of calls against real relational semantics (conditional-
 * UPDATE affected-row counts, INSERT...ON CONFLICT idempotency, ORDER BY
 * id DESC LIMIT trimming) without a live D1 database or wrangler --
 * mirrors fake-redis.js's role/discipline exactly (fake the external
 * store, run the real production logic on top of it), applied to the one
 * D1 database this platform now has.
 *
 * NOT a general SQL engine: this recognizes exactly the fixed set of
 * statement shapes notification-store.js and scripts/migrate-
 * notifications-redis-to-d1.js actually emit (enumerated in this file's
 * dispatch table below, each tied to its real call site in a comment),
 * dispatched by matching a few characteristic substrings rather than by
 * parsing arbitrary SQL. This is intentional, not a shortcut: the
 * production SQL text itself was already empirically verified against a
 * REAL local Cloudflare D1 database (`wrangler d1 execute --local`,
 * documented in the Cloudflare-Only Alert Runtime certification doc) --
 * what this fixture needs to prove is that notification-store.js's own
 * JS logic (retry math, dead-letter thresholds, claim-token threading,
 * disposition strings) behaves correctly given real conditional-mutation
 * semantics, not that D1's SQL engine works (already proven separately).
 * If a new statement shape is ever added to those two files without a
 * matching branch here, every affected test fails loudly (no matching
 * branch = a thrown error), not silently -- there is no silent fallback.
 */

function createFakeD1() {
  const preferences = new Map(); // owner_id -> row
  const jobs = new Map(); // delivery_id -> row
  const deliveryLog = []; // rows with an autoincrement id
  const deadLetters = [];
  const auditLog = [];
  let nextLogId = 1, nextDeadLetterId = 1, nextAuditId = 1;
  let lastAffected = 0;

  function cloneRow(row) { return row ? { ...row } : row; }

  function trimToNewest(arr, ownerId, limit) {
    const owned = arr.filter(r => r.owner_id === ownerId).sort((a, b) => b.id - a.id);
    const keepIds = new Set(owned.slice(0, limit).map(r => r.id));
    let removed = 0;
    for (let i = arr.length - 1; i >= 0; i--) {
      if (arr[i].owner_id === ownerId && !keepIds.has(arr[i].id)) { arr.splice(i, 1); removed++; }
    }
    return removed;
  }

  function selectByOwnerOrdered(arr, ownerId, limit, mapCols) {
    return arr.filter(r => r.owner_id === ownerId)
      .sort((a, b) => b.id - a.id)
      .slice(0, limit)
      .map(r => mapCols ? mapCols(r) : cloneRow(r));
  }

  // Mirrors d1.js's own query()/run()/runMutationWithChanges() contract
  // exactly -- see that file's header for why runMutationWithChanges
  // never trusts meta.changes/rows_written, only an affected-row count.
  // Here that count is tracked directly as a side effect of each branch
  // below (no literal "SELECT changes()" text is ever parsed -- that's
  // an implementation detail internal to the real d1.js's exec(), not
  // part of the public surface notification-store.js actually calls).
  function exec(sql, params) {
    const p = params || [];

    /* ── notification_preferences ───────────────────────────────── */

    if (sql.includes('SELECT webhook_secret FROM notification_preferences')) {
      const row = preferences.get(p[0]);
      return { rows: row ? [{ webhook_secret: row.webhook_secret != null ? row.webhook_secret : null }] : [] };
    }
    if (sql.includes('SELECT * FROM notification_preferences')) {
      const row = preferences.get(p[0]);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.includes('INSERT INTO notification_preferences')) {
      // Dynamic column list -- extract "(col1, col2, ...)" right after
      // the table name, matching updatePreferences()/rotateWebhookSecret()/
      // the migration script's own dynamic-column-list construction.
      const colsMatch = sql.match(/INSERT INTO notification_preferences \(([^)]+)\)/);
      const cols = colsMatch[1].split(',').map(c => c.trim());
      const ownerId = p[cols.indexOf('owner_id')];
      const existing = preferences.get(ownerId) || {
        owner_id: ownerId, email_enabled: 1, email_override: '', webhook_enabled: 0,
        webhook_url: '', webhook_secret: null, webhook_configured_at: null, updated_at: null,
      };
      const row = { ...existing };
      cols.forEach((col, i) => { row[col] = p[i]; });
      preferences.set(ownerId, row);
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── notification_delivery_log ──────────────────────────────── */

    if (sql.startsWith('INSERT INTO notification_delivery_log')) {
      const [owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at] = p;
      deliveryLog.push({ id: nextLogId++, owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_delivery_log')) {
      const [ownerId, , limit] = p;
      lastAffected = trimToNewest(deliveryLog, ownerId, limit);
      return { rows: [] };
    }
    if (sql.startsWith('SELECT channel, event_id, watchlist_id, status, error, attempt, attempted_at FROM notification_delivery_log')) {
      const [ownerId, limit] = p;
      return { rows: selectByOwnerOrdered(deliveryLog, ownerId, limit, r => ({
        channel: r.channel, event_id: r.event_id, watchlist_id: r.watchlist_id, status: r.status,
        error: r.error, attempt: r.attempt, attempted_at: r.attempted_at,
      })) };
    }

    /* ── notification_dead_letters ──────────────────────────────── */

    if (sql.startsWith('INSERT INTO notification_dead_letters')) {
      const [owner_id, event_id, watchlist_id, channel, attempts, reason, dead_lettered_at] = p;
      deadLetters.push({ id: nextDeadLetterId++, owner_id, event_id, watchlist_id, channel, attempts, reason, dead_lettered_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_dead_letters')) {
      const [ownerId, , limit] = p;
      lastAffected = trimToNewest(deadLetters, ownerId, limit);
      return { rows: [] };
    }
    if (sql.startsWith('SELECT event_id, watchlist_id, channel, attempts, reason, dead_lettered_at FROM notification_dead_letters')) {
      const [ownerId, limit] = p;
      return { rows: selectByOwnerOrdered(deadLetters, ownerId, limit, r => ({
        event_id: r.event_id, watchlist_id: r.watchlist_id, channel: r.channel,
        attempts: r.attempts, reason: r.reason, dead_lettered_at: r.dead_lettered_at,
      })) };
    }

    /* ── notification_audit_log ─────────────────────────────────── */

    if (sql.startsWith('INSERT INTO notification_audit_log')) {
      const [owner_id, action, data, ts] = p;
      auditLog.push({ id: nextAuditId++, owner_id, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_audit_log')) {
      const [ownerId, , limit] = p;
      lastAffected = trimToNewest(auditLog, ownerId, limit);
      return { rows: [] };
    }

    /* ── notification_delivery_jobs ─────────────────────────────── */

    // enqueuePendingDelivery(): literal 'pending'/0 for state/attempt_count.
    if (sql.includes("VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)")) {
      const [delivery_id, event_id, owner_id, watchlist_id, channel, next_attempt_at, schema_version, created_at, updated_at] = p;
      if (jobs.has(delivery_id)) { lastAffected = 0; return { rows: [] }; } // ON CONFLICT DO NOTHING
      jobs.set(delivery_id, {
        delivery_id, event_id, owner_id, watchlist_id, channel, state: 'pending',
        attempt_count: 0, next_attempt_at, claim_token: null, claimed_at: null, lease_expires_at: null,
        schema_version, created_at, updated_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    // migrate-notifications-redis-to-d1.js's enqueue variant: attempt_count
    // is itself a bound param (backfilling a real prior attempt count),
    // not the literal 0 the live enqueue path always uses.
    if (sql.includes("VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)")) {
      const [delivery_id, event_id, owner_id, watchlist_id, channel, attempt_count, next_attempt_at, schema_version, created_at, updated_at] = p;
      if (jobs.has(delivery_id)) { lastAffected = 0; return { rows: [] }; }
      jobs.set(delivery_id, {
        delivery_id, event_id, owner_id, watchlist_id, channel, state: 'pending',
        attempt_count, next_attempt_at, claim_token: null, claimed_at: null, lease_expires_at: null,
        schema_version, created_at, updated_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT MIN(next_attempt_at)')) {
      const values = [...jobs.values()].map(j => j.next_attempt_at);
      return { rows: [{ oldest: values.length ? Math.min(...values) : null }] };
    }
    // Unique discriminator, not startsWith: the real statement's actual
    // template-literal text has a newline between "notification_delivery_
    // jobs" and "WHERE" (see notification-store.js's getDuePendingDeliveries),
    // so a startsWith check assuming a single space there would silently
    // never match. "ORDER BY next_attempt_at ASC" appears in no other
    // statement this fixture handles, so this is safe regardless of
    // surrounding whitespace/line breaks or check ordering below.
    if (sql.includes('ORDER BY next_attempt_at ASC')) {
      const [now1, now2, limit] = p;
      const due = [...jobs.values()].filter(j => {
        if (j.next_attempt_at > now1) return false;
        if (j.state === 'pending' || j.state === 'retry') return true;
        if (j.state === 'claimed' && j.lease_expires_at < now2) return true;
        return false;
      }).sort((a, b) => a.next_attempt_at - b.next_attempt_at).slice(0, limit);
      return { rows: due.map(cloneRow) };
    }
    if (sql.includes("SET state='claimed', claim_token=")) {
      const [claimToken, claimedAt, leaseExpiresAt, deliveryId, now1, now2] = p;
      const job = jobs.get(deliveryId);
      const claimable = job && job.next_attempt_at <= now1 &&
        ((job.state === 'pending' || job.state === 'retry') || (job.state === 'claimed' && job.lease_expires_at < now2));
      if (!claimable) { lastAffected = 0; return { rows: [] }; }
      job.state = 'claimed'; job.claim_token = claimToken; job.claimed_at = claimedAt; job.lease_expires_at = leaseExpiresAt;
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes("SET state='retry', claim_token=NULL, claimed_at=NULL, lease_expires_at=NULL")) {
      const [deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      if (!job || job.claim_token !== claimToken || job.state !== 'claimed') { lastAffected = 0; return { rows: [] }; }
      job.state = 'retry'; job.claim_token = null; job.claimed_at = null; job.lease_expires_at = null;
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes("SET state='retry', attempt_count=")) {
      const [attemptCount, nextAttemptAt, updatedAt, deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      if (!job || job.claim_token !== claimToken || job.state !== 'claimed') { lastAffected = 0; return { rows: [] }; }
      job.state = 'retry'; job.attempt_count = attemptCount; job.next_attempt_at = nextAttemptAt;
      job.claim_token = null; job.claimed_at = null; job.lease_expires_at = null; job.updated_at = updatedAt;
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=?')) {
      const [deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      const match = job && job.claim_token === claimToken && job.state === 'claimed';
      return { rows: match ? [cloneRow(job)] : [] };
    }
    if (sql.startsWith('DELETE FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=?')) {
      const [deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      if (!job || job.claim_token !== claimToken || job.state !== 'claimed') { lastAffected = 0; return { rows: [] }; }
      jobs.delete(deliveryId);
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_delivery_jobs WHERE delivery_id=?')) {
      const [deliveryId] = p;
      lastAffected = jobs.delete(deliveryId) ? 1 : 0;
      return { rows: [] };
    }

    throw new Error(`fake-d1: no matching statement branch for SQL: ${sql}`);
  }

  return {
    query: async (sql, params) => exec(sql, params).rows,
    run: async (sql, params) => { const r = exec(sql, params); return { results: r.rows, success: true, meta: {} }; },
    runMutationWithChanges: async (sql, params) => { exec(sql, params); return lastAffected; },
    setD1Binding: () => {},
    isConfigured: () => true,
    _dump: () => ({ preferences, jobs, deliveryLog, deadLetters, auditLog }),
    _reset: () => {
      preferences.clear(); jobs.clear();
      deliveryLog.length = 0; deadLetters.length = 0; auditLog.length = 0;
      nextLogId = 1; nextDeadLetterId = 1; nextAuditId = 1; lastAffected = 0;
    },
  };
}

module.exports = { createFakeD1 };
