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

  // Watchlists / change-detection (Cloudflare-Only Runtime Completion v2)
  const watchlists = new Map(); // id -> row
  const watchlistEntities = []; // { watchlist_id, entity_type, entity_id, created_at }
  const watchlistAuditLog = []; // rows with an autoincrement id
  const entitySnapshots = new Map(); // "type|id" -> row
  const changeEvents = new Map(); // event_id -> row
  const ownerFeed = []; // { owner_id, event_id, observed_at_ms }
  let evalCursor = null; // null until first write, matching "no row yet"
  let nextWlAuditId = 1;

  // Defense Profiles (Customer Telemetry & Environment-Aware Defense
  // Coverage Fabric v1) -- migrations/0003_defense_profiles.sql
  const defenseProfiles = new Map(); // id -> row
  const defenseProfileTechnologies = []; // { profile_id, category, technology_id, custom_label, created_at }
  const defenseProfileTelemetry = []; // { profile_id, data_source, status, updated_at }
  const defenseProfileAuditLog = []; // rows with an autoincrement id
  let nextDpAuditId = 1;

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

    /* ── watchlists ──────────────────────────────────────────────── */

    if (sql.startsWith('SELECT * FROM watchlists WHERE id = ?')) {
      const row = watchlists.get(p[0]);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.startsWith('SELECT COUNT(*) AS cnt FROM watchlists WHERE owner_id = ?')) {
      const cnt = [...watchlists.values()].filter(w => w.owner_id === p[0]).length;
      return { rows: [{ cnt }] };
    }
    if (sql.includes('LEFT JOIN watchlist_entities we ON we.watchlist_id = w.id')) {
      const [ownerId] = p;
      const rows = [...watchlists.values()]
        .filter(w => w.owner_id === ownerId)
        .map(w => ({ ...w, entity_count: watchlistEntities.filter(e => e.watchlist_id === w.id).length }))
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      return { rows };
    }
    if (sql.startsWith('INSERT INTO watchlists (id, owner_id, name, description, status, schema_version, created_at, updated_at)')) {
      const [id, owner_id, name, description, status, schema_version, created_at, updated_at] = p;
      watchlists.set(id, { id, owner_id, name, description, status, schema_version, created_at, updated_at, last_evaluated_at: null });
      lastAffected = 1;
      return { rows: [] };
    }
    // Generic dynamic UPDATE watchlists SET <cols> WHERE id = ? -- handles
    // both updateWatchlist()'s dynamic column list and addEntity()/
    // removeEntity()'s fixed `updated_at = ?` update uniformly: both are
    // the same underlying operation (set some columns, keyed by id), and
    // in the edge case where updateWatchlist() only touches updated_at
    // the two call sites produce textually IDENTICAL SQL -- correct
    // either way since the semantic effect is identical.
    if (sql.startsWith('UPDATE watchlists SET') && !sql.includes('last_evaluated_at')) {
      const setMatch = sql.match(/UPDATE watchlists SET (.+) WHERE id = \?/s);
      const cols = setMatch[1].split(',').map(c => c.trim().replace(/\s*=\s*\?$/, ''));
      const id = p[p.length - 1];
      const row = watchlists.get(id);
      if (row) { cols.forEach((col, i) => { row[col] = p[i]; }); lastAffected = 1; } else { lastAffected = 0; }
      return { rows: [] };
    }
    if (sql.startsWith('UPDATE watchlists SET last_evaluated_at = ? WHERE id IN')) {
      const [nowIso, ...ids] = p;
      let count = 0;
      for (const id of ids) { const row = watchlists.get(id); if (row) { row.last_evaluated_at = nowIso; count++; } }
      lastAffected = count;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlists WHERE id = ?')) {
      lastAffected = watchlists.delete(p[0]) ? 1 : 0;
      return { rows: [] };
    }

    /* ── watchlist_entities ──────────────────────────────────────── */

    if (sql.startsWith('SELECT COUNT(*) AS cnt FROM watchlist_entities WHERE watchlist_id = ?')) {
      const cnt = watchlistEntities.filter(e => e.watchlist_id === p[0]).length;
      return { rows: [{ cnt }] };
    }
    if (sql.startsWith('SELECT entity_type, entity_id FROM watchlist_entities WHERE watchlist_id = ?')) {
      const rows = watchlistEntities
        .filter(e => e.watchlist_id === p[0])
        .sort((a, b) => (a.entity_type + a.entity_id).localeCompare(b.entity_type + b.entity_id))
        .map(e => ({ entity_type: e.entity_type, entity_id: e.entity_id }));
      return { rows };
    }
    if (sql.includes('ON CONFLICT(watchlist_id, entity_type, entity_id) DO NOTHING')) {
      const [watchlist_id, entity_type, entity_id, created_at] = p;
      const exists = watchlistEntities.some(e => e.watchlist_id === watchlist_id && e.entity_type === entity_type && e.entity_id === entity_id);
      if (exists) { lastAffected = 0; return { rows: [] }; }
      watchlistEntities.push({ watchlist_id, entity_type, entity_id, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlist_entities WHERE watchlist_id = ? AND entity_type = ? AND entity_id = ?')) {
      const [watchlist_id, entity_type, entity_id] = p;
      const idx = watchlistEntities.findIndex(e => e.watchlist_id === watchlist_id && e.entity_type === entity_type && e.entity_id === entity_id);
      if (idx === -1) { lastAffected = 0; return { rows: [] }; }
      watchlistEntities.splice(idx, 1);
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlist_entities WHERE watchlist_id = ?')) {
      const before = watchlistEntities.length;
      for (let i = watchlistEntities.length - 1; i >= 0; i--) {
        if (watchlistEntities[i].watchlist_id === p[0]) watchlistEntities.splice(i, 1);
      }
      lastAffected = before - watchlistEntities.length;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT DISTINCT entity_type, entity_id FROM watchlist_entities')) {
      const seen = new Set();
      const rows = [];
      for (const e of watchlistEntities) {
        const key = `${e.entity_type}|${e.entity_id}`;
        if (!seen.has(key)) { seen.add(key); rows.push({ entity_type: e.entity_type, entity_id: e.entity_id }); }
      }
      return { rows };
    }
    if (sql.includes('JOIN watchlists w ON w.id = we.watchlist_id')) {
      const [entityType, entityId] = p;
      const rows = watchlistEntities
        .filter(e => e.entity_type === entityType && e.entity_id === entityId)
        .map(e => ({ watchlist_id: e.watchlist_id, watchlist: watchlists.get(e.watchlist_id) }))
        .filter(x => x.watchlist && x.watchlist.status !== 'paused')
        .map(x => ({ watchlist_id: x.watchlist_id, owner_id: x.watchlist.owner_id }));
      return { rows };
    }

    /* ── watchlist_audit_log ─────────────────────────────────────── */

    if (sql.startsWith('INSERT INTO watchlist_audit_log')) {
      const [action, data, ts] = p;
      watchlistAuditLog.push({ id: nextWlAuditId++, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlist_audit_log')) {
      const [limit] = p;
      const keepIds = new Set(watchlistAuditLog.slice().sort((a, b) => b.id - a.id).slice(0, limit).map(r => r.id));
      const before = watchlistAuditLog.length;
      for (let i = watchlistAuditLog.length - 1; i >= 0; i--) {
        if (!keepIds.has(watchlistAuditLog[i].id)) watchlistAuditLog.splice(i, 1);
      }
      lastAffected = before - watchlistAuditLog.length;
      return { rows: [] };
    }

    /* ── entity_snapshots ────────────────────────────────────────── */

    if (sql.startsWith('SELECT schema_version, fingerprint, state, snapshotted_at FROM entity_snapshots')) {
      const [entityType, entityId] = p;
      const row = entitySnapshots.get(`${entityType}|${entityId}`);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.includes('ON CONFLICT(entity_type, entity_id) DO UPDATE')) {
      const [entityType, entityId, schema_version, fingerprint, state, snapshotted_at] = p;
      entitySnapshots.set(`${entityType}|${entityId}`, { schema_version, fingerprint, state, snapshotted_at });
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── change_events ───────────────────────────────────────────── */

    if (sql.includes('ON CONFLICT(event_id) DO NOTHING')) {
      const [event_id, entity_type, entity_id, observed_at, payload, created_at] = p;
      if (changeEvents.has(event_id)) { lastAffected = 0; return { rows: [] }; }
      changeEvents.set(event_id, { event_id, entity_type, entity_id, observed_at, payload, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT payload FROM change_events WHERE event_id = ?')) {
      const row = changeEvents.get(p[0]);
      return { rows: row ? [{ payload: row.payload }] : [] };
    }
    if (sql.startsWith('SELECT event_id, payload FROM change_events WHERE event_id IN')) {
      const rows = p.map(id => changeEvents.get(id)).filter(Boolean).map(r => ({ event_id: r.event_id, payload: r.payload }));
      return { rows };
    }

    /* ── owner_feed ──────────────────────────────────────────────── */

    if (sql.includes('ON CONFLICT(owner_id, event_id) DO NOTHING')) {
      const [owner_id, event_id, observed_at_ms] = p;
      const exists = ownerFeed.some(f => f.owner_id === owner_id && f.event_id === event_id);
      if (exists) { lastAffected = 0; return { rows: [] }; }
      ownerFeed.push({ owner_id, event_id, observed_at_ms });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM owner_feed')) {
      const [ownerId, , limit] = p;
      const keep = new Set(
        ownerFeed.filter(f => f.owner_id === ownerId)
          .sort((a, b) => b.observed_at_ms - a.observed_at_ms || b.event_id.localeCompare(a.event_id))
          .slice(0, limit).map(f => f.event_id)
      );
      const before = ownerFeed.length;
      for (let i = ownerFeed.length - 1; i >= 0; i--) {
        if (ownerFeed[i].owner_id === ownerId && !keep.has(ownerFeed[i].event_id)) ownerFeed.splice(i, 1);
      }
      lastAffected = before - ownerFeed.length;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT event_id FROM owner_feed WHERE owner_id = ?')) {
      const [ownerId, limit, offset] = p;
      const rows = ownerFeed.filter(f => f.owner_id === ownerId)
        .sort((a, b) => b.observed_at_ms - a.observed_at_ms || b.event_id.localeCompare(a.event_id))
        .slice(offset, offset + limit)
        .map(f => ({ event_id: f.event_id }));
      return { rows };
    }
    if (sql.startsWith('SELECT COUNT(*) AS cnt FROM owner_feed WHERE owner_id = ?')) {
      const cnt = ownerFeed.filter(f => f.owner_id === p[0]).length;
      return { rows: [{ cnt }] };
    }

    /* ── watchlist_eval_state ────────────────────────────────────── */

    if (sql.startsWith('SELECT cursor FROM watchlist_eval_state WHERE id = 1')) {
      return { rows: evalCursor === null ? [] : [{ cursor: evalCursor }] };
    }
    if (sql.includes('ON CONFLICT(id) DO UPDATE SET cursor')) {
      evalCursor = p[0];
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── defense_profiles ────────────────────────────────────────── */

    if (sql.startsWith('SELECT * FROM defense_profiles WHERE owner_id = ?')) {
      const row = [...defenseProfiles.values()].find(r => r.owner_id === p[0]);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.startsWith('UPDATE defense_profiles SET name = ?, updated_at = ? WHERE id = ?')) {
      const [name, updated_at, id] = p;
      const row = defenseProfiles.get(id);
      if (row) { row.name = name; row.updated_at = updated_at; lastAffected = 1; } else { lastAffected = 0; }
      return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO defense_profiles (id, owner_id, name, schema_version, created_at, updated_at)')) {
      const [id, owner_id, name, schema_version, created_at, updated_at] = p;
      defenseProfiles.set(id, { id, owner_id, name, schema_version, created_at, updated_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM defense_profiles WHERE id = ?')) {
      lastAffected = defenseProfiles.delete(p[0]) ? 1 : 0;
      return { rows: [] };
    }

    /* ── defense_profile_technologies ───────────────────────────── */

    if (sql.startsWith('SELECT category, technology_id, custom_label FROM defense_profile_technologies WHERE profile_id = ?')) {
      const rows = defenseProfileTechnologies
        .filter(t => t.profile_id === p[0])
        .sort((a, b) => (a.category + a.technology_id).localeCompare(b.category + b.technology_id))
        .map(t => ({ category: t.category, technology_id: t.technology_id, custom_label: t.custom_label }));
      return { rows };
    }
    if (sql.startsWith('DELETE FROM defense_profile_technologies WHERE profile_id = ?')) {
      const before = defenseProfileTechnologies.length;
      for (let i = defenseProfileTechnologies.length - 1; i >= 0; i--) {
        if (defenseProfileTechnologies[i].profile_id === p[0]) defenseProfileTechnologies.splice(i, 1);
      }
      lastAffected = before - defenseProfileTechnologies.length;
      return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO defense_profile_technologies (profile_id, category, technology_id, custom_label, created_at)')) {
      const [profile_id, category, technology_id, custom_label, created_at] = p;
      defenseProfileTechnologies.push({ profile_id, category, technology_id, custom_label, created_at });
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── defense_profile_telemetry ──────────────────────────────── */

    if (sql.startsWith('SELECT data_source, status FROM defense_profile_telemetry WHERE profile_id = ?')) {
      const rows = defenseProfileTelemetry
        .filter(t => t.profile_id === p[0])
        .sort((a, b) => a.data_source.localeCompare(b.data_source))
        .map(t => ({ data_source: t.data_source, status: t.status }));
      return { rows };
    }
    if (sql.startsWith('DELETE FROM defense_profile_telemetry WHERE profile_id = ?')) {
      const before = defenseProfileTelemetry.length;
      for (let i = defenseProfileTelemetry.length - 1; i >= 0; i--) {
        if (defenseProfileTelemetry[i].profile_id === p[0]) defenseProfileTelemetry.splice(i, 1);
      }
      lastAffected = before - defenseProfileTelemetry.length;
      return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO defense_profile_telemetry (profile_id, data_source, status, updated_at)')) {
      const [profile_id, data_source, status, updated_at] = p;
      defenseProfileTelemetry.push({ profile_id, data_source, status, updated_at });
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── defense_profile_audit_log ──────────────────────────────── */

    if (sql.startsWith('INSERT INTO defense_profile_audit_log')) {
      const [action, data, ts] = p;
      defenseProfileAuditLog.push({ id: nextDpAuditId++, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM defense_profile_audit_log')) {
      const [limit] = p;
      const keepIds = new Set(defenseProfileAuditLog.slice().sort((a, b) => b.id - a.id).slice(0, limit).map(r => r.id));
      const before = defenseProfileAuditLog.length;
      for (let i = defenseProfileAuditLog.length - 1; i >= 0; i--) {
        if (!keepIds.has(defenseProfileAuditLog[i].id)) defenseProfileAuditLog.splice(i, 1);
      }
      lastAffected = before - defenseProfileAuditLog.length;
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
    _dump: () => ({
      preferences, jobs, deliveryLog, deadLetters, auditLog,
      watchlists, watchlistEntities, watchlistAuditLog, entitySnapshots, changeEvents, ownerFeed,
      defenseProfiles, defenseProfileTechnologies, defenseProfileTelemetry, defenseProfileAuditLog,
    }),
    _reset: () => {
      preferences.clear(); jobs.clear();
      deliveryLog.length = 0; deadLetters.length = 0; auditLog.length = 0;
      nextLogId = 1; nextDeadLetterId = 1; nextAuditId = 1; lastAffected = 0;
      watchlists.clear(); watchlistEntities.length = 0; watchlistAuditLog.length = 0;
      entitySnapshots.clear(); changeEvents.clear(); ownerFeed.length = 0;
      evalCursor = null; nextWlAuditId = 1;
      defenseProfiles.clear(); defenseProfileTechnologies.length = 0;
      defenseProfileTelemetry.length = 0; defenseProfileAuditLog.length = 0; nextDpAuditId = 1;
    },
  };
}

module.exports = { createFakeD1 };
