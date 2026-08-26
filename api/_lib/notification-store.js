/**
 * SENTINEL APEX — Notification Preferences, Delivery Log & Retry Queue
 * (Cloudflare D1 — Cloudflare-Only Alert Runtime v1)
 *
 * MIGRATION NOTE: this module previously stored one JSON blob per
 * (owner_id, event_id) in Redis, with a nested channels_pending array and
 * an attempts object keyed by channel — Redis has no native relational
 * row concept, so that was the natural shape there. D1 is real SQL, so
 * the natural (and simpler) shape is one ROW per (owner_id, event_id,
 * channel) in notification_delivery_jobs — buildDeliveryId(), unchanged
 * below, is that row's primary key directly. See
 * migrations/0001_notification_delivery.sql's header for the full design
 * rationale and docs/audits/SENTINEL-APEX-CLOUDFLARE-RUNTIME-DEPENDENCY-
 * INVENTORY.md §0 for this tranche's scope boundary (watchlists/change-
 * detection stay Redis-backed via watchlist-store.js/change-engine.js,
 * out of scope here).
 *
 * Every exported function name and its PUBLIC-facing contract (preferences,
 * delivery log, dead letters, audit log) is unchanged from the Redis
 * version. The five functions used exclusively by notification-
 * dispatch.js's processDueDeliveries() loop — getDuePendingDeliveries,
 * claimDeliveryChannel, releaseDeliveryChannel, recordAttemptOutcome,
 * cancelDeliveryChannel — are NOT called from api/v1/notifications.js or
 * anywhere else outside this file's own dispatch collaborator, confirmed
 * by reading every call site before this rewrite; their parameter/return
 * shapes changed to fit the new per-row schema (a flat job row + a
 * claim_token instead of a nested per-channel attempts map + a separate
 * Redis claim key), and notification-dispatch.js was updated in the same
 * change to match — an internal contract between two co-migrated files,
 * not a public API break.
 *
 * Claim/lease/stale-worker protection: Redis's SET...NX...PX gave a claim
 * that self-expired via Redis's own TTL, requiring no separate sweep. D1
 * has no TTL primitive, so the claim UPDATE below checks lease_expires_at
 * explicitly in its own WHERE clause (a stale, expired claim is exactly
 * as claimable as a plain pending/retry row), and every mutation that
 * completes a claim (recordAttemptOutcome, releaseDeliveryChannel) must
 * re-verify claim_token in its own WHERE clause before applying — a
 * worker whose lease already expired and was reclaimed by someone else
 * can never finalize a newer claim's outcome. This is a genuine new
 * capability the Redis design could not express this cleanly, not a
 * downgrade.
 */
'use strict';

const crypto = require('crypto');
const d1 = require('./d1');
const { generateWebhookSecret } = require('./webhook-signing');

const NOTIFICATION_SCHEMA_VERSION = '1.0';
const MAX_DELIVERY_LOG_ENTRIES = 500;
const MAX_DEAD_LETTER_ENTRIES = 200;
const MAX_RETRY_ATTEMPTS = 5;
// Minutes to wait before the next attempt, indexed by attempt count
// (1st retry after a failure = index 1, etc.). Purely a next_attempt_at
// timestamp the due-jobs query checks against.
const BACKOFF_MINUTES = [0, 2, 10, 30, 120];
// Upper bound on a remote endpoint's Retry-After (a malicious endpoint
// must not be able to defer delivery for years). A cooperative endpoint
// asking for a longer defer than this gets capped, not obeyed verbatim.
const MAX_RETRY_AFTER_SECONDS = 3600;
// How long a delivery claim holds before it self-expires and becomes
// claimable again (lease recovery). Comfortably longer than one channel's
// own worst-case latency (WEBHOOK_TIMEOUT_MS=8s in notification-
// dispatch.js, plus D1 round trips and a slow email provider call) so a
// healthy in-flight attempt is never preempted by its own lease expiring,
// but short enough that a genuinely crashed worker's job recovers within
// one dispatch cycle, not indefinitely.
const CLAIM_LEASE_MS = 90 * 1000;

const AUDIT_LOG_MAX_ENTRIES = 10000; // matches watchlist-store.js's auditWatchlistAction() bound

// Stable identity for one (owner, event, channel) delivery -- deliberately
// STABLE ACROSS RETRIES of the same semantic delivery, not a fresh ID per
// attempt: the same semantic delivery must never create duplicate jobs
// merely because the scheduler runs twice. Used both as the D1 row's
// primary key and as the X-Sentinel-Delivery-Id a customer's webhook
// receiver can dedupe on -- one canonical construction, not two.
function buildDeliveryId(ownerId, eventId, channel) {
  return `dlv_${ownerId}_${eventId}_${channel}`;
}

function generateClaimToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Same shape/trim policy as watchlist-store.js's auditWatchlistAction() --
// a separate table (not a reuse of the watchlist or payment domains' own
// audit logs), since each domain's audit trail is hardcoded to its own
// store and mixing NOTIFY_* entries into either would blur an otherwise-
// clean audit trail per domain. Never logs a secret value -- callers pass
// only non-sensitive fields.
async function auditNotificationAction(ownerId, action, data = {}) {
  try {
    await d1.run(
      'INSERT INTO notification_audit_log (owner_id, action, data, ts) VALUES (?, ?, ?, ?)',
      [ownerId, action, JSON.stringify(data), new Date().toISOString()]
    );
    await d1.run(
      `DELETE FROM notification_audit_log WHERE owner_id=? AND id NOT IN
       (SELECT id FROM notification_audit_log WHERE owner_id=? ORDER BY id DESC LIMIT ?)`,
      [ownerId, ownerId, AUDIT_LOG_MAX_ENTRIES]
    ).catch(() => {});
  } catch (_) {
    // Audit failure must never break the main flow (matches
    // watchlist-store.js's/payment-utils.js's auditLog() behavior).
  }
}

/* ───────────────────────── preferences ───────────────────────── */

// email defaults ON (the account's own registration email, lowest-risk
// channel, tied to something the owner explicitly created — a watchlist)
// -- webhook defaults OFF (cannot fire without an explicit URL anyway).
// No row at all (never touched preferences) reads as those same defaults.
async function getPreferences(ownerId) {
  const rows = await d1.query('SELECT * FROM notification_preferences WHERE owner_id = ?', [ownerId]);
  const row = rows[0];
  return {
    schema_version: NOTIFICATION_SCHEMA_VERSION,
    email_enabled: row ? Boolean(row.email_enabled) : true,
    email_override: (row && row.email_override) || '',
    webhook_enabled: row ? Boolean(row.webhook_enabled) : false,
    webhook_url: (row && row.webhook_url) || '',
    has_webhook_secret: Boolean(row && row.webhook_secret),
    webhook_configured_at: (row && row.webhook_configured_at) || null,
    updated_at: (row && row.updated_at) || null,
  };
}

// Internal-only — the raw secret used to sign deliveries. Never call this
// from a code path that returns its result in an API response.
async function getWebhookSecret(ownerId) {
  const rows = await d1.query('SELECT webhook_secret FROM notification_preferences WHERE owner_id = ?', [ownerId]);
  return rows[0] ? rows[0].webhook_secret : null;
}

// Partial update via INSERT ... ON CONFLICT DO UPDATE, columns chosen
// dynamically from a fixed, hardcoded whitelist (never from request
// input — sec.assertFieldWhitelist in the router already restricts which
// body keys reach this function at all), values always bound as
// parameters. A brand-new row's omitted columns take their schema
// DEFAULT (email_enabled=1, webhook_enabled=0, ...) exactly as before;
// an existing row's omitted columns are left untouched by the UPDATE
// clause, matching the old HMSET's partial-field-write semantics.
async function updatePreferences(ownerId, { email_enabled, email_override, webhook_enabled, webhook_url } = {}) {
  const now = new Date().toISOString();
  const cols = ['owner_id', 'updated_at'];
  const vals = [ownerId, now];
  const setClauses = ['updated_at = excluded.updated_at'];
  if (email_enabled !== undefined) {
    cols.push('email_enabled'); vals.push(email_enabled ? 1 : 0);
    setClauses.push('email_enabled = excluded.email_enabled');
  }
  if (email_override !== undefined) {
    cols.push('email_override'); vals.push(String(email_override || ''));
    setClauses.push('email_override = excluded.email_override');
  }
  if (webhook_url !== undefined) {
    cols.push('webhook_url'); vals.push(String(webhook_url || ''));
    setClauses.push('webhook_url = excluded.webhook_url');
  }
  if (webhook_enabled !== undefined) {
    cols.push('webhook_enabled'); vals.push(webhook_enabled ? 1 : 0);
    setClauses.push('webhook_enabled = excluded.webhook_enabled');
  }
  const placeholders = cols.map(() => '?').join(', ');
  await d1.run(
    `INSERT INTO notification_preferences (${cols.join(', ')}) VALUES (${placeholders})
     ON CONFLICT(owner_id) DO UPDATE SET ${setClauses.join(', ')}`,
    vals
  );
  return getPreferences(ownerId);
}

// Generates (or rotates) the signing secret, returned ONCE in this call's
// return value only — never re-readable afterward via any public API,
// matching generateApiKey()'s show-once precedent in middleware.js.
async function rotateWebhookSecret(ownerId) {
  const secret = generateWebhookSecret();
  const now = new Date().toISOString();
  await d1.run(
    `INSERT INTO notification_preferences (owner_id, updated_at, webhook_secret, webhook_configured_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(owner_id) DO UPDATE SET
       updated_at = excluded.updated_at,
       webhook_secret = excluded.webhook_secret,
       webhook_configured_at = excluded.webhook_configured_at`,
    [ownerId, now, secret, now]
  );
  return secret;
}

/* ───────────────────────── delivery log ───────────────────────── */

async function recordDelivery(ownerId, { channel, eventId, watchlistId, status, error, attempt }) {
  await d1.run(
    `INSERT INTO notification_delivery_log (owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [ownerId, channel, eventId, watchlistId || null, status, error ? String(error).slice(0, 300) : null, attempt || 0, new Date().toISOString()]
  );
  await d1.run(
    `DELETE FROM notification_delivery_log WHERE owner_id=? AND id NOT IN
     (SELECT id FROM notification_delivery_log WHERE owner_id=? ORDER BY id DESC LIMIT ?)`,
    [ownerId, ownerId, MAX_DELIVERY_LOG_ENTRIES]
  ).catch(() => {});
}

async function listDeliveries(ownerId, { limit = 50 } = {}) {
  const bounded = Math.max(1, Math.min(limit, 200));
  return d1.query(
    'SELECT channel, event_id, watchlist_id, status, error, attempt, attempted_at FROM notification_delivery_log WHERE owner_id=? ORDER BY id DESC LIMIT ?',
    [ownerId, bounded]
  );
}

/* ───────────────────────── dead letter ───────────────────────── */

async function moveToDeadLetter(ownerId, record) {
  await d1.run(
    `INSERT INTO notification_dead_letters (owner_id, event_id, watchlist_id, channel, attempts, reason, dead_lettered_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [ownerId, record.event_id, record.watchlist_id || null, record.channel, record.attempts, record.reason, new Date().toISOString()]
  );
  await d1.run(
    `DELETE FROM notification_dead_letters WHERE owner_id=? AND id NOT IN
     (SELECT id FROM notification_dead_letters WHERE owner_id=? ORDER BY id DESC LIMIT ?)`,
    [ownerId, ownerId, MAX_DEAD_LETTER_ENTRIES]
  ).catch(() => {});
}

async function listDeadLetters(ownerId, { limit = 50 } = {}) {
  const bounded = Math.max(1, Math.min(limit, 200));
  return d1.query(
    'SELECT event_id, watchlist_id, channel, attempts, reason, dead_lettered_at FROM notification_dead_letters WHERE owner_id=? ORDER BY id DESC LIMIT ?',
    [ownerId, bounded]
  );
}

/* ───────────────────────── pending-delivery queue ───────────────────────── */

// Idempotent per channel via INSERT ... ON CONFLICT(delivery_id) DO
// NOTHING, verified via the empirically-proven changes()-affected-row
// mechanism (d1.js's runMutationWithChanges — see that file's header for
// why meta.changes/rows_written is deliberately not used here). Each
// channel's own idempotency is airtight regardless of call ordering: two
// concurrent enqueue calls for the same (owner, event) can race
// channel-by-channel, but the primary key guarantees the final state is
// always exactly one row per requested channel, never a duplicate and
// never a partial loss — a real improvement the relational schema gives
// over the old design's single all-or-nothing blob (which could not
// express "channel A already existed, channel B is new" at all).
async function enqueuePendingDelivery({ ownerId, eventId, watchlistId, channels }) {
  if (!channels || channels.length === 0) return { created: false, channels_created: [] };
  const now = Date.now();
  const nowIso = new Date().toISOString();
  const channelsCreated = [];
  for (const channel of channels) {
    const deliveryId = buildDeliveryId(ownerId, eventId, channel);
    const affected = await d1.runMutationWithChanges(
      `INSERT INTO notification_delivery_jobs
         (delivery_id, event_id, owner_id, watchlist_id, channel, state, attempt_count, next_attempt_at, schema_version, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)
       ON CONFLICT(delivery_id) DO NOTHING`,
      [deliveryId, eventId, ownerId, watchlistId || null, channel, now, NOTIFICATION_SCHEMA_VERSION, nowIso, nowIso]
    );
    if (affected > 0) channelsCreated.push(channel);
  }
  return { created: channelsCreated.length > 0, channels_created: channelsCreated };
}

// Flat rows, one per (owner, event, channel) job that's actually due now
// — a stale/expired claim counts as due too (WHERE below), so a crashed
// worker's job is picked back up in the same call that would pick up a
// plain pending one, no separate sweep required. The caller
// (notification-dispatch.js) groups these by (owner_id, event_id) itself
// so it only fetches the underlying event/watchlist/preferences once per
// group, not once per channel.
async function getDuePendingDeliveries(limit = 100) {
  const bounded = Math.max(1, Math.min(limit, 500));
  const now = Date.now();
  return d1.query(
    `SELECT * FROM notification_delivery_jobs
     WHERE next_attempt_at <= ?
       AND (state IN ('pending', 'retry') OR (state = 'claimed' AND lease_expires_at < ?))
     ORDER BY next_attempt_at ASC
     LIMIT ?`,
    [now, now, bounded]
  );
}

// Atomic claim-with-lease: the ONLY thing that makes two concurrent
// processDueDeliveries() invocations (an overlapping cron run, a manual
// run racing a scheduled one, anything) safe to run without application-
// level double-delivery. A single conditional UPDATE decides "did I just
// acquire this" via its own affected-row count (runMutationWithChanges),
// covering both a fresh pending/retry row AND a stale claim whose lease
// already expired — one WHERE clause, not a separate recovery pass.
// Returns { claimed, claimToken } — claimToken must be threaded through
// to whichever of recordAttemptOutcome/releaseDeliveryChannel resolves
// this claim, so a worker whose lease has since been reclaimed by someone
// else can never finalize a newer claim's outcome (stale-worker guard).
async function claimDeliveryChannel({ deliveryId }) {
  const now = Date.now();
  const claimToken = generateClaimToken();
  const affected = await d1.runMutationWithChanges(
    `UPDATE notification_delivery_jobs
     SET state='claimed', claim_token=?, claimed_at=?, lease_expires_at=?
     WHERE delivery_id=?
       AND next_attempt_at<=?
       AND (state IN ('pending','retry') OR (state='claimed' AND lease_expires_at<?))`,
    [claimToken, now, now + CLAIM_LEASE_MS, deliveryId, now, now]
  );
  return { claimed: affected > 0, claimToken: affected > 0 ? claimToken : null };
}

// Best-effort early release after a channel's outcome is already recorded
// via recordAttemptOutcome, so a fast success/failure doesn't make a
// DIFFERENT retry of the same channel wait out the full lease window
// unnecessarily. Correctness never depends on this running — the lease's
// own expiration guarantees eventual reclaimability regardless (e.g. the
// process dies right after sending, before this line is ever reached).
// The claim_token match means this is a genuine no-op once
// recordAttemptOutcome has already transitioned the row away from
// state='claimed' (the normal case): only the exception-before-outcome
// path (a throw from the deliver/lookup calls in notification-
// dispatch.js's try block) actually needs this to un-stick the row before
// its lease would otherwise expire on its own.
async function releaseDeliveryChannel({ deliveryId, claimToken }) {
  try {
    await d1.run(
      `UPDATE notification_delivery_jobs
       SET state='retry', claim_token=NULL, claimed_at=NULL, lease_expires_at=NULL
       WHERE delivery_id=? AND claim_token=? AND state='claimed'`,
      [deliveryId, claimToken]
    );
  } catch (_) {
    // Matches the Redis version's own best-effort .catch(() => {}) here.
  }
}

// Applies one channel's attempt outcome: on success or terminal dead-
// letter, deletes the job row (fully resolved); on a retryable failure,
// reschedules it. Every mutation re-verifies claim_token AND
// state='claimed' in its own WHERE clause — the stale-worker guard: a
// worker whose lease already expired and was reclaimed by someone else
// gets affected=0 back and returns 'unresolved' instead of silently
// finalizing an outcome that isn't its to finalize. Returns a disposition
// string -- 'delivered' | 'retrying' | 'dead_lettered' | 'unresolved' --
// so a caller building a run summary reads the ACTUAL decision this
// function made instead of re-deriving it from the same inputs a second
// time, which could silently drift out of sync with the real logic below.
//
// retryable=false (permanent-failure fast path) dead-letters immediately
// regardless of attempt count -- retrying a destination that can never
// succeed (e.g. 404/410) only wastes the retry budget a transient failure
// might actually need. retryAfterSeconds, when given, overrides the
// BACKOFF_MINUTES table for this one reschedule, bounded by
// MAX_RETRY_AFTER_SECONDS so a malicious or misconfigured endpoint cannot
// defer delivery indefinitely. Both default to the pre-existing always-
// retry-until-MAX_RETRY_ATTEMPTS behavior when omitted.
async function recordAttemptOutcome({ deliveryId, claimToken, success, retryable, retryAfterSeconds }) {
  if (success) {
    const affected = await d1.runMutationWithChanges(
      `DELETE FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=? AND state='claimed'`,
      [deliveryId, claimToken]
    );
    return affected > 0 ? 'delivered' : 'unresolved';
  }

  // One extra read here vs. the old Redis GET-the-whole-blob: D1 has no
  // single call that both reads a row's current attempt_count AND
  // conditionally updates it, so the current count is fetched first
  // (still scoped to this exact claim_token, so a stale claim reads
  // nothing and correctly falls through to 'unresolved' below).
  const rows = await d1.query(
    `SELECT * FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=? AND state='claimed'`,
    [deliveryId, claimToken]
  );
  const job = rows[0];
  if (!job) return 'unresolved'; // stale claim -- someone else already resolved this

  const newCount = job.attempt_count + 1;
  const permanentNow = retryable === false;
  if (permanentNow || newCount >= MAX_RETRY_ATTEMPTS) {
    await moveToDeadLetter(job.owner_id, {
      event_id: job.event_id, watchlist_id: job.watchlist_id, channel: job.channel, attempts: newCount,
      reason: permanentNow ? 'PERMANENT_FAILURE' : 'MAX_RETRY_ATTEMPTS_EXHAUSTED',
    });
    const affected = await d1.runMutationWithChanges(
      `DELETE FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=? AND state='claimed'`,
      [deliveryId, claimToken]
    );
    return affected > 0 ? 'dead_lettered' : 'unresolved';
  }

  const boundedRetryAfterMs = retryAfterSeconds != null
    ? Math.min(Math.max(retryAfterSeconds, 0), MAX_RETRY_AFTER_SECONDS) * 1000
    : null;
  const delayMs = boundedRetryAfterMs != null
    ? boundedRetryAfterMs
    : BACKOFF_MINUTES[Math.min(newCount, BACKOFF_MINUTES.length - 1)] * 60 * 1000;
  const affected = await d1.runMutationWithChanges(
    `UPDATE notification_delivery_jobs
     SET state='retry', attempt_count=?, next_attempt_at=?, claim_token=NULL, claimed_at=NULL, lease_expires_at=NULL, updated_at=?
     WHERE delivery_id=? AND claim_token=? AND state='claimed'`,
    [newCount, Date.now() + delayMs, new Date().toISOString(), deliveryId, claimToken]
  );
  return affected > 0 ? 'retrying' : 'unresolved';
}

// Cleanly drops a channel's job without touching its attempt count or
// dead-lettering it (a customer turned the channel off between enqueue
// and delivery — not a failure, so no retry/backoff/dead-letter semantics
// apply). Runs BEFORE any claim is attempted (matches notification-
// dispatch.js's own eligibility-check-before-claim ordering), so there is
// no claim_token to verify here — same as the pre-migration behavior.
async function cancelDeliveryChannel({ deliveryId }) {
  await d1.run('DELETE FROM notification_delivery_jobs WHERE delivery_id=?', [deliveryId]);
}

// Observability: how overdue the MOST overdue still-pending job is, in
// seconds. Every remaining row in notification_delivery_jobs is
// unresolved by definition (success/dead-letter delete their row), so
// this is a plain MIN() over the whole table — the more actionable SRE
// signal (a growing backlog with no visible errors is the classic
// silent-failure indicator this metric exists to catch), not "time since
// creation". 0 (never negative) when nothing is overdue yet; null when
// the table is empty.
async function getOldestPendingAgeSeconds() {
  const rows = await d1.query('SELECT MIN(next_attempt_at) AS oldest FROM notification_delivery_jobs', []);
  const oldestDueAt = rows[0] && rows[0].oldest;
  if (oldestDueAt == null || !Number.isFinite(oldestDueAt)) return null;
  return Math.max(0, Math.floor((Date.now() - oldestDueAt) / 1000));
}

module.exports = {
  NOTIFICATION_SCHEMA_VERSION,
  MAX_RETRY_ATTEMPTS,
  BACKOFF_MINUTES,
  MAX_RETRY_AFTER_SECONDS,
  CLAIM_LEASE_MS,
  buildDeliveryId,
  auditNotificationAction,
  getPreferences,
  updatePreferences,
  rotateWebhookSecret,
  getWebhookSecret,
  recordDelivery,
  listDeliveries,
  listDeadLetters,
  enqueuePendingDelivery,
  getDuePendingDeliveries,
  claimDeliveryChannel,
  releaseDeliveryChannel,
  recordAttemptOutcome,
  cancelDeliveryChannel,
  getOldestPendingAgeSeconds,
};
