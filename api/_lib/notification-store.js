/**
 * SENTINEL APEX — Notification Preferences, Delivery Log & Retry Queue
 *
 * Same architectural discipline as watchlist-store.js: Redis-native,
 * customer-owned operational state, never a second intelligence store —
 * this module holds nothing about *what* an event says, only *whether and
 * how* a given owner wants to be told about it and what happened when we
 * tried. The event itself remains change-engine.js's `event:{id}` record,
 * read by reference here, never copied.
 *
 * Reuses the exact hash/sorted-set/audit patterns already established in
 * watchlist-store.js (hashToObject, bounded ZREMRANGEBYRANK trims,
 * try/catch-swallowed audit writes) rather than inventing parallel ones.
 *
 * Retry model: one pending-delivery record per (ownerId, eventId) — not
 * per channel — with each channel (email/webhook) tracking its own
 * attempt count and next_attempt_at independently inside that record.
 * `notify:pending_queue` is a single global sorted set scored by the
 * SOONEST still-pending channel's next_attempt_at, so "what's due" is one
 * bounded ZRANGEBYSCORE query; a channel that dead-letters (exhausts
 * MAX_RETRY_ATTEMPTS) is removed from channels_pending without blocking a
 * still-retrying sibling channel on the same event.
 *
 * No live cron delivers these — same disclosed posture as change-engine.js
 * (see that module's docstring): a delivery only actually happens when
 * scripts/deliver-watchlist-notifications.js is run, manually or by
 * whatever external scheduler an operator wires up later.
 */
'use strict';

const redis = require('./redis');
const { generateWebhookSecret } = require('./webhook-signing');

const NOTIFICATION_SCHEMA_VERSION = '1.0';
const MAX_DELIVERY_LOG_ENTRIES = 500;
const MAX_DEAD_LETTER_ENTRIES = 200;
const MAX_RETRY_ATTEMPTS = 5;
// Minutes to wait before the next attempt, indexed by attempt count
// (1st retry after a failure = index 1, etc.). Purely a next_attempt_at
// timestamp a manually-run sweep checks against -- see module docstring.
const BACKOFF_MINUTES = [0, 2, 10, 30, 120];
// Upper bound on a remote endpoint's Retry-After (Phase 22 of the
// orchestration mandate: "a malicious endpoint must not be able to defer
// delivery for years"). A cooperative endpoint asking for a longer defer
// than this gets capped, not obeyed verbatim.
const MAX_RETRY_AFTER_SECONDS = 3600;
// How long a delivery claim holds before it self-expires and becomes
// claimable again (lease recovery -- Phase 12/51/98). Comfortably longer
// than one channel's own worst-case latency (WEBHOOK_TIMEOUT_MS=8s in
// notification-dispatch.js, plus Redis round trips and a slow email
// provider call) so a healthy in-flight attempt is never preempted by
// its own lease expiring, but short enough that a genuinely crashed
// worker's job recovers within one dispatch cycle, not indefinitely.
const CLAIM_LEASE_MS = 90 * 1000;

const PENDING_QUEUE_KEY = 'notify:pending_queue';
const AUDIT_LOG_KEY = 'audit:notify:log';
const AUDIT_LOG_MAX_ENTRIES = 10000; // matches watchlist-store.js's auditWatchlistAction() bound

function prefsKey(ownerId) { return `notify:prefs:${ownerId}`; }
function deliveryLogKey(ownerId) { return `notify:delivery_log:${ownerId}`; }
function deadLetterKey(ownerId) { return `notify:dead_letter:${ownerId}`; }
function pendingRecordKey(ownerId, eventId) { return `notify:pending:${ownerId}:${eventId}`; }
function pendingMember(ownerId, eventId) { return `${ownerId}:${eventId}`; }
function splitMember(member) {
  const idx = member.lastIndexOf(':');
  return [member.slice(0, idx), member.slice(idx + 1)];
}
function claimKey(deliveryId) { return `notify:claim:${deliveryId}`; }

// Stable identity for one (owner, event, channel) delivery -- deliberately
// STABLE ACROSS RETRIES of the same semantic delivery, not a fresh ID per
// attempt: "the same semantic delivery must never create duplicate jobs
// merely because the scheduler runs twice" (orchestration mandate Phase
// 8). Used both as the atomic claim key's identity and as the
// X-Sentinel-Delivery-Id a customer's webhook receiver can dedupe on --
// one canonical construction (Principle 3), not two.
function buildDeliveryId(ownerId, eventId, channel) {
  return `dlv_${ownerId}_${eventId}_${channel}`;
}

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

// Same shape/trim policy as watchlist-store.js's auditWatchlistAction()
// -- a separate key (not a reuse of audit:watchlist:log or the payment
// domain's audit:payment:log), since each domain's auditLog-equivalent
// is hardcoded to its own key and mixing "NOTIFY_*" entries into either
// would blur an otherwise-clean audit trail per domain (orchestration
// mandate Phase 42: "record configuration created/updated, secret
// rotated, channel enabled/disabled, manual retry"). Never logs a
// secret value -- callers pass only non-sensitive fields.
async function auditNotificationAction(ownerId, action, data = {}) {
  try {
    const entry = JSON.stringify({ owner_id: ownerId, action, ts: new Date().toISOString(), ...data });
    await redis.zadd(AUDIT_LOG_KEY, Date.now(), entry);
    await redis.pipeline([
      ['ZREMRANGEBYRANK', AUDIT_LOG_KEY, '0', String(-(AUDIT_LOG_MAX_ENTRIES + 1))],
    ]).catch(() => {});
  } catch (_) {
    // Audit failure must never break the main flow (matches
    // watchlist-store.js's/payment-utils.js's auditLog() behavior).
  }
}

/* ───────────────────────── preferences ───────────────────────── */

// email defaults ON (the account's own registration email, lowest-risk
// channel, tied to something the owner explicitly created — a watchlist)
// -- webhook defaults OFF (cannot fire without an explicit URL anyway).
async function getPreferences(ownerId) {
  const stored = hashToObject(await redis.hgetall(prefsKey(ownerId))) || {};
  return {
    schema_version: NOTIFICATION_SCHEMA_VERSION,
    email_enabled: stored.email_enabled === undefined ? true : stored.email_enabled === 'true',
    email_override: stored.email_override || '',
    webhook_enabled: stored.webhook_enabled === 'true',
    webhook_url: stored.webhook_url || '',
    has_webhook_secret: Boolean(stored.webhook_secret),
    webhook_configured_at: stored.webhook_configured_at || null,
    updated_at: stored.updated_at || null,
  };
}

// Internal-only — the raw secret used to sign deliveries. Never call this
// from a code path that returns its result in an API response.
async function getWebhookSecret(ownerId) {
  return redis.hget(prefsKey(ownerId), 'webhook_secret');
}

async function updatePreferences(ownerId, { email_enabled, email_override, webhook_enabled, webhook_url } = {}) {
  const fields = { updated_at: new Date().toISOString() };
  if (email_enabled !== undefined) fields.email_enabled = String(Boolean(email_enabled));
  if (email_override !== undefined) fields.email_override = String(email_override || '');
  if (webhook_url !== undefined) fields.webhook_url = String(webhook_url || '');
  if (webhook_enabled !== undefined) fields.webhook_enabled = String(Boolean(webhook_enabled));
  await redis.hmset(prefsKey(ownerId), fields);
  return getPreferences(ownerId);
}

// Generates (or rotates) the signing secret, returned ONCE in this call's
// return value only — never re-readable afterward via any public API,
// matching generateApiKey()'s show-once precedent in middleware.js.
async function rotateWebhookSecret(ownerId) {
  const secret = generateWebhookSecret();
  await redis.hmset(prefsKey(ownerId), {
    webhook_secret: secret,
    webhook_configured_at: new Date().toISOString(),
  });
  return secret;
}

/* ───────────────────────── delivery log ───────────────────────── */

async function recordDelivery(ownerId, { channel, eventId, watchlistId, status, error, attempt }) {
  const entry = JSON.stringify({
    channel, event_id: eventId, watchlist_id: watchlistId || null,
    status, error: error ? String(error).slice(0, 300) : null, attempt: attempt || 0,
    attempted_at: new Date().toISOString(),
  });
  const key = deliveryLogKey(ownerId);
  await redis.zadd(key, Date.now(), entry);
  await redis.pipeline([
    ['ZREMRANGEBYRANK', key, '0', String(-(MAX_DELIVERY_LOG_ENTRIES + 1))],
  ]).catch(() => {});
}

async function listDeliveries(ownerId, { limit = 50 } = {}) {
  const bounded = Math.max(1, Math.min(limit, 200));
  const raw = await redis.zrevrange(deliveryLogKey(ownerId), 0, bounded - 1);
  return (raw || []).map(parseJsonSafe).filter(Boolean);
}

/* ───────────────────────── dead letter ───────────────────────── */

async function moveToDeadLetter(ownerId, record) {
  const entry = JSON.stringify({ ...record, dead_lettered_at: new Date().toISOString() });
  const key = deadLetterKey(ownerId);
  await redis.zadd(key, Date.now(), entry);
  await redis.pipeline([
    ['ZREMRANGEBYRANK', key, '0', String(-(MAX_DEAD_LETTER_ENTRIES + 1))],
  ]).catch(() => {});
}

async function listDeadLetters(ownerId, { limit = 50 } = {}) {
  const bounded = Math.max(1, Math.min(limit, 200));
  const raw = await redis.zrevrange(deadLetterKey(ownerId), 0, bounded - 1);
  return (raw || []).map(parseJsonSafe).filter(Boolean);
}

/* ───────────────────────── pending-delivery queue ───────────────────────── */

// Idempotent via SET...NX (same atomic-create discipline as change-
// engine.js's persistEventIfNew — see that function's own comment): a
// plain GET-then-SET here would leave a real TOCTOU window if
// evaluateWatchedEntities() were ever invoked twice concurrently (no
// distributed lock exists for that script — see the certification doc's
// Known Limitations), letting a second call reset an in-flight channel's
// attempt count/backoff. NX makes "already exists" and "just created" one
// atomic round trip, closing that window regardless of caller concurrency.
async function enqueuePendingDelivery({ ownerId, eventId, watchlistId, channels }) {
  if (!channels || channels.length === 0) return { created: false };
  const key = pendingRecordKey(ownerId, eventId);
  const now = Date.now();
  const attempts = {};
  for (const c of channels) attempts[c] = { count: 0, next_attempt_at: now };
  const record = {
    schema_version: NOTIFICATION_SCHEMA_VERSION,
    owner_id: ownerId, event_id: eventId, watchlist_id: watchlistId || null,
    channels_pending: [...channels], attempts,
    created_at: new Date().toISOString(),
  };
  const created = await redis.setnx(key, JSON.stringify(record));
  if (!created) return { created: false };
  await redis.zadd(PENDING_QUEUE_KEY, now, pendingMember(ownerId, eventId));
  return { created: true };
}

// Returns full records whose soonest-pending channel is due now. The
// caller (notification-dispatch.js) is responsible for checking each
// individual channel's own next_attempt_at before attempting it — a
// record can be "due" because of channel A while channel B still has a
// later backoff.
async function getDuePendingDeliveries(limit = 100) {
  const members = await redis.zrangebyscore(PENDING_QUEUE_KEY, 0, Date.now());
  const bounded = (members || []).slice(0, Math.max(1, Math.min(limit, 500)));
  const records = [];
  for (const member of bounded) {
    const [ownerId, eventId] = splitMember(member);
    const raw = await redis.get(pendingRecordKey(ownerId, eventId));
    const record = parseJsonSafe(raw);
    if (record) records.push(record);
    else await redis.zrem(PENDING_QUEUE_KEY, member); // orphaned index entry
  }
  return records;
}

// Atomic claim-with-lease (Phase 11): the ONLY thing that may make two
// concurrent processDueDeliveries() invocations (an overlapping scheduled
// run, a manual run racing a scheduled one, anything) safe to run without
// application-level double-delivery. Backed by SET...NX...PX -- a single
// round trip decides "did I just acquire this" and sets its own
// self-expiring recovery window, so no separate lease-sweep job is
// needed (see CLAIM_LEASE_MS above and redis.js's setnxpx comment).
// Returns true iff THIS call acquired the claim.
async function claimDeliveryChannel({ ownerId, eventId, channel }) {
  const deliveryId = buildDeliveryId(ownerId, eventId, channel);
  const result = await redis.setnxpx(claimKey(deliveryId), String(Date.now()), CLAIM_LEASE_MS);
  return Boolean(result);
}

// Best-effort early release after a channel's outcome is already
// recorded, so a fast success/failure doesn't make a DIFFERENT retry of
// the same channel wait out the full lease window unnecessarily. Purely
// a throughput nicety -- correctness never depends on this running (the
// PX expiry alone guarantees eventual reclaimability even if this call
// is never reached, e.g. the process dies right after sending).
async function releaseDeliveryChannel({ ownerId, eventId, channel }) {
  const deliveryId = buildDeliveryId(ownerId, eventId, channel);
  await redis.del(claimKey(deliveryId)).catch(() => {});
}

// Shared "remove this channel, persist or delete the record" tail used
// by every exit path that drops a channel from channels_pending
// (success, dead-letter, and clean cancellation) -- one implementation
// of this bookkeeping (Principle 3), not three near-identical copies.
async function removeChannelAndPersist(ownerId, eventId, record, channel) {
  record.channels_pending = record.channels_pending.filter(c => c !== channel);
  delete record.attempts[channel];
  const key = pendingRecordKey(ownerId, eventId);
  if (record.channels_pending.length === 0) {
    await redis.del(key);
    await redis.zrem(PENDING_QUEUE_KEY, pendingMember(ownerId, eventId));
    return;
  }
  await redis.set(key, JSON.stringify(record));
  const nextDue = Math.min(...record.channels_pending.map(c => record.attempts[c].next_attempt_at));
  await redis.zadd(PENDING_QUEUE_KEY, nextDue, pendingMember(ownerId, eventId));
}

// Applies one channel's attempt outcome: on success, drops the channel
// from channels_pending; on failure, bumps its attempt count and either
// reschedules it or dead-letters that channel only, leaving any other
// still-pending channel untouched. Removes the whole record once no
// channel remains pending. Returns a disposition string --
// 'delivered' | 'retrying' | 'dead_lettered' | 'unresolved' (the
// already-resolved-elsewhere early-return) -- so a caller building a run
// summary (Phase 55) reads the ACTUAL decision this function made
// instead of re-deriving it from the same inputs a second time, which
// could silently drift out of sync with the real logic above.
//
// retryable=false (Phase 25, permanent-failure fast path) dead-letters
// immediately regardless of attempt count -- retrying a destination that
// can never succeed (e.g. 404/410) only wastes the retry budget a
// transient failure might actually need. retryAfterSeconds (Phase 22),
// when given, overrides the BACKOFF_MINUTES table for this one
// reschedule, bounded by MAX_RETRY_AFTER_SECONDS so a malicious or
// misconfigured endpoint cannot defer delivery indefinitely. Both
// default to the pre-existing always-retry-until-MAX_RETRY_ATTEMPTS
// behavior when omitted, so this remains backward compatible with any
// caller that only passes {ownerId, eventId, channel, success}.
async function recordAttemptOutcome({ ownerId, eventId, channel, success, retryable, retryAfterSeconds }) {
  const key = pendingRecordKey(ownerId, eventId);
  const record = parseJsonSafe(await redis.get(key));
  if (!record || !record.channels_pending.includes(channel)) return 'unresolved'; // already resolved elsewhere

  if (success) {
    await removeChannelAndPersist(ownerId, eventId, record, channel);
    return 'delivered';
  }

  const prevCount = (record.attempts[channel] && record.attempts[channel].count) || 0;
  const newCount = prevCount + 1;
  const permanentNow = retryable === false;
  if (permanentNow || newCount >= MAX_RETRY_ATTEMPTS) {
    await moveToDeadLetter(ownerId, {
      event_id: eventId, watchlist_id: record.watchlist_id, channel, attempts: newCount,
      reason: permanentNow ? 'PERMANENT_FAILURE' : 'MAX_RETRY_ATTEMPTS_EXHAUSTED',
    });
    await removeChannelAndPersist(ownerId, eventId, record, channel);
    return 'dead_lettered';
  }

  const boundedRetryAfterMs = retryAfterSeconds != null
    ? Math.min(Math.max(retryAfterSeconds, 0), MAX_RETRY_AFTER_SECONDS) * 1000
    : null;
  const delayMs = boundedRetryAfterMs != null
    ? boundedRetryAfterMs
    : BACKOFF_MINUTES[Math.min(newCount, BACKOFF_MINUTES.length - 1)] * 60 * 1000;
  record.attempts[channel] = { count: newCount, next_attempt_at: Date.now() + delayMs };
  await redis.set(key, JSON.stringify(record));
  const nextDue = Math.min(...record.channels_pending.map(c => record.attempts[c].next_attempt_at));
  await redis.zadd(PENDING_QUEUE_KEY, nextDue, pendingMember(ownerId, eventId));
  return 'retrying';
}

// Cleanly drops a channel from a pending record without touching its
// attempt count or dead-lettering it (Phase 74: "do not continue sending
// after explicit disable"). Not a failure -- the channel is simply no
// longer eligible (the customer turned it off between enqueue and
// delivery), so no retry/backoff/dead-letter semantics apply.
async function cancelDeliveryChannel({ ownerId, eventId, channel }) {
  const record = parseJsonSafe(await redis.get(pendingRecordKey(ownerId, eventId)));
  if (!record || !record.channels_pending.includes(channel)) return;
  await removeChannelAndPersist(ownerId, eventId, record, channel);
}

// Observability (Phase 52): how overdue the MOST overdue still-pending
// channel is, in seconds. pending_queue is scored by next_attempt_at, so
// this answers "how far behind is the dispatcher" -- the more actionable
// SRE signal (a growing backlog with no visible errors is the classic
// silent-failure indicator this metric exists to catch), not "time since
// creation". 0 (never negative) when nothing is overdue yet; null when
// the queue is empty.
async function getOldestPendingAgeSeconds() {
  const rows = await redis.zrange(PENDING_QUEUE_KEY, 0, 0, true); // [member, score]
  if (!rows || rows.length < 2) return null;
  const oldestDueAt = Number(rows[1]);
  if (!Number.isFinite(oldestDueAt)) return null;
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
