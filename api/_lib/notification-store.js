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

const PENDING_QUEUE_KEY = 'notify:pending_queue';

function prefsKey(ownerId) { return `notify:prefs:${ownerId}`; }
function deliveryLogKey(ownerId) { return `notify:delivery_log:${ownerId}`; }
function deadLetterKey(ownerId) { return `notify:dead_letter:${ownerId}`; }
function pendingRecordKey(ownerId, eventId) { return `notify:pending:${ownerId}:${eventId}`; }
function pendingMember(ownerId, eventId) { return `${ownerId}:${eventId}`; }
function splitMember(member) {
  const idx = member.lastIndexOf(':');
  return [member.slice(0, idx), member.slice(idx + 1)];
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

// Applies one channel's attempt outcome: on success, drops the channel
// from channels_pending; on failure, bumps its attempt count and either
// reschedules it or (at MAX_RETRY_ATTEMPTS) dead-letters that channel
// only, leaving any other still-pending channel untouched. Removes the
// whole record once no channel remains pending.
async function recordAttemptOutcome({ ownerId, eventId, channel, success }) {
  const key = pendingRecordKey(ownerId, eventId);
  const record = parseJsonSafe(await redis.get(key));
  if (!record || !record.channels_pending.includes(channel)) return; // already resolved elsewhere

  if (success) {
    record.channels_pending = record.channels_pending.filter(c => c !== channel);
    delete record.attempts[channel];
  } else {
    const prevCount = (record.attempts[channel] && record.attempts[channel].count) || 0;
    const newCount = prevCount + 1;
    if (newCount >= MAX_RETRY_ATTEMPTS) {
      await moveToDeadLetter(ownerId, {
        event_id: eventId, watchlist_id: record.watchlist_id, channel, attempts: newCount,
      });
      record.channels_pending = record.channels_pending.filter(c => c !== channel);
      delete record.attempts[channel];
    } else {
      const delayMinutes = BACKOFF_MINUTES[Math.min(newCount, BACKOFF_MINUTES.length - 1)];
      record.attempts[channel] = { count: newCount, next_attempt_at: Date.now() + delayMinutes * 60 * 1000 };
    }
  }

  if (record.channels_pending.length === 0) {
    await redis.del(key);
    await redis.zrem(PENDING_QUEUE_KEY, pendingMember(ownerId, eventId));
    return;
  }

  await redis.set(key, JSON.stringify(record));
  const nextDue = Math.min(...record.channels_pending.map(c => record.attempts[c].next_attempt_at));
  await redis.zadd(PENDING_QUEUE_KEY, nextDue, pendingMember(ownerId, eventId));
}

module.exports = {
  NOTIFICATION_SCHEMA_VERSION,
  MAX_RETRY_ATTEMPTS,
  BACKOFF_MINUTES,
  getPreferences,
  updatePreferences,
  rotateWebhookSecret,
  getWebhookSecret,
  recordDelivery,
  listDeliveries,
  listDeadLetters,
  enqueuePendingDelivery,
  getDuePendingDeliveries,
  recordAttemptOutcome,
};
