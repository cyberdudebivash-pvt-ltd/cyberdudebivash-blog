/**
 * SENTINEL APEX — Watchlist Notification Dispatch (Alert Delivery v1)
 *
 * The layer between "a new change event was matched to a watcher"
 * (change-engine.js) and an actual email/webhook leaving this server.
 * Two responsibilities, deliberately kept separate from notification-
 * store.js's persistence and webhook-signing.js's crypto/SSRF concerns:
 *
 *   dispatchNewEvent()      -- called once per (owner, event) right after
 *                               change-engine.js fans an event out to its
 *                               feed; decides which channels are eligible
 *                               and enqueues them. Never sends anything
 *                               itself -- enqueue-only, so change detection
 *                               never blocks on network I/O.
 *   processDueDeliveries()  -- the actual sender. Reused for BOTH a
 *                               channel's first attempt and every retry --
 *                               one code path, not two, since
 *                               notification-store.js models a first
 *                               attempt as "already due at enqueue time"
 *                               rather than as a special case.
 *
 * Reuses, does not reinvent: api/_lib/resend.js's sendEmail()/
 * canSendEmail() (the same transactional-email client the registration
 * welcome-email flow already uses), api/_lib/webhook-signing.js's HMAC
 * scheme and SSRF guard, api/_lib/watchlist-store.js's getWatchlist()
 * (ownership-checked, public-shaped) for the watchlist name shown in an
 * alert.
 *
 * Honesty constraint (same as change-engine.js's own docstring): nothing
 * here runs on a live schedule. dispatchNewEvent() only executes when
 * scripts/evaluate-watchlist-changes.js is run; processDueDeliveries()
 * only executes when scripts/deliver-watchlist-notifications.js is run.
 * This is a real, working delivery mechanism -- not yet a "real-time
 * alerting" product claim, and this module makes no such claim anywhere
 * in its content (email/webhook copy below says what changed and why,
 * never "instantly" or "in real time").
 */
'use strict';

const redis = require('./redis');
const resend = require('./resend');
const store = require('./watchlist-store');
const notify = require('./notification-store');
const { signPayload, isSafeWebhookUrl } = require('./webhook-signing');

// Lazy require, same reasoning as change-engine.js's own loadIntelLib():
// change-engine.js will require this module (to call dispatchNewEvent()
// right after fanning an event out to a watcher's feed), so requiring
// change-engine.js back at this module's top would be a load-order
// circular require. By the time processDueDeliveries() actually runs
// (never during either module's own initial load), both are already
// fully initialized.
function loadChangeEngine() {
  return require('./change-engine');
}

const WEBHOOK_TIMEOUT_MS = 8000;
const MAX_WEBHOOK_RESPONSE_BYTES = 4096; // only used for the truncated error detail we log
const DASHBOARD_URL = 'https://blog.cyberdudebivash.in/api-dashboard.html';

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* ───────────────────────── email content ───────────────────────── */

// Mirrors auth.js's buildWelcomeEmail() structure exactly (subject/text/
// html triple, plain-language body, single template). Unlike
// buildWelcomeEmail()'s inputs (mostly server-generated: API key, fixed
// URLs), watchlistName and entity-derived text here can contain whatever
// characters a customer's own watchlist name or an upstream source
// record contains -- every interpolated value is escaped for the html
// body (the text body needs no escaping; it is never parsed as markup).
function buildWatchlistAlertEmail({ event, watchlistName, dashboardUrl = DASHBOARD_URL }) {
  const entityLabel = event.entity_type === 'cve' ? event.entity_id : `Campaign: ${event.entity_id}`;
  const subject = `[${event.importance}] ${entityLabel} — ${humanizeChangeType(event.change_type)}`;
  const text = [
    `A change was detected on a watchlist you own.`,
    '',
    `Watchlist: ${watchlistName}`,
    `Entity: ${entityLabel}`,
    `Change: ${humanizeChangeType(event.change_type)}`,
    `Importance: ${event.importance}`,
    event.reason ? `Why it matters: ${event.reason}` : '',
    event.recommended_action ? `Recommended action: ${event.recommended_action}` : '',
    '',
    `View this in your dashboard: ${dashboardUrl}`,
    '',
    'This alert reflects a real, detected change in canonical intelligence — not a routine data refresh.',
    '',
    '— CYBERDUDEBIVASH SENTINEL APEX',
  ].filter(line => line !== '').join('\n');
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
<p>A change was detected on a watchlist you own.</p>
<table style="border-collapse:collapse;margin:12px 0" cellpadding="4">
<tr><td style="color:#666">Watchlist</td><td><strong>${escapeHtml(watchlistName)}</strong></td></tr>
<tr><td style="color:#666">Entity</td><td><strong>${escapeHtml(entityLabel)}</strong></td></tr>
<tr><td style="color:#666">Change</td><td>${escapeHtml(humanizeChangeType(event.change_type))}</td></tr>
<tr><td style="color:#666">Importance</td><td>${escapeHtml(event.importance)}</td></tr>
</table>
${event.reason ? `<p><strong>Why it matters:</strong> ${escapeHtml(event.reason)}</p>` : ''}
${event.recommended_action ? `<p><strong>Recommended action:</strong> ${escapeHtml(event.recommended_action)}</p>` : ''}
<p><a href="${escapeHtml(dashboardUrl)}">View this in your dashboard</a></p>
<p style="color:#666;font-size:13px">This alert reflects a real, detected change in canonical intelligence — not a routine data refresh.</p>
<p>— CYBERDUDEBIVASH SENTINEL APEX</p>
</div>`;
  return { subject, text, html };
}

function humanizeChangeType(changeType) {
  return String(changeType || '').replace(/_/g, ' ').toLowerCase();
}

/* ───────────────────────── per-channel delivery ───────────────────────── */

async function deliverEmailChannel({ email, event, watchlistName }) {
  if (!resend.canSendEmail()) return { success: false, error: 'EMAIL_NOT_CONFIGURED' };
  if (!email) return { success: false, error: 'NO_RECIPIENT' };
  const { subject, text, html } = buildWatchlistAlertEmail({ event, watchlistName });
  try {
    await resend.sendEmail({ to: email, subject, html, text });
    return { success: true };
  } catch (e) {
    return { success: false, error: e && e.message ? e.message : 'SEND_FAILED' };
  }
}

async function deliverWebhookChannel({ url, secret, event, watchlistId, watchlistName }) {
  const check = await isSafeWebhookUrl(url);
  if (!check.safe) return { success: false, error: `UNSAFE_URL:${check.reason}` };

  const payload = JSON.stringify({
    id: `evt_${event.event_id}`,
    type: 'watchlist.change_event',
    created_at: new Date().toISOString(),
    data: {
      event_id: event.event_id, entity_type: event.entity_type, entity_id: event.entity_id,
      change_type: event.change_type, importance: event.importance,
      before: event.before, after: event.after, observed_at: event.observed_at,
      source_refs: event.source_refs, evidence_refs: event.evidence_refs,
      reason: event.reason, recommended_action: event.recommended_action,
      watchlist: { id: watchlistId, name: watchlistName },
    },
  });
  const timestampSeconds = Math.floor(Date.now() / 1000);
  const signature = signPayload(secret, timestampSeconds, payload);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      redirect: 'error', // never follow a redirect -- see webhook-signing.js's SSRF-guard docstring
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-Signature': signature,
        'X-Sentinel-Event': 'watchlist.change_event',
        'User-Agent': 'SentinelApex-Webhooks/1.0',
      },
      body: payload,
    });
    if (res.ok) return { success: true };
    const detail = await res.text().catch(() => '');
    return { success: false, error: `HTTP_${res.status}:${detail.slice(0, MAX_WEBHOOK_RESPONSE_BYTES)}` };
  } catch (e) {
    const reason = e && e.name === 'AbortError' ? 'TIMEOUT' : (e && e.message) || 'NETWORK_ERROR';
    return { success: false, error: reason };
  } finally {
    clearTimeout(timer);
  }
}

// The pending-delivery record only carries ownerId, not the account's
// email -- that lives in the customer-identity store (auth.js's
// handleRegister writes user:id:{userId} -> API-key hash, and the full
// record including email is at user:key:{hash}). This is the same
// 2-hop lookup auth.js's own registration path uses, reused here rather
// than duplicating a userId->email index that doesn't otherwise exist.
// Returns '' (never throws) if the account was deleted or the lookup
// fails -- a missing account email correctly falls through to
// deliverEmailChannel's own NO_RECIPIENT failure, not a crash.
async function getOwnerAccountEmail(ownerId) {
  try {
    const hash = await redis.get(`user:id:${ownerId}`);
    if (!hash) return '';
    const flat = await redis.hgetall(`user:key:${hash}`);
    if (!flat || !Array.isArray(flat)) return '';
    const idx = flat.indexOf('email');
    return idx !== -1 ? (flat[idx + 1] || '') : '';
  } catch (_) {
    return '';
  }
}

/* ───────────────────────── orchestration ───────────────────────── */

// Called once per (owner, event) immediately after change-engine.js fans
// an event out to a watcher's feed. Reads CURRENT preferences (not a
// snapshot from watchlist-creation time) so a customer who enables
// notifications after already watching an entity still gets alerted on
// the next real change. Enqueue-only -- no network I/O here.
async function dispatchNewEvent({ ownerId, watchlistId, event }) {
  const prefs = await notify.getPreferences(ownerId);
  const channels = [];
  if (prefs.email_enabled) {
    // Only an explicit override needs a fresh lookup skipped -- otherwise
    // confirm the account actually has a resolvable email before
    // enqueueing a channel that could never succeed. A cheap read now
    // avoids a guaranteed NO_RECIPIENT failure (and a wasted retry
    // schedule) at delivery time later.
    const hasTarget = prefs.email_override || await getOwnerAccountEmail(ownerId);
    if (hasTarget) channels.push('email');
  }
  if (prefs.webhook_enabled && prefs.webhook_url && prefs.has_webhook_secret) channels.push('webhook');
  if (channels.length === 0) return { enqueued: false };
  const result = await notify.enqueuePendingDelivery({ ownerId, eventId: event.event_id, watchlistId, channels });
  return { enqueued: result.created, channels };
}

// The sender. Safe to invoke repeatedly/concurrently is NOT assumed --
// scripts/deliver-watchlist-notifications.js is expected to run as a
// single manual/scheduled invocation at a time, matching change-engine's
// own evaluator posture (no distributed-lock mechanism exists in this
// tranche; documented in the certification doc's Known Limitations).
async function processDueDeliveries({ limit = 100 } = {}) {
  const records = await notify.getDuePendingDeliveries(limit);
  const results = { records_processed: 0, attempts: 0, delivered: 0, retried: 0, dead_lettered: 0 };
  const now = Date.now();

  for (const record of records) {
    results.records_processed++;
    const event = await loadChangeEngine().getEventById(record.event_id);
    const watchlistResult = record.watchlist_id ? await store.getWatchlist(record.watchlist_id, record.owner_id) : null;
    const watchlistName = watchlistResult && watchlistResult.watchlist ? watchlistResult.watchlist.name : '(deleted watchlist)';
    const prefs = await notify.getPreferences(record.owner_id);

    for (const channel of record.channels_pending) {
      const due = record.attempts[channel] && record.attempts[channel].next_attempt_at <= now;
      if (!due) continue;

      // The underlying event or watchlist may have been deleted between
      // enqueue and delivery -- fail this channel out cleanly (dead-letter
      // after retries, same as any other failure) rather than throwing.
      if (!event) {
        await notify.recordAttemptOutcome({ ownerId: record.owner_id, eventId: record.event_id, channel, success: false });
        await notify.recordDelivery(record.owner_id, {
          channel, eventId: record.event_id, watchlistId: record.watchlist_id,
          status: 'failed', error: 'EVENT_NOT_FOUND', attempt: (record.attempts[channel] || {}).count || 0,
        });
        results.attempts++;
        continue;
      }

      let outcome;
      if (channel === 'email') {
        const email = prefs.email_override || await getOwnerAccountEmail(record.owner_id);
        outcome = await deliverEmailChannel({ email, event, watchlistName });
      } else if (channel === 'webhook') {
        const secret = await notify.getWebhookSecret(record.owner_id);
        outcome = secret
          ? await deliverWebhookChannel({ url: prefs.webhook_url, secret, event, watchlistId: record.watchlist_id, watchlistName })
          : { success: false, error: 'NO_SECRET_CONFIGURED' };
      } else {
        outcome = { success: false, error: 'UNKNOWN_CHANNEL' };
      }

      results.attempts++;
      await notify.recordAttemptOutcome({ ownerId: record.owner_id, eventId: record.event_id, channel, success: outcome.success });
      await notify.recordDelivery(record.owner_id, {
        channel, eventId: record.event_id, watchlistId: record.watchlist_id,
        status: outcome.success ? 'delivered' : 'failed', error: outcome.error,
        attempt: ((record.attempts[channel] || {}).count || 0) + 1,
      });
      if (outcome.success) results.delivered++;
      else {
        const willRetry = ((record.attempts[channel] || {}).count || 0) + 1 < notify.MAX_RETRY_ATTEMPTS;
        if (willRetry) results.retried++; else results.dead_lettered++;
      }
    }
  }

  return results;
}

module.exports = {
  buildWatchlistAlertEmail,
  deliverEmailChannel,
  deliverWebhookChannel,
  dispatchNewEvent,
  processDueDeliveries,
};
