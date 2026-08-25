/**
 * SENTINEL APEX — Watchlist Notification Preferences & Delivery Log
 * Matches the established api/v1/*.js router convention exactly
 * (guardRequest -> globalIpRateLimit -> authenticate() per handler ->
 * action= dispatch -> successResponse/apiError), same as watchlists.js.
 *
 * Routing: /api/v1/notifications?action={action}
 *
 *  action=preferences            GET   Current notification preferences (never includes the webhook secret)
 *  action=update-preferences      POST  Update channels. Body: {email_enabled?, email_override?, webhook_enabled?, webhook_url?}
 *  action=rotate-webhook-secret     POST  Generate/replace the signing secret. Returned ONCE in this call's response only.
 *  action=test-webhook               POST  Send a synthetic test delivery to the configured webhook URL now (not queued).
 *  action=deliveries                   GET   Recent delivery attempts (both channels, success and failure). ?limit=
 *  action=dead-letters                   GET   Deliveries that exhausted retries. ?limit=
 *  action=retry-dead-letter               POST  Re-queue one dead-lettered (event_id, channel) as a fresh delivery attempt (Phase 73: a controlled new attempt, not a history reset -- the original dead-letter entry stays as a record). Body: {event_id, channel}
 *
 * Ownership is always the authenticated caller's own userId -- there is
 * no per-watchlist scoping here (notification preferences are account-
 * level, matching how a customer has ONE inbox/ONE webhook endpoint, not
 * one per watchlist).
 */
'use strict';

const sec = require('../_lib/security');
const { authenticate, successResponse, apiError } = require('../_lib/middleware');
const { parseBody } = require('../_lib/payment-utils');
const notify = require('../_lib/notification-store');
const { isSafeWebhookUrl } = require('../_lib/webhook-signing');
const { deliverWebhookChannel } = require('../_lib/notification-dispatch');

const VALID_ACTIONS = 'preferences, update-preferences, rotate-webhook-secret, test-webhook, deliveries, dead-letters, retry-dead-letter';

const FIELDS = {
  'update-preferences': ['email_enabled', 'email_override', 'webhook_enabled', 'webhook_url'],
  'retry-dead-letter': ['event_id', 'channel'],
};
const RETRYABLE_CHANNELS = new Set(['email', 'webhook']);
const MAX_DEAD_LETTER_SCAN = 200;

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,24}$/;
const MAX_URL_LENGTH = 500;

module.exports = async (req, res) => {
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes: 10240,
  });
  if (!ok_guard) return;

  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  if (!action) {
    return apiError(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);
  }

  switch (action) {
    case 'preferences':           return handlePreferences(req, res);
    case 'update-preferences':     return handleUpdatePreferences(req, res);
    case 'rotate-webhook-secret':   return handleRotateSecret(req, res);
    case 'test-webhook':             return handleTestWebhook(req, res);
    case 'deliveries':                return handleDeliveries(req, res);
    case 'dead-letters':               return handleDeadLetters(req, res);
    case 'retry-dead-letter':          return handleRetryDeadLetter(req, res);
    default:
      return apiError(res, 400, 'INVALID_ACTION', `Unknown action: "${action}". Valid: ${VALID_ACTIONS}`);
  }
};

/* ─── helpers ─────────────────────────────────────────────────── */

async function readValidatedBody(req, res, action) {
  if (req.method !== 'POST') {
    apiError(res, 405, 'METHOD_NOT_ALLOWED', `POST required for action=${action}`);
    return null;
  }
  let body;
  try {
    body = await parseBody(req);
  } catch (_) {
    apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON.');
    return null;
  }
  const whitelistErr = sec.assertFieldWhitelist(body || {}, FIELDS[action] || []);
  if (whitelistErr) {
    apiError(res, 400, 'INVALID_FIELDS', whitelistErr);
    return null;
  }
  return body || {};
}

/* ─── GET ?action=preferences ─────────────────────────────────── */
async function handlePreferences(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const preferences = await notify.getPreferences(user.userId);
  return successResponse(res, { preferences });
}

/* ─── POST ?action=update-preferences ─────────────────────────── */
async function handleUpdatePreferences(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'update-preferences');
  if (body === null) return;

  const updates = {};

  if (body.email_enabled !== undefined) updates.email_enabled = Boolean(body.email_enabled);

  if (body.email_override !== undefined) {
    const trimmed = String(body.email_override || '').trim();
    if (trimmed && !EMAIL_RE.test(trimmed)) {
      return apiError(res, 400, 'INVALID_EMAIL', 'email_override is not a valid email address.');
    }
    updates.email_override = trimmed;
  }

  if (body.webhook_url !== undefined) {
    const trimmed = String(body.webhook_url || '').trim();
    if (trimmed) {
      if (trimmed.length > MAX_URL_LENGTH) {
        return apiError(res, 400, 'INVALID_WEBHOOK_URL', `webhook_url must be ${MAX_URL_LENGTH} characters or fewer.`);
      }
      const check = await isSafeWebhookUrl(trimmed);
      if (!check.safe) {
        return apiError(res, 400, 'UNSAFE_WEBHOOK_URL',
          'webhook_url must be a public HTTPS endpoint (not localhost, a private/internal address, or a cloud metadata address).');
      }
    }
    updates.webhook_url = trimmed;
    // Clearing the URL always disables the channel -- an "enabled but no
    // URL" state can never be reached through this endpoint.
    if (!trimmed) updates.webhook_enabled = false;
  }

  if (body.webhook_enabled !== undefined) {
    const wantsEnabled = Boolean(body.webhook_enabled);
    if (wantsEnabled) {
      const current = await notify.getPreferences(user.userId);
      const willHaveUrl = updates.webhook_url !== undefined ? updates.webhook_url : current.webhook_url;
      const willHaveSecret = current.has_webhook_secret;
      if (!willHaveUrl) {
        return apiError(res, 400, 'WEBHOOK_URL_REQUIRED', 'Set webhook_url before enabling webhook notifications.');
      }
      if (!willHaveSecret) {
        return apiError(res, 400, 'WEBHOOK_SECRET_REQUIRED', 'Generate a webhook secret (action=rotate-webhook-secret) before enabling webhook notifications.');
      }
    }
    updates.webhook_enabled = wantsEnabled;
  }

  const preferences = await notify.updatePreferences(user.userId, updates);
  // Field NAMES only, never the values themselves (Phase 78: privacy
  // minimization) -- an audit trail needs to answer "what changed and
  // when," not store a second copy of the customer's email/webhook URL.
  await notify.auditNotificationAction(user.userId, 'PREFERENCES_UPDATED', { fields_changed: Object.keys(updates) });
  return successResponse(res, { preferences });
}

/* ─── POST ?action=rotate-webhook-secret ──────────────────────── */
async function handleRotateSecret(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  if (req.method !== 'POST') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const secret = await notify.rotateWebhookSecret(user.userId);
  await notify.auditNotificationAction(user.userId, 'WEBHOOK_SECRET_ROTATED');
  return successResponse(res, {
    webhook_secret: secret,
    warning: 'Store this securely — it will not be shown again. Configure your endpoint to verify the X-Sentinel-Signature header using this value.',
  });
}

/* ─── POST ?action=test-webhook ───────────────────────────────── */
async function handleTestWebhook(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  if (req.method !== 'POST') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const prefs = await notify.getPreferences(user.userId);
  if (!prefs.webhook_url) return apiError(res, 400, 'WEBHOOK_URL_REQUIRED', 'Set webhook_url first (action=update-preferences).');
  if (!prefs.has_webhook_secret) return apiError(res, 400, 'WEBHOOK_SECRET_REQUIRED', 'Generate a webhook secret first (action=rotate-webhook-secret).');
  const secret = await notify.getWebhookSecret(user.userId);

  // A clearly-synthetic test event -- never real intelligence. importance/
  // change_type/entity_id are obviously placeholder values, not a claim
  // about any real CVE or campaign.
  const testEvent = {
    event_id: `test_${Date.now()}`,
    entity_type: 'cve', entity_id: 'CVE-0000-0000', change_type: 'TEST_DELIVERY',
    importance: 'LOW', before: null, after: null, observed_at: new Date().toISOString(),
    source_refs: [], evidence_refs: [],
    reason: 'This is a test delivery triggered from your SENTINEL APEX dashboard — not a real intelligence change.',
    recommended_action: 'No action needed. This confirms your webhook endpoint is reachable and correctly signed.',
  };

  const outcome = await deliverWebhookChannel({
    url: prefs.webhook_url, secret, event: testEvent,
    watchlistId: null, watchlistName: '(test delivery)',
    deliveryId: notify.buildDeliveryId(user.userId, testEvent.event_id, 'webhook'),
  });
  await notify.recordDelivery(user.userId, {
    channel: 'webhook', eventId: testEvent.event_id, watchlistId: null,
    status: outcome.success ? 'delivered' : 'failed', error: outcome.error, attempt: 0,
  });
  return successResponse(res, { success: outcome.success, error: outcome.error || null });
}

/* ─── GET ?action=deliveries ───────────────────────────────────── */
async function handleDeliveries(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 50, 200));
  const deliveries = await notify.listDeliveries(user.userId, { limit });
  return successResponse(res, { deliveries }, { count: deliveries.length });
}

/* ─── GET ?action=dead-letters ─────────────────────────────────── */
async function handleDeadLetters(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 50, 200));
  const deadLetters = await notify.listDeadLetters(user.userId, { limit });
  return successResponse(res, { dead_letters: deadLetters }, { count: deadLetters.length });
}

/* ─── POST ?action=retry-dead-letter ───────────────────────────── */
// Orchestration mandate Phase 73/74: only a dead-lettered delivery this
// caller actually owns, on a channel still enabled/configured, may be
// requeued -- and doing so creates a controlled NEW pending attempt
// (fresh MAX_RETRY_ATTEMPTS budget) rather than resurrecting or mutating
// the original dead-letter record, which stays exactly as it was: an
// honest history entry of "this channel dead-lettered once."
async function handleRetryDeadLetter(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'retry-dead-letter');
  if (body === null) return;

  const eventId = String(body.event_id || '').trim();
  const channel = String(body.channel || '').trim();
  if (!eventId || !RETRYABLE_CHANNELS.has(channel)) {
    return apiError(res, 400, 'INVALID_FIELDS', 'event_id and channel ("email" or "webhook") are required.');
  }

  // Ownership + existence check via the caller's OWN dead-letter list --
  // never trust a request-supplied event_id's ownership (Phase 45/46).
  // A bounded scan (<=200 entries, this store's own retention cap) is
  // sufficient; no separate by-event_id index is needed at this volume.
  const deadLetters = await notify.listDeadLetters(user.userId, { limit: MAX_DEAD_LETTER_SCAN });
  const match = deadLetters.find(d => d.event_id === eventId && d.channel === channel);
  if (!match) {
    return apiError(res, 404, 'NOT_FOUND', 'No dead-lettered delivery found for that event_id/channel on this account.');
  }

  const prefs = await notify.getPreferences(user.userId);
  const stillEligible = channel === 'email'
    ? prefs.email_enabled
    : Boolean(prefs.webhook_enabled && prefs.webhook_url && prefs.has_webhook_secret);
  if (!stillEligible) {
    return apiError(res, 400, 'CHANNEL_NOT_ELIGIBLE', `The ${channel} channel is not currently enabled/configured — update it before retrying.`);
  }

  const result = await notify.enqueuePendingDelivery({
    ownerId: user.userId, eventId, watchlistId: match.watchlist_id || null, channels: [channel],
  });
  await notify.auditNotificationAction(user.userId, 'MANUAL_RETRY_REQUESTED', { event_id: eventId, channel });
  return successResponse(res, { requeued: result.created });
}
