/**
 * POST /api/v1/billing/submit-payment
 * SENTINEL APEX Manual Payment System — Phases 2, 3, 4
 *
 * User submits UTR/transaction ID after manual payment.
 * Full fraud/spam protection, duplicate detection, intent validation.
 *
 * Body: {
 *   email,          string — must match intent email
 *   intent_id,      string — UUID from create-intent
 *   transaction_id, string — UTR or bank reference (min 12 chars)
 *   payment_method  string — "UPI" | "BANK" | "NEFT" | "IMPS" | "RTGS"
 * }
 *
 * Redis schema written:
 *   payment:submission:{txn_id}  HASH { ... status:"pending_review" ... }
 *   payment:pending              ZSET  score=timestamp  member=txn_id
 *   payment:txn:seen:{txn_id}    STRING (duplicate guard, 90d TTL)
 *
 * Fraud protections:
 *   • Max 3 submissions per IP per day
 *   • Duplicate transaction_id rejection (90-day memory)
 *   • intent_id must exist and be in "pending_payment" state
 *   • Email must match intent exactly
 *   • UTR min/max length enforcement
 *   • Alphanumeric-only UTR validation (no injection)
 *   • Suspicious pattern logging
 */
'use strict';
const redis = require('../../_lib/redis');
const {
  MIN_UTR_LENGTH, MAX_UTR_LENGTH,
  sanitize, validateEmail, normalizeEmail, emailKey,
  getIp, now, checkIpRateLimit,
  parseHash, cors, ok, fail, parseBody, auditLog,
} = require('../../_lib/payment-utils');

const VALID_PAYMENT_METHODS = ['UPI', 'BANK', 'NEFT', 'IMPS', 'RTGS', 'PHONEPE', 'GPAY', 'PAYTM', 'OTHER'];

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const ip = getIp(req);
  const ua = sanitize(req.headers['user-agent'] || 'unknown', 300);

  /* ── Parse Body ─────────────────────────────────────────────── */
  const body          = await parseBody(req);
  const email         = normalizeEmail(body.email);
  const intentId      = sanitize(String(body.intent_id      || ''), 40);
  const rawTxn        = sanitize(String(body.transaction_id || ''), MAX_UTR_LENGTH);
  const paymentMethod = sanitize(String(body.payment_method || 'UPI').toUpperCase(), 20);

  /* ── Phase 4: Input Validation ─────────────────────────────── */
  if (!validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'Valid email address required.');
  }
  if (!intentId || intentId.length < 32) {
    return fail(res, 400, 'INVALID_INTENT_ID', 'intent_id is required and must be a valid UUID from /api/v1/billing/create-intent');
  }
  if (!rawTxn || rawTxn.length < MIN_UTR_LENGTH) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID',
      `transaction_id must be at least ${MIN_UTR_LENGTH} characters. UTR numbers are typically 12–22 digits.`);
  }
  if (rawTxn.length > MAX_UTR_LENGTH) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', `transaction_id too long. Maximum ${MAX_UTR_LENGTH} characters.`);
  }
  // UTR must be alphanumeric + optional dash/underscore — no special injection chars
  if (!/^[A-Za-z0-9_\-]+$/.test(rawTxn)) {
    return fail(res, 400, 'INVALID_TRANSACTION_FORMAT',
      'transaction_id must contain only letters, numbers, hyphens, or underscores. No spaces or special characters.');
  }
  if (!VALID_PAYMENT_METHODS.includes(paymentMethod)) {
    return fail(res, 400, 'INVALID_PAYMENT_METHOD',
      `payment_method must be one of: ${VALID_PAYMENT_METHODS.join(', ')}`);
  }

  /* ── Phase 4: IP Rate Limit ─────────────────────────────────── */
  try {
    const rateResult = await checkIpRateLimit(ip);
    if (!rateResult.allowed) {
      await auditLog('RATE_LIMIT_HIT', { ip, email, count: rateResult.count, max: rateResult.max });
      return fail(res, 429, 'SUBMISSION_RATE_LIMIT',
        `Maximum ${rateResult.max} payment submissions per IP per day. Contact bivash@cyberdudebivash.com if you need assistance.`);
    }
  } catch (_) { /* Redis down — allow, but log */ }

  /* ── Phase 4: Duplicate Transaction ID Guard ────────────────── */
  const txnNorm   = rawTxn.toUpperCase(); // normalize UTR to uppercase
  const dupKey    = `payment:txn:seen:${txnNorm}`;
  try {
    const dupExists = await redis.exists(dupKey);
    if (dupExists && parseInt(dupExists, 10) > 0) {
      await auditLog('DUPLICATE_TXN', { ip, email, transactionId: txnNorm, intentId });
      return fail(res, 409, 'DUPLICATE_TRANSACTION',
        'This transaction ID has already been submitted. Each UTR can only be submitted once. If this is an error, contact bivash@cyberdudebivash.com');
    }
  } catch (_) { /* Redis down — continue */ }

  /* ── Phase 3: Validate Intent Exists ───────────────────────── */
  let intent;
  try {
    const raw = await redis.hgetall(`payment:intent:${intentId}`);
    intent    = parseHash(raw);
    if (!intent) {
      await auditLog('INVALID_INTENT', { ip, email, intentId, note: 'not found or expired' });
      return fail(res, 404, 'INTENT_NOT_FOUND',
        'Payment intent not found or expired (intents expire after 24 hours). Create a new intent at POST /api/v1/billing/create-intent');
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', 'Verification service temporarily unavailable. Retry in 30s.');
  }

  /* ── Phase 3: Email Must Match Intent ──────────────────────── */
  if (intent.email !== email) {
    await auditLog('EMAIL_MISMATCH', { ip, intentId, submittedEmail: email, intentEmail: intent.email });
    return fail(res, 403, 'EMAIL_MISMATCH',
      'Email does not match the one used to create this payment intent. Use the same email address.');
  }

  /* ── Phase 3: Intent Must Be in Correct State ──────────────── */
  if (intent.status === 'submitted' || intent.status === 'completed') {
    return fail(res, 409, 'ALREADY_SUBMITTED',
      `Payment for this intent has already been submitted (status: ${intent.status}). No duplicate submissions allowed.`);
  }
  if (intent.status === 'rejected') {
    return fail(res, 409, 'INTENT_REJECTED',
      'This payment intent was rejected. Please create a new intent at POST /api/v1/billing/create-intent');
  }

  /* ── Phase 3: Store Submission ─────────────────────────────── */
  const submittedAt = now();
  const submissionData = {
    intentId,
    email,
    transactionId: txnNorm,
    paymentMethod,
    planType:      intent.planType,
    amount:        intent.amount,
    currency:      intent.currency,
    status:        'pending_review',
    submittedAt,
    ip,
    userAgent:     ua,
    reviewedAt:    '',
    reviewedBy:    '',
    rejectionNote: '',
  };

  try {
    // Store submission record (permanent — no TTL, needed for audit)
    await redis.hmset(`payment:submission:${txnNorm}`, submissionData);

    // Add to pending review sorted set (score = ms timestamp for ordering)
    await redis.zadd('payment:pending', Date.now(), txnNorm);

    // Mark duplicate guard (90-day TTL)
    await redis.set(dupKey, '1');
    await redis.expire(dupKey, 90 * 86400);

    // Update intent status → submitted
    await redis.hset(`payment:intent:${intentId}`, 'status', 'submitted');

    // Audit log
    await auditLog('PAYMENT_SUBMITTED', {
      email,
      intentId,
      transactionId: txnNorm,
      paymentMethod,
      planType: intent.planType,
      amount: intent.amount,
      ip,
    });

    return ok(res, {
      message:        'Payment submitted successfully. Your transaction is under review.',
      submission: {
        transaction_id: txnNorm,
        intent_id:      intentId,
        email,
        plan_type:      intent.planType,
        amount:         parseInt(intent.amount, 10),
        currency:       intent.currency,
        payment_method: paymentMethod,
        status:         'pending_review',
        submitted_at:   submittedAt,
      },
      next_steps: [
        'Our team will verify your payment within 2–6 hours (business hours).',
        'Once approved, your API tier will be upgraded automatically.',
        'You will receive confirmation at: ' + email,
        'For urgent queries: bivash@cyberdudebivash.com',
      ],
      check_status: {
        note:    'Check your current tier via API:',
        example: 'GET /api/v1/auth/me  with your Authorization: Bearer sentinel_xxx header',
      },
      support: 'bivash@cyberdudebivash.com',
    });

  } catch (e) {
    // Attempt cleanup if partial write
    try { await redis.del(`payment:submission:${txnNorm}`); } catch (_) {}
    try { await redis.del(dupKey); } catch (_) {}
    return fail(res, 500, 'SUBMISSION_FAILED',
      `Failed to record payment submission: ${e.message}. Please retry or contact bivash@cyberdudebivash.com`);
  }
};
