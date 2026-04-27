/**
 * POST /api/v1/admin/payments/approve
 * SENTINEL APEX Manual Payment System — Phases 5, 6, 11
 *
 * Admin approves a payment submission → upgrades user tier in Redis.
 * Full audit trail written. Handles both registered and pre-registered users.
 *
 * Protected by X-Admin-Key header (env: ADMIN_SECRET_KEY).
 *
 * Body: { transaction_id, notes? }
 *
 * On approval:
 *   1. Fetch submission → validate status is pending_review
 *   2. Fetch intent    → get plan/tier
 *   3. Upgrade user:key:{hash} tier in Redis
 *   4. If user not yet registered → store user:pending:tier:{email}
 *   5. Update submission status → "approved"
 *   6. Update intent status    → "completed"
 *   7. Move txn: payment:pending ZREM, payment:approved ZADD
 *   8. Write full audit log entry
 */
'use strict';
const redis = require('../../../_lib/redis');
const {
  PLANS,
  isAdminAuthorized, parseHash,
  sanitize, normalizeEmail, emailKey,
  now, getIp,
  upgradeUserTier,
  cors, ok, fail, parseBody, auditLog,
} = require('../../../_lib/payment-utils');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  /* ── Admin Auth ─────────────────────────────────────────────── */
  if (!isAdminAuthorized(req)) {
    await auditLog('ADMIN_AUTH_FAIL', { ip: getIp(req), endpoint: 'approve', ua: req.headers['user-agent'] || '' });
    return fail(res, 401, 'UNAUTHORIZED', 'Valid X-Admin-Key header required.');
  }

  /* ── Parse Body ─────────────────────────────────────────────── */
  const body = await parseBody(req);
  const txnRaw = sanitize(String(body.transaction_id || ''), 64).toUpperCase();
  const notes  = sanitize(String(body.notes || ''), 500);

  if (!txnRaw || txnRaw.length < 4) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', 'transaction_id is required.');
  }

  /* ── Fetch Submission ───────────────────────────────────────── */
  let submission;
  try {
    const raw = await redis.hgetall(`payment:submission:${txnRaw}`);
    submission = parseHash(raw);
    if (!submission) {
      return fail(res, 404, 'SUBMISSION_NOT_FOUND',
        `No submission found for transaction_id "${txnRaw}". Verify the UTR and try again.`);
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', `Redis error: ${e.message}`);
  }

  /* ── Validate Submission State ──────────────────────────────── */
  if (submission.status === 'approved') {
    return fail(res, 409, 'ALREADY_APPROVED',
      `Transaction ${txnRaw} was already approved at ${submission.reviewedAt}. User tier already upgraded.`);
  }
  if (submission.status === 'rejected') {
    return fail(res, 409, 'ALREADY_REJECTED',
      `Transaction ${txnRaw} was rejected at ${submission.reviewedAt}. Re-approve not allowed via this endpoint. Contact engineering.`);
  }
  if (submission.status !== 'pending_review') {
    return fail(res, 409, 'INVALID_STATE',
      `Cannot approve submission in state "${submission.status}". Expected "pending_review".`);
  }

  /* ── Determine Plan & New Tier ──────────────────────────────── */
  const planType = submission.planType || 'pro';
  const plan     = PLANS[planType] || PLANS.pro;
  const newTier  = plan.tier;
  const email    = submission.email;
  const approvedAt = now();
  const adminIp    = getIp(req);

  /* ── Upgrade User Tier ──────────────────────────────────────── */
  let upgradeResult;
  try {
    upgradeResult = await upgradeUserTier(email, newTier, {
      transactionId: txnRaw,
      intentId:      submission.intentId,
      approvedAt,
      adminNote:     notes,
    });
  } catch (e) {
    return fail(res, 500, 'UPGRADE_FAILED',
      `Tier upgrade failed: ${e.message}. Redis error — submission NOT marked approved. Safe to retry.`);
  }

  /* ── Update Submission Status ───────────────────────────────── */
  try {
    await redis.hmset(`payment:submission:${txnRaw}`, {
      status:        'approved',
      reviewedAt:    approvedAt,
      reviewedBy:    `admin@${adminIp}`,
      approvalNote:  notes,
    });

    // Update intent status → completed
    if (submission.intentId) {
      await redis.hset(`payment:intent:${submission.intentId}`, 'status', 'completed');
    }

    // Move txn_id from pending → approved sorted set
    await redis.pipeline([
      ['ZREM', 'payment:pending',  txnRaw],
      ['ZADD', 'payment:approved', String(Date.now()), txnRaw],
    ]);

    // Track total approvals
    await redis.incr('analytics:payments:approved:total').catch(() => {});

  } catch (e) {
    // Tier upgraded but status update partial — log for manual fix
    await auditLog('APPROVAL_STATUS_UPDATE_FAILED', {
      transactionId: txnRaw,
      email,
      error: e.message,
      note: 'CRITICAL: Tier was upgraded but submission status update failed. Manual Redis fix required.',
    });
    // Still return success since the important part (tier upgrade) worked
  }

  /* ── Full Audit Log ─────────────────────────────────────────── */
  await auditLog('PAYMENT_APPROVED', {
    transactionId: txnRaw,
    intentId:      submission.intentId,
    email,
    planType,
    newTier,
    amount:        submission.amount,
    currency:      submission.currency,
    paymentMethod: submission.paymentMethod,
    submittedAt:   submission.submittedAt,
    approvedAt,
    adminIp,
    notes,
    upgradeResult,
  });

  return ok(res, {
    message:   `Payment approved. User ${email} upgraded to ${newTier.toUpperCase()} tier.`,
    approval: {
      transaction_id: txnRaw,
      intent_id:      submission.intentId,
      email,
      plan_type:      planType,
      new_tier:       newTier,
      amount:         parseInt(submission.amount || '0', 10),
      currency:       submission.currency,
      payment_method: submission.paymentMethod,
      approved_at:    approvedAt,
      notes,
    },
    user_upgrade: {
      email,
      tier:               newTier,
      upgrade_status:     upgradeResult.upgraded ? 'LIVE — user can now access pro endpoints' : 'PENDING_REGISTRATION',
      pending_note:       upgradeResult.pending
        ? `User has not registered yet. Pending tier stored — will activate automatically when they register at POST /api/v1/auth/register`
        : null,
    },
    verification: 'User can verify their tier at GET /api/v1/auth/me',
  });
};
