/**
 * POST /api/v1/admin/payments/reject
 * SENTINEL APEX Manual Payment System — Phase 5 (Rejection)
 *
 * Admin rejects a fraudulent/invalid payment submission.
 * Logs reason, marks submission rejected, updates intent.
 * Does NOT downgrade any tier (none was granted).
 *
 * Protected by X-Admin-Key header (env: ADMIN_SECRET_KEY).
 *
 * Body: { transaction_id, reason }
 */
'use strict';
const redis = require('../../../_lib/redis');
const {
  isAdminAuthorized, parseHash,
  sanitize, now, getIp,
  cors, ok, fail, parseBody, auditLog,
} = require('../../../_lib/payment-utils');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  /* ── Admin Auth ─────────────────────────────────────────────── */
  if (!isAdminAuthorized(req)) {
    await auditLog('ADMIN_AUTH_FAIL', { ip: getIp(req), endpoint: 'reject' });
    return fail(res, 401, 'UNAUTHORIZED', 'Valid X-Admin-Key header required.');
  }

  /* ── Parse Body ─────────────────────────────────────────────── */
  const body   = await parseBody(req);
  const txnRaw = sanitize(String(body.transaction_id || ''), 64).toUpperCase();
  const reason = sanitize(String(body.reason || 'No reason provided'), 500);

  if (!txnRaw || txnRaw.length < 4) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', 'transaction_id is required.');
  }
  if (!reason || reason.trim().length < 5) {
    return fail(res, 400, 'REASON_REQUIRED',
      'A rejection reason of at least 5 characters is required for audit purposes.');
  }

  /* ── Fetch Submission ───────────────────────────────────────── */
  let submission;
  try {
    const raw = await redis.hgetall(`payment:submission:${txnRaw}`);
    submission = parseHash(raw);
    if (!submission) {
      return fail(res, 404, 'SUBMISSION_NOT_FOUND', `No submission found for transaction_id "${txnRaw}".`);
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', `Redis error: ${e.message}`);
  }

  if (submission.status === 'approved') {
    return fail(res, 409, 'ALREADY_APPROVED',
      `Cannot reject an already-approved transaction. If this is fraudulent, contact engineering for manual tier revocation.`);
  }
  if (submission.status === 'rejected') {
    return fail(res, 409, 'ALREADY_REJECTED',
      `Transaction ${txnRaw} was already rejected at ${submission.reviewedAt}.`);
  }

  const rejectedAt = now();
  const adminIp    = getIp(req);

  try {
    // Update submission
    await redis.hmset(`payment:submission:${txnRaw}`, {
      status:        'rejected',
      reviewedAt:    rejectedAt,
      reviewedBy:    `admin@${adminIp}`,
      rejectionNote: reason,
    });

    // Update intent
    if (submission.intentId) {
      await redis.hset(`payment:intent:${submission.intentId}`, 'status', 'rejected');
    }

    // Move from pending → rejected sorted set
    await redis.pipeline([
      ['ZREM', 'payment:pending',  txnRaw],
      ['ZADD', 'payment:rejected', String(Date.now()), txnRaw],
    ]);

    // Analytics
    await redis.incr('analytics:payments:rejected:total').catch(() => {});

    // Audit log
    await auditLog('PAYMENT_REJECTED', {
      transactionId: txnRaw,
      intentId:      submission.intentId,
      email:         submission.email,
      planType:      submission.planType,
      amount:        submission.amount,
      paymentMethod: submission.paymentMethod,
      submittedAt:   submission.submittedAt,
      rejectedAt,
      adminIp,
      reason,
    });

    return ok(res, {
      message:  `Transaction ${txnRaw} rejected. No tier upgrade applied.`,
      rejection: {
        transaction_id: txnRaw,
        email:          submission.email,
        plan_type:      submission.planType,
        status:         'rejected',
        rejected_at:    rejectedAt,
        reason,
      },
      note: 'The duplicate-transaction guard remains active for this UTR (90-day window).',
    });

  } catch (e) {
    return fail(res, 500, 'REJECTION_FAILED', `Failed to record rejection: ${e.message}`);
  }
};
