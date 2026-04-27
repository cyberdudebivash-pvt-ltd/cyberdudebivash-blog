/**
 * GET /api/v1/admin/payments/pending
 * SENTINEL APEX Manual Payment System — Phase 5
 *
 * Lists all payment submissions awaiting admin review.
 * Protected by X-Admin-Key header (env: ADMIN_SECRET_KEY).
 *
 * Query params:
 *   ?limit=50   — max submissions to return (default 50, max 200)
 *   ?offset=0   — pagination offset
 *   ?status=all — "pending_review" (default), "approved", "rejected", "all"
 *
 * Returns full submission details including email, UTR, plan, timestamp.
 */
'use strict';
const redis = require('../../../_lib/redis');
const {
  isAdminAuthorized, parseHash,
  cors, ok, fail, auditLog, getIp,
} = require('../../../_lib/payment-utils');

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  /* ── Admin Auth ─────────────────────────────────────────────── */
  if (!isAdminAuthorized(req)) {
    await auditLog('ADMIN_AUTH_FAIL', { ip: getIp(req), endpoint: 'pending', ua: req.headers['user-agent'] || '' });
    return fail(res, 401, 'UNAUTHORIZED', 'Valid X-Admin-Key header required. Set ADMIN_SECRET_KEY in Vercel environment variables.');
  }

  /* ── Query Params ────────────────────────────────────────────── */
  const limit  = Math.min(parseInt(req.query?.limit  || '50',  10), 200);
  const offset = Math.max(parseInt(req.query?.offset || '0',   10), 0);
  const status = String(req.query?.status || 'pending_review');

  try {
    let txnIds = [];

    if (status === 'all') {
      // Get from both sets merged
      const pending  = await redis.zrevrange('payment:pending',  0, 999) || [];
      const approved = await redis.zrevrange('payment:approved', 0, 999) || [];
      const rejected = await redis.zrevrange('payment:rejected', 0, 999) || [];
      // Merge & de-dup, most recent first — we'll sort after fetching
      txnIds = [...new Set([...pending, ...approved, ...rejected])];
    } else if (status === 'approved') {
      txnIds = await redis.zrevrange('payment:approved', 0, 999) || [];
    } else if (status === 'rejected') {
      txnIds = await redis.zrevrange('payment:rejected', 0, 999) || [];
    } else {
      // Default: pending_review
      txnIds = await redis.zrevrange('payment:pending', 0, 999) || [];
    }

    if (!Array.isArray(txnIds)) txnIds = [];

    const total = txnIds.length;
    const page  = txnIds.slice(offset, offset + limit);

    if (page.length === 0) {
      return ok(res, {
        submissions: [],
        total,
        limit,
        offset,
        filter: status,
        message: total === 0
          ? 'No payment submissions found.'
          : `No submissions at offset ${offset}. Total: ${total}`,
      });
    }

    // Batch-fetch all submissions via pipeline
    const pipeline = page.map(txn => ['HGETALL', `payment:submission:${txn}`]);
    let results;
    try {
      results = await redis.pipeline(pipeline);
    } catch (_) {
      // Fall back to sequential fetch
      results = await Promise.all(page.map(txn => redis.hgetall(`payment:submission:${txn}`)));
    }

    const submissions = results.map((raw, idx) => {
      const obj = parseHash(raw);
      if (!obj) {
        // Submission key missing — orphan entry
        return {
          transaction_id: page[idx],
          status:         'unknown',
          note:           'Submission data not found in Redis (may have expired)',
        };
      }
      return {
        transaction_id: obj.transactionId,
        intent_id:      obj.intentId,
        email:          obj.email,
        plan_type:      obj.planType,
        amount:         parseInt(obj.amount || '0', 10),
        currency:       obj.currency,
        payment_method: obj.paymentMethod,
        status:         obj.status,
        submitted_at:   obj.submittedAt,
        reviewed_at:    obj.reviewedAt   || null,
        reviewed_by:    obj.reviewedBy   || null,
        rejection_note: obj.rejectionNote || null,
        ip:             obj.ip,
        user_agent:     obj.userAgent,
      };
    });

    // Sort by submittedAt desc (newest first) if "all" mode mixed sets
    if (status === 'all') {
      submissions.sort((a, b) => {
        const at = a.submitted_at || '';
        const bt = b.submitted_at || '';
        return bt.localeCompare(at);
      });
    }

    return ok(res, {
      submissions,
      total,
      limit,
      offset,
      filter: status,
      pagination: {
        has_more: offset + limit < total,
        next_offset: offset + limit < total ? offset + limit : null,
      },
      approve_endpoint: 'POST /api/v1/admin/payments/approve  { "transaction_id": "..." }',
      reject_endpoint:  'POST /api/v1/admin/payments/reject   { "transaction_id": "...", "reason": "..." }',
    });

  } catch (e) {
    return fail(res, 500, 'FETCH_FAILED', `Failed to fetch submissions: ${e.message}`);
  }
};
