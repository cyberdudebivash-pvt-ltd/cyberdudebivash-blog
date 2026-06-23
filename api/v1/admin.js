/**
 * SENTINEL APEX — Consolidated Admin Router
 * Single serverless function handling ALL admin payment operations.
 * SECURITY: All routes require X-Admin-Key header (env: ADMIN_SECRET_KEY).
 *
 * Routing: /api/v1/admin?action={action}
 *
 *  action=pending    GET   List payment submissions (filterable by status)
 *  action=approve    POST  Approve payment → upgrade user tier in Redis
 *  action=reject     POST  Reject payment with reason + audit trail
 *  action=audit      GET   Full event audit log from Redis sorted set
 *
 * Backward-compat: vercel.json rewrites /api/v1/admin/payments/* here.
 */
'use strict';
const redis = require('../_lib/redis');
const {
  PLANS,
  isAdminAuthorized, parseHash,
  sanitize, normalizeEmail, emailKey,
  now,
  upgradeUserTier,
  ok, fail, parseBody, auditLog,
} = require('../_lib/payment-utils');
const sec = require('../_lib/security');

/* ─── Main Router ─────────────────────────────────────────────── */
module.exports = async (req, res) => {
  /* Phase 1: global guard — security headers, method check, size limit */
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes:   10240,
  });
  if (!ok_guard) return;

  /* Phase 4: admin-specific IP rate limit (50 req/min) */
  if (!(await sec.adminIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  const ip     = sec.getIp(req);

  if (!action) {
    return fail(res, 400, 'MISSING_ACTION',
      'action required. Valid: pending, approve, reject, audit, razorpay-orders, product-orders. All routes require X-Admin-Key header.');
  }

  /* Phase 3: Admin auth gate — timing-safe, X-Admin-Key only */
  if (!sec.verifyAdminKey(req)) {
    await auditLog('ADMIN_AUTH_FAIL', {
      ip,
      action,
      endpoint: 'admin-router',
      ua:       sanitize(req.headers['user-agent'] || '', 200),
    });
    return fail(res, 401, 'UNAUTHORIZED',
      'Valid X-Admin-Key header required.');
  }

  /* ─── Route Dispatcher ───────────────────────────────────────── */
  switch (action) {
    case 'pending':          return handlePending(req, res);
    case 'approve':          return handleApprove(req, res);
    case 'reject':           return handleReject(req, res);
    case 'audit':            return handleAudit(req, res);
    case 'razorpay-orders':  return handleRazorpayOrders(req, res);
    case 'product-orders':   return handleProductOrders(req, res);
    default:
      return fail(res, 400, 'INVALID_ACTION',
        `Unknown action: "${action}". Valid: pending, approve, reject, audit, razorpay-orders, product-orders`);
  }
};

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/admin?action=pending
   List payment submissions. Filterable by status.
   Query: ?status=pending_review|approved|rejected|all  ?limit=50  ?offset=0
═══════════════════════════════════════════════════════════════ */
async function handlePending(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const limit  = Math.min(parseInt(req.query.limit  || '50',  10), 200);
  const offset = Math.max(parseInt(req.query.offset || '0',   10), 0);
  const status = String(req.query.status || 'pending_review');

  try {
    let txnIds = [];

    if (status === 'all') {
      const [p, a, r] = await Promise.all([
        redis.zrevrange('payment:pending',  0, 999),
        redis.zrevrange('payment:approved', 0, 999),
        redis.zrevrange('payment:rejected', 0, 999),
      ]);
      txnIds = [...new Set([...(p||[]), ...(a||[]), ...(r||[])])];
    } else if (status === 'approved') {
      txnIds = await redis.zrevrange('payment:approved', 0, 999) || [];
    } else if (status === 'rejected') {
      txnIds = await redis.zrevrange('payment:rejected', 0, 999) || [];
    } else {
      txnIds = await redis.zrevrange('payment:pending', 0, 999) || [];
    }

    if (!Array.isArray(txnIds)) txnIds = [];

    const total = txnIds.length;
    const page  = txnIds.slice(offset, offset + limit);

    if (page.length === 0) {
      return ok(res, {
        submissions: [], total, limit, offset, filter: status,
        message: total === 0 ? 'No submissions found.' : `No submissions at offset ${offset}. Total: ${total}`,
      });
    }

    /* ── Batch-fetch via pipeline ─────────────────────────── */
    let results;
    try {
      results = await redis.pipeline(page.map(txn => ['HGETALL', `payment:submission:${txn}`]));
    } catch (_) {
      results = await Promise.all(page.map(txn => redis.hgetall(`payment:submission:${txn}`)));
    }

    const submissions = results.map((raw, idx) => {
      const obj = parseHash(raw);
      if (!obj) return { transaction_id: page[idx], status: 'unknown', note: 'Data not found in Redis' };
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
        reviewed_at:    obj.reviewedAt    || null,
        reviewed_by:    obj.reviewedBy    || null,
        rejection_note: obj.rejectionNote || null,
        ip:             obj.ip,
      };
    });

    if (status === 'all') {
      submissions.sort((a, b) => (b.submitted_at || '').localeCompare(a.submitted_at || ''));
    }

    return ok(res, {
      submissions, total, limit, offset, filter: status,
      pagination: {
        has_more:    offset + limit < total,
        next_offset: offset + limit < total ? offset + limit : null,
      },
      approve_endpoint: 'POST /api/v1/admin?action=approve  { "transaction_id": "..." }',
      reject_endpoint:  'POST /api/v1/admin?action=reject   { "transaction_id": "...", "reason": "..." }',
    });

  } catch (e) {
    return fail(res, 500, 'FETCH_FAILED', sec.safeError(e, 'Failed to fetch submissions. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/admin?action=approve
   Approve payment → upgrade user tier immediately.
   Body: { transaction_id, notes? }
═══════════════════════════════════════════════════════════════ */
async function handleApprove(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const body   = await parseBody(req);
  const txnRaw = sanitize(String(body.transaction_id || ''), 64).toUpperCase();
  const notes  = sanitize(String(body.notes || ''), 500);

  if (!txnRaw || txnRaw.length < 4) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', 'transaction_id is required.');
  }

  /* ── Fetch submission ─────────────────────────────────────── */
  let submission;
  try {
    submission = parseHash(await redis.hgetall(`payment:submission:${txnRaw}`));
    if (!submission) {
      return fail(res, 404, 'SUBMISSION_NOT_FOUND', `No submission found for "${txnRaw}".`);
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', sec.safeError(e, 'Storage unavailable. Please retry.'));
  }

  /* ── State guard ──────────────────────────────────────────── */
  if (submission.status === 'approved') {
    return fail(res, 409, 'ALREADY_APPROVED',
      `Transaction ${txnRaw} was already approved at ${submission.reviewedAt}.`);
  }
  if (submission.status === 'rejected') {
    return fail(res, 409, 'ALREADY_REJECTED',
      `Transaction ${txnRaw} was already rejected. Contact engineering for reversal.`);
  }
  if (submission.status !== 'pending_review') {
    return fail(res, 409, 'INVALID_STATE', `Cannot approve in state "${submission.status}".`);
  }

  /* ── Determine tier ───────────────────────────────────────── */
  const planType   = submission.planType || 'pro';
  const plan       = PLANS[planType] || PLANS.pro;
  const newTier    = plan.tier;
  const email      = submission.email;
  const approvedAt = now();
  const adminIp    = sec.getIp(req);

  /* ── Upgrade user tier in Redis ───────────────────────────── */
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
      sec.safeError(e, 'Tier upgrade failed. Submission NOT marked approved — safe to retry.'));
  }

  /* ── Update submission + sorted sets ─────────────────────── */
  try {
    await redis.hmset(`payment:submission:${txnRaw}`, {
      status:       'approved',
      reviewedAt:   approvedAt,
      reviewedBy:   `admin@${adminIp}`,
      approvalNote: notes,
    });
    if (submission.intentId) {
      await redis.hset(`payment:intent:${submission.intentId}`, 'status', 'completed');
    }
    await redis.pipeline([
      ['ZREM', 'payment:pending',  txnRaw],
      ['ZADD', 'payment:approved', String(Date.now()), txnRaw],
    ]);
    await redis.incr('analytics:payments:approved:total').catch(() => {});
  } catch (e) {
    await auditLog('APPROVAL_STATUS_UPDATE_FAILED', {
      transactionId: txnRaw, email, error: sec.safeError(e, 'Status update failed'),
      note: 'CRITICAL: Tier upgraded but status update partial. Verify manually.',
    });
    // Tier was upgraded — still return success
  }

  await auditLog('PAYMENT_APPROVED', {
    transactionId: txnRaw, intentId: submission.intentId,
    email, planType, newTier, amount: submission.amount,
    paymentMethod: submission.paymentMethod, submittedAt: submission.submittedAt,
    approvedAt, adminIp, notes, upgradeResult,
  });

  return ok(res, {
    message: `Payment approved. ${email} upgraded to ${newTier.toUpperCase()} tier.`,
    approval: {
      transaction_id: txnRaw, intent_id: submission.intentId,
      email, plan_type: planType, new_tier: newTier,
      amount: parseInt(submission.amount || '0', 10),
      currency: submission.currency, payment_method: submission.paymentMethod,
      approved_at: approvedAt, notes,
    },
    user_upgrade: {
      email, tier: newTier,
      upgrade_status: upgradeResult.upgraded
        ? 'LIVE — user can now access pro endpoints'
        : 'PENDING_REGISTRATION — will activate on next registration',
    },
    verification: 'User can verify tier at GET /api/v1/auth?action=me',
  });
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/admin?action=reject
   Reject payment with mandatory reason. No tier change.
   Body: { transaction_id, reason }
═══════════════════════════════════════════════════════════════ */
async function handleReject(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const body   = await parseBody(req);
  const txnRaw = sanitize(String(body.transaction_id || ''), 64).toUpperCase();
  const reason = sanitize(String(body.reason || ''), 500);

  if (!txnRaw || txnRaw.length < 4) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', 'transaction_id is required.');
  }
  if (!reason || reason.trim().length < 5) {
    return fail(res, 400, 'REASON_REQUIRED', 'A rejection reason (min 5 chars) is required for audit.');
  }

  let submission;
  try {
    submission = parseHash(await redis.hgetall(`payment:submission:${txnRaw}`));
    if (!submission) {
      return fail(res, 404, 'SUBMISSION_NOT_FOUND', `No submission found for "${txnRaw}".`);
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', sec.safeError(e, 'Storage unavailable. Please retry.'));
  }

  if (submission.status === 'approved') {
    return fail(res, 409, 'ALREADY_APPROVED',
      'Cannot reject an approved transaction. Contact engineering for manual tier revocation.');
  }
  if (submission.status === 'rejected') {
    return fail(res, 409, 'ALREADY_REJECTED',
      `Transaction ${txnRaw} was already rejected at ${submission.reviewedAt}.`);
  }

  const rejectedAt = now();
  const adminIp    = sec.getIp(req);

  try {
    await redis.hmset(`payment:submission:${txnRaw}`, {
      status:        'rejected',
      reviewedAt:    rejectedAt,
      reviewedBy:    `admin@${adminIp}`,
      rejectionNote: reason,
    });
    if (submission.intentId) {
      await redis.hset(`payment:intent:${submission.intentId}`, 'status', 'rejected');
    }
    await redis.pipeline([
      ['ZREM', 'payment:pending',  txnRaw],
      ['ZADD', 'payment:rejected', String(Date.now()), txnRaw],
    ]);
    await redis.incr('analytics:payments:rejected:total').catch(() => {});

    await auditLog('PAYMENT_REJECTED', {
      transactionId: txnRaw, intentId: submission.intentId,
      email: submission.email, planType: submission.planType,
      amount: submission.amount, paymentMethod: submission.paymentMethod,
      submittedAt: submission.submittedAt,
      rejectedAt, adminIp, reason,
    });

    return ok(res, {
      message:  `Transaction ${txnRaw} rejected. No tier upgrade applied.`,
      rejection: {
        transaction_id: txnRaw, email: submission.email,
        plan_type: submission.planType, status: 'rejected',
        rejected_at: rejectedAt, reason,
      },
      note: 'Duplicate-transaction guard remains active (90-day window).',
    });

  } catch (e) {
    return fail(res, 500, 'REJECTION_FAILED', sec.safeError(e, 'Failed to record rejection. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/admin?action=audit
   Full payment audit log, filterable by action type.
   Query: ?limit=100  ?offset=0  ?action=PAYMENT_APPROVED
═══════════════════════════════════════════════════════════════ */
async function handleAudit(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const limit  = Math.min(parseInt(req.query.limit  || '100', 10), 500);
  const offset = Math.max(parseInt(req.query.offset || '0',   10), 0);
  const filter = String(req.query.filter || req.query.action_filter || '').toUpperCase();

  try {
    const raw = await redis.zrevrange('audit:payment:log', 0, 999);
    if (!raw || !Array.isArray(raw)) {
      return ok(res, { entries: [], total: 0, limit, offset });
    }

    let entries = raw.map(item => {
      try { return JSON.parse(item); } catch (_) { return { raw: item }; }
    });

    if (filter) {
      entries = entries.filter(e => (e.action || '').toUpperCase().includes(filter));
    }

    const total = entries.length;
    const page  = entries.slice(offset, offset + limit);

    return ok(res, {
      entries: page, total, limit, offset,
      filter: filter || 'none',
      action_types: [
        'INTENT_CREATED', 'PAYMENT_SUBMITTED', 'PAYMENT_APPROVED',
        'PAYMENT_REJECTED', 'TIER_UPGRADED', 'ADMIN_AUTH_FAIL',
        'DUPLICATE_TXN', 'RATE_LIMIT_HIT', 'EMAIL_MISMATCH', 'INVALID_INTENT',
        'RAZORPAY_ORDER_CREATED', 'RAZORPAY_PAYMENT_VERIFIED',
        'RAZORPAY_SIGNATURE_INVALID', 'RAZORPAY_ORDER_MISMATCH',
        'RAZORPAY_WEBHOOK_PAYMENT_CAPTURED',
      ],
    });

  } catch (e) {
    return fail(res, 500, 'AUDIT_FETCH_FAILED', sec.safeError(e, 'Failed to fetch audit log. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/admin?action=razorpay-orders
   Reconciliation view of Razorpay orders — surfaces any order whose
   payment may have been captured by Razorpay but never reached
   verify-razorpay-payment or the webhook (e.g. browser closed mid-
   redirect, webhook misconfigured). Razorpay payments bypass the
   manual approve/reject queue by design, so this is the dedicated
   visibility path for that automated flow.
   Query: ?limit=50  ?offset=0  ?status=created|paid|all (default: all)
═══════════════════════════════════════════════════════════════ */
async function handleRazorpayOrders(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const limit        = Math.min(parseInt(req.query.limit  || '50', 10), 200);
  const offset        = Math.max(parseInt(req.query.offset || '0',  10), 0);
  const statusFilter  = String(req.query.status || 'all').toLowerCase();

  try {
    const orderIds = await redis.zrevrange('payment:rzp:orders', 0, 999) || [];
    const total    = orderIds.length;
    const page     = orderIds.slice(offset, offset + limit);

    if (page.length === 0) {
      return ok(res, {
        orders: [], total, limit, offset, filter: statusFilter,
        message: total === 0 ? 'No Razorpay orders found.' : `No orders at offset ${offset}. Total: ${total}`,
      });
    }

    let results;
    try {
      results = await redis.pipeline(page.map(id => ['HGETALL', `payment:rzp:order:${id}`]));
    } catch (_) {
      results = await Promise.all(page.map(id => redis.hgetall(`payment:rzp:order:${id}`)));
    }

    let orders = results.map((raw, idx) => {
      const obj = parseHash(raw);
      if (!obj) {
        return {
          order_id: page[idx], status: 'expired_unpaid',
          note: 'Order hash expired (24h TTL) without being marked paid — likely an abandoned checkout.',
        };
      }
      return {
        order_id:    obj.orderId,
        email:       obj.email,
        plan_type:   obj.planType,
        amount:      parseInt(obj.amount || '0', 10),
        currency:    obj.currency,
        status:      obj.status,
        payment_id:  obj.paymentId  || null,
        created_at:  obj.createdAt,
        verified_at: obj.verifiedAt || null,
        ip:          obj.ip,
        flag:        obj.status === 'created' ? 'AWAITING_PAYMENT_OR_VERIFICATION' : null,
      };
    });

    if (statusFilter !== 'all') {
      orders = orders.filter(o => o.status === statusFilter);
    }

    return ok(res, {
      orders, total, limit, offset, filter: statusFilter,
      pagination: {
        has_more:    offset + limit < total,
        next_offset: offset + limit < total ? offset + limit : null,
      },
      note: 'Orders with status="created" older than ~1 hour may indicate a payment captured by Razorpay that never completed verification. Cross-check the order_id against Razorpay Dashboard → Payments before contacting the customer or manually upgrading their tier.',
    });

  } catch (e) {
    return fail(res, 500, 'FETCH_FAILED', sec.safeError(e, 'Failed to fetch Razorpay orders. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/admin?action=product-orders
   Fulfillment queue for one-time digital product purchases
   (Sigma/YARA packs, threat reports, playbooks — see products.html).
   No automated file delivery exists yet, so every "paid" order here
   needs the deliverable emailed manually to the buyer.
   Query: ?limit=50  ?offset=0  ?status=created|paid|all (default: all)
═══════════════════════════════════════════════════════════════ */
async function handleProductOrders(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const limit       = Math.min(parseInt(req.query.limit  || '50', 10), 200);
  const offset       = Math.max(parseInt(req.query.offset || '0',  10), 0);
  const statusFilter = String(req.query.status || 'all').toLowerCase();

  try {
    const orderIds = await redis.zrevrange('payment:product:orders', 0, 999) || [];
    const total    = orderIds.length;
    const page     = orderIds.slice(offset, offset + limit);

    if (page.length === 0) {
      return ok(res, {
        orders: [], total, limit, offset, filter: statusFilter,
        message: total === 0 ? 'No product orders found.' : `No orders at offset ${offset}. Total: ${total}`,
      });
    }

    let results;
    try {
      results = await redis.pipeline(page.map(id => ['HGETALL', `payment:product:order:${id}`]));
    } catch (_) {
      results = await Promise.all(page.map(id => redis.hgetall(`payment:product:order:${id}`)));
    }

    let orders = results.map((raw, idx) => {
      const obj = parseHash(raw);
      if (!obj) {
        return {
          session_id: page[idx], status: 'expired_unpaid',
          note: 'Checkout session hash expired (24h TTL) without being marked paid — likely an abandoned checkout.',
        };
      }
      return {
        session_id:  obj.sessionId,
        email:       obj.email,
        product_id:  obj.productId,
        product_name: obj.productName,
        amount:      parseInt(obj.amount || '0', 10),
        currency:    obj.currency,
        status:      obj.status,
        created_at:  obj.createdAt,
        paid_at:     obj.paidAt || null,
        ip:          obj.ip,
        flag:        obj.status === 'paid' ? 'NEEDS_MANUAL_FULFILLMENT' : null,
      };
    });

    if (statusFilter !== 'all') {
      orders = orders.filter(o => o.status === statusFilter);
    }

    return ok(res, {
      orders, total, limit, offset, filter: statusFilter,
      pagination: {
        has_more:    offset + limit < total,
        next_offset: offset + limit < total ? offset + limit : null,
      },
      note: 'Orders with status="paid" need the digital deliverable emailed manually to the buyer — no automated file delivery exists yet.',
    });

  } catch (e) {
    return fail(res, 500, 'FETCH_FAILED', sec.safeError(e, 'Failed to fetch product orders. Please retry.'));
  }
}
