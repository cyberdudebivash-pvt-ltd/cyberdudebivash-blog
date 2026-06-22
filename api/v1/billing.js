/**
 * SENTINEL APEX — Consolidated Billing Router
 * Single serverless function handling ALL billing/payment endpoints.
 * Note: Stripe webhook kept separate (api/v1/billing/webhook.js) — requires raw body.
 *
 * Routing: /api/v1/billing?action={action}
 *
 *  action=create-intent    POST  Generate payment intent UUID, store in Redis 24h
 *  action=submit-payment   POST  Accept UTR with fraud protection + duplicate guard
 *  action=status           GET   User self-service payment status check
 *  action=subscribe        POST  Create Stripe checkout session (when available)
 *
 * Backward-compat: vercel.json rewrites old /api/v1/billing/* paths here.
 */
'use strict';
const redis  = require('../_lib/redis');
const stripe = require('../_lib/stripe');
const {
  authenticate, apiError, respond, corsHeaders,
} = require('../_lib/middleware');
const {
  PLANS, PAYMENT_INSTRUCTIONS,
  MIN_UTR_LENGTH, MAX_UTR_LENGTH,
  INTENT_TTL_SECONDS, SUBMISSION_TTL_SECONDS,
  generateIntentId, sanitize, validateEmail, normalizeEmail, emailKey,
  now, parseHash, ok, fail, parseBody, auditLog,
} = require('../_lib/payment-utils');
const sec = require('../_lib/security');

/* ─── Allowed payment methods ─────────────────────────────────── */
const VALID_PAYMENT_METHODS = new Set(['UPI', 'BANK', 'NEFT', 'IMPS', 'RTGS', 'PHONEPE', 'GPAY', 'PAYTM', 'OTHER']);

/* ─── Allowed fields per action (whitelist) ───────────────────── */
const FIELDS = {
  'create-intent':  ['email', 'plan_type'],
  'submit-payment': ['email', 'intent_id', 'utr_number', 'transaction_id', 'payment_method'],
};

/* ─── Main Router ─────────────────────────────────────────────── */
module.exports = async (req, res) => {
  /* Phase 1: global guard — sets security headers, checks method/size */
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes:   10240,
  });
  if (!ok_guard) return;

  /* Phase 4: global IP rate limit */
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();

  if (!action) {
    return fail(res, 400, 'MISSING_ACTION',
      'action parameter required. Valid: create-intent, submit-payment, status, subscribe.');
  }

  /* ─── Route Dispatcher ───────────────────────────────────────── */
  switch (action) {
    case 'create-intent':   return handleCreateIntent(req, res);
    case 'submit-payment':  return handleSubmitPayment(req, res);
    case 'status':          return handlePaymentStatus(req, res);
    case 'subscribe':       return handleSubscribe(req, res);
    default:
      return fail(res, 400, 'INVALID_ACTION',
        `Unknown action: "${action}". Valid: create-intent, submit-payment, status, subscribe`);
  }
};

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=create-intent
   Generate a payment intent before user transfers money.
   Body: { email, plan_type: "pro"|"enterprise" }
═══════════════════════════════════════════════════════════════ */
async function handleCreateIntent(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const ip   = sec.getIp(req);
  const body = await parseBody(req);

  /* Phase 2: field whitelist — reject unexpected fields */
  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS['create-intent']);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email    = normalizeEmail(body.email);
  const planType = sanitize(String(body.plan_type || '').toLowerCase(), 20);

  /* Phase 2: strict input validation */
  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  if (!sec.validatePlan(planType)) {
    return fail(res, 400, 'INVALID_PLAN', 'plan_type must be "pro" or "enterprise"');
  }

  /* Phase 4: intent creation IP rate limit (5/day/IP) */
  if (!(await sec.intentIpRateLimit(req, res))) return;

  /* ── Deduplicate: return existing pending intent ──────────── */
  try {
    const ref = await redis.get(`payment:intent:ref:${emailKey(email)}:${planType}`);
    if (ref) {
      const existRaw = await redis.hgetall(`payment:intent:${ref}`);
      const existing = parseHash(existRaw);
      if (existing && existing.status === 'pending_payment') {
        const plan = PLANS[planType];
        return ok(res, {
          message: 'Existing payment intent retrieved.',
          intent: {
            intent_id: existing.intentId, email: existing.email,
            plan_type: existing.planType, amount: parseInt(existing.amount, 10),
            currency: existing.currency, status: existing.status,
            created_at: existing.createdAt, expires_in: '24 hours from creation',
          },
          payment_instructions: PAYMENT_INSTRUCTIONS,
          next_step: 'Transfer the exact amount then POST /api/v1/billing?action=submit-payment',
        });
      }
    }
  } catch (_) { /* create fresh */ }

  /* ── Generate intent ──────────────────────────────────────── */
  const intentId  = generateIntentId();
  const plan      = PLANS[planType];
  const createdAt = now();
  const ua        = sanitize(req.headers['user-agent'] || 'unknown', 200);

  try {
    await redis.hmset(`payment:intent:${intentId}`, {
      intentId, email, planType,
      amount:    String(plan.amount),
      currency:  plan.currency,
      status:    'pending_payment',
      createdAt, ip, userAgent: ua,
    });
    await redis.expire(`payment:intent:${intentId}`, 86400);
    await redis.set(`payment:intent:ref:${emailKey(email)}:${planType}`, intentId);
    await redis.expire(`payment:intent:ref:${emailKey(email)}:${planType}`, 86400);

    await auditLog('INTENT_CREATED', { intentId, email, planType, amount: plan.amount, ip });

    return ok(res, {
      message: 'Payment intent created.',
      intent: {
        intent_id: intentId, email, plan_type: planType, plan_label: plan.label,
        amount: plan.amount, currency: plan.currency, period: plan.period,
        description: plan.description, status: 'pending_payment',
        created_at: createdAt, expires_in: '24 hours',
      },
      payment_instructions: {
        upi:  PAYMENT_INSTRUCTIONS.upi,
        bank: PAYMENT_INSTRUCTIONS.bank,
        important: [
          `Transfer exactly ₹${plan.amount} (${plan.currency})`,
          `Include intent ID "${intentId}" in payment remarks`,
          'Complete within 24 hours',
          'After payment, POST /api/v1/billing?action=submit-payment',
        ],
      },
      next_step: {
        endpoint: 'POST /api/v1/billing?action=submit-payment',
        payload: { email, intent_id: intentId, transaction_id: '<UTR>', payment_method: 'UPI or BANK' },
      },
      support: 'bivash@cyberdudebivash.com',
    }, 201);

  } catch (e) {
    return fail(res, 500, 'INTENT_CREATE_FAILED', sec.safeError(e, 'Failed to create payment intent. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=submit-payment
   Accept UTR submission with fraud protection.
   Body: { email, intent_id, transaction_id, payment_method }
═══════════════════════════════════════════════════════════════ */
async function handleSubmitPayment(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const ip   = sec.getIp(req);
  const ua   = sanitize(req.headers['user-agent'] || 'unknown', 200);
  const body = await parseBody(req);

  /* Phase 2: field whitelist */
  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS['submit-payment']);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email         = normalizeEmail(body.email);
  const intentId      = sanitize(String(body.intent_id || body.transaction_id?.match?.(/^[0-9a-f-]{36}$/) ? '' : ''), 40);
  const rawUTR        = sec.normalizeUTR(String(body.utr_number || body.transaction_id || ''));
  const paymentMethod = sanitize(String(body.payment_method || 'UPI').toUpperCase(), 20);
  const intentIdRaw   = sanitize(String(body.intent_id || ''), 40);

  /* Phase 2: strict validation */
  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'Valid email address required.');
  }
  if (!sec.validateUUID(intentIdRaw)) {
    return fail(res, 400, 'INVALID_INTENT_ID',
      'intent_id must be a valid UUID v4 (from action=create-intent).');
  }
  if (!sec.validateUTR(rawUTR)) {
    return fail(res, 400, 'INVALID_UTR',
      `UTR must be 8–64 alphanumeric characters only. Example: 427110170556`);
  }
  if (!VALID_PAYMENT_METHODS.has(paymentMethod)) {
    return fail(res, 400, 'INVALID_PAYMENT_METHOD',
      `payment_method must be one of: ${[...VALID_PAYMENT_METHODS].join(', ')}`);
  }

  const txnNorm = rawUTR; // already uppercased + sanitized by normalizeUTR

  /* Phase 4: IP submission rate limit (3/day/IP) */
  if (!(await sec.submissionIpRateLimit(req, res))) {
    await auditLog('RATE_LIMIT_HIT', { ip, email, endpoint: 'submit-payment' });
    return;
  }

  /* ── Phase 5+6: Duplicate UTR Guard (90-day atomic block) ────── */
  const dupKey = `payment:txn:seen:${txnNorm}`;
  try {
    const dup = await redis.exists(dupKey);
    if (dup && parseInt(dup, 10) > 0) {
      await auditLog('DUPLICATE_TXN', { ip, email, transactionId: txnNorm });
      return fail(res, 409, 'DUPLICATE_TRANSACTION',
        'This transaction reference has already been submitted. Each UTR can only be used once.');
    }
  } catch (_) { /* allow if Redis down — approve step also deduplicates */ }

  /* ── Phase 5: Validate Intent ─────────────────────────────────── */
  let intent;
  try {
    intent = parseHash(await redis.hgetall(`payment:intent:${intentIdRaw}`));
    if (!intent) {
      await auditLog('INVALID_INTENT', { ip, email, intentId: intentIdRaw, note: 'not found or expired' });
      return fail(res, 404, 'INTENT_NOT_FOUND',
        'Payment intent not found or expired (24h TTL). Please create a new one.');
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', 'Verification service temporarily unavailable. Retry in 30s.');
  }

  /* Phase 5: email must exactly match intent */
  if (intent.email !== email) {
    await auditLog('EMAIL_MISMATCH', { ip, intentId: intentIdRaw, submittedEmail: email, intentEmail: intent.email });
    return fail(res, 403, 'EMAIL_MISMATCH',
      'Email does not match the intent. Use the same email from payment intent creation.');
  }

  /* Phase 5: intent must be unconsumed */
  if (intent.status === 'submitted' || intent.status === 'completed') {
    return fail(res, 409, 'INTENT_ALREADY_USED',
      `This payment intent has already been submitted (status: ${intent.status}). Each intent is single-use.`);
  }
  if (intent.status === 'rejected') {
    return fail(res, 409, 'INTENT_REJECTED',
      'This intent was rejected. Please create a new payment intent.');
  }
  if (intent.status !== 'pending_payment') {
    return fail(res, 409, 'INVALID_INTENT_STATUS',
      `Intent cannot be used in status "${intent.status}".`);
  }

  /* ── Phase 6: Store Submission with mandatory TTL ─────────────── */
  const submittedAt = now();
  try {
    await redis.hmset(`payment:submission:${txnNorm}`, {
      intentId:      intentIdRaw,
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
    });

    /* MANDATORY: every Redis write gets a TTL */
    await redis.expire(`payment:submission:${txnNorm}`, SUBMISSION_TTL_SECONDS); // 90 days
    await redis.zadd('payment:pending', Date.now(), txnNorm);
    await redis.setex(dupKey, SUBMISSION_TTL_SECONDS, '1');            // atomic set+TTL
    await redis.hset(`payment:intent:${intentIdRaw}`, 'status', 'submitted');  // consume intent

    await auditLog('PAYMENT_SUBMITTED', {
      email, intentId: intentIdRaw, transactionId: txnNorm, paymentMethod,
      planType: intent.planType, amount: intent.amount, ip,
    });

    return ok(res, {
      message: 'Payment submitted for review. Verification within 2–6 business hours.',
      submission: {
        transaction_id: txnNorm,
        intent_id:      intentIdRaw,
        email,
        plan_type:      intent.planType,
        amount:         parseInt(intent.amount, 10),
        currency:       intent.currency,
        payment_method: paymentMethod,
        status:         'pending_review',
        submitted_at:   submittedAt,
      },
      next_steps: [
        'Your API tier upgrades automatically once payment is verified.',
        `Poll status: GET /api/v1/billing?action=status&transaction_id=${txnNorm}&email=${encodeURIComponent(email)}`,
      ],
      support: 'bivash@cyberdudebivash.com',
    });

  } catch (e) {
    try { await redis.del(`payment:submission:${txnNorm}`); } catch (_) {}
    try { await redis.del(dupKey); } catch (_) {}
    return fail(res, 500, 'SUBMISSION_FAILED', sec.safeError(e, 'Submission failed. Please retry or contact support.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/billing?action=status&transaction_id=XXX&email=xxx
   User self-service payment status check.
═══════════════════════════════════════════════════════════════ */
async function handlePaymentStatus(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const txnRaw = sec.normalizeUTR(String(req.query.transaction_id || ''));
  const email  = normalizeEmail(req.query.email || '');

  if (!sec.validateUTR(txnRaw)) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID',
      'transaction_id must be a valid alphanumeric UTR (8–64 characters).');
  }
  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'email query parameter required.');
  }

  try {
    const sub = parseHash(await redis.hgetall(`payment:submission:${txnRaw}`));
    if (!sub) {
      return fail(res, 404, 'NOT_FOUND',
        'No submission found for this transaction ID. Verify UTR or submit via action=submit-payment');
    }
    if (sub.email !== email) {
      return fail(res, 403, 'FORBIDDEN', 'Email does not match this submission.');
    }

    const STATUS_MESSAGES = {
      pending_review: 'Under review — typical verification time: 2–6 hours on business days.',
      approved:       'Approved! Your API tier has been upgraded. Check GET /api/v1/auth?action=me',
      rejected:       'Payment could not be verified. Contact bivash@cyberdudebivash.com',
    };

    return ok(res, {
      payment_status: {
        transaction_id: txnRaw,
        plan_type:      sub.planType,
        amount:         parseInt(sub.amount || '0', 10),
        currency:       sub.currency,
        payment_method: sub.paymentMethod,
        status:         sub.status,
        status_message: STATUS_MESSAGES[sub.status] || `Status: ${sub.status}`,
        submitted_at:   sub.submittedAt,
        reviewed_at:    sub.reviewedAt   || null,
        rejection_note: sub.status === 'rejected' ? (sub.rejectionNote || null) : null,
      },
    });

  } catch (e) {
    return fail(res, 500, 'STATUS_CHECK_FAILED', sec.safeError(e, 'Status check unavailable. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=subscribe
   Create Stripe Checkout session for automated billing.
   Body: { plan: "pro"|"enterprise" }
   Requires API key auth.
═══════════════════════════════════════════════════════════════ */
async function handleSubscribe(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const user = await authenticate(req, res);
  if (!user) return;

  let body = {};
  try {
    body = await parseBody(req);
  } catch (_) {}

  const plan = String(body.plan || 'pro').toLowerCase();
  if (!['starter', 'pro', 'enterprise'].includes(plan)) {
    return fail(res, 400, 'INVALID_PLAN', 'plan must be "starter", "pro", or "enterprise"');
  }
  if (user.tier === plan || user.tier === 'enterprise') {
    return fail(res, 400, 'ALREADY_ON_PLAN', `You are already on the ${user.tier} plan.`);
  }
  if (!process.env.STRIPE_SECRET_KEY) {
    return fail(res, 503, 'BILLING_UNAVAILABLE',
      `Automated billing not configured. Use manual payment: POST /api/v1/billing?action=create-intent — or contact bivash@cyberdudebivash.com`);
  }

  try {
    const base    = process.env.NEXT_PUBLIC_BASE_URL || 'https://blog.cyberdudebivash.in';
    const session = await stripe.createCheckoutSession(
      user.email, plan,
      `${base}/api-dashboard.html?session_id={CHECKOUT_SESSION_ID}&status=success`,
      `${base}/api-dashboard.html?status=cancelled`
    );

    return ok(res, {
      checkout_url: session.url,
      session_id:   session.id,
      plan,
      price: { starter: '₹2,499/month', pro: '₹1,499/month', enterprise: 'Custom pricing' }[plan],
    });

  } catch (e) {
    return fail(res, 500, 'CHECKOUT_FAILED', sec.safeError(e, 'Checkout unavailable. Use manual payment or contact support.'));
  }
}
