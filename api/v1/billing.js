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
  generateIntentId, sanitize, validateEmail, normalizeEmail, emailKey,
  getIp, now, checkIpRateLimit, parseHash,
  cors, ok, fail, parseBody, auditLog,
} = require('../_lib/payment-utils');

/* ─── CORS helper ─────────────────────────────────────────────── */
function setCors(res) {
  Object.entries(corsHeaders()).forEach(([k, v]) => res.setHeader(k, v));
}

/* ─── Max intents per IP per day ──────────────────────────────── */
const MAX_INTENTS_PER_IP_PER_DAY = 5;
const VALID_PAYMENT_METHODS      = ['UPI', 'BANK', 'NEFT', 'IMPS', 'RTGS', 'PHONEPE', 'GPAY', 'PAYTM', 'OTHER'];

/* ─── Main Router ─────────────────────────────────────────────── */
module.exports = async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = String(req.query.action || '').toLowerCase().trim();

  if (!action) {
    return fail(res, 400, 'MISSING_ACTION',
      'action parameter required. Valid: create-intent, submit-payment, status, subscribe. ' +
      'Example: POST /api/v1/billing?action=create-intent');
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

  const ip   = getIp(req);
  const body = await parseBody(req);

  const email    = normalizeEmail(body.email);
  const planType = sanitize(String(body.plan_type || '').toLowerCase(), 20);

  /* ── Validate ─────────────────────────────────────────────── */
  if (!validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  if (!PLANS[planType]) {
    return fail(res, 400, 'INVALID_PLAN', 'plan_type must be "pro" or "enterprise"');
  }

  /* ── IP rate limit ────────────────────────────────────────── */
  try {
    const rk = `payment:intent_rate:${ip}:${new Date().toISOString().slice(0,10).replace(/-/g,'')}`;
    const cnt = await redis.incr(rk);
    if (cnt === 1) await redis.expire(rk, 86400);
    if (cnt > MAX_INTENTS_PER_IP_PER_DAY) {
      return fail(res, 429, 'TOO_MANY_INTENTS',
        `Maximum ${MAX_INTENTS_PER_IP_PER_DAY} payment intents per IP per day.`);
    }
  } catch (_) { /* allow if Redis down */ }

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
    return fail(res, 500, 'INTENT_CREATE_FAILED', `Failed to create intent: ${e.message}`);
  }
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=submit-payment
   Accept UTR submission with fraud protection.
   Body: { email, intent_id, transaction_id, payment_method }
═══════════════════════════════════════════════════════════════ */
async function handleSubmitPayment(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const ip   = getIp(req);
  const ua   = sanitize(req.headers['user-agent'] || 'unknown', 300);
  const body = await parseBody(req);

  const email         = normalizeEmail(body.email);
  const intentId      = sanitize(String(body.intent_id      || ''), 40);
  const rawTxn        = sanitize(String(body.transaction_id || ''), MAX_UTR_LENGTH);
  const paymentMethod = sanitize(String(body.payment_method || 'UPI').toUpperCase(), 20);

  /* ── Input Validation ─────────────────────────────────────── */
  if (!validateEmail(email)) return fail(res, 400, 'INVALID_EMAIL', 'Valid email required.');
  if (!intentId || intentId.length < 32) {
    return fail(res, 400, 'INVALID_INTENT_ID', 'intent_id is required (UUID from action=create-intent)');
  }
  if (!rawTxn || rawTxn.length < MIN_UTR_LENGTH) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID',
      `transaction_id must be ≥${MIN_UTR_LENGTH} characters. UTR numbers are typically 12–22 digits.`);
  }
  if (rawTxn.length > MAX_UTR_LENGTH) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', `transaction_id max ${MAX_UTR_LENGTH} characters.`);
  }
  if (!/^[A-Za-z0-9_\-]+$/.test(rawTxn)) {
    return fail(res, 400, 'INVALID_TRANSACTION_FORMAT',
      'transaction_id must be alphanumeric (letters, numbers, hyphens, underscores only).');
  }
  if (!VALID_PAYMENT_METHODS.includes(paymentMethod)) {
    return fail(res, 400, 'INVALID_PAYMENT_METHOD',
      `payment_method must be one of: ${VALID_PAYMENT_METHODS.join(', ')}`);
  }

  /* ── IP Rate Limit ────────────────────────────────────────── */
  try {
    const rateResult = await checkIpRateLimit(ip);
    if (!rateResult.allowed) {
      await auditLog('RATE_LIMIT_HIT', { ip, email, count: rateResult.count });
      return fail(res, 429, 'SUBMISSION_RATE_LIMIT',
        `Max ${rateResult.max} payment submissions per IP per day.`);
    }
  } catch (_) { /* allow */ }

  /* ── Duplicate UTR Guard ──────────────────────────────────── */
  const txnNorm = rawTxn.toUpperCase();
  const dupKey  = `payment:txn:seen:${txnNorm}`;
  try {
    const dup = await redis.exists(dupKey);
    if (dup && parseInt(dup, 10) > 0) {
      await auditLog('DUPLICATE_TXN', { ip, email, transactionId: txnNorm });
      return fail(res, 409, 'DUPLICATE_TRANSACTION',
        'This transaction ID has already been submitted. Each UTR can only be submitted once.');
    }
  } catch (_) { /* allow */ }

  /* ── Validate Intent ──────────────────────────────────────── */
  let intent;
  try {
    intent = parseHash(await redis.hgetall(`payment:intent:${intentId}`));
    if (!intent) {
      await auditLog('INVALID_INTENT', { ip, email, intentId, note: 'not found or expired' });
      return fail(res, 404, 'INTENT_NOT_FOUND',
        'Payment intent not found or expired (24h TTL). Create new via action=create-intent');
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', 'Verification service unavailable. Retry in 30s.');
  }

  if (intent.email !== email) {
    await auditLog('EMAIL_MISMATCH', { ip, intentId, submittedEmail: email, intentEmail: intent.email });
    return fail(res, 403, 'EMAIL_MISMATCH', 'Email does not match the one used to create this intent.');
  }
  if (['submitted', 'completed'].includes(intent.status)) {
    return fail(res, 409, 'ALREADY_SUBMITTED',
      `Payment for this intent already submitted (status: ${intent.status}).`);
  }
  if (intent.status === 'rejected') {
    return fail(res, 409, 'INTENT_REJECTED', 'This intent was rejected. Create a new one via action=create-intent');
  }

  /* ── Store Submission ─────────────────────────────────────── */
  const submittedAt = now();
  try {
    await redis.hmset(`payment:submission:${txnNorm}`, {
      intentId, email, transactionId: txnNorm, paymentMethod,
      planType: intent.planType, amount: intent.amount, currency: intent.currency,
      status: 'pending_review', submittedAt, ip, userAgent: ua,
      reviewedAt: '', reviewedBy: '', rejectionNote: '',
    });
    await redis.zadd('payment:pending', Date.now(), txnNorm);
    await redis.set(dupKey, '1');
    await redis.expire(dupKey, 90 * 86400);
    await redis.hset(`payment:intent:${intentId}`, 'status', 'submitted');

    await auditLog('PAYMENT_SUBMITTED', {
      email, intentId, transactionId: txnNorm, paymentMethod,
      planType: intent.planType, amount: intent.amount, ip,
    });

    return ok(res, {
      message: 'Payment submitted successfully. Your transaction is under review.',
      submission: {
        transaction_id: txnNorm, intent_id: intentId, email,
        plan_type: intent.planType, amount: parseInt(intent.amount, 10),
        currency: intent.currency, payment_method: paymentMethod,
        status: 'pending_review', submitted_at: submittedAt,
      },
      next_steps: [
        'Our team will verify your payment within 2–6 hours (business hours).',
        'Once approved, your API tier will be upgraded automatically.',
        `Check status: GET /api/v1/billing?action=status&transaction_id=${txnNorm}&email=${email}`,
      ],
      support: 'bivash@cyberdudebivash.com',
    });

  } catch (e) {
    try { await redis.del(`payment:submission:${txnNorm}`); } catch (_) {}
    try { await redis.del(dupKey); } catch (_) {}
    return fail(res, 500, 'SUBMISSION_FAILED', `Submission failed: ${e.message}. Retry or contact support.`);
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/billing?action=status&transaction_id=XXX&email=xxx
   User self-service payment status check.
═══════════════════════════════════════════════════════════════ */
async function handlePaymentStatus(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const txnRaw = sanitize(String(req.query.transaction_id || ''), 64).toUpperCase();
  const email  = normalizeEmail(req.query.email || '');

  if (!txnRaw || txnRaw.length < 6) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID', 'transaction_id query parameter required.');
  }
  if (!validateEmail(email)) {
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
    return fail(res, 500, 'STATUS_CHECK_FAILED', `Status check failed: ${e.message}`);
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
  if (!['pro', 'enterprise'].includes(plan)) {
    return fail(res, 400, 'INVALID_PLAN', 'plan must be "pro" or "enterprise"');
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
      price: plan === 'pro' ? '₹1,499/month' : 'Custom pricing',
    });

  } catch (e) {
    return fail(res, 500, 'CHECKOUT_FAILED', `Checkout session failed: ${e.message}`);
  }
}
