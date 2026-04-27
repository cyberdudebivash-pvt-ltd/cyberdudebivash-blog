/**
 * POST /api/v1/billing/create-intent
 * SENTINEL APEX Manual Payment System — Phase 1
 *
 * Creates a payment intent before the user transfers money.
 * Returns an intent_id, exact amount, and payment instructions.
 *
 * Body: { email, plan_type: "pro" | "enterprise" }
 *
 * Redis schema:
 *   payment:intent:{intent_id}  HASH {
 *     intentId, email, planType, amount, currency,
 *     status, createdAt, ip, userAgent
 *   }  TTL: 24h
 *
 * No API key required — accessible to unregistered users.
 * Rate limited: max 5 intents per IP per day (separate from submission limit).
 */
'use strict';
const redis = require('../../_lib/redis');
const {
  PLANS, PAYMENT_INSTRUCTIONS,
  generateIntentId, sanitize, validateEmail, normalizeEmail, emailKey,
  getIp, now, checkIpRateLimit,
  cors, ok, fail, parseBody, auditLog,
} = require('../../_lib/payment-utils');

const MAX_INTENTS_PER_IP_PER_DAY = 5;

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  /* ── Parse & Sanitize Body ─────────────────────────────────── */
  const body      = await parseBody(req);
  const email     = normalizeEmail(body.email);
  const planType  = sanitize(String(body.plan_type || '').toLowerCase(), 20);

  /* ── Input Validation ──────────────────────────────────────── */
  if (!validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required. Example: you@domain.com');
  }
  if (!PLANS[planType]) {
    return fail(res, 400, 'INVALID_PLAN',
      `plan_type must be "pro" or "enterprise". Received: "${planType}"`);
  }

  /* ── IP Rate Limit (intent creation) ──────────────────────── */
  const ip = getIp(req);
  const intentRateKey = `payment:intent_rate:${ip}:${new Date().toISOString().slice(0,10).replace(/-/g,'')}`;
  try {
    const intentCount = await redis.incr(intentRateKey);
    if (intentCount === 1) await redis.expire(intentRateKey, 86400);
    if (intentCount > MAX_INTENTS_PER_IP_PER_DAY) {
      return fail(res, 429, 'TOO_MANY_INTENTS',
        `Maximum ${MAX_INTENTS_PER_IP_PER_DAY} payment intents per IP per day. Try again tomorrow or contact support.`);
    }
  } catch (_) { /* Redis unavailable — allow */ }

  /* ── Detect Pending Intent for Same Email+Plan ─────────────── */
  try {
    const existingRef = await redis.get(`payment:intent:ref:${emailKey(email)}:${planType}`);
    if (existingRef) {
      const existingRaw = await redis.hgetall(`payment:intent:${existingRef}`);
      if (existingRaw && Array.isArray(existingRaw) && existingRaw.length > 0) {
        const existing = {};
        for (let i = 0; i < existingRaw.length; i += 2) existing[existingRaw[i]] = existingRaw[i + 1];
        if (existing.status === 'pending_payment') {
          // Return existing intent instead of creating a duplicate
          const plan = PLANS[planType];
          return ok(res, {
            message: 'Existing payment intent retrieved. Complete payment using the details below.',
            intent:  {
              intent_id:    existing.intentId,
              email:        existing.email,
              plan_type:    existing.planType,
              amount:       parseInt(existing.amount, 10),
              currency:     existing.currency,
              status:       existing.status,
              created_at:   existing.createdAt,
              expires_in:   '24 hours from creation',
            },
            payment_instructions: PAYMENT_INSTRUCTIONS,
            next_step: 'Transfer the exact amount, then submit your UTR/transaction ID at POST /api/v1/billing/submit-payment',
          });
        }
      }
    }
  } catch (_) { /* ignore — create fresh intent */ }

  /* ── Generate Intent ────────────────────────────────────────── */
  const intentId = generateIntentId();
  const plan     = PLANS[planType];
  const createdAt = now();
  const ua        = sanitize(req.headers['user-agent'] || 'unknown', 200);

  try {
    // Store intent in Redis (24h TTL)
    await redis.hmset(`payment:intent:${intentId}`, {
      intentId,
      email,
      planType,
      amount:    String(plan.amount),
      currency:  plan.currency,
      status:    'pending_payment',
      createdAt,
      ip,
      userAgent: ua,
    });
    await redis.expire(`payment:intent:${intentId}`, 86400);

    // Email+plan → intentId reference (so we can de-dup)
    await redis.set(`payment:intent:ref:${emailKey(email)}:${planType}`, intentId);
    await redis.expire(`payment:intent:ref:${emailKey(email)}:${planType}`, 86400);

    // Audit
    await auditLog('INTENT_CREATED', { intentId, email, planType, amount: plan.amount, ip });

    return ok(res, {
      message: 'Payment intent created. Follow the instructions below to complete payment.',
      intent: {
        intent_id:   intentId,
        email,
        plan_type:   planType,
        plan_label:  plan.label,
        amount:      plan.amount,
        currency:    plan.currency,
        period:      plan.period,
        description: plan.description,
        status:      'pending_payment',
        created_at:  createdAt,
        expires_in:  '24 hours',
      },
      payment_instructions: {
        upi:  PAYMENT_INSTRUCTIONS.upi,
        bank: PAYMENT_INSTRUCTIONS.bank,
        important: [
          `Transfer exactly ₹${plan.amount} (${plan.currency})`,
          `Include intent ID "${intentId}" in payment remarks/notes`,
          `Complete payment within 24 hours`,
          `After payment, submit your UTR/transaction ID via POST /api/v1/billing/submit-payment`,
        ],
      },
      next_step: {
        endpoint: 'POST /api/v1/billing/submit-payment',
        payload:  {
          email,
          intent_id:      intentId,
          transaction_id: '<your UTR / transaction reference>',
          payment_method: 'UPI or BANK',
        },
      },
      support: 'bivash@cyberdudebivash.com',
    }, 201);

  } catch (e) {
    return fail(res, 500, 'INTENT_CREATE_FAILED',
      `Failed to create payment intent: ${e.message}. Please retry or contact bivash@cyberdudebivash.com`);
  }
};
