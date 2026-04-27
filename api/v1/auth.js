/**
 * SENTINEL APEX — Consolidated Auth Router
 * Single serverless function handling ALL authentication endpoints.
 *
 * Routing: /api/v1/auth?action={action}
 *
 *  action=register   POST  Create account + generate API key
 *  action=me         GET   Authenticated user profile + tier info
 *  action=usage      GET   Per-key daily usage breakdown (last N days)
 *
 * Backward-compat: vercel.json rewrites old /api/v1/auth/* and
 *   /api/v1/keys/usage paths to this handler.
 */
'use strict';
const crypto  = require('crypto');
const redis   = require('../_lib/redis');
const {
  authenticate, respond, apiError, successResponse, corsHeaders,
  generateApiKey, hashKey, RATE_LIMITS,
} = require('../_lib/middleware');

/* ─── Helpers ─────────────────────────────────────────────────── */
function setCors(res) {
  Object.entries(corsHeaders()).forEach(([k, v]) => res.setHeader(k, v));
}

function today() { return new Date().toISOString().slice(0,10).replace(/-/g,''); }

function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0,10).replace(/-/g,'');
}

/* ─── Main Router ─────────────────────────────────────────────── */
module.exports = async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = String(req.query.action || '').toLowerCase().trim();

  if (!action) {
    return apiError(res, 400, 'MISSING_ACTION',
      'action parameter required. Valid: register, me, usage. ' +
      'Example: POST /api/v1/auth?action=register');
  }

  /* ─── Route Dispatcher ──────────────────────────────────────── */
  switch (action) {

    case 'register': return handleRegister(req, res);
    case 'me':       return handleMe(req, res);
    case 'usage':    return handleUsage(req, res);

    default:
      return apiError(res, 400, 'INVALID_ACTION',
        `Unknown action: "${action}". Valid: register, me, usage`);
  }
};

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/auth?action=register
   Create account, generate API key, store in Redis.
   Body: { email, name?, plan? }
═══════════════════════════════════════════════════════════════ */
async function handleRegister(req, res) {
  if (req.method !== 'POST') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'POST required for action=register');
  }

  /* ── Parse Body ─────────────────────────────────────────── */
  let body = {};
  try {
    if (typeof req.body === 'object' && req.body !== null) body = req.body;
    else if (typeof req.body === 'string') body = JSON.parse(req.body);
  } catch (_) {
    return apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON: { email, name?, plan? }');
  }

  const email = String(body.email || '').trim().toLowerCase();
  const plan  = String(body.plan  || 'free').trim().toLowerCase();
  const name  = String(body.name  || '').trim().slice(0, 100)
    .replace(/<[^>]*>/g, '').replace(/[<>"'`]/g, ''); // sanitize

  /* ── Validate ───────────────────────────────────────────── */
  if (!email || !/^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,}$/.test(email)) {
    return apiError(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  if (!['free', 'pro', 'enterprise'].includes(plan)) {
    return apiError(res, 400, 'INVALID_PLAN', 'plan must be: free, pro, or enterprise');
  }
  if (plan !== 'free') {
    return apiError(res, 402, 'PAYMENT_REQUIRED',
      `Plan "${plan}" requires payment. Complete checkout at https://blog.cyberdudebivash.in/api-dashboard.html`);
  }

  try {
    /* ── Duplicate check ────────────────────────────────── */
    const safeEmail = email.replace(/[^a-z0-9_.-]/g, '_');
    const emailKey  = `user:email:${safeEmail}`;
    const existing  = await redis.get(emailKey);

    if (existing) {
      return respond(res, 200, {
        success: false,
        error: { code: 'EMAIL_EXISTS', message: 'Email already registered. Visit /api-dashboard.html to retrieve your key details.' },
        meta:  { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      });
    }

    /* ── Check for pre-approved tier (paid before registering) */
    let activeTier      = 'free';
    let tierActivatedBy = null;
    try {
      const pendingRaw = await redis.get(`user:pending:tier:${safeEmail}`);
      if (pendingRaw) {
        const pending = JSON.parse(pendingRaw);
        if (pending && pending.tier && ['pro', 'enterprise'].includes(pending.tier)) {
          activeTier      = pending.tier;
          tierActivatedBy = pending.transactionId || 'manual_payment';
          await redis.del(`user:pending:tier:${safeEmail}`).catch(() => {});
        }
      }
    } catch (_) { /* best-effort */ }

    /* ── Create user ────────────────────────────────────── */
    const userId = 'usr_' + crypto.randomBytes(12).toString('hex');
    const apiKey = generateApiKey();
    const hash   = hashKey(apiKey);
    const now    = new Date().toISOString();

    await redis.hmset(`user:key:${hash}`, {
      userId,
      email,
      name,
      tier:          activeTier,
      createdAt:     now,
      lastSeen:      now,
      totalRequests: '0',
      keyHash:       hash.slice(0, 16),
      ...(tierActivatedBy ? {
        upgradedAt:     now,
        upgradedVia:    'manual_payment',
        subscriptionId: tierActivatedBy,
      } : {}),
    });

    await redis.set(emailKey,                `${userId}`);
    await redis.set(`user:id:${userId}`,     hash);
    await redis.incr('analytics:registrations:total').catch(() => {});
    await redis.incr(`analytics:registrations:${now.slice(0,10)}`).catch(() => {});

    const RATE_MAP = { free: 100, pro: 5000, enterprise: 999999 };

    return respond(res, 201, {
      success: true,
      message: activeTier !== 'free'
        ? `API key generated. Pre-approved ${activeTier.toUpperCase()} tier activated automatically.`
        : 'API key generated successfully. Store this key securely — it will not be shown again.',
      user: {
        user_id:    userId,
        email,
        tier:       activeTier,
        created_at: now,
        ...(tierActivatedBy ? { tier_activated_by: 'manual_payment' } : {}),
      },
      api_key:       apiKey,
      rate_limit:    { requests_per_day: RATE_MAP[activeTier] || 100, tier: activeTier },
      usage:         { endpoint: `Authorization: Bearer ${apiKey}` },
      upgrade_url:   'https://blog.cyberdudebivash.in/pricing.html',
      dashboard_url: 'https://blog.cyberdudebivash.in/api-dashboard.html',
      docs_url:      'https://blog.cyberdudebivash.in/api.html',
      meta: {
        platform:  'CYBERDUDEBIVASH SENTINEL APEX v4.0',
        timestamp: now,
        warning:   'This API key is shown only once. Store it in a secure vault.',
      },
    });

  } catch (e) {
    return apiError(res, 500, 'REGISTRATION_FAILED',
      `Registration failed: ${e.message}. Please retry or contact bivash@cyberdudebivash.com`);
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/auth?action=me
   Authenticated user profile, tier, usage stats.
═══════════════════════════════════════════════════════════════ */
async function handleMe(req, res) {
  if (req.method !== 'GET') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required for action=me');
  }

  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const raw     = await redis.hgetall(`user:key:${user.keyHash}`);
    const userObj = {};
    if (Array.isArray(raw)) {
      for (let i = 0; i < raw.length; i += 2) userObj[raw[i]] = raw[i + 1];
    }

    const rateKey   = `ratelimit:${user.keyHash}:${today()}`;
    const usedToday = parseInt(await redis.get(rateKey) || '0', 10);
    const limit     = RATE_LIMITS[user.tier] || 100;

    return successResponse(res, {
      user: {
        user_id:         userObj.userId       || user.userId,
        email:           userObj.email        || user.email,
        name:            userObj.name         || '',
        tier:            userObj.tier         || user.tier,
        created_at:      userObj.createdAt    || null,
        last_seen:       userObj.lastSeen     || null,
        total_requests:  parseInt(userObj.totalRequests || '0', 10),
      },
      usage: {
        today:        usedToday,
        daily_limit:  limit,
        remaining:    Math.max(0, limit - usedToday),
        reset_at:     new Date(new Date().setUTCHours(24,0,0,0)).toISOString(),
        percent_used: Math.round((usedToday / limit) * 100),
      },
      tier_features: {
        free:       { intel_items: 10, ioc_access: false, detection_rules: false, description_full: false, rate_limit: 100 },
        pro:        { intel_items: 50, ioc_access: true,  detection_rules: true,  description_full: true,  rate_limit: 5000 },
        enterprise: { intel_items: 'unlimited', ioc_access: true, detection_rules: true, description_full: true, rate_limit: 'unlimited', stix_export: true, bulk_export: true },
      }[user.tier] || {},
      upgrade_url: user.tier !== 'enterprise' ? 'https://blog.cyberdudebivash.in/pricing.html' : null,
    }, {
      endpoint: '/api/v1/auth?action=me',
    });

  } catch (e) {
    return apiError(res, 500, 'PROFILE_ERROR', e.message);
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/auth?action=usage&days=7
   Per-key daily usage breakdown for the last N days.
═══════════════════════════════════════════════════════════════ */
async function handleUsage(req, res) {
  if (req.method !== 'GET') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required for action=usage');
  }

  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const days  = Math.min(30, Math.max(1, parseInt(req.query.days || '7', 10)));
    const limit = RATE_LIMITS[user.tier] || 100;

    const dateKeys    = Array.from({ length: days }, (_, i) => `ratelimit:${user.keyHash}:${daysAgo(i)}`);
    const usageCounts = await redis.pipeline(dateKeys.map(k => ['GET', k]));

    const dailyUsage = dateKeys.map((k, i) => ({
      date:     daysAgo(i).replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'),
      requests: parseInt(usageCounts[i] || '0', 10),
      limit,
      percent:  Math.round((parseInt(usageCounts[i] || '0', 10) / limit) * 100),
    })).reverse();

    const totalThisPeriod = dailyUsage.reduce((s, d) => s + d.requests, 0);
    const avgPerDay       = Math.round(totalThisPeriod / days);
    const peakDay         = dailyUsage.reduce((best, d) => d.requests > best.requests ? d : best, dailyUsage[0]);

    return successResponse(res, {
      usage_summary: {
        period_days:    days,
        total_requests: totalThisPeriod,
        avg_per_day:    avgPerDay,
        peak_day:       peakDay,
        daily_limit:    limit,
        tier:           user.tier,
      },
      daily_breakdown: dailyUsage,
      projection: {
        monthly_estimate:     avgPerDay * 30,
        monthly_limit:        limit * 30,
        near_limit:           avgPerDay > limit * 0.7,
        upgrade_recommended:  avgPerDay > limit * 0.7 && user.tier !== 'enterprise',
      },
      upgrade_url: user.tier !== 'enterprise' ? 'https://blog.cyberdudebivash.in/pricing.html' : null,
    }, {
      endpoint: '/api/v1/auth?action=usage',
    });

  } catch (e) {
    return apiError(res, 500, 'USAGE_ERROR', e.message);
  }
}
