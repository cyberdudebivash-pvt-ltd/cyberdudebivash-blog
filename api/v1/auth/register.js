/**
 * POST /api/v1/auth/register
 * Register user, generate API key, store in Redis.
 * Body: { email, plan? }
 * Returns: { api_key, tier, user_id }
 */
'use strict';
const crypto    = require('crypto');
const redis     = require('../../_lib/redis');
const { generateApiKey, hashKey, respond, apiError, corsHeaders } = require('../../_lib/middleware');

const VALID_PLANS = ['free', 'pro', 'enterprise'];

module.exports = async (req, res) => {
  Object.entries(corsHeaders()).forEach(([k, v]) => res.setHeader(k, v));

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  // Parse body
  let body = {};
  try {
    if (typeof req.body === 'object' && req.body !== null) body = req.body;
    else if (typeof req.body === 'string') body = JSON.parse(req.body);
  } catch (_) {
    return apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON with {email, plan}');
  }

  const email = String(body.email || '').trim().toLowerCase();
  const plan  = String(body.plan || 'free').trim().toLowerCase();
  const name  = String(body.name || '').trim().slice(0, 100);

  // Validate email
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return apiError(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  if (!VALID_PLANS.includes(plan)) {
    return apiError(res, 400, 'INVALID_PLAN', `Plan must be one of: ${VALID_PLANS.join(', ')}`);
  }
  if (plan !== 'free') {
    return apiError(res, 402, 'PAYMENT_REQUIRED',
      `Plan '${plan}' requires payment. Complete checkout at https://blog.cyberdudebivash.in/api-dashboard.html then you will be upgraded automatically.`);
  }

  try {
    // Check if email already registered
    const emailKey = `user:email:${email.replace('@','_at_')}`;
    const existingUserId = await redis.get(emailKey);

    if (existingUserId) {
      // Return existing key info (don't expose the actual key again)
      return respond(res, 200, {
        success: false,
        error:   { code: 'EMAIL_EXISTS', message: 'Email already registered. Visit api-dashboard.html to retrieve your key details.' },
        meta:    { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      });
    }

    // Generate user ID and API key
    const userId = 'usr_' + crypto.randomBytes(12).toString('hex');
    const apiKey = generateApiKey();
    const hash   = hashKey(apiKey);

    // Store user record in Redis
    const now = new Date().toISOString();
    await redis.hmset(`user:key:${hash}`, {
      userId,
      email,
      name,
      tier:           'free',
      createdAt:      now,
      lastSeen:       now,
      totalRequests:  '0',
      keyHash:        hash.slice(0, 16),
    });

    // Email → userId mapping (for lookup)
    await redis.set(emailKey, userId);

    // userId → key hash mapping
    await redis.set(`user:id:${userId}`, hash);

    // Track registration count
    await redis.incr('analytics:registrations:total').catch(() => {});
    await redis.incr(`analytics:registrations:${now.slice(0,10)}`).catch(() => {});

    respond(res, 201, {
      success: true,
      message: 'API key generated successfully. Store this key securely — it will not be shown again.',
      user: {
        user_id:    userId,
        email,
        tier:       'free',
        created_at: now,
      },
      api_key:       apiKey,
      rate_limit:    { requests_per_day: 100, tier: 'free' },
      usage:         { endpoint: 'Authorization: Bearer ' + apiKey },
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
    apiError(res, 500, 'REGISTRATION_FAILED',
      `Registration failed: ${e.message}. Please retry or contact bivash@cyberdudebivash.com`);
  }
};
