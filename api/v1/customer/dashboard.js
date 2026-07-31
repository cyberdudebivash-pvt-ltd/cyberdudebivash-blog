/**
 * SENTINEL APEX — Customer Self-Service Dashboard
 * GET /api/v1/customer/dashboard?email={email}
 *
 * Returns:
 * - Purchase history (all digital products)
 * - Subscription status (API plans)
 * - Download links for purchased products
 * - API key and tier status
 */
'use strict';

const redis = require('../../_lib/redis');
const { normalizeEmail, emailKey, ok, fail, parseBody, now } = require('../../_lib/payment-utils');
const deliveryLib = require('../../_lib/product-delivery');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Powered-By', 'CYBERDUDEBIVASH SENTINEL APEX v4.0');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  }

  const email = normalizeEmail(req.query.email || '');
  if (!email || !/^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,}$/.test(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'Valid email query parameter required.');
  }

  try {
    /* ── Fetch all purchases for this email ───────────────────────── */
    const purchases = await deliveryLib.getPurchaseHistory(email, redis);

    /* ── Fetch subscription tier (if registered) ────────────────────── */
    const safeEmail = emailKey(email);
    const userId = await redis.get(`user:email:${safeEmail}`);
    let subscription = null;
    let apiKey = null;
    if (userId) {
      const userHash = await redis.get(`user:id:${userId}`);
      if (userHash) {
        const userData = await redis.hgetall(`user:key:${userHash}`);
        if (userData && userData.length > 0) {
          const obj = {};
          for (let i = 0; i < userData.length; i += 2) obj[userData[i]] = userData[i + 1];
          subscription = {
            tier: obj.tier || 'free',
            rate_limit: obj.rateLimit || 100,
            activated_at: obj.createdAt,
            expires_at: obj.tierExpiresAt || null,
            upgraded_via: obj.upgradedVia || 'signup',
          };
          apiKey = userHash;
        }
      }
    }

    return ok(res, {
      email,
      dashboard: {
        purchases: purchases.map(p => ({
          purchase_id: p.purchaseId,
          product_id: p.productId,
          product_name: p.productName,
          purchased_at: p.purchasedAt,
          download_url: p.downloadUrl,
          expires_in: p.expiresIn,
          status: p.status || 'available',
        })),
        subscription: subscription || {
          tier: 'free',
          message: 'Not registered. Create account or upgrade to API plan.',
        },
        ...(apiKey ? { api_key: apiKey } : {}),
      },
      next_steps: [
        'Use download_url to retrieve purchased products (valid for ' + (purchases.length > 0 ? purchases[0].expiresIn : 'permanent') + ')',
        subscription ? `Your API tier: ${subscription.tier}` : 'Register to activate API subscription',
        'API docs: https://intel.cyberdudebivash.com/api/docs',
      ],
    });

  } catch (e) {
    return fail(res, 500, 'DASHBOARD_ERROR', 'Failed to load dashboard. Please retry.');
  }
};
