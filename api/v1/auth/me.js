/**
 * GET /api/v1/auth/me
 * Returns authenticated user's profile, tier, usage stats.
 */
'use strict';
const redis = require('../../_lib/redis');
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');

function today() { return new Date().toISOString().slice(0,10).replace(/-/g,''); }

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const userData = await redis.hgetall(`user:key:${user.keyHash}`);
    const userObj = {};
    if (Array.isArray(userData)) {
      for (let i = 0; i < userData.length; i += 2) userObj[userData[i]] = userData[i + 1];
    }

    // Today's usage
    const rateKey = `ratelimit:${user.keyHash}:${today()}`;
    const usedToday = parseInt(await redis.get(rateKey) || '0', 10);

    const LIMITS = { free: 100, pro: 5000, enterprise: 999999 };
    const limit = LIMITS[user.tier] || 100;

    successResponse(res, {
      user: {
        user_id:       userObj.userId      || user.userId,
        email:         userObj.email       || user.email,
        name:          userObj.name        || '',
        tier:          userObj.tier        || user.tier,
        created_at:    userObj.createdAt   || null,
        last_seen:     userObj.lastSeen    || null,
        total_requests: parseInt(userObj.totalRequests || '0', 10),
      },
      usage: {
        today:          usedToday,
        daily_limit:    limit,
        remaining:      Math.max(0, limit - usedToday),
        reset_at:       new Date(new Date().setUTCHours(24,0,0,0)).toISOString(),
        percent_used:   Math.round((usedToday / limit) * 100),
      },
      tier_features: {
        free:       { intel_items: 10, ioc_access: false, detection_rules: false, description_full: false, rate_limit: 100 },
        pro:        { intel_items: 50, ioc_access: true,  detection_rules: true,  description_full: true,  rate_limit: 5000 },
        enterprise: { intel_items: 'unlimited', ioc_access: true, detection_rules: true, description_full: true, rate_limit: 'unlimited', stix_export: true, bulk_export: true },
      }[user.tier] || {},
      upgrade_url:   user.tier !== 'enterprise' ? 'https://blog.cyberdudebivash.in/pricing.html' : null,
    }, {
      endpoint: '/api/v1/auth/me',
    });

  } catch (e) {
    apiError(res, 500, 'PROFILE_ERROR', e.message);
  }
};
