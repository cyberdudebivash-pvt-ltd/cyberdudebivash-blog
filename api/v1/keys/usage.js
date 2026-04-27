/**
 * GET /api/v1/keys/usage
 * Per-key usage stats + analytics for the last 7 days.
 */
'use strict';
const redis = require('../../_lib/redis');
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');

function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0,10).replace(/-/g,'');
}

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const days = Math.min(30, parseInt(req.query.days || '7', 10));
    const LIMITS = { free: 100, pro: 5000, enterprise: 999999 };
    const limit = LIMITS[user.tier] || 100;

    // Fetch last N days of usage
    const dateKeys = Array.from({ length: days }, (_, i) => `ratelimit:${user.keyHash}:${daysAgo(i)}`);
    const usageCounts = await redis.pipeline(dateKeys.map(k => ['GET', k]));

    const dailyUsage = dateKeys.map((k, i) => ({
      date:     daysAgo(i).replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'),
      requests: parseInt(usageCounts[i] || '0', 10),
      limit,
      percent:  Math.round(((parseInt(usageCounts[i] || '0', 10)) / limit) * 100),
    })).reverse();

    const totalThisPeriod = dailyUsage.reduce((s, d) => s + d.requests, 0);
    const avgPerDay = Math.round(totalThisPeriod / days);
    const peakDay = dailyUsage.reduce((best, d) => d.requests > best.requests ? d : best, dailyUsage[0]);

    successResponse(res, {
      usage_summary: {
        period_days:      days,
        total_requests:   totalThisPeriod,
        avg_per_day:      avgPerDay,
        peak_day:         peakDay,
        daily_limit:      limit,
        tier:             user.tier,
      },
      daily_breakdown: dailyUsage,
      projection: {
        monthly_estimate: avgPerDay * 30,
        monthly_limit:    limit * 30,
        near_limit:       avgPerDay > limit * 0.7,
        upgrade_recommended: avgPerDay > limit * 0.7 && user.tier !== 'enterprise',
      },
      upgrade_url: user.tier !== 'enterprise' ? 'https://blog.cyberdudebivash.in/pricing.html' : null,
    }, {
      endpoint: '/api/v1/keys/usage',
    });
  } catch (e) {
    apiError(res, 500, 'USAGE_ERROR', e.message);
  }
};
