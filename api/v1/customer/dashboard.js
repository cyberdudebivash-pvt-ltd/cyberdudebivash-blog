/**
 * SENTINEL APEX — Authenticated Customer Self-Service Dashboard
 * GET /api/v1/customer/dashboard
 *
 * Ownership is derived exclusively from the caller's API key. The legacy
 * `?email=` lookup was an IDOR/privacy defect: anyone who knew an email could
 * request that customer's purchase/subscription data and the endpoint even
 * echoed API-key material. This replacement never accepts customer identity in
 * the URL and never returns credentials.
 */
'use strict';

const { authenticate } = require('../../_lib/middleware');
const premiumCommerce = require('../../_lib/premium-commerce-service');
const sec = require('../../_lib/security');

function fail(res, status, code, message) {
  sec.applySecurityHeaders(res);
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json({
    success: false,
    error: { code, message },
    meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
  });
}

module.exports = async (req, res) => {
  const guarded = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'], maxBodyBytes: 0 });
  if (!guarded) return;
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const purchases = await premiumCommerce.listLibrary(user, 100);
    sec.applySecurityHeaders(res);
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({
      success: true,
      data: {
        customer: { user_id: user.userId, email: user.email || '', tier: user.tier || 'free' },
        premium_intelligence: {
          purchases,
          count: purchases.length,
          library_url: '/customer-library.html',
          store_url: '/intelligence-store.html',
        },
      },
      meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
    });
  } catch (_) {
    return fail(res, 503, 'DASHBOARD_UNAVAILABLE', 'Customer dashboard is temporarily unavailable. Please retry.');
  }
};
