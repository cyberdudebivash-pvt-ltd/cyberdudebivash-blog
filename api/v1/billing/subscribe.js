/**
 * POST /api/v1/billing/subscribe
 * Creates a Stripe Checkout session for plan upgrade.
 * Body: { plan: 'pro'|'enterprise' }
 * Returns: { checkout_url }
 */
'use strict';
const { authenticate, apiError, respond, corsHeaders } = require('../../_lib/middleware');
const stripe = require('../../_lib/stripe');

module.exports = async (req, res) => {
  Object.entries(corsHeaders()).forEach(([k, v]) => res.setHeader(k, v));
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const user = await authenticate(req, res);
  if (!user) return;

  let body = {};
  try {
    if (typeof req.body === 'object') body = req.body;
    else body = JSON.parse(req.body);
  } catch (_) {}

  const plan = String(body.plan || 'pro').toLowerCase();
  if (!['pro', 'enterprise'].includes(plan)) {
    return apiError(res, 400, 'INVALID_PLAN', "Plan must be 'pro' or 'enterprise'");
  }
  if (user.tier === plan || (user.tier === 'enterprise')) {
    return apiError(res, 400, 'ALREADY_ON_PLAN', `You are already on the ${user.tier} plan.`);
  }
  if (!process.env.STRIPE_SECRET_KEY) {
    return apiError(res, 503, 'BILLING_UNAVAILABLE',
      `Billing not yet configured. Contact bivash@cyberdudebivash.com to upgrade to ${plan} (${ plan === 'pro' ? '$49/month' : 'custom pricing' }).`);
  }

  try {
    const base = process.env.NEXT_PUBLIC_BASE_URL || 'https://blog.cyberdudebivash.in';
    const session = await stripe.createCheckoutSession(
      user.email,
      plan,
      `${base}/api-dashboard.html?session_id={CHECKOUT_SESSION_ID}&status=success`,
      `${base}/api-dashboard.html?status=cancelled`
    );

    respond(res, 200, {
      success:      true,
      checkout_url: session.url,
      session_id:   session.id,
      plan,
      price:        plan === 'pro' ? '$49/month (7-day free trial)' : 'Custom pricing',
      meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
    });
  } catch (e) {
    apiError(res, 500, 'CHECKOUT_FAILED', `Checkout session failed: ${e.message}`);
  }
};
