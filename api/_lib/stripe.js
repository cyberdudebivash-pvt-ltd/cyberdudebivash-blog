/**
 * SENTINEL APEX — Stripe REST Client (zero npm dependencies)
 * Uses Stripe REST API directly via fetch.
 * Required env vars: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
 * Price IDs: STRIPE_PRICE_PRO (monthly $49), STRIPE_PRICE_ENTERPRISE (custom)
 */
'use strict';
const crypto = require('crypto');

const STRIPE_KEY       = process.env.STRIPE_SECRET_KEY       || '';
const WEBHOOK_SECRET   = process.env.STRIPE_WEBHOOK_SECRET   || '';
const PRICE_PRO        = process.env.STRIPE_PRICE_PRO        || '';
const PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE || '';

const STRIPE_BASE = 'https://api.stripe.com/v1';

function stripeHeaders() {
  return {
    'Authorization': `Bearer ${STRIPE_KEY}`,
    'Content-Type':  'application/x-www-form-urlencoded',
    'Stripe-Version': '2023-10-16',
  };
}

function encodeBody(obj) {
  return Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

async function stripeRequest(method, path, body = null) {
  const opts = { method, headers: stripeHeaders() };
  if (body && method !== 'GET') opts.body = encodeBody(body);
  const res = await fetch(`${STRIPE_BASE}${path}`, opts);
  const json = await res.json();
  if (!res.ok) throw new Error(`Stripe error: ${json.error?.message || JSON.stringify(json)}`);
  return json;
}

// Verify Stripe webhook signature
function verifyWebhook(rawBody, signature) {
  if (!WEBHOOK_SECRET) return false;
  const parts = {};
  signature.split(',').forEach(p => {
    const [k, v] = p.split('=');
    parts[k] = v;
  });
  const timestamp = parts.t;
  const sig       = parts.v1;
  if (!timestamp || !sig) return false;
  const payload = `${timestamp}.${rawBody}`;
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
}

// Create or retrieve Stripe customer
async function getOrCreateCustomer(email, userId) {
  // Search for existing customer
  const search = await stripeRequest('GET', `/customers/search?query=email:"${encodeURIComponent(email)}"&limit=1`);
  if (search.data && search.data.length > 0) return search.data[0];
  return stripeRequest('POST', '/customers', { email, metadata: { userId } });
}

// Create subscription
async function createSubscription(customerId, priceId, trialDays = 0) {
  const body = { customer: customerId, 'items[0][price]': priceId };
  if (trialDays > 0) body.trial_period_days = String(trialDays);
  return stripeRequest('POST', '/subscriptions', body);
}

// Create checkout session (hosted payment page)
async function createCheckoutSession(email, plan, successUrl, cancelUrl) {
  const priceId = plan === 'enterprise' ? PRICE_ENTERPRISE : PRICE_PRO;
  if (!priceId) throw new Error(`Price ID for plan '${plan}' not configured`);
  return stripeRequest('POST', '/checkout/sessions', {
    mode:                        'subscription',
    customer_email:              email,
    'line_items[0][price]':      priceId,
    'line_items[0][quantity]':   '1',
    success_url:                 successUrl,
    cancel_url:                  cancelUrl,
    'subscription_data[trial_period_days]': plan === 'pro' ? '7' : '0',
    'metadata[plan]':            plan,
  });
}

// Cancel subscription
async function cancelSubscription(subscriptionId) {
  return stripeRequest('DELETE', `/subscriptions/${subscriptionId}`);
}

// Retrieve customer's active subscriptions
async function getCustomerSubscriptions(customerId) {
  return stripeRequest('GET', `/subscriptions?customer=${customerId}&status=active&limit=5`);
}

// Map Stripe plan → internal tier
function planToTier(plan) {
  if (!plan) return 'free';
  const p = String(plan).toLowerCase();
  if (p.includes('enterprise')) return 'enterprise';
  if (p.includes('pro'))        return 'pro';
  return 'free';
}

module.exports = {
  verifyWebhook,
  getOrCreateCustomer,
  createSubscription,
  createCheckoutSession,
  cancelSubscription,
  getCustomerSubscriptions,
  planToTier,
  PRICE_PRO,
  PRICE_ENTERPRISE,
};
