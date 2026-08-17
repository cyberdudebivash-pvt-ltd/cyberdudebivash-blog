/**
 * SENTINEL APEX — Stripe REST Client (zero npm dependencies)
 * Uses Stripe REST API directly via fetch.
 * Required env vars: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
 * Price IDs: STRIPE_PRICE_PRO, STRIPE_PRICE_ENTERPRISE (custom).
 * STRIPE_PRICE_PRO must point at a Stripe Price object matching the
 * canonical amount in api/_lib/payment-utils.js (PLANS.pro — currently
 * ₹1,499/mo, ≈$18) — verify this in the Stripe dashboard directly; a code
 * change here cannot confirm what the live env var actually points at.
 * See docs/PRICING.md.
 */
'use strict';
const crypto = require('crypto');

const STRIPE_KEY       = process.env.STRIPE_SECRET_KEY       || '';
const WEBHOOK_SECRET   = process.env.STRIPE_WEBHOOK_SECRET   || '';
const PRICE_STARTER    = process.env.STRIPE_PRICE_STARTER    || '';
const PRICE_PRO        = process.env.STRIPE_PRICE_PRO        || '';
const PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE || '';

const PRICE_BY_PLAN = { starter: PRICE_STARTER, pro: PRICE_PRO, enterprise: PRICE_ENTERPRISE };

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
  if (typeof signature !== 'string') return false;
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
  try {
    // crypto.timingSafeEqual throws (rather than returning false) when the
    // two buffers differ in byte length -- and `sig` is attacker-supplied
    // from the request header, so any signature whose hex doesn't decode
    // to exactly 32 bytes (expected's fixed SHA-256 digest length) throws
    // here, uncaught, for anyone who sends one -- no valid secret needed.
    // Mirrors razorpay.js#verifyWebhookSignature's existing guard around
    // the identical call; this function was simply missing it.
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
  } catch (_) {
    return false;
  }
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
  const priceId = PRICE_BY_PLAN[plan];
  if (!priceId) throw new Error(`Price ID for plan '${plan}' not configured`);
  return stripeRequest('POST', '/checkout/sessions', {
    mode:                        'subscription',
    customer_email:              email,
    'line_items[0][price]':      priceId,
    'line_items[0][quantity]':   '1',
    success_url:                 successUrl,
    cancel_url:                  cancelUrl,
    'subscription_data[trial_period_days]': (plan === 'pro' || plan === 'starter') ? '7' : '0',
    'metadata[plan]':            plan,
  });
}

// Create a one-time Checkout Session for a digital product (mode=payment).
// Uses inline price_data — no pre-created Stripe Price object required,
// since the product catalog (api/_lib/products-catalog.js) is the source
// of truth for name/amount rather than the Stripe dashboard.
async function createProductCheckoutSession(email, productId, product, successUrl, cancelUrl) {
  return stripeRequest('POST', '/checkout/sessions', {
    mode:                                       'payment',
    customer_email:                             email,
    'line_items[0][price_data][currency]':      product.currency,
    'line_items[0][price_data][unit_amount]':   String(product.amount),
    'line_items[0][price_data][product_data][name]': product.name,
    'line_items[0][quantity]':                  '1',
    success_url:                                successUrl,
    cancel_url:                                 cancelUrl,
    'metadata[product_id]':                     productId,
    'metadata[kind]':                            'digital_product',
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
  if (p.includes('starter'))    return 'starter';
  return 'free';
}

module.exports = {
  verifyWebhook,
  getOrCreateCustomer,
  createSubscription,
  createCheckoutSession,
  createProductCheckoutSession,
  cancelSubscription,
  getCustomerSubscriptions,
  planToTier,
  PRICE_STARTER,
  PRICE_PRO,
  PRICE_ENTERPRISE,
};
