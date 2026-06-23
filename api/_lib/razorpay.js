/**
 * SENTINEL APEX — Razorpay REST Client (zero npm dependencies)
 * Uses Razorpay REST API directly via fetch + HTTP Basic Auth.
 * Required env vars: RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET
 * Docs: https://razorpay.com/docs/api/orders/ , https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/build-integration/
 */
'use strict';
const crypto = require('crypto');

const KEY_ID          = process.env.RAZORPAY_KEY_ID          || '';
const KEY_SECRET       = process.env.RAZORPAY_KEY_SECRET      || '';
const WEBHOOK_SECRET   = process.env.RAZORPAY_WEBHOOK_SECRET  || '';

const RAZORPAY_BASE = 'https://api.razorpay.com/v1';

/** True once both API keys are configured (Vercel env). */
function configured() {
  return Boolean(KEY_ID && KEY_SECRET);
}

function authHeader() {
  const token = Buffer.from(`${KEY_ID}:${KEY_SECRET}`).toString('base64');
  return `Basic ${token}`;
}

async function razorpayRequest(method, path, body = null) {
  if (!configured()) throw new Error('Razorpay not configured');
  const opts = {
    method,
    headers: {
      'Authorization': authHeader(),
      'Content-Type':  'application/json',
    },
  };
  if (body && method !== 'GET') opts.body = JSON.stringify(body);
  const res  = await fetch(`${RAZORPAY_BASE}${path}`, opts);
  const json = await res.json();
  if (!res.ok) throw new Error(`Razorpay error: ${json.error?.description || JSON.stringify(json)}`);
  return json;
}

/**
 * Create a Razorpay Order. Amount must already be in the smallest currency
 * unit (paise for INR) — caller is responsible for the rupees→paise conversion.
 */
async function createOrder(amountInPaise, currency, receipt, notes = {}) {
  return razorpayRequest('POST', '/orders', {
    amount:          amountInPaise,
    currency,
    receipt,
    notes,
    payment_capture: 1, // auto-capture — funds settle without a separate capture call
  });
}

/** Fetch a payment by ID — server-side confirmation lookup. */
async function fetchPayment(paymentId) {
  return razorpayRequest('GET', `/payments/${paymentId}`);
}

/**
 * Verify the checkout.js client success-callback signature.
 * HMAC-SHA256("{order_id}|{payment_id}", key_secret) === razorpay_signature
 * A valid signature is cryptographic proof the payment was completed.
 */
function verifyPaymentSignature(orderId, paymentId, signature) {
  if (!KEY_SECRET || !orderId || !paymentId || !signature) return false;
  const expected = crypto
    .createHmac('sha256', KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(String(signature), 'hex'));
  } catch (_) {
    return false; // malformed signature (wrong length/encoding)
  }
}

/**
 * Verify a Razorpay webhook signature.
 * HMAC-SHA256(rawBody, webhook_secret) === X-Razorpay-Signature header
 */
function verifyWebhookSignature(rawBody, signature) {
  if (!WEBHOOK_SECRET || !signature) return false;
  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(String(signature), 'hex'));
  } catch (_) {
    return false;
  }
}

module.exports = {
  configured,
  createOrder,
  fetchPayment,
  verifyPaymentSignature,
  verifyWebhookSignature,
  KEY_ID, // safe to expose client-side — required by checkout.js
};
