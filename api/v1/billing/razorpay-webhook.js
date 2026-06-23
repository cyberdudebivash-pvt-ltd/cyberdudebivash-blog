/**
 * POST /api/v1/billing/razorpay-webhook
 * Razorpay webhook handler — backup confirmation path for instant checkout.
 * Covers the case where the browser closes/redirects before the client-side
 * verify-razorpay-payment call completes. Idempotent against the same
 * replay guard used by action=verify-razorpay-payment (payment:rzp:txn:seen:*).
 *
 * CRITICAL: Configure in Razorpay Dashboard → Settings → Webhooks
 *   URL:    https://blog.cyberdudebivash.in/api/v1/billing/razorpay-webhook
 *   Events: payment.captured, order.paid
 */
'use strict';
const redis     = require('../../_lib/redis');
const razorpay  = require('../../_lib/razorpay');
const sec       = require('../../_lib/security');
const {
  PLANS, normalizeEmail, parseHash, now, auditLog, upgradeUserTier,
  SUBMISSION_TTL_SECONDS,
} = require('../../_lib/payment-utils');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST required' });
  }

  const sig = req.headers['x-razorpay-signature'];
  if (!sig) return res.status(400).json({ error: 'Missing X-Razorpay-Signature' });

  // Raw body required for signature verification — see security.js readRawBody
  let rawBody;
  try {
    rawBody = await sec.readRawBody(req);
  } catch (_) {
    return res.status(413).json({ error: 'Payload too large or unreadable' });
  }

  if (!razorpay.verifyWebhookSignature(rawBody, sig)) {
    console.error('[RAZORPAY WEBHOOK] Invalid signature');
    return res.status(400).json({ error: 'Invalid signature' });
  }

  let event;
  try {
    event = typeof req.body === 'object' ? req.body : JSON.parse(rawBody);
  } catch (_) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log(`[RAZORPAY WEBHOOK] Event: ${event.event}`);

  try {
    switch (event.event) {
      case 'payment.captured':
      case 'order.paid': {
        const payment   = event.payload?.payment?.entity || {};
        const orderId   = payment.order_id;
        const paymentId = payment.id;
        if (!orderId || !paymentId) break;

        const dupKey = `payment:rzp:txn:seen:${paymentId}`;
        const dup    = await redis.exists(dupKey).catch(() => 0);
        if (dup && parseInt(dup, 10) > 0) break; // already processed via verify-razorpay-payment

        const order = parseHash(await redis.hgetall(`payment:rzp:order:${orderId}`));
        if (!order || order.status === 'paid') break;

        const email = normalizeEmail(order.email);
        const tier  = (PLANS[order.planType] || {}).tier || order.planType;
        await redis.setex(dupKey, SUBMISSION_TTL_SECONDS, '1');
        await redis.hmset(`payment:rzp:order:${orderId}`, {
          status: 'paid', paymentId, verifiedAt: now(),
        });
        await redis.expire(`payment:rzp:order:${orderId}`, SUBMISSION_TTL_SECONDS);

        await upgradeUserTier(email, tier, {
          transactionId: paymentId,
          gateway:       'razorpay_webhook',
          orderId,
        });

        await auditLog('RAZORPAY_WEBHOOK_PAYMENT_CAPTURED', {
          email, planType: order.planType, orderId, paymentId, amount: order.amount,
        });
        break;
      }
      default:
        console.log(`[RAZORPAY WEBHOOK] Unhandled event: ${event.event}`);
    }

    res.status(200).json({ received: true, event: event.event });
  } catch (e) {
    console.error(`[RAZORPAY WEBHOOK] Handler error: ${e.message}`);
    res.status(500).json({ error: 'Webhook handler failed' });
  }
};

// Disable Vercel's automatic body parsing — we need the exact raw bytes
// Razorpay signed, not a re-serialization of the parsed object.
module.exports.config = { api: { bodyParser: false } };
