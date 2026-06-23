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
const {
  normalizeEmail, parseHash, now, auditLog, upgradeUserTier,
  SUBMISSION_TTL_SECONDS,
} = require('../../_lib/payment-utils');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST required' });
  }

  const sig = req.headers['x-razorpay-signature'];
  if (!sig) return res.status(400).json({ error: 'Missing X-Razorpay-Signature' });

  let rawBody;
  try {
    rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  } catch (_) {
    return res.status(400).json({ error: 'Cannot read body' });
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
        await redis.setex(dupKey, SUBMISSION_TTL_SECONDS, '1');
        await redis.hmset(`payment:rzp:order:${orderId}`, {
          status: 'paid', paymentId, verifiedAt: now(),
        });

        await upgradeUserTier(email, order.planType, {
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
