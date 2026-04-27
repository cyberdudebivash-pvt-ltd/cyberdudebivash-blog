/**
 * POST /api/v1/billing/webhook
 * Stripe webhook handler — upgrades/downgrades user tiers on payment events.
 * CRITICAL: This must be configured in Stripe Dashboard → Webhooks
 * Events handled: checkout.session.completed, customer.subscription.deleted,
 *   customer.subscription.updated, invoice.payment_failed
 */
'use strict';
const redis  = require('../../_lib/redis');
const stripe = require('../../_lib/stripe');
const { planToTier } = stripe;

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST required' });
  }

  const sig = req.headers['stripe-signature'];
  if (!sig) return res.status(400).json({ error: 'Missing Stripe-Signature' });

  // Get raw body for signature verification
  let rawBody;
  try {
    rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  } catch (_) {
    return res.status(400).json({ error: 'Cannot read body' });
  }

  // Verify signature
  if (!stripe.verifyWebhook(rawBody, sig)) {
    console.error('[WEBHOOK] Invalid Stripe signature');
    return res.status(400).json({ error: 'Invalid signature' });
  }

  let event;
  try {
    event = typeof req.body === 'object' ? req.body : JSON.parse(rawBody);
  } catch (_) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log(`[WEBHOOK] Event: ${event.type}`);

  try {
    switch (event.type) {

      // Checkout completed → upgrade user tier
      case 'checkout.session.completed': {
        const session = event.data.object;
        const email   = session.customer_email || session.customer_details?.email;
        const plan    = session.metadata?.plan || 'pro';
        const tier    = planToTier(plan);
        if (email) await upgradeTier(email, tier, session.subscription || session.id);
        break;
      }

      // Subscription active → ensure correct tier
      case 'customer.subscription.updated': {
        const sub  = event.data.object;
        const cust = await getCustomerEmail(sub.customer);
        if (cust) {
          const tier = sub.status === 'active' ? planToTier(sub.metadata?.plan || sub.items?.data?.[0]?.price?.nickname || 'pro') : 'free';
          await upgradeTier(cust, tier, sub.id);
        }
        break;
      }

      // Subscription cancelled → downgrade to free
      case 'customer.subscription.deleted': {
        const sub  = event.data.object;
        const cust = await getCustomerEmail(sub.customer);
        if (cust) await downgradeTier(cust, sub.id);
        break;
      }

      // Payment failed → warn, don't immediately downgrade (grace period)
      case 'invoice.payment_failed': {
        const inv  = event.data.object;
        const cust = await getCustomerEmail(inv.customer);
        if (cust) {
          const emailKey = `user:email:${cust.replace('@','_at_')}`;
          const userId   = await redis.get(emailKey);
          if (userId) {
            const hash    = await redis.get(`user:id:${userId}`);
            if (hash) await redis.hset(`user:key:${hash}`, 'paymentWarning', new Date().toISOString());
          }
        }
        break;
      }

      default:
        console.log(`[WEBHOOK] Unhandled event type: ${event.type}`);
    }

    res.status(200).json({ received: true, type: event.type });
  } catch (e) {
    console.error(`[WEBHOOK] Handler error: ${e.message}`);
    res.status(500).json({ error: `Webhook handler failed: ${e.message}` });
  }
};

// Upgrade user tier in Redis
async function upgradeTier(email, newTier, subscriptionId) {
  const emailKey = `user:email:${email.replace('@','_at_')}`;
  const userId   = await redis.get(emailKey);
  if (!userId) {
    console.warn(`[WEBHOOK] No user found for email: ${email}`);
    return;
  }
  const hash = await redis.get(`user:id:${userId}`);
  if (!hash) return;

  await redis.hmset(`user:key:${hash}`, {
    tier:           newTier,
    subscriptionId: subscriptionId || '',
    upgradedAt:     new Date().toISOString(),
    paymentWarning: '',
  });
  console.log(`[WEBHOOK] Upgraded ${email} → ${newTier}`);
}

// Downgrade user to free tier
async function downgradeTier(email, subscriptionId) {
  const emailKey = `user:email:${email.replace('@','_at_')}`;
  const userId   = await redis.get(emailKey);
  if (!userId) return;
  const hash = await redis.get(`user:id:${userId}`);
  if (!hash) return;

  await redis.hmset(`user:key:${hash}`, {
    tier:           'free',
    subscriptionId: '',
    downgradedAt:   new Date().toISOString(),
    cancelledSub:   subscriptionId || '',
  });
  console.log(`[WEBHOOK] Downgraded ${email} → free`);
}

// Retrieve customer email from Stripe (needed to map to local user)
async function getCustomerEmail(customerId) {
  try {
    const res = await fetch(`https://api.stripe.com/v1/customers/${customerId}`, {
      headers: { Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}` },
    });
    const data = await res.json();
    return data.email || null;
  } catch (_) { return null; }
}
