/**
 * SENTINEL APEX — Subscription Management (Razorpay Recurring)
 * Handles recurring billing for API plans (monthly/annual).
 * Subscription lifecycle: created → active → (pause) → cancel
 */
'use strict';

const crypto = require('crypto');

/**
 * Create a subscription (recurring order).
 * Razorpay API: POST /subscriptions
 * Requires: razorpay client, plan details, customer email
 */
async function createSubscription(razorpayClient, email, planType, planData, options = {}) {
  if (!razorpayClient.configured()) {
    throw new Error('Razorpay not configured');
  }

  const amountInPaise = planData.amount * 100; // INR rupees → paise
  const period = options.period || 'monthly'; // 'monthly' | 'yearly'
  const totalCount = period === 'yearly' ? 1 : 12; // # of billing cycles

  try {
    const subscriptionData = {
      plan_id: `plan_${planType}_${period}`,
      customer_notify: 1, // Razorpay sends email to customer
      quantity: 1,
      total_count: totalCount,
      start_at: Math.floor(Date.now() / 1000), // immediate start
      notes: {
        email,
        planType,
        tier: planData.tier,
        rateLimit: planData.rateLimit,
      },
    };

    // Razorpay Subscriptions API
    const result = await razorpayClient.razorpayRequest('POST', '/subscriptions', subscriptionData);
    return {
      subscription_id: result.id,
      status: result.status, // 'created', 'active', 'paused', 'cancelled', 'completed', 'halted'
      amount: amountInPaise,
      currency: 'INR',
      period,
      next_billing_at: result.current_start,
      created_at: new Date().toISOString(),
    };
  } catch (e) {
    throw new Error(`Subscription creation failed: ${e.message}`);
  }
}

/**
 * Fetch subscription status from Razorpay.
 */
async function getSubscription(razorpayClient, subscriptionId) {
  if (!razorpayClient.configured()) {
    throw new Error('Razorpay not configured');
  }

  try {
    const result = await razorpayClient.razorpayRequest('GET', `/subscriptions/${subscriptionId}`, null);
    return {
      subscription_id: result.id,
      status: result.status,
      email: result.notes?.email,
      plan_type: result.notes?.planType,
      amount: result.quantity * (result.plan_interval ? 10000 : 0), // TODO: map from plan
      next_billing_at: result.current_end,
      paused_at: result.paused_at,
      ended_at: result.ended_at,
    };
  } catch (e) {
    throw new Error(`Failed to fetch subscription: ${e.message}`);
  }
}

/**
 * Pause a subscription (customer stops paying until resumption).
 */
async function pauseSubscription(razorpayClient, subscriptionId) {
  if (!razorpayClient.configured()) {
    throw new Error('Razorpay not configured');
  }

  try {
    const result = await razorpayClient.razorpayRequest(
      'POST',
      `/subscriptions/${subscriptionId}/pause`,
      { pause_at: 'now' }
    );
    return {
      subscription_id: result.id,
      status: result.status,
      paused_at: result.paused_at,
    };
  } catch (e) {
    throw new Error(`Failed to pause subscription: ${e.message}`);
  }
}

/**
 * Resume a paused subscription.
 */
async function resumeSubscription(razorpayClient, subscriptionId) {
  if (!razorpayClient.configured()) {
    throw new Error('Razorpay not configured');
  }

  try {
    const result = await razorpayClient.razorpayRequest(
      'POST',
      `/subscriptions/${subscriptionId}/resume`,
      { resume_at: 'now' }
    );
    return {
      subscription_id: result.id,
      status: result.status,
      next_billing_at: result.current_end,
    };
  } catch (e) {
    throw new Error(`Failed to resume subscription: ${e.message}`);
  }
}

/**
 * Cancel a subscription (permanent termination).
 */
async function cancelSubscription(razorpayClient, subscriptionId, options = {}) {
  if (!razorpayClient.configured()) {
    throw new Error('Razorpay not configured');
  }

  try {
    const cancelData = {
      // 'now': cancel immediately
      // 'end_of_cycle': cancel at end of current cycle
      cancel_at: options.cancelAt || 'now',
      notes: options.notes,
    };
    const result = await razorpayClient.razorpayRequest(
      'POST',
      `/subscriptions/${subscriptionId}/cancel`,
      cancelData
    );
    return {
      subscription_id: result.id,
      status: result.status,
      ended_at: result.ended_at,
      cancelled_at: new Date().toISOString(),
    };
  } catch (e) {
    throw new Error(`Failed to cancel subscription: ${e.message}`);
  }
}

/**
 * Store subscription in Redis for fast lookup.
 */
async function storeSubscriptionRecord(redis, email, subscriptionData) {
  const key = `subscription:${subscriptionData.subscription_id}`;
  const userKey = `subscription:user:${email}:${subscriptionData.subscription_id}`;

  try {
    // Main subscription record (90-day TTL)
    await redis.hmset(key, {
      subscriptionId: subscriptionData.subscription_id,
      email,
      planType: subscriptionData.plan_type,
      status: subscriptionData.status,
      amount: String(subscriptionData.amount),
      currency: subscriptionData.currency,
      period: subscriptionData.period,
      createdAt: subscriptionData.created_at,
      nextBillingAt: subscriptionData.next_billing_at || '',
      pausedAt: '',
      cancelledAt: '',
    });
    await redis.expire(key, 7776000); // 90 days

    // User index (same TTL)
    await redis.set(userKey, subscriptionData.subscription_id);
    await redis.expire(userKey, 7776000);

    // Sorted set for enumeration
    await redis.zadd('subscriptions:active', Date.now(), subscriptionData.subscription_id);

    return true;
  } catch (e) {
    console.error(`Failed to store subscription: ${e.message}`);
    return false;
  }
}

/**
 * Retrieve subscription from cache.
 */
async function getSubscriptionRecord(redis, subscriptionId) {
  try {
    const data = await redis.hgetall(`subscription:${subscriptionId}`);
    if (!data || data.length === 0) return null;
    const obj = {};
    for (let i = 0; i < data.length; i += 2) obj[data[i]] = data[i + 1];
    return obj;
  } catch (e) {
    return null;
  }
}

/**
 * List subscriptions for a user.
 */
async function getUserSubscriptions(redis, email) {
  try {
    const allSubs = await redis.keys(`subscription:user:${email}:*`);
    const subs = [];
    for (const key of allSubs) {
      const subId = await redis.get(key);
      if (subId) {
        const data = await getSubscriptionRecord(redis, subId);
        if (data) subs.push(data);
      }
    }
    return subs;
  } catch (e) {
    return [];
  }
}

/**
 * Handle Razorpay subscription webhook events.
 * Expected events:
 *  - subscription.created: initial subscription created
 *  - subscription.activated: first charge succeeded
 *  - subscription.paused: subscription paused
 *  - subscription.resumed: subscription resumed
 *  - subscription.halted: subscription halted (payment failures)
 *  - subscription.cancelled: subscription cancelled
 */
function handleSubscriptionWebhook(event, redis, paymentUtils) {
  const eventType = event.event;
  const subscriptionData = event.payload.subscription.entity;

  switch (eventType) {
    case 'subscription.activated':
      // First payment successful — upgrade user tier
      return handleSubscriptionActivated(subscriptionData, redis, paymentUtils);
    case 'subscription.paused':
      return handleSubscriptionPaused(subscriptionData, redis);
    case 'subscription.halted':
      // Multiple payment failures
      return handleSubscriptionHalted(subscriptionData, redis);
    case 'subscription.cancelled':
      return handleSubscriptionCancelled(subscriptionData, redis);
    default:
      return { handled: false };
  }
}

async function handleSubscriptionActivated(data, redis, paymentUtils) {
  const email = data.notes?.email;
  const planType = data.notes?.planType;
  if (!email || !planType) return { handled: false };

  try {
    const result = await paymentUtils.upgradeUserTier(email, planType, {
      transactionId: data.id,
      gateway: 'razorpay_subscription',
      subscriptionId: data.id,
    });
    return { handled: true, upgraded: result.upgraded };
  } catch (e) {
    console.error(`Subscription activation failed for ${email}: ${e.message}`);
    return { handled: true, error: e.message };
  }
}

async function handleSubscriptionPaused(data, redis) {
  const subId = data.id;
  try {
    await redis.hset(`subscription:${subId}`, 'status', 'paused');
    await redis.hset(`subscription:${subId}`, 'pausedAt', new Date().toISOString());
    return { handled: true, paused: true };
  } catch (e) {
    return { handled: true, error: e.message };
  }
}

async function handleSubscriptionHalted(data, redis) {
  const subId = data.id;
  try {
    await redis.hset(`subscription:${subId}`, 'status', 'halted');
    // In production: send email to user asking to update payment method
    return { handled: true, halted: true };
  } catch (e) {
    return { handled: true, error: e.message };
  }
}

async function handleSubscriptionCancelled(data, redis) {
  const subId = data.id;
  try {
    await redis.hset(`subscription:${subId}`, 'status', 'cancelled');
    await redis.hset(`subscription:${subId}`, 'cancelledAt', new Date().toISOString());
    // In production: downgrade user tier to free
    return { handled: true, cancelled: true };
  } catch (e) {
    return { handled: true, error: e.message };
  }
}

module.exports = {
  createSubscription,
  getSubscription,
  pauseSubscription,
  resumeSubscription,
  cancelSubscription,
  storeSubscriptionRecord,
  getSubscriptionRecord,
  getUserSubscriptions,
  handleSubscriptionWebhook,
};
