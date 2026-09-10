'use strict';

// checkout.session.completed (and subscription.updated) used to call a
// local upgradeTier() that only worked if the buyer had already registered
// an API key: no user record existed yet, so it hit `if (!userId) { warn;
// return; }` and silently dropped the paid upgrade. This is the exact
// case that opens up once action=subscribe accepts first-time buyers
// (billing-subscribe.test.js) -- a completed Stripe payment must not be
// able to vanish. The fix delegates to the shared, pending-tier-aware
// upgradeUserTier() already used by the Razorpay flow.

jest.mock('../../../_lib/redis', () => ({
  hmset: jest.fn(async () => 'OK'),
  expire: jest.fn(async () => 1),
  get: jest.fn(async () => null),
}));
jest.mock('../../../_lib/stripe', () => ({
  verifyWebhook: jest.fn(() => true),
  planToTier: jest.fn((plan) => (plan === 'enterprise' ? 'enterprise' : plan === 'pro' ? 'pro' : 'starter')),
}));
jest.mock('../../../_lib/security', () => ({
  readRawBody: jest.fn(async () => JSON.stringify(global.__WEBHOOK_TEST_EVENT__)),
}));
jest.mock('../../../_lib/payment-utils', () => ({
  now: () => '2026-01-01T00:00:00.000Z',
  auditLog: jest.fn(async () => {}),
  upgradeUserTier: jest.fn(),
}));

const { upgradeUserTier, auditLog } = require('../../../_lib/payment-utils');
const handler = require('../webhook');

function mockReq(event) {
  global.__WEBHOOK_TEST_EVENT__ = event;
  return { method: 'POST', headers: { 'stripe-signature': 't=1,v1=deadbeef' }, body: event };
}

function mockRes() {
  const res = { statusCode: null, body: null };
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  return res;
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('checkout.session.completed', () => {
  test('a subscription payment for a not-yet-registered email stores a pending tier instead of silently dropping the payment', async () => {
    upgradeUserTier.mockResolvedValue({ upgraded: false, pending: true, reason: 'USER_NOT_REGISTERED' });

    const event = {
      type: 'checkout.session.completed',
      data: { object: {
        id: 'cs_test_1', mode: 'subscription', customer_email: 'newbuyer@example.com',
        metadata: { plan: 'pro' }, subscription: 'sub_abc',
      } },
    };

    const res = mockRes();
    await handler(mockReq(event), res);

    expect(upgradeUserTier).toHaveBeenCalledWith('newbuyer@example.com', 'pro', { transactionId: 'sub_abc' });
    expect(res.statusCode).toBe(200);
  });

  test('a subscription payment for an already-registered email upgrades their tier immediately', async () => {
    upgradeUserTier.mockResolvedValue({ upgraded: true, pending: false });

    const event = {
      type: 'checkout.session.completed',
      data: { object: {
        id: 'cs_test_2', mode: 'subscription', customer_email: 'existing@example.com',
        metadata: { plan: 'enterprise' }, subscription: 'sub_def',
      } },
    };

    const res = mockRes();
    await handler(mockReq(event), res);

    expect(upgradeUserTier).toHaveBeenCalledWith('existing@example.com', 'enterprise', { transactionId: 'sub_def' });
    expect(res.statusCode).toBe(200);
  });

  test('a one-time digital-product purchase (not a subscription) never calls upgradeUserTier at all', async () => {
    const event = {
      type: 'checkout.session.completed',
      data: { object: {
        id: 'cs_test_3', mode: 'payment', customer_email: 'buyer@example.com',
        metadata: { kind: 'digital_product', product_id: 'ioc-megapack' }, amount_total: 4900,
      } },
    };

    const res = mockRes();
    await handler(mockReq(event), res);

    expect(upgradeUserTier).not.toHaveBeenCalled();
    expect(auditLog).toHaveBeenCalledWith('PRODUCT_PURCHASE_COMPLETED', expect.objectContaining({ productId: 'ioc-megapack' }));
    expect(res.statusCode).toBe(200);
  });
});
