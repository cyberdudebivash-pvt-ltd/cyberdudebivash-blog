'use strict';

// action=subscribe used to hard-require an existing API key (authenticate())
// before it would even create a Stripe Checkout session -- meaning a brand
// new, never-registered buyer had no way to pay by card at all, regardless
// of whether Stripe was configured. This is the one Stripe-specific gap
// left after the audit: Razorpay already supports a first-time buyer via
// create-razorpay-order (email + plan, no account needed yet); this fix
// brings the Stripe path to parity without changing the existing
// authenticated-upgrade behavior at all.
process.env.STRIPE_SECRET_KEY = 'sk_test_dummy_for_unit_tests';

jest.mock('../../_lib/redis', () => ({}));
jest.mock('../../_lib/middleware', () => ({
  authenticate:   jest.fn(),
  extractApiKey:  jest.fn(),
  apiError:       jest.fn(),
  respond:        jest.fn(),
  corsHeaders:    jest.fn(),
}));
jest.mock('../../_lib/stripe', () => ({
  createCheckoutSession: jest.fn(async () => ({ id: 'cs_test_123', url: 'https://checkout.stripe.com/cs_test_123' })),
}));
jest.mock('../../_lib/razorpay', () => ({ configured: () => true }));
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return {
    ...actual,
    guardRequest:       jest.fn(async () => true),
    globalIpRateLimit:  jest.fn(async () => true),
    intentIpRateLimit:  jest.fn(async () => true),
  };
});

const { authenticate, extractApiKey } = require('../../_lib/middleware');
const stripe = require('../../_lib/stripe');
const handler = require('../billing-legacy');

function mockReq(body, headers = {}) {
  return { method: 'POST', query: { action: 'subscribe' }, body, headers, url: '/api/v1/billing' };
}

function mockRes() {
  const res = { headers: {}, statusCode: null, body: null };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('action=subscribe — existing authenticated behavior is preserved', () => {
  test('an API key is used to authenticate, and the account email is used for checkout, not any client-supplied one', async () => {
    extractApiKey.mockReturnValue('sentinel_realkey');
    authenticate.mockResolvedValue({ tier: 'free', email: 'realaccount@example.com' });

    const res = mockRes();
    await handler(mockReq({ plan: 'pro', email: 'attacker-supplied@example.com' }, { authorization: 'Bearer sentinel_realkey' }), res);

    expect(authenticate).toHaveBeenCalledTimes(1);
    expect(stripe.createCheckoutSession).toHaveBeenCalledWith(
      'realaccount@example.com', 'pro', expect.any(String), expect.any(String)
    );
    expect(res.statusCode).toBe(200);
  });

  test('an authenticated account already on the requested (or a higher) plan is rejected before any checkout session is created', async () => {
    extractApiKey.mockReturnValue('sentinel_realkey');
    authenticate.mockResolvedValue({ tier: 'enterprise', email: 'realaccount@example.com' });

    const res = mockRes();
    await handler(mockReq({ plan: 'pro' }, { authorization: 'Bearer sentinel_realkey' }), res);

    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('ALREADY_ON_PLAN');
  });

  test('an invalid API key still fails closed exactly as before (authenticate() owns the response)', async () => {
    extractApiKey.mockReturnValue('sentinel_bad');
    authenticate.mockImplementation(async (req, res2) => {
      res2.status(401).json({ success: false, error: { code: 'UNAUTHORIZED' } });
      return null;
    });

    const res = mockRes();
    await handler(mockReq({ plan: 'pro' }, { authorization: 'Bearer sentinel_bad' }), res);

    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });
});

describe('action=subscribe — new first-time-buyer path (no API key yet)', () => {
  test('a request with no API key can still create a Stripe Checkout session using a validated request-body email', async () => {
    extractApiKey.mockReturnValue(null);

    const res = mockRes();
    await handler(mockReq({ plan: 'pro', email: 'newbuyer@example.com' }, {}), res);

    expect(authenticate).not.toHaveBeenCalled();
    expect(stripe.createCheckoutSession).toHaveBeenCalledWith(
      'newbuyer@example.com', 'pro', expect.any(String), expect.any(String)
    );
    expect(res.statusCode).toBe(200);
    expect(res.body.checkout_url).toBe('https://checkout.stripe.com/cs_test_123');
  });

  test('a first-time buyer with a malformed email is rejected before any checkout session is created', async () => {
    extractApiKey.mockReturnValue(null);

    const res = mockRes();
    await handler(mockReq({ plan: 'pro', email: 'not-an-email' }, {}), res);

    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_EMAIL');
  });

  test('a first-time buyer with no email at all is rejected, never silently defaulting to an empty/undefined identity', async () => {
    extractApiKey.mockReturnValue(null);

    const res = mockRes();
    await handler(mockReq({ plan: 'pro' }, {}), res);

    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_EMAIL');
  });

  test('still fails closed with BILLING_UNAVAILABLE when Stripe is not configured, even for a valid first-time buyer', async () => {
    const original = process.env.STRIPE_SECRET_KEY;
    delete process.env.STRIPE_SECRET_KEY;
    extractApiKey.mockReturnValue(null);

    const res = mockRes();
    await handler(mockReq({ plan: 'pro', email: 'newbuyer@example.com' }, {}), res);

    expect(stripe.createCheckoutSession).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(503);
    expect(res.body.error.code).toBe('BILLING_UNAVAILABLE');

    process.env.STRIPE_SECRET_KEY = original;
  });
});
