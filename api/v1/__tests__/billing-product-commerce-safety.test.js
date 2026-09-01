'use strict';

jest.mock('../billing-legacy', () => jest.fn(async (_req, res) => res.status(200).json({ legacy: true })));
jest.mock('../../_lib/security', () => ({ applySecurityHeaders: jest.fn() }));

const billing = require('../billing');
const legacy = require('../billing-legacy');

function response() {
  const r = { statusCode: null, body: null, headers: {} };
  r.setHeader = jest.fn((k, v) => { r.headers[k] = v; });
  r.status = jest.fn((code) => { r.statusCode = code; return r; });
  r.json = jest.fn((body) => { r.body = body; return r; });
  return r;
}

describe('one-time digital-product commerce safety gate', () => {
  beforeEach(() => jest.clearAllMocks());

  test.each(['create-product-checkout', 'verify-product-payment'])(
    'fails closed for %s before legacy payment code can accept/process money',
    async (action) => {
      const res = response();
      await billing({ method: 'POST', query: { action }, headers: {} }, res);

      expect(res.statusCode).toBe(503);
      expect(res.body.error.code).toBe('PRODUCT_COMMERCE_REBUILDING');
      expect(res.body.error.message).toMatch(/No payment has been accepted/i);
      expect(legacy).not.toHaveBeenCalled();
    }
  );

  test('does not interfere with subscription/manual billing actions', async () => {
    const res = response();
    await billing({ method: 'GET', query: { action: 'plans' }, headers: {} }, res);

    expect(legacy).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ legacy: true });
  });
});
