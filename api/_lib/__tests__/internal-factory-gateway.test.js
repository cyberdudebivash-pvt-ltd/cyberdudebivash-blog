'use strict';

jest.mock('../security', () => ({
  applySecurityHeaders: jest.fn(),
  guardRequest: jest.fn(async () => true),
}));

const {
  createInternalFactoryGateway,
  injectVerifiedActor,
  MAX_LIMIT,
  MAX_QUERY_LENGTH,
} = require('../internal-factory-gateway');

function response() {
  const r = { statusCode: null, body: null, headers: {} };
  r.setHeader = jest.fn((k, v) => { r.headers[k] = v; });
  r.status = jest.fn((code) => { r.statusCode = code; return r; });
  r.json = jest.fn((body) => { r.body = body; return r; });
  r.end = jest.fn(() => r);
  return r;
}

describe('Intel Factory internal HTTP gateway', () => {
  test('blocks unauthenticated callers before legacy report/product code runs', async () => {
    const legacy = jest.fn();
    const gateway = createInternalFactoryGateway(legacy, {
      guardRequest: async () => true,
      requireAnalyst: async (_req, res, fail) => {
        fail(res, 401, 'UNAUTHORIZED', 'analyst required');
        return null;
      },
    });
    const res = response();

    await gateway({ method: 'POST', query: {}, headers: {}, body: {} }, res);

    expect(res.statusCode).toBe(401);
    expect(legacy).not.toHaveBeenCalled();
  });

  test('overwrites caller-supplied analyst/reviewer/approver/publisher identity', async () => {
    const legacy = jest.fn(async (req) => req.body);
    const gateway = createInternalFactoryGateway(legacy, {
      guardRequest: async () => true,
      requireAnalyst: async () => ({ id: 'analyst-verified', name: 'Verified Analyst', role: 'reviewer' }),
    });
    const req = {
      method: 'PUT', query: {}, headers: {},
      body: { approver: 'spoofed', reviewer: 'spoofed', publisher: 'spoofed', analyst: 'spoofed', role: 'owner' },
    };

    await gateway(req, response());

    expect(req.body.analyst).toBe('analyst-verified');
    expect(req.body.reviewer).toBe('analyst-verified');
    expect(req.body.approver).toBe('analyst-verified');
    expect(req.body.publisher).toBe('analyst-verified');
    expect(req.body.role).toBe('reviewer');
    expect(legacy).toHaveBeenCalledTimes(1);
  });

  test('clamps list limits to a hard maximum', async () => {
    const legacy = jest.fn();
    const gateway = createInternalFactoryGateway(legacy, {
      guardRequest: async () => true,
      requireAnalyst: async () => ({ id: 'a1', role: 'analyst' }),
    });
    const req = { method: 'GET', query: { limit: '999999' }, headers: {} };

    await gateway(req, response());

    expect(req.query.limit).toBe(String(MAX_LIMIT));
    expect(legacy).toHaveBeenCalledTimes(1);
  });

  test('rejects malformed limits rather than forwarding surprising values', async () => {
    const legacy = jest.fn();
    const gateway = createInternalFactoryGateway(legacy, {
      guardRequest: async () => true,
      requireAnalyst: async () => ({ id: 'a1', role: 'analyst' }),
    });
    const res = response();

    await gateway({ method: 'GET', query: { limit: '-1' }, headers: {} }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_LIMIT');
    expect(legacy).not.toHaveBeenCalled();
  });

  test('rejects oversized product-search query text', async () => {
    const legacy = jest.fn();
    const gateway = createInternalFactoryGateway(legacy, {
      guardRequest: async () => true,
      requireAnalyst: async () => ({ id: 'a1', role: 'analyst' }),
    });
    const res = response();

    await gateway({ method: 'GET', query: { q: 'x'.repeat(MAX_QUERY_LENGTH + 1) }, headers: {} }, res);

    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('QUERY_TOO_LONG');
    expect(legacy).not.toHaveBeenCalled();
  });

  test('OPTIONS is handled without analyst authentication', async () => {
    const legacy = jest.fn();
    const requireAnalyst = jest.fn();
    const gateway = createInternalFactoryGateway(legacy, { requireAnalyst, guardRequest: async () => true });
    const res = response();

    await gateway({ method: 'OPTIONS', query: {}, headers: {} }, res);

    expect(res.statusCode).toBe(204);
    expect(requireAnalyst).not.toHaveBeenCalled();
    expect(legacy).not.toHaveBeenCalled();
  });
});

describe('verified actor injection', () => {
  test('preserves business fields while replacing identity fields', () => {
    const req = { body: { reportType: 'incident', reviewer: 'fake' } };
    injectVerifiedActor(req, { id: 'verified', role: 'analyst' });
    expect(req.body.reportType).toBe('incident');
    expect(req.body.reviewer).toBe('verified');
  });
});
