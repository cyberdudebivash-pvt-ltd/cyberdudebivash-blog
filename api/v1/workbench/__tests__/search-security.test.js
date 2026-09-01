'use strict';

jest.mock('../../../_lib/redis', () => ({
  zrevrange: jest.fn(async () => []),
  smembers: jest.fn(async () => []),
  hgetall: jest.fn(async () => []),
}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn(async () => ({ id: 'analyst-1' })) }));
jest.mock('../../../_lib/intelligence-manager', () => ({ IntelligenceManager: jest.fn(() => ({ getIntelligence: jest.fn() })) }));
jest.mock('../../../_lib/graph-engine', () => ({ GraphEngine: jest.fn(() => ({ getEntity: jest.fn() })) }));

const handler = require('../search');

function mockReq(query = {}) {
  return { method: 'GET', query, headers: {}, url: '/api/v1/workbench/search' };
}

function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(code => { res.statusCode = code; return res; });
  res.json = jest.fn(body => { res.body = body; return res; });
  res.end = jest.fn(() => res);
  return res;
}

describe('Workbench search input bounds', () => {
  test('clamps arbitrarily large limit to 100', async () => {
    const res = mockRes();
    await handler(mockReq({ q: 'threat', limit: '999999999' }), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.limit).toBe(100);
  });

  test('normalizes invalid/negative limits safely', async () => {
    expect(handler._test.parseLimit('not-a-number')).toBe(50);
    expect(handler._test.parseLimit('-10')).toBe(1);
    expect(handler._test.parseLimit('101')).toBe(100);
  });

  test('rejects a query longer than 200 characters', async () => {
    const res = mockRes();
    await handler(mockReq({ q: 'a'.repeat(201) }), res);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('QUERY_TOO_LONG');
  });

  test('rejects unknown search type instead of silently scanning all stores', async () => {
    const res = mockRes();
    await handler(mockReq({ q: 'threat', type: 'everything-forever' }), res);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_TYPE');
  });
});
