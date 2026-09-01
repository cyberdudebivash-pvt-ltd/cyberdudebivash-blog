'use strict';

jest.mock('../../_lib/security', () => ({
  guardRequest: jest.fn(async () => true),
  globalIpRateLimit: jest.fn(async () => true),
}));

jest.mock('../../_lib/middleware', () => ({
  authenticate: jest.fn(),
  apiError: jest.fn((res, status, code, message) => res.status(status).json({ success: false, error: { code, message } })),
}));

jest.mock('../../_lib/intel', () => ({
  getSearchIndex: jest.fn(() => ({ documents: [] })),
  getIocDetailAPI: jest.fn(),
}));

jest.mock('../../_lib/detection-rules', () => ({
  searchRules: jest.fn(() => []),
  getStats: jest.fn(() => ({ total_rules: 0 })),
  exportRules: jest.fn(() => ''),
  getRule: jest.fn(),
}));

const { authenticate } = require('../../_lib/middleware');
const intel = require('../../_lib/intel');
const detectionRules = require('../../_lib/detection-rules');
const iocSearch = require('../ioc/search');
const iocDetail = require('../ioc/[id]');
const detectionList = require('../detections/rules');
const detectionDetail = require('../detections/rules/[id]');

function req(path, query = {}, method = 'GET') {
  return { method, query, url: path, headers: {}, socket: {} };
}

function res() {
  const r = { statusCode: 200, body: null, headers: {} };
  r.setHeader = jest.fn((k, v) => { r.headers[k] = v; });
  r.status = jest.fn(code => { r.statusCode = code; return r; });
  r.json = jest.fn(body => { r.body = body; return r; });
  r.send = jest.fn(body => { r.body = body; return r; });
  r.end = jest.fn(() => r);
  return r;
}

beforeEach(() => {
  jest.clearAllMocks();
  authenticate.mockResolvedValue({ tier: 'pro', userId: 'u1', keyHash: 'h1' });
  intel.getSearchIndex.mockReturnValue({ documents: [] });
});

function unauthenticated() {
  authenticate.mockImplementation(async (_req, response) => {
    response.status(401).json({ success: false, error: { code: 'UNAUTHORIZED' } });
    return null;
  });
}

describe('legacy IOC compatibility endpoints', () => {
  test('search rejects unauthenticated access before canonical data is read', async () => {
    unauthenticated();
    const response = res();
    await iocSearch(req('/api/v1/ioc/search'), response);
    expect(response.statusCode).toBe(401);
    expect(intel.getSearchIndex).not.toHaveBeenCalled();
  });

  test('search rejects non-IOC paid tiers', async () => {
    authenticate.mockResolvedValue({ tier: 'free', userId: 'u1', keyHash: 'h1' });
    const response = res();
    await iocSearch(req('/api/v1/ioc/search'), response);
    expect(response.statusCode).toBe(403);
    expect(response.body.error.code).toBe('TIER_RESTRICTED');
  });

  test('search reads the canonical graph-derived index and hard-clamps limit', async () => {
    intel.getSearchIndex.mockReturnValue({
      documents: [
        { id: 'ioc:1', type: 'ioc', name: 'evil.example', ioc_type: 'domain', confidence: 'HIGH', detail_url: '/api/v1/intel?action=ioc&id=ioc%3A1' },
        { id: 'CVE-2026-1', type: 'cve', name: 'not-an-ioc' },
      ],
    });
    const response = res();
    await iocSearch(req('/api/v1/ioc/search', { limit: '999999', query: 'evil' }), response);
    expect(response.statusCode).toBe(200);
    expect(response.body.count).toBe(1);
    expect(response.body.pagination.limit).toBe(100);
    expect(response.body.iocs[0].id).toBe('ioc:1');
    expect(response.headers.Deprecation).toBe('true');
  });

  test('detail rejects unauthenticated access', async () => {
    unauthenticated();
    const response = res();
    await iocDetail(req('/api/v1/ioc/ioc:1', { id: 'ioc:1' }), response);
    expect(response.statusCode).toBe(401);
    expect(intel.getIocDetailAPI).not.toHaveBeenCalled();
  });
});

describe('legacy detection compatibility endpoints', () => {
  test('list rejects unauthenticated access before rule-store lookup', async () => {
    unauthenticated();
    const response = res();
    await detectionList(req('/api/v1/detections/rules'), response);
    expect(response.statusCode).toBe(401);
    expect(detectionRules.searchRules).not.toHaveBeenCalled();
  });

  test('list rejects overlong search input', async () => {
    const response = res();
    await detectionList(req('/api/v1/detections/rules', { query: 'x'.repeat(201) }), response);
    expect(response.statusCode).toBe(400);
    expect(response.body.error.code).toBe('QUERY_TOO_LONG');
  });

  test('detail rejects unauthenticated access before rule-store lookup', async () => {
    unauthenticated();
    const response = res();
    await detectionDetail(req('/api/v1/detections/rules/abc', { id: 'abc' }), response);
    expect(response.statusCode).toBe(401);
    expect(detectionRules.getRule).not.toHaveBeenCalled();
  });
});
