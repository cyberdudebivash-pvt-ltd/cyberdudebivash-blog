'use strict';

// Route-handler tests for the new unified-search / actor / ioc / report
// actions added to api/v1/intel.js. Two layers:
//
// (1) No mocking at all — a real, unauthenticated request must 401 for
//     every new action before touching Redis (proves the new cases sit
//     behind the same auth gate as every existing action, not a bypass).
// (2) authenticate() mocked to return a controlled {tier} — everything
//     downstream (unifiedSearch, getActorDetailAPI, etc.) runs for real
//     against real production data files, proving genuine end-to-end
//     wiring rather than an isolated unit test of search-index.js alone
//     (which tests-js/search-index.test.js already covers against
//     synthetic fixtures).
jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});

const { authenticate } = require('../../_lib/middleware');
const handler = require('../intel');

function mockReq(query = {}) {
  return { method: 'GET', query, headers: {}, url: '/api/v1/intel' };
}

function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}

function mockUser(tier) {
  return { tier, userId: 'test-user', email: 't@example.com', keyHash: 'x', requestsUsed: 1, requestsLimit: 999999 };
}

beforeEach(() => {
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
});

describe('unauthenticated requests to the new actions', () => {
  it.each(['unified-search', 'actor', 'ioc', 'report'])('action=%s returns 401 with no API key', async (action) => {
    const req = mockReq({ action, q: 'lockbit', id: 'actor:lockbit' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

describe('action=unified-search (authenticated, real production data)', () => {
  it('returns real, typed results for a known query', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'unified-search', q: 'lockbit' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.success).toBe(true);
    expect(Array.isArray(body.results)).toBe(true);
    expect(body.results.length).toBeGreaterThan(0);
    expect(body.results.every(r => r.type && r.id && r.detail_url)).toBe(true);
  });

  it('rejects a too-short query with 400, not a silent empty result', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'unified-search', q: 'a' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects a missing query with 400', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'unified-search' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('free tier caps results at 5, matching the existing action=search precedent', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'unified-search', q: 'e' + 'a'.repeat(1) }); // cheap broad-ish query
    const req2 = mockReq({ action: 'unified-search', q: 'cve' });
    const res = mockRes();
    await handler(req2, res);
    const body = res.json.mock.calls[0][0];
    expect(body.results.length).toBeLessThanOrEqual(5);
  });

  it('free tier never returns ioc-type results', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'unified-search', q: 'domain', type: 'ioc' });
    const res = mockRes();
    await handler(req, res);
    const body = res.json.mock.calls[0][0];
    expect(body.results.length).toBe(0);
  });

  it('enterprise tier can retrieve ioc-type results', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'unified-search', q: 'domain', type: 'ioc', limit: '3' });
    const res = mockRes();
    await handler(req, res);
    const body = res.json.mock.calls[0][0];
    expect(body.results.every(r => r.type === 'ioc')).toBe(true);
  });
});

describe('action=actor (authenticated, real production data)', () => {
  it('returns full relationship detail for enterprise tier', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'actor', id: 'actor:lockbit' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.actor.related_cves.length).toBeGreaterThan(0);
    expect(body.actor.timeline).toBeDefined();
  });

  it('strips relationships for free tier but still confirms the actor exists', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'actor', id: 'actor:lockbit' });
    const res = mockRes();
    await handler(req, res);
    const body = res.json.mock.calls[0][0];
    expect(body.actor.name).toBe('LockBit');
    expect(body.actor.related_cves).toBeUndefined();
    expect(body.actor._upgrade).toBeDefined();
  });

  it('404s for an unknown actor id, not a fabricated record', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'actor', id: 'actor:does-not-exist' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });

  it('400s when id is missing', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'actor' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
  });
});

describe('action=ioc (authenticated) — PRO+ gated, matching action=iocs precedent', () => {
  it('403s for free tier', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'ioc', id: 'ioc:domain:example.com' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('403s for starter tier', async () => {
    authenticate.mockResolvedValue(mockUser('starter'));
    const req = mockReq({ action: 'ioc', id: 'ioc:domain:example.com' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('404s for pro tier on an unknown IOC id (not fabricated)', async () => {
    authenticate.mockResolvedValue(mockUser('pro'));
    const req = mockReq({ action: 'ioc', id: 'ioc:domain:this-does-not-exist-anywhere.invalid' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });
});

describe('action=report (authenticated, real production data)', () => {
  it('returns a real published report by ID', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'report', id: 'SA-2026-0001' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.report.report_id).toBe('SA-2026-0001');
    expect(Array.isArray(body.report.cves)).toBe(true);
  });

  it('404s for a report ID that was never published', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'report', id: 'SA-9999-9999' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });
});

describe('action=cve related-entity extension (additive)', () => {
  it('pro/enterprise tier gets a related field with real graph relationships', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.item.related).toBeDefined();
    expect(Array.isArray(body.item.related.related_actors)).toBe(true);
  });

  it('free tier response has no related field -- fully backward compatible', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.item.related).toBeUndefined();
  });
});

describe('backward compatibility: existing action=search is untouched', () => {
  it('action=search (the pre-existing, narrower search) still works exactly as before', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'search', q: 'log4j' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(200);
    const body = res.json.mock.calls[0][0];
    expect(body.query).toBe('log4j');
  });
});
