'use strict';

// Route-handler tests for intelligence/correlations.js. Two things to prove:
// (1) the routing-gap fix (resolvePathParts/MOUNT_PATH) actually resolves
// real sub-paths to the correct handler -- previously every request here
// 404'd at Vercel's routing layer before this code ever ran, per
// request-path.js's docstring; (2) each handler now returns an explicit,
// honest 501 rather than either crashing (the real CorrelationEngine class
// has no correlateThreatsActors/detectCampaigns/clusterMalwareVariants/
// clusterInfrastructure methods at all) or silently returning a fabricated
// empty result (correlateIOCs(id) exists but is shaped for a whole
// investigation object, not an entity ID, so calling it with a string id
// always returns [] regardless of what's actually in the graph). See
// correlations.js's notImplemented() comment for the full explanation.
jest.mock('../../../_lib/redis', () => ({}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { CorrelationEngine } = require('../../../_lib/correlation-engine');
const handler = require('../correlations');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/intelligence/correlations' };
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
  requireAnalyst.mockReset();
  requireAnalyst.mockResolvedValue(CALLER);
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('unauthenticated requests never reach a handler', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'actor-1/actors' }), res);

  expect(res.statusCode).toBe(401);
});

test('the real CorrelationEngine class has none of the entity-ID methods these routes were written against', () => {
  // Documents the root cause directly against the real class (not a mock),
  // so this test fails loudly the day someone adds these methods -- which
  // is exactly when the 501s below should be revisited.
  const engine = new CorrelationEngine({}, {});
  expect(typeof engine.correlateThreatsActors).not.toBe('function');
  expect(typeof engine.detectCampaigns).not.toBe('function');
  expect(typeof engine.clusterMalwareVariants).not.toBe('function');
  expect(typeof engine.clusterInfrastructure).not.toBe('function');
});

test('GET /{id}/actors routes correctly (routing fix) but returns 501, not a crash', async () => {
  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'actor-1/actors' }), res);

  expect(res.statusCode).toBe(501);
  expect(res.body.error.code).toBe('CORRELATION_NOT_IMPLEMENTED');
});

test('GET /{id}/campaigns routes correctly but returns 501, not a crash', async () => {
  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'actor-1/campaigns' }), res);

  expect(res.statusCode).toBe(501);
  expect(res.body.error.code).toBe('CAMPAIGN_DETECTION_NOT_IMPLEMENTED');
});

test('GET /{id}/malware-variants routes correctly but returns 501, not a crash', async () => {
  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'family-1/malware-variants' }), res);

  expect(res.statusCode).toBe(501);
  expect(res.body.error.code).toBe('MALWARE_CLUSTERING_NOT_IMPLEMENTED');
});

test('GET /{id}/infrastructure routes correctly but returns 501, not a crash', async () => {
  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'infra-1/infrastructure' }), res);

  expect(res.statusCode).toBe(501);
  expect(res.body.error.code).toBe('INFRA_CLUSTERING_NOT_IMPLEMENTED');
});

test('GET /{id}/iocs routes correctly and returns 501 rather than a silently-empty fabricated result', async () => {
  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'ioc-1/iocs' }), res);

  expect(res.statusCode).toBe(501);
  expect(res.body.error.code).toBe('IOC_CORRELATION_NOT_IMPLEMENTED');
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('DELETE'), res);

  expect(res.statusCode).toBe(404);
});

test('an unrecognized action under a valid id still 404s', async () => {
  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'actor-1/unknown-action' }), res);

  expect(res.statusCode).toBe(404);
});
