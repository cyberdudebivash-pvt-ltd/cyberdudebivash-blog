'use strict';

// Route-handler tests for intelligence/publish.js. This file's routes were
// all safe 1-segment ('submit'/'approve'/'publish'/'retract'/'pending'/
// 'published', none gated on `id`) or 2-segment ('status/{id}') shapes even
// before the fix -- the only defect here was the routing gap itself (every
// sub-path 404'd at Vercel before this code could run, per
// request-path.js), which resolvePathParts/MOUNT_PATH now closes. These
// tests prove each route is actually reachable and that every write path
// attributes to the authenticated caller.
jest.mock('../../../_lib/redis', () => ({
  zrange: jest.fn(),
  zrevrange: jest.fn(),
}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const redis = require('../../../_lib/redis');
const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { PublishingPipeline } = require('../../../_lib/publishing-pipeline');
const handler = require('../publish');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/intelligence/publish' };
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
  redis.zrange.mockReset().mockResolvedValue([]);
  redis.zrevrange.mockReset().mockResolvedValue([]);
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('unauthenticated requests never reach a pipeline method', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });
  const spy = jest.spyOn(PublishingPipeline.prototype, 'submitForReview');

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'submit', body: { intelligence_id: 'intel-1' } }), res);

  expect(res.statusCode).toBe(401);
  expect(spy).not.toHaveBeenCalled();
});

test('POST /submit submits for review, attributed to the caller', async () => {
  const spy = jest.spyOn(PublishingPipeline.prototype, 'submitForReview')
    .mockResolvedValue({ id: 'intel-1', status: 'review' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'submit',
    body: { intelligence_id: 'intel-1', reason: 'ready for review' },
  }), res);

  expect(spy).toHaveBeenCalledWith('intel-1', 'analyst-1', 'ready for review');
  expect(res.body.intelligence.id).toBe('intel-1');
});

test('POST /submit rejects a request missing intelligence_id before calling the pipeline', async () => {
  const spy = jest.spyOn(PublishingPipeline.prototype, 'submitForReview');

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'submit', body: {} }), res);

  expect(res.statusCode).toBe(400);
  expect(spy).not.toHaveBeenCalled();
});

test('POST /approve approves for publication, attributed to the caller', async () => {
  const spy = jest.spyOn(PublishingPipeline.prototype, 'approveForPublication')
    .mockResolvedValue({ id: 'intel-1', status: 'approved' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'approve',
    body: { intelligence_id: 'intel-1', reason: 'looks good', feedback: 'nice work' },
  }), res);

  expect(spy).toHaveBeenCalledWith('intel-1', 'analyst-1', 'looks good', 'nice work');
});

test('POST /publish publishes to production, attributed to the caller', async () => {
  const spy = jest.spyOn(PublishingPipeline.prototype, 'publishToProduction')
    .mockResolvedValue({ id: 'intel-1', status: 'published' });

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'publish', body: { intelligence_id: 'intel-1' } }), res);

  expect(spy).toHaveBeenCalledWith('intel-1', 'analyst-1', '');
  expect(res.statusCode).toBe(201);
});

test('POST /retract retracts from production, attributed to the caller', async () => {
  const spy = jest.spyOn(PublishingPipeline.prototype, 'retractFromProduction')
    .mockResolvedValue({ id: 'intel-1', status: 'retracted' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'retract',
    body: { intelligence_id: 'intel-1', reason: 'false positive' },
  }), res);

  expect(spy).toHaveBeenCalledWith('intel-1', 'analyst-1', 'false positive');
});

test('GET /status/{id} resolves the real intelligence ID, not the literal "status"', async () => {
  const spy = jest.spyOn(PublishingPipeline.prototype, 'getPipelineStatus')
    .mockResolvedValue({ id: 'intel-1', status: 'published' });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'status/intel-1' }), res);

  expect(spy).toHaveBeenCalledWith('intel-1');
  expect(res.body.status.id).toBe('intel-1');
});

test('GET /status/{id} 404s when the pipeline has no status for that ID', async () => {
  jest.spyOn(PublishingPipeline.prototype, 'getPipelineStatus').mockResolvedValue(null);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'status/missing-id' }), res);

  expect(res.statusCode).toBe(404);
});

test('GET /pending lists items awaiting review from the review status set', async () => {
  redis.zrange.mockResolvedValue(['intel-1', 'intel-2']);
  const spy = jest.spyOn(PublishingPipeline.prototype, 'getPipelineStatus')
    .mockImplementation(async id => ({ id, status: 'review' }));

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'pending' }), res);

  expect(redis.zrange).toHaveBeenCalledWith('intelligence:by:status:review', 0, -1);
  expect(spy).toHaveBeenCalledTimes(2);
  expect(res.body.count).toBe(2);
});

test('GET /published lists recently published intelligence up to the given limit', async () => {
  redis.zrevrange.mockResolvedValue(['intel-3']);
  jest.spyOn(PublishingPipeline.prototype, 'getPipelineStatus')
    .mockResolvedValue({ id: 'intel-3', status: 'published' });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'published', query: { limit: '5' } }), res);

  expect(redis.zrevrange).toHaveBeenCalledWith('intelligence:published:feed', 0, 4);
  expect(res.body.published).toEqual([{ id: 'intel-3', status: 'published' }]);
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('DELETE'), res);

  expect(res.statusCode).toBe(404);
});
