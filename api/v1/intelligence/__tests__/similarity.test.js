'use strict';

// Route-handler tests for intelligence/similarity.js. Covers the routing-gap
// fix (resolvePathParts/MOUNT_PATH -- every sub-path here 404'd before this
// code could run) and the handleMergeDuplicates identity-trust fix: it used
// to read `analyst` straight from the request body and pass it to
// similarityEngine.mergeDuplicates() as the acting identity, unverified --
// the same class of bug already fixed for every other write path in this
// codebase (investigations.js, cases.js, graph.js, objects.js). It now takes
// the authenticated `caller` and uses caller.id, matching that precedent.
jest.mock('../../../_lib/redis', () => ({}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { SimilarityEngine } = require('../../../_lib/similarity-engine');
const handler = require('../similarity');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/intelligence/similarity' };
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

test('unauthenticated requests never reach a similarity engine method', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });
  const spy = jest.spyOn(SimilarityEngine.prototype, 'findSimilarEntities');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'e1/find' }), res);

  expect(res.statusCode).toBe(401);
  expect(spy).not.toHaveBeenCalled();
});

test('GET /{id}/find resolves the real entity ID and applies threshold/limit query params', async () => {
  const spy = jest.spyOn(SimilarityEngine.prototype, 'findSimilarEntities')
    .mockResolvedValue([{ entity: { id: 'e2' }, score: 0.8 }]);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'e1/find', query: { threshold: '0.5', limit: '10' } }), res);

  expect(spy).toHaveBeenCalledWith('e1', 0.5, 10);
  expect(res.body.entityId).toBe('e1');
  expect(res.body.count).toBe(1);
});

test('GET /{id}/ioc-matches resolves the real IOC ID', async () => {
  const spy = jest.spyOn(SimilarityEngine.prototype, 'findIOCMatches')
    .mockResolvedValue({ exact: [], related: [] });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'ioc-1/ioc-matches' }), res);

  expect(spy).toHaveBeenCalledWith('ioc-1');
  expect(res.body.iocId).toBe('ioc-1');
});

test('GET /duplicates detects duplicates with the given minSimilarity', async () => {
  const spy = jest.spyOn(SimilarityEngine.prototype, 'detectDuplicates').mockResolvedValue([]);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'duplicates', query: { minSimilarity: '0.95' } }), res);

  expect(spy).toHaveBeenCalledWith(0.95);
});

test('POST /merge merges duplicates attributed to the authenticated caller, not a client-supplied analyst field', async () => {
  const spy = jest.spyOn(SimilarityEngine.prototype, 'mergeDuplicates')
    .mockResolvedValue({ merged: true, keepEntity: 'e1', mergeEntity: 'e2' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'merge',
    body: { keepEntity: 'e1', mergeEntity: 'e2', reason: 'confirmed duplicate', analyst: 'attacker-supplied' },
  }), res);

  expect(spy).toHaveBeenCalledWith('e1', 'e2', 'analyst-1', 'confirmed duplicate');
  expect(res.body.merged).toBe(true);
});

test('POST /merge rejects a request missing keepEntity/mergeEntity before calling the engine', async () => {
  const spy = jest.spyOn(SimilarityEngine.prototype, 'mergeDuplicates');

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'merge', body: { keepEntity: 'e1' } }), res);

  expect(res.statusCode).toBe(400);
  expect(spy).not.toHaveBeenCalled();
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('DELETE'), res);

  expect(res.statusCode).toBe(404);
});
