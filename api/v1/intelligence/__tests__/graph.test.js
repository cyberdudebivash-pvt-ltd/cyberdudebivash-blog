'use strict';

// Route-handler tests for intelligence/graph.js. The critical case here is
// path-finding (GET /{sourceId}/path/{targetId}): the generic `id` computed
// at the top of the handler (pathParts[length-2]) lands on the literal
// segment 'path' for this three-segment shape, not the real source entity
// ID -- so the path-finding branch must derive sourceId itself rather than
// reuse that module-level `id`. This test proves findShortestPath is called
// with the real source/target IDs, not with 'path' as the source.
jest.mock('../../../_lib/redis', () => ({}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { GraphEngine } = require('../../../_lib/graph-engine');
const { GraphTraversal } = require('../../../_lib/graph-traversal');
const { RelationshipEngine } = require('../../../_lib/relationship-engine');
const handler = require('../graph');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/intelligence/graph' };
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

test('unauthenticated requests never reach a graph engine method', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });
  const spy = jest.spyOn(GraphEngine.prototype, 'getEntity');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'e1/entity' }), res);

  expect(res.statusCode).toBe(401);
  expect(spy).not.toHaveBeenCalled();
});

test('GET /{id}/entity fetches the entity and its relationship counts', async () => {
  const entitySpy = jest.spyOn(GraphEngine.prototype, 'getEntity').mockResolvedValue({ id: 'e1', type: 'ip' });
  jest.spyOn(GraphEngine.prototype, 'getOutgoingRelationships').mockResolvedValue([{}, {}]);
  jest.spyOn(GraphEngine.prototype, 'getIncomingRelationships').mockResolvedValue([{}]);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'e1/entity' }), res);

  expect(entitySpy).toHaveBeenCalledWith('e1');
  expect(res.body.entity.id).toBe('e1');
  expect(res.body.relationships).toEqual({ outgoing: 2, incoming: 1 });
});

test('GET /{id}/related runs a bounded BFS from the given entity', async () => {
  const spy = jest.spyOn(GraphTraversal.prototype, 'findRelatedEntitiesBFS').mockResolvedValue([]);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'e1/related' }), res);

  expect(spy).toHaveBeenCalledWith('e1', 2, 50);
});

test('GET /{sourceId}/path/{targetId} passes the real source and target IDs, not the literal "path"', async () => {
  const spy = jest.spyOn(GraphTraversal.prototype, 'findShortestPath')
    .mockResolvedValue({ path: ['e1', 'e2'], relationships: [{}] });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'e1/path/e2' }), res);

  expect(spy).toHaveBeenCalledWith('e1', 'e2', 5);
  expect(res.body.source).toBe('e1');
  expect(res.body.target).toBe('e2');
});

test('GET /{sourceId}/path/{targetId} 404s when no path exists', async () => {
  jest.spyOn(GraphTraversal.prototype, 'findShortestPath').mockResolvedValue(null);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'e1/path/e2' }), res);

  expect(res.statusCode).toBe(404);
});

test('POST /relationship creates a relationship attributed to the caller, not a client-supplied actor', async () => {
  const spy = jest.spyOn(RelationshipEngine.prototype, 'linkIntelligence').mockResolvedValue({ id: 'rel-1' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'relationship',
    body: {
      source: 'e1', target: 'e2', type: 'communicates_with',
      evidence: ['ev1'], sources: ['src1'], reason: 'seen together', actor: 'attacker-supplied',
    },
  }), res);

  expect(spy).toHaveBeenCalledWith('e1', 'e2', 'communicates_with', {
    evidence: ['ev1'], sources: ['src1'], actor: 'analyst-1', reason: 'seen together',
  });
  expect(res.statusCode).toBe(201);
});

test('DELETE /{id}/relationship deletes the relationship attributed to the caller', async () => {
  const spy = jest.spyOn(GraphEngine.prototype, 'deleteRelationship').mockResolvedValue(true);

  const res = mockRes();
  await handler(mockReq('DELETE', { apexSubpath: 'rel-1/relationship', body: { reason: 'incorrect link' } }), res);

  expect(spy).toHaveBeenCalledWith('rel-1', 'analyst-1', 'incorrect link');
});

test('GET /stats returns graph-wide statistics', async () => {
  const spy = jest.spyOn(GraphEngine.prototype, 'getGraphStats').mockResolvedValue({ entities: 10 });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'stats' }), res);

  expect(spy).toHaveBeenCalled();
  expect(res.body.entities).toBe(10);
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('PATCH'), res);

  expect(res.statusCode).toBe(404);
});
