'use strict';

// Route-handler tests for intelligence/objects.js. Proves three things
// together: (1) the auth gate blocks unauthenticated requests; (2) the
// base-path CREATE/SEARCH routes are reachable now that they no longer
// require `!id` -- `id` (pathParts[length-2]) is always the literal
// 'intelligence' segment for the bare `/objects` path, which is truthy, so
// the old `!id` check could never pass; (3) the bare-ID GET/PUT routes are
// reachable now that they check `id === 'objects' && action` instead of the
// old `id && !action`, which could never be true for `/objects/{realId}`
// (action always holds the real ID there, never empty) -- the same fix
// pattern already proven in investigations.js/cases.js.
jest.mock('../../../_lib/redis', () => ({}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { IntelligenceManager } = require('../../../_lib/intelligence-manager');
const { LIFECYCLE_STATES } = require('../../../_lib/intelligence-object');
const handler = require('../objects');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/intelligence/objects' };
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

test('unauthenticated requests never reach a manager method', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });
  const spy = jest.spyOn(IntelligenceManager.prototype, 'getIntelligence');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'intel-123' }), res);

  expect(res.statusCode).toBe(401);
  expect(spy).not.toHaveBeenCalled();
});

test('POST /objects (base path) creates with the authenticated caller as actor', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'storeIntelligence')
    .mockResolvedValue({ id: 'intel-new', type: 'ioc' });

  const res = mockRes();
  await handler(mockReq('POST', { body: { type: 'IOC', title: 'New IOC', description: 'd' } }), res);

  expect(spy).toHaveBeenCalledWith('IOC', expect.objectContaining({ title: 'New IOC' }), 'analyst-1');
  expect(res.statusCode).toBe(201);
  expect(res.body.intelligence.id).toBe('intel-new');
});

test('POST /objects rejects an unknown type before calling the manager', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'storeIntelligence');

  const res = mockRes();
  await handler(mockReq('POST', { body: { type: 'not_a_real_type', title: 'X' } }), res);

  expect(res.statusCode).toBe(400);
  expect(spy).not.toHaveBeenCalled();
});

test('GET /objects (base path) searches with query filters', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'searchIntelligence').mockResolvedValue([]);

  const res = mockRes();
  await handler(mockReq('GET', { query: { type: 'ioc', q: 'evil.example' } }), res);

  expect(spy).toHaveBeenCalledWith({ type: 'ioc', q: 'evil.example' });
});

test('GET /objects/{id} (bare ID) resolves the real ID, not the literal "objects"', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'getIntelligence')
    .mockResolvedValue({ id: 'intel-123', title: 'Bare ID fetch' });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'intel-123' }), res);

  expect(spy).toHaveBeenCalledWith('intel-123');
  expect(res.statusCode).toBe(200);
  expect(res.body.intelligence.id).toBe('intel-123');
});

test('GET /objects/{id} 404s when the object does not exist', async () => {
  jest.spyOn(IntelligenceManager.prototype, 'getIntelligence').mockResolvedValue(null);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'missing-id' }), res);

  expect(res.statusCode).toBe(404);
});

test('PUT /objects/{id} (bare ID) resolves the real ID and attributes the update to the caller', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'updateIntelligence')
    .mockResolvedValue({ id: 'intel-123', title: 'Updated' });

  const res = mockRes();
  await handler(mockReq('PUT', { apexSubpath: 'intel-123', body: { title: 'Updated', reason: 'correction' } }), res);

  expect(spy).toHaveBeenCalledWith('intel-123', { title: 'Updated', reason: 'correction' }, 'analyst-1', 'correction');
});

test('POST /objects/{id}/review is not shadowed by the bare-ID fallback and attributes to the caller', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'transitionIntelligence')
    .mockResolvedValue({ id: 'intel-123', status: LIFECYCLE_STATES.REVIEW });
  const getSpy = jest.spyOn(IntelligenceManager.prototype, 'getIntelligence');

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'intel-123/review', body: { reason: 'ready' } }), res);

  expect(spy).toHaveBeenCalledWith('intel-123', LIFECYCLE_STATES.REVIEW, 'analyst-1', 'ready');
  expect(getSpy).not.toHaveBeenCalled();
});

test('POST /objects/{id}/approve transitions to APPROVED, attributed to the caller', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'transitionIntelligence')
    .mockResolvedValue({ id: 'intel-123', status: LIFECYCLE_STATES.APPROVED });

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'intel-123/approve', body: {} }), res);

  expect(spy).toHaveBeenCalledWith('intel-123', LIFECYCLE_STATES.APPROVED, 'analyst-1', 'Approved for publication');
});

test('POST /objects/{id}/publish publishes, attributed to the caller', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'publishIntelligence')
    .mockResolvedValue({ id: 'intel-123', status: LIFECYCLE_STATES.PUBLISHED });

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'intel-123/publish' }), res);

  expect(spy).toHaveBeenCalledWith('intel-123', 'analyst-1');
});

test('POST /objects/{id}/retract retracts, attributed to the caller, not a client-supplied field', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'retractIntelligence')
    .mockResolvedValue({ id: 'intel-123', status: LIFECYCLE_STATES.RETRACTED });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'intel-123/retract',
    body: { reason: 'false positive', actor: 'attacker-supplied' },
  }), res);

  expect(spy).toHaveBeenCalledWith('intel-123', 'analyst-1', 'false positive');
});

test('GET /objects/{id}/history returns version history, not shadowed by the bare-ID fallback', async () => {
  const spy = jest.spyOn(IntelligenceManager.prototype, 'getIntelligenceHistory')
    .mockResolvedValue([{ version: 1 }]);
  const getSpy = jest.spyOn(IntelligenceManager.prototype, 'getIntelligence');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'intel-123/history' }), res);

  expect(spy).toHaveBeenCalledWith('intel-123');
  expect(getSpy).not.toHaveBeenCalled();
  expect(res.body.history).toEqual([{ version: 1 }]);
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('DELETE'), res);

  expect(res.statusCode).toBe(404);
});
