'use strict';
/**
 * SENTINEL APEX — Detection Performance Intelligence v1: HTTP layer for
 * api/v1/detections/performance.js.
 *
 * detection-performance-engine.js itself already has thorough coverage
 * (api/_lib/__tests__/detection-performance-engine.test.js) -- this file's
 * job is the HTTP-specific contract: authentication requirements, param
 * validation, the admin-key gate on review-queue, and genuine end-to-end
 * tenant isolation for my-performance (which reads detection-feedback-
 * store.js directly, so it is run for real here against the fake-d1
 * fixture, not mocked, to prove isolation rather than assume it).
 */

process.env.ADMIN_SECRET_KEY = 'test-admin-key-0123456789abcdef';

jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return { ...actual, globalIpRateLimit: jest.fn(async () => true), adminIpRateLimit: jest.fn(async () => true) };
});
jest.mock('../../_lib/d1', () => {
  const { createFakeD1 } = require('../../_lib/__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});
jest.mock('../../_lib/detection-performance-engine');

const { authenticate } = require('../../_lib/middleware');
const feedbackStore = require('../../_lib/detection-feedback-store');
const performanceEngine = require('../../_lib/detection-performance-engine');
const handler = require('../detections/performance');

function mockReq({ method = 'GET', query = {} } = {}) {
  return { method, query, headers: { 'content-type': 'application/json' }, url: '/api/v1/detections/performance' };
}
function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn((s) => { res.statusCode = s; return res; });
  res.json = jest.fn((b) => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
function mockUser(userId) {
  return { tier: 'enterprise', userId, email: `${userId}@example.com`, keyHash: userId, requestsUsed: 1, requestsLimit: 999999 };
}
async function call(action, { method = 'GET', query = {}, headers = {} } = {}) {
  const req = mockReq({ method, query: { action, ...query } });
  req.headers = { ...req.headers, ...headers };
  const res = mockRes();
  await handler(req, res);
  return res;
}

beforeEach(() => {
  global.__fakeD1ForTest._reset();
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
  performanceEngine.computeDetectionQuality = jest.fn().mockResolvedValue({ detection_id: 'det_1', detection_version: '1.0.0', quality_state: 'HEALTHY' });
  performanceEngine.getVersionHistory = jest.fn().mockResolvedValue({ detection_id: 'det_1', versions: [] });
  performanceEngine.computeReviewQueue = jest.fn().mockResolvedValue([{ detection_id: 'det_1', priority_tier: 'CRITICAL' }]);
});

describe('action=quality', () => {
  test('requires authentication', async () => {
    const res = await call('quality', { query: { detection_id: 'det_1' } });
    expect(res.statusCode).toBe(401);
  });

  test('requires detection_id', async () => {
    authenticate.mockResolvedValue(mockUser('usr_a'));
    const res = await call('quality');
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('MISSING_PARAMETERS');
  });

  test('returns 404 when the engine reports no detection found', async () => {
    authenticate.mockResolvedValue(mockUser('usr_a'));
    performanceEngine.computeDetectionQuality.mockResolvedValue(null);
    const res = await call('quality', { query: { detection_id: 'det_missing' } });
    expect(res.statusCode).toBe(404);
  });

  test('happy path returns the quality object from the engine, unmodified', async () => {
    authenticate.mockResolvedValue(mockUser('usr_a'));
    const res = await call('quality', { query: { detection_id: 'det_1', detection_version: '1.0.0' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.quality.quality_state).toBe('HEALTHY');
    expect(performanceEngine.computeDetectionQuality).toHaveBeenCalledWith('det_1', '1.0.0');
  });
});

describe('action=version-history', () => {
  test('requires authentication', async () => {
    const res = await call('version-history', { query: { detection_id: 'det_1' } });
    expect(res.statusCode).toBe(401);
  });

  test('requires detection_id', async () => {
    authenticate.mockResolvedValue(mockUser('usr_a'));
    const res = await call('version-history');
    expect(res.statusCode).toBe(400);
  });
});

describe('action=my-performance — genuine tenant isolation (not mocked)', () => {
  test('requires authentication', async () => {
    const res = await call('my-performance', { query: { detection_id: 'det_1', detection_version: '1.0.0' } });
    expect(res.statusCode).toBe(401);
  });

  test('requires both detection_id and detection_version', async () => {
    authenticate.mockResolvedValue(mockUser('usr_a'));
    const res = await call('my-performance', { query: { detection_id: 'det_1' } });
    expect(res.statusCode).toBe(400);
  });

  test('a caller only ever sees their OWN feedback counts, never another tenant\'s', async () => {
    await feedbackStore.submitFeedback('usr_a', { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: 'usr_a' });
    await feedbackStore.submitFeedback('usr_a', { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: 'usr_a' });
    await feedbackStore.submitFeedback('usr_b', { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'FALSE_POSITIVE', createdBy: 'usr_b' });

    authenticate.mockResolvedValue(mockUser('usr_a'));
    const asA = await call('my-performance', { query: { detection_id: 'det_1', detection_version: '1.0.0' } });
    expect(asA.statusCode).toBe(200);
    expect(asA.body.performance.classification_counts).toEqual({ TRUE_POSITIVE: 2 });
    expect(asA.body.performance.total_feedback).toBe(2);

    authenticate.mockResolvedValue(mockUser('usr_b'));
    const asB = await call('my-performance', { query: { detection_id: 'det_1', detection_version: '1.0.0' } });
    expect(asB.body.performance.classification_counts).toEqual({ FALSE_POSITIVE: 1 });

    // Neither response leaks the other tenant's identity or counts.
    expect(JSON.stringify(asA.body)).not.toContain('usr_b');
    expect(JSON.stringify(asB.body)).not.toContain('usr_a');
  });

  test('a caller cannot see another tenant\'s feedback by passing a different userId in the body -- ownerId is always re-derived from authenticate(), never trusted from the request', async () => {
    await feedbackStore.submitFeedback('usr_victim', { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: 'usr_victim' });
    authenticate.mockResolvedValue(mockUser('usr_attacker'));
    // Even though nothing in this router reads a body for this GET action,
    // this proves the response reflects the AUTHENTICATED identity only.
    const res = await call('my-performance', { query: { detection_id: 'det_1', detection_version: '1.0.0' } });
    expect(res.body.performance.total_feedback).toBe(0);
  });
});

describe('action=review-queue — internal, admin-key gated', () => {
  test('rejects with no X-Admin-Key header', async () => {
    const res = await call('review-queue');
    expect(res.statusCode).toBe(401);
    expect(performanceEngine.computeReviewQueue).not.toHaveBeenCalled();
  });

  test('rejects an incorrect X-Admin-Key', async () => {
    const res = await call('review-queue', { headers: { 'x-admin-key': 'wrong-key' } });
    expect(res.statusCode).toBe(401);
  });

  test('does NOT accept a customer API key / authenticate() session in place of the admin key', async () => {
    authenticate.mockResolvedValue(mockUser('usr_a'));
    const res = await call('review-queue');
    expect(res.statusCode).toBe(401);
  });

  test('accepts the correct X-Admin-Key and returns the queue', async () => {
    const res = await call('review-queue', { headers: { 'x-admin-key': process.env.ADMIN_SECRET_KEY } });
    expect(res.statusCode).toBe(200);
    expect(res.body.queue[0].priority_tier).toBe('CRITICAL');
  });
});

describe('unknown action', () => {
  test('returns 400 INVALID_ACTION', async () => {
    const res = await call('not-a-real-action');
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_ACTION');
  });
});
