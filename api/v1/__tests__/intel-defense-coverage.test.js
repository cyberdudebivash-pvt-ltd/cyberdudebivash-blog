'use strict';

// Route-handler tests for the new action=defense-coverage added to
// api/v1/intel.js. Unlike intel-detections.test.js (which needed no D1
// mock -- those actions only read canonical, file-backed intel), this
// action reads the caller's own Defense Profile via defense-profile-store.js
// (D1-backed), so D1 is mocked here too, same fixture as watchlists.test.js.
jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});
jest.mock('../../_lib/redis', () => {
  const { createFakeRedis } = require('../../_lib/__fixtures__/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});
jest.mock('../../_lib/d1', () => {
  const { createFakeD1 } = require('../../_lib/__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const { authenticate } = require('../../_lib/middleware');
const handler = require('../intel');
const defenseProfileHandler = require('../defense-profile');

function mockReq({ method = 'GET', query = {}, body = null } = {}) {
  return { method, query, headers: { 'content-type': 'application/json' }, url: '/api/v1/intel', body: body === null ? undefined : body };
}
function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.send = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
function mockUser(tier, userId) {
  return { tier, userId, email: `${userId}@example.com`, keyHash: userId, requestsUsed: 1, requestsLimit: 999999 };
}
async function callIntel(query, { method = 'GET' } = {}) {
  const req = mockReq({ method, query });
  const res = mockRes();
  await handler(req, res);
  return res;
}
async function saveProfile(userId, body) {
  authenticate.mockResolvedValue(mockUser('enterprise', userId));
  const req = mockReq({ method: 'POST', query: { action: 'save' }, body });
  const res = mockRes();
  await defenseProfileHandler(req, res);
  return res;
}

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  global.__fakeD1ForTest._reset();
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
});

describe('unauthenticated', () => {
  test('action=defense-coverage returns 401 with no API key', async () => {
    const res = await callIntel({ action: 'defense-coverage', type: 'cve', id: 'CVE-2023-27351' });
    expect(res.statusCode).toBe(401);
  });
});

describe('validation', () => {
  test('missing type -> 400', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const res = await callIntel({ action: 'defense-coverage', id: 'CVE-2023-27351' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('UNSUPPORTED_ENTITY_TYPE');
  });
  test('missing id -> 400', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const res = await callIntel({ action: 'defense-coverage', type: 'cve' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('MISSING_COVERAGE_ID');
  });
  test('unknown entity -> 404', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const res = await callIntel({ action: 'defense-coverage', type: 'cve', id: 'CVE-1999-99999' });
    expect(res.statusCode).toBe(404);
  });
});

describe('workflow D -- no profile configured, real CVE', () => {
  test('global coverage still fully computed, customer dimension honestly UNKNOWN_PROFILE', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_never_configured'));
    const res = await callIntel({ action: 'defense-coverage', type: 'cve', id: 'CVE-2023-27351' });
    expect(res.body.success).toBe(true);
    expect(res.body.coverage.profile_configured).toBe(false);
    expect(res.body.coverage.observed_techniques).toBeGreaterThan(0);
    const t1490 = res.body.coverage.techniques.find(t => t.id === 'T1490');
    expect(t1490.customer_status).toBe('UNKNOWN_PROFILE');
    expect(t1490.status).toBe('COVERED'); // global truth unaffected
  });
});

describe('workflow A -- Microsoft customer, real CVE, real RELEASED KQL detection, telemetry available', () => {
  test('T1490 resolves READY end-to-end through the real router + real store + real compatibility engine', async () => {
    const saveRes = await saveProfile('usr_msft', {
      name: 'Contoso SOC',
      technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }, { category: 'edr_xdr', technology_id: 'microsoft-defender-xdr' }],
      telemetry: { process_creation: 'AVAILABLE' },
    });
    expect(saveRes.body.success).toBe(true);

    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_msft'));
    const res = await callIntel({ action: 'defense-coverage', type: 'cve', id: 'CVE-2023-27351' });
    expect(res.body.coverage.profile_configured).toBe(true);
    const t1490 = res.body.coverage.techniques.find(t => t.id === 'T1490');
    expect(t1490.customer_status).toBe('READY');
    expect(t1490.customer_format_used).toBe('kql');
    expect(t1490.recommended_detection.detection_id).toBeTruthy();
  });
});

describe('workflow B -- same detection, telemetry explicitly missing', () => {
  test('T1490 resolves TELEMETRY_GAP with an explicit missing-source explanation', async () => {
    await saveProfile('usr_gap', {
      technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }],
      telemetry: { process_creation: 'NOT_AVAILABLE' },
    });
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_gap'));
    const res = await callIntel({ action: 'defense-coverage', type: 'cve', id: 'CVE-2023-27351' });
    const t1490 = res.body.coverage.techniques.find(t => t.id === 'T1490');
    expect(t1490.customer_status).toBe('TELEMETRY_GAP');
    expect(t1490.customer_missing_telemetry.length).toBeGreaterThan(0);
  });
});

describe('workflow C -- Splunk-only-shaped scenario using a real SIEM with no validated generator (QRadar)', () => {
  test('T1490 resolves UNSUPPORTED_PLATFORM, never a fabricated query language', async () => {
    await saveProfile('usr_qradar', {
      technologies: [{ category: 'siem', technology_id: 'qradar' }],
      telemetry: { process_creation: 'AVAILABLE' },
    });
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_qradar'));
    const res = await callIntel({ action: 'defense-coverage', type: 'cve', id: 'CVE-2023-27351' });
    const t1490 = res.body.coverage.techniques.find(t => t.id === 'T1490');
    expect(t1490.customer_status).toBe('UNSUPPORTED_PLATFORM');
    expect(t1490.customer_format_used).toBeNull();
  });
});

describe('cross-tenant isolation through the real authenticated router path', () => {
  test('customer A\'s Defense Profile never leaks into customer B\'s coverage computation', async () => {
    await saveProfile('usr_a', { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } });
    // usr_b never configures anything.
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const res = await callIntel({ action: 'defense-coverage', type: 'cve', id: 'CVE-2023-27351' });
    expect(res.body.coverage.profile_configured).toBe(false);
  });
});
