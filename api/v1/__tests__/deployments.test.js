'use strict';

process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = 'c'.repeat(64);

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
// This file's cases each drive a real multi-step (preview/approve/execute)
// lifecycle through the HTTP layer, so the *number* of requests per test
// legitimately exceeds security.js's global 10-req/min-per-IP budget once
// summed across the whole suite (the mocked req objects share one
// synthetic IP) -- the exact scenario api/v1/__tests__/billing.test.js's
// own header already documents this same mock for. authenticate() and
// D1/detection/compatibility mocks below are unaffected -- only the
// unrelated cross-cutting IP throttle is bypassed.
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return { ...actual, globalIpRateLimit: jest.fn(async () => true) };
});
jest.mock('../../_lib/d1', () => {
  const { createFakeD1 } = require('../../_lib/__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});
jest.mock('../../_lib/detection-rules');
jest.mock('../../_lib/detection-intelligence');
jest.mock('../../_lib/defense-compatibility');
jest.mock('../../_lib/defense-profile-store');
jest.mock('../../_lib/intel', () => ({
  getDossierAPI: jest.fn(() => ({
    found: true, unsupported: false,
    dossier: { attack_context: { techniques: [{ id: 'T1490', source: 'linked_report' }] } },
  })),
}));

const { authenticate } = require('../../_lib/middleware');
const detectionRules = require('../../_lib/detection-rules');
const detectionIntelligence = require('../../_lib/detection-intelligence');
const defenseCompatibility = require('../../_lib/defense-compatibility');
const defenseProfileStore = require('../../_lib/defense-profile-store');
const connectorsHandler = require('../connectors');
const handler = require('../deployments');

function mockReq({ method = 'GET', query = {}, body = null } = {}) {
  return { method, query, headers: { 'content-type': 'application/json' }, url: '/api/v1/deployments', body: body === null ? undefined : body };
}
function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
function mockUser(tier, userId) {
  return { tier, userId, email: `${userId}@example.com`, keyHash: userId, requestsUsed: 1, requestsLimit: 999999 };
}
async function call(action, { method = 'GET', query = {}, body = null } = {}) {
  const req = mockReq({ method, query: { action, ...query }, body });
  const res = mockRes();
  await handler(req, res);
  return res;
}
async function callConnectors(action, opts) {
  const req = mockReq({ ...opts, query: { action, ...(opts?.query || {}) } });
  const res = mockRes();
  await connectorsHandler(req, res);
  return res;
}

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  global.__fakeD1ForTest._reset();
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
  detectionRules.getRule.mockReset().mockImplementation(() => ({
    id: 'det_test_1', technique_id: 'T1490', title: 'Test Rule', description: 'desc', level: 'high', data_source: 'process_creation',
    platforms: { kql: 'X | where 1==1' }, suricata: [], governance: { status: 'GENERATED', version: '1.0.0' }, source: { articles: ['CVE-2023-27351'] },
  }));
  detectionIntelligence.classifyAttackEvidence.mockReset().mockReturnValue('SOURCE_ATTRIBUTED');
  detectionIntelligence.toCanonicalDetectionObject.mockReset().mockImplementation(() => ({
    status: 'RELEASED', version: '1.0.0', formats: { kql: { content: 'X | where 1==1', maturity: 'Production Ready With Limitations' } },
    attack: [{ id: 'T1490', evidence_state: 'SOURCE_ATTRIBUTED' }], telemetry_requirements: {},
  }));
  defenseCompatibility.evaluateDetectionCompatibility.mockReset().mockReturnValue({ status: 'READY', format_used: 'kql', sigma_portable: false, missing_telemetry: [], explanation: 'Ready.' });
  defenseProfileStore.getProfile.mockReset().mockResolvedValue({ profile: { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } } });
});

async function createSandboxConnector(userId) {
  authenticate.mockResolvedValue(mockUser('enterprise', userId));
  const res = await callConnectors('create', { method: 'POST', body: { platform: 'mock-siem', name: 'Sandbox', target_config: {} } });
  return res.body.connector.id;
}

describe('unauthenticated requests', () => {
  for (const [action, method] of [['list', 'GET'], ['preview', 'POST'], ['execute', 'POST']]) {
    test(`action=${action} returns 401 with no API key`, async () => {
      const res = await call(action, { method });
      expect(res.statusCode).toBe(401);
    });
  }
});

describe('full lifecycle via the HTTP layer', () => {
  test('preview -> approve -> execute reaches VERIFIED with a 200 response shape', async () => {
    const connectorId = await createSandboxConnector('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));

    const preview = await call('preview', { method: 'POST', body: { connector_id: connectorId, detection_id: 'det_test_1', entity_type: 'cve', entity_id: 'CVE-2023-27351' } });
    expect(preview.statusCode).toBe(200);
    const deploymentId = preview.body.preview.deployment_id;

    const approve = await call('approve', { method: 'POST', query: { id: deploymentId }, body: {} });
    expect(approve.statusCode).toBe(200);

    const execute = await call('execute', { method: 'POST', query: { id: deploymentId }, body: {} });
    expect(execute.statusCode).toBe(200);
    expect(execute.body.deployment.state).toBe('VERIFIED');
  });

  test('a blocked preview (not RELEASED) returns 409 with a machine-readable reason header', async () => {
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue({ status: 'REVIEW_REQUIRED', version: '1.0.0', formats: {}, attack: [] });
    const connectorId = await createSandboxConnector('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const preview = await call('preview', { method: 'POST', body: { connector_id: connectorId, detection_id: 'det_test_1', entity_type: 'cve', entity_id: 'CVE-2023-27351' } });
    expect(preview.statusCode).toBe(409);
    expect(preview.headers['X-Deployment-Block-Reason']).toBe('DETECTION_NOT_RELEASED');
  });
});

describe('tenant isolation over HTTP', () => {
  test("owner B's execute against owner A's deployment id returns 404, not the deployment's real state", async () => {
    const connectorId = await createSandboxConnector('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const preview = await call('preview', { method: 'POST', body: { connector_id: connectorId, detection_id: 'det_test_1', entity_type: 'cve', entity_id: 'CVE-2023-27351' } });
    const deploymentId = preview.body.preview.deployment_id;
    await call('approve', { method: 'POST', query: { id: deploymentId }, body: {} });

    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const crossTenant = await call('execute', { method: 'POST', query: { id: deploymentId }, body: {} });
    expect(crossTenant.statusCode).toBe(404);
  });
});

describe('history never leaks another owner\'s attempts', () => {
  test('history for a nonexistent/foreign deployment id 404s before touching the attempts table', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const res = await call('history', { query: { id: 'dep_totally_made_up' } });
    expect(res.statusCode).toBe(404);
  });
});
