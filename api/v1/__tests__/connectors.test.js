'use strict';

process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = 'b'.repeat(64);

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
// See deployments.test.js's identical comment: this suite's per-test call
// volume legitimately exceeds security.js's unrelated global 10-req/min-
// per-IP budget when summed across the file (shared synthetic IP) --
// bypassed the same way api/v1/__tests__/billing.test.js already does.
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

const { authenticate } = require('../../_lib/middleware');
const handler = require('../connectors');

function mockReq({ method = 'GET', query = {}, body = null } = {}) {
  return { method, query, headers: { 'content-type': 'application/json' }, url: '/api/v1/connectors', body: body === null ? undefined : body };
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

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  global.__fakeD1ForTest._reset();
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
});

describe('unauthenticated requests', () => {
  for (const [action, method] of [['platforms', 'GET'], ['entitlements', 'GET'], ['list', 'GET'], ['create', 'POST'], ['test-connection', 'POST'], ['disable', 'POST']]) {
    test(`action=${action} returns 401 with no API key`, async () => {
      const res = await call(action, { method });
      expect(res.statusCode).toBe(401);
    });
  }
});

describe('platforms', () => {
  test('lists every known platform honestly, including not-yet-implemented ones', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('platforms');
    expect(res.statusCode).toBe(200);
    const ids = res.body.platforms.map(p => p.id);
    expect(ids).toEqual(expect.arrayContaining(['mock-siem', 'microsoft-sentinel', 'splunk-enterprise-security', 'elastic-security']));
    const splunk = res.body.platforms.find(p => p.id === 'splunk-enterprise-security');
    expect(splunk.capabilities.deploy_supported).toBe(false);
    expect(splunk.not_implemented_reason).toBeTruthy();
  });
});

describe('create + list + cross-tenant isolation', () => {
  test('a created connector is visible to its owner and invisible to another owner', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const created = await call('create', { method: 'POST', body: { platform: 'mock-siem', name: 'My Sandbox', target_config: {} } });
    expect(created.statusCode).toBe(200);
    const connectorId = created.body.connector.id;

    const listAsA = await call('list');
    expect(listAsA.body.connectors.some(c => c.id === connectorId)).toBe(true);

    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    const getAsB = await call('get', { query: { id: connectorId } });
    expect(getAsB.statusCode).toBe(404);
  });

  test('rejects unknown fields in the body (field whitelisting)', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('create', { method: 'POST', body: { platform: 'mock-siem', name: 'X', target_config: {}, owner_id: 'usr_b' } });
    expect(res.statusCode).toBe(400);
  });
});

describe('test-connection is read-only', () => {
  test('never returns a credential value in its response', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const created = await call('create', {
      method: 'POST',
      body: { platform: 'microsoft-sentinel', name: 'Prod', target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'r', workspace_name: 'w', client_id: 'c' }, credential: { client_secret: 'super-secret-value' } },
    });
    const res = await call('test-connection', { method: 'POST', query: { id: created.body.connector.id }, body: {} });
    expect(JSON.stringify(res.body)).not.toContain('super-secret-value');
  });
});
