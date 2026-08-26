'use strict';

// Route-handler tests for api/v1/defense-profile.js. Same two-layer pattern
// as api/v1/__tests__/watchlists.test.js: (1) unauthenticated -> 401 before
// touching any profile logic; (2) authenticate() mocked to a controlled
// {tier, userId}, everything downstream (defense-profile-store.js) runs for
// real against a fake in-memory D1.
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
const handler = require('../defense-profile');

function mockReq({ method = 'GET', query = {}, body = null } = {}) {
  return { method, query, headers: { 'content-type': 'application/json' }, url: '/api/v1/defense-profile', body: body === null ? undefined : body };
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
  for (const action of ['get', 'save', 'delete', 'taxonomy', 'entitlements']) {
    test(`action=${action} returns 401 with no API key`, async () => {
      const res = await call(action, { method: action === 'save' || action === 'delete' ? 'POST' : 'GET' });
      expect(res.statusCode).toBe(401);
    });
  }
});

describe('missing/invalid action', () => {
  test('no action -> 400 MISSING_ACTION', async () => {
    const req = mockReq({ query: {} });
    const res = mockRes();
    await handler(req, res);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('MISSING_ACTION');
  });
  test('unknown action -> 400 INVALID_ACTION', async () => {
    const res = await call('not-a-real-action');
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_ACTION');
  });
});

describe('action=taxonomy', () => {
  test('returns the static reference vocabulary once authenticated', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('taxonomy');
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.categories).toContain('siem');
    expect(res.body.technologies.siem.some(t => t.id === 'microsoft-sentinel')).toBe(true);
    expect(res.body.data_sources).toContain('process_creation');
  });

  test('GET only', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('taxonomy', { method: 'POST', body: {} });
    expect(res.statusCode).toBe(405);
  });
});

describe('action=get (no profile configured)', () => {
  test('returns {profile: null}, not an error (mandate Phase 37 safe default)', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('get');
    expect(res.body.success).toBe(true);
    expect(res.body.profile).toBeNull();
  });
});

describe('action=save + action=get round trip', () => {
  test('saves and reads back the same profile for the same authenticated owner', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const saveRes = await call('save', {
      method: 'POST',
      body: { name: 'Prod SOC', technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } },
    });
    expect(saveRes.body.success).toBe(true);
    expect(saveRes.body.profile.name).toBe('Prod SOC');

    const getRes = await call('get');
    expect(getRes.body.profile.id).toBe(saveRes.body.profile.id);
    expect(getRes.body.profile.telemetry).toEqual({ process_creation: 'AVAILABLE' });
  });

  test('rejects a field not on the whitelist (e.g. attempted owner_id override)', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('save', { method: 'POST', body: { name: 'x', owner_id: 'usr_someone_else' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_FIELDS');
  });

  test('rejects an invalid technology with a 400, not a 500', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('save', { method: 'POST', body: { technologies: [{ category: 'siem', technology_id: 'not-real' }] } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_TECHNOLOGIES');
  });

  test('POST only', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('save', { method: 'GET' });
    expect(res.statusCode).toBe(405);
  });
});

describe('action=delete', () => {
  test('NOT_FOUND when no profile exists', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('delete', { method: 'POST', body: {} });
    expect(res.statusCode).toBe(404);
  });

  test('deletes an existing profile', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('save', { method: 'POST', body: { name: 'x' } });
    const delRes = await call('delete', { method: 'POST', body: {} });
    expect(delRes.body.deleted).toBe(true);
    const getRes = await call('get');
    expect(getRes.body.profile).toBeNull();
  });
});

describe('multi-tenant isolation via the real authenticated router path', () => {
  test('owner A cannot read owner B\'s profile via this router, ownership is always the authenticated userId, never client input', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('save', { method: 'POST', body: { name: 'A env', technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }] } });

    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    const bGet = await call('get');
    expect(bGet.body.profile).toBeNull(); // B sees nothing of A's, despite no id ever being passed by the client

    const bSave = await call('save', { method: 'POST', body: { name: 'B env' } });
    expect(bSave.body.profile.name).toBe('B env');

    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const aGetAgain = await call('get');
    expect(aGetAgain.body.profile.name).toBe('A env'); // unaffected by B's save
  });

  test('owner A deleting has no effect on owner B\'s profile', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('save', { method: 'POST', body: { name: 'A env' } });
    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    await call('save', { method: 'POST', body: { name: 'B env' } });
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('delete', { method: 'POST', body: {} });

    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    const bGet = await call('get');
    expect(bGet.body.profile.name).toBe('B env');
  });
});

describe('action=entitlements', () => {
  test('reflects whether the caller currently has a profile configured', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const before = await call('entitlements');
    expect(before.body.usage.profile_configured).toBe(false);
    await call('save', { method: 'POST', body: {} });
    const after = await call('entitlements');
    expect(after.body.usage.profile_configured).toBe(true);
  });
});
