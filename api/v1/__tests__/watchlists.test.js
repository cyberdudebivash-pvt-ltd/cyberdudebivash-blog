'use strict';

// Route-handler tests for api/v1/watchlists.js. Same two-layer pattern as
// api/v1/__tests__/intel-dossier.test.js: (1) an unauthenticated request
// must 401 before touching any watchlist logic, (2) authenticate() mocked
// to return a controlled {tier, userId} while everything downstream
// (watchlist-store.js, change-engine.js) runs for real -- against a fake
// in-memory Redis (api/_lib/__tests__/fixtures/fake-redis.js) rather than
// a live Upstash instance, since watchlists are customer-owned mutable
// state, unlike the read-only canonical intel the dossier tests exercise
// against real production data.
jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});
jest.mock('../../_lib/redis', () => {
  const { createFakeRedis } = require('../../_lib/__tests__/fixtures/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});

const { authenticate } = require('../../_lib/middleware');
const handler = require('../watchlists');

function mockReq({ method = 'GET', query = {}, body = null, ip } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (ip) headers['x-forwarded-for'] = ip;
  return {
    method, query, headers, url: '/api/v1/watchlists',
    body: body === null ? undefined : body,
  };
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

async function call(action, { method = 'GET', query = {}, body = null, ip } = {}) {
  const req = mockReq({ method, query: { action, ...query }, body, ip });
  const res = mockRes();
  await handler(req, res);
  return res;
}

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
});

describe('unauthenticated requests', () => {
  for (const action of ['list', 'create', 'get', 'update', 'delete', 'add-entity', 'remove-entity', 'feed', 'entitlements']) {
    test(`action=${action} returns 401 with no API key`, async () => {
      const res = await call(action, { method: action === 'list' || action === 'get' || action === 'feed' || action === 'entitlements' ? 'GET' : 'POST' });
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
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('bogus-action');
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_ACTION');
  });
});

describe('field whitelist / prototype pollution defense (Phase 11/59)', () => {
  test('an unexpected body field on create is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('create', { method: 'POST', body: { name: 'L', evil: 'x' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_FIELDS');
  });

  test('__proto__ as a body field is rejected, not merged into any object', async () => {
    // Built via JSON.parse, not an object literal: `{ __proto__: {...} }`
    // as literal syntax sets the object's prototype rather than creating
    // an own enumerable property, which would not actually exercise
    // assertFieldWhitelist's Object.keys() check. A real attacker's JSON
    // body (`JSON.parse('{"__proto__":...}')`) DOES produce a real own
    // property named "__proto__" -- that's the shape under test here.
    const maliciousBody = JSON.parse('{"name":"L","__proto__":{"polluted":true}}');
    expect(Object.prototype.hasOwnProperty.call(maliciousBody, '__proto__')).toBe(true);

    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('create', { method: 'POST', body: maliciousBody });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_FIELDS');
    expect({}.polluted).toBeUndefined();
  });
});

describe('method enforcement', () => {
  test('create via GET is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('create', { method: 'GET' });
    expect(res.statusCode).toBe(405);
  });
  test('list via POST is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('list', { method: 'POST' });
    expect(res.statusCode).toBe(405);
  });
});

describe('full CRUD + entity lifecycle (authenticated, real store logic)', () => {
  test('create -> list -> get -> update -> add-entity -> list-entities -> remove-entity -> delete', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));

    const created = await call('create', { method: 'POST', body: { name: 'My CVEs', description: 'tracked' } });
    expect(created.statusCode).toBe(200);
    const id = created.body.watchlist.id;
    expect(id).toMatch(/^wl_/);

    const listed = await call('list');
    expect(listed.body.watchlists).toHaveLength(1);
    expect(listed.body.watchlists[0].id).toBe(id);

    const got = await call('get', { query: { id } });
    expect(got.statusCode).toBe(200);
    expect(got.body.watchlist.name).toBe('My CVEs');

    const updated = await call('update', { method: 'POST', body: { id, name: 'Renamed' } });
    expect(updated.statusCode).toBe(200);
    expect(updated.body.watchlist.name).toBe('Renamed');

    const added = await call('add-entity', { method: 'POST', body: { id, entity_type: 'cve', entity_id: 'CVE-2026-4321' } });
    expect(added.statusCode).toBe(200);
    expect(added.body.entity).toEqual({ type: 'cve', id: 'CVE-2026-4321' });

    const entities = await call('list-entities', { query: { id } });
    expect(entities.body.entities).toEqual([{ type: 'cve', id: 'CVE-2026-4321' }]);

    const removed = await call('remove-entity', { method: 'POST', body: { id, entity_type: 'cve', entity_id: 'CVE-2026-4321' } });
    expect(removed.statusCode).toBe(200);

    const deleted = await call('delete', { method: 'POST', body: { id } });
    expect(deleted.statusCode).toBe(200);

    const gone = await call('get', { query: { id } });
    expect(gone.statusCode).toBe(404);
  });

  test('adding an unsupported entity type returns 400 UNSUPPORTED_ENTITY_TYPE, not a fabricated success', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const created = await call('create', { method: 'POST', body: { name: 'L' } });
    const res = await call('add-entity', { method: 'POST', body: { id: created.body.watchlist.id, entity_type: 'malware', entity_id: 'x' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('UNSUPPORTED_ENTITY_TYPE');
  });
});

describe('ownership isolation at the HTTP layer (Phase 7)', () => {
  test('customer B gets 404 for customer A\'s watchlist ID, GET and POST alike', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const created = await call('create', { method: 'POST', body: { name: 'A only' } });
    const id = created.body.watchlist.id;

    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const getAsB = await call('get', { query: { id } });
    expect(getAsB.statusCode).toBe(404);
    const updateAsB = await call('update', { method: 'POST', body: { id, name: 'hijacked' } });
    expect(updateAsB.statusCode).toBe(404);
    const deleteAsB = await call('delete', { method: 'POST', body: { id } });
    expect(deleteAsB.statusCode).toBe(404);
    const addAsB = await call('add-entity', { method: 'POST', body: { id, entity_type: 'cve', entity_id: 'CVE-2026-1234' } });
    expect(addAsB.statusCode).toBe(404);
  });
});

describe('watchlist limits surfaced at the HTTP layer', () => {
  test('exceeding MAX_WATCHLISTS_PER_OWNER returns 429 LIMIT_REACHED', async () => {
    // Distinct x-forwarded-for per call: the global per-IP limiter
    // (10 req/min, api/_lib/security.js) is deliberately unrelated to the
    // per-owner watchlist limit under test here (MAX_WATCHLISTS_PER_OWNER
    // = 20) -- a single fake IP hammering 20 requests would trip the
    // global limiter first and produce a misleading RATE_LIMIT_EXCEEDED
    // instead of exercising LIMIT_REACHED at all.
    const { MAX_WATCHLISTS_PER_OWNER } = require('../../_lib/watchlist-store');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    for (let i = 0; i < MAX_WATCHLISTS_PER_OWNER; i++) {
      const r = await call('create', { method: 'POST', body: { name: `L${i}` }, ip: `10.0.0.${i}` });
      expect(r.statusCode).toBe(200);
    }
    const overLimit = await call('create', { method: 'POST', body: { name: 'one too many' }, ip: '10.0.0.250' });
    expect(overLimit.statusCode).toBe(429);
    expect(overLimit.body.error.code).toBe('LIMIT_REACHED');
  });
});

describe('entitlements endpoint', () => {
  test('returns entitlement limits and current usage', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('create', { method: 'POST', body: { name: 'L' } });
    const res = await call('entitlements');
    expect(res.statusCode).toBe(200);
    expect(res.body.entitlements.enabled).toBe(true);
    expect(res.body.usage.watchlists_used).toBe(1);
  });
});

describe('monitoring feed tier gating (Phase 12/29, mirrors dossier tier_info)', () => {
  async function seedOneRelationshipEvent(ownerId) {
    authenticate.mockResolvedValue(mockUser('enterprise', ownerId));
    const created = await call('create', { method: 'POST', body: { name: 'L' } });
    await call('add-entity', { method: 'POST', body: { id: created.body.watchlist.id, entity_type: 'cve', entity_id: 'CVE-2026-5555' } });

    const engine = require('../../_lib/change-engine');
    const outcome = await engine.evaluateEntity({
      entityType: 'cve', entityId: 'CVE-2026-5555',
      intel: { getCVEDetail: () => ({ found: true, item: { cvss: 5 } }) },
      graph: { nodes: {}, edges: [] }, reportsIndexData: { reports: [] },
    });
    expect(outcome.status).toBe('baseline_established');

    const changed = await engine.evaluateEntity({
      entityType: 'cve', entityId: 'CVE-2026-5555',
      intel: { getCVEDetail: () => ({ found: true, item: { cvss: 5, cisa_kev: false, exploited: false } }) },
      graph: { nodes: { 'CVE-2026-5555': { id: 'CVE-2026-5555' }, 'campaign:z': { id: 'campaign:z' } }, edges: [
        { source: 'CVE-2026-5555', target: 'campaign:z', relationship: 'includes', confidence: 0.9, sources: [], first_seen: null },
      ] },
      reportsIndexData: { reports: [] },
    });
    expect(changed.events.some(e => e.change_type === 'CVE_NEW_CAMPAIGN_ASSOCIATION')).toBe(true);
  }

  test('free tier sees relationships_gated: true and no related-entity value on relationship-type events', async () => {
    await seedOneRelationshipEvent('usr_free');
    authenticate.mockResolvedValue(mockUser('free', 'usr_free'));
    const res = await call('feed');
    expect(res.statusCode).toBe(200);
    const relEvent = res.body.events.find(e => e.change_type === 'CVE_NEW_CAMPAIGN_ASSOCIATION');
    expect(relEvent.relationships_gated).toBe(true);
    expect(relEvent.related).toBeNull();
  });

  test('enterprise tier sees the full event including the related entity', async () => {
    await seedOneRelationshipEvent('usr_ent');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_ent'));
    const res = await call('feed');
    const relEvent = res.body.events.find(e => e.change_type === 'CVE_NEW_CAMPAIGN_ASSOCIATION');
    expect(relEvent.relationships_gated).toBeUndefined();
    expect(relEvent.related).toEqual({ id: 'campaign:z', type: 'campaign' });
  });

  test('feed pagination returns meta.total and meta.next_cursor', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_page'));
    const res = await call('feed', { query: { limit: '20', cursor: '0' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.meta).toHaveProperty('total');
    expect(res.body.meta).toHaveProperty('next_cursor');
  });
});
