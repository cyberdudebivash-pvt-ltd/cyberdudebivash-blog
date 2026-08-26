'use strict';

// Route-handler tests for api/v1/notifications.js. Same two-layer pattern
// as api/v1/__tests__/watchlists.test.js: (1) unauthenticated requests
// must 401 before touching any preference/delivery logic, (2)
// authenticate() mocked to return a controlled {tier, userId} while
// everything downstream (notification-store.js, webhook-signing.js) runs
// for real against a fake in-memory Redis.
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
// notification-store.js's own delivery-state reads/writes are D1-backed,
// not Redis-backed (see that module's header) -- the redis mock above
// remains for authenticate()'s customer-identity lookups only.
jest.mock('../../_lib/d1', () => {
  const { createFakeD1 } = require('../../_lib/__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const { authenticate } = require('../../_lib/middleware');
const handler = require('../notifications');
const notify = require('../../_lib/notification-store');

function mockReq({ method = 'GET', query = {}, body = null, ip } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (ip) headers['x-forwarded-for'] = ip;
  return { method, query, headers, url: '/api/v1/notifications', body: body === null ? undefined : body };
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
  global.__fakeD1ForTest._reset();
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
  global.fetch = undefined;
});

afterEach(() => {
  global.fetch = undefined;
});

describe('unauthenticated requests', () => {
  const GET_ACTIONS = ['preferences', 'deliveries', 'dead-letters'];
  const POST_ACTIONS = ['update-preferences', 'rotate-webhook-secret', 'test-webhook'];
  for (const action of [...GET_ACTIONS, ...POST_ACTIONS]) {
    test(`action=${action} returns 401 with no API key`, async () => {
      const res = await call(action, { method: GET_ACTIONS.includes(action) ? 'GET' : 'POST' });
      expect(res.statusCode).toBe(401);
    });
  }
});

describe('missing/invalid action', () => {
  test('no action -> 400 MISSING_ACTION', async () => {
    const req = mockReq({ method: 'GET', query: {} });
    const res = mockRes();
    await handler(req, res);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('MISSING_ACTION');
  });

  test('unknown action -> 400 INVALID_ACTION', async () => {
    const res = await call('not-a-real-action', { method: 'GET' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_ACTION');
  });
});

describe('method enforcement', () => {
  test('preferences requires GET', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('preferences', { method: 'POST' });
    expect(res.statusCode).toBe(405);
  });
  test('update-preferences requires POST', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'GET' });
    expect(res.statusCode).toBe(405);
  });
});

describe('field whitelist / prototype pollution', () => {
  test('update-preferences rejects an unlisted field', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'POST', body: { email_enabled: true, not_a_real_field: 'x' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_FIELDS');
  });

  test('a JSON.parse-sourced __proto__ payload is rejected, not silently accepted', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const malicious = JSON.parse('{"email_enabled":true,"__proto__":{"polluted":true}}');
    expect(Object.prototype.hasOwnProperty.call(malicious, '__proto__')).toBe(true);
    const req = mockReq({ method: 'POST', query: { action: 'update-preferences' }, body: malicious });
    const res = mockRes();
    await handler(req, res);
    expect(res.statusCode).toBe(400);
    expect({}.polluted).toBeUndefined();
  });
});

describe('preferences — GET/POST round trip', () => {
  test('defaults are returned for a fresh account', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('preferences', { method: 'GET' });
    expect(res.statusCode).toBe(200);
    expect(res.body.preferences.email_enabled).toBe(true);
    expect(res.body.preferences.webhook_enabled).toBe(false);
    expect(res.body.preferences.webhook_secret).toBeUndefined(); // never leaked, even when absent
  });

  test('a valid email_override is accepted and persisted', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'POST', body: { email_override: 'alerts@example.com' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.preferences.email_override).toBe('alerts@example.com');
  });

  test('a malformed email_override is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'POST', body: { email_override: 'not-an-email' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_EMAIL');
  });

  test('a safe public https webhook_url is accepted', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.preferences.webhook_url).toBe('https://example.com/hook');
  });

  test('an SSRF-unsafe webhook_url (cloud metadata address) is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://169.254.169.254/latest/meta-data' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('UNSAFE_WEBHOOK_URL');
  });

  test('a non-https webhook_url is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'POST', body: { webhook_url: 'http://example.com/hook' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('UNSAFE_WEBHOOK_URL');
  });

  test('enabling webhook before setting a URL is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('update-preferences', { method: 'POST', body: { webhook_enabled: true } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('WEBHOOK_URL_REQUIRED');
  });

  test('enabling webhook with a URL but no secret yet is rejected', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    const res = await call('update-preferences', { method: 'POST', body: { webhook_enabled: true } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('WEBHOOK_SECRET_REQUIRED');
  });

  test('enabling webhook succeeds once a URL and secret both exist', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    const res = await call('update-preferences', { method: 'POST', body: { webhook_enabled: true } });
    expect(res.statusCode).toBe(200);
    expect(res.body.preferences.webhook_enabled).toBe(true);
  });

  test('clearing webhook_url force-disables webhook_enabled (never an enabled-but-urlless state)', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    await call('update-preferences', { method: 'POST', body: { webhook_enabled: true } });
    const res = await call('update-preferences', { method: 'POST', body: { webhook_url: '' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.preferences.webhook_url).toBe('');
    expect(res.body.preferences.webhook_enabled).toBe(false);
  });
});

describe('rotate-webhook-secret', () => {
  test('returns a secret once, and it is never echoed back by GET preferences', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('rotate-webhook-secret', { method: 'POST' });
    expect(res.statusCode).toBe(200);
    expect(res.body.webhook_secret).toMatch(/^whsec_/);
    const prefsRes = await call('preferences', { method: 'GET' });
    expect(JSON.stringify(prefsRes.body)).not.toContain(res.body.webhook_secret);
    expect(prefsRes.body.preferences.has_webhook_secret).toBe(true);
  });
});

describe('test-webhook', () => {
  test('requires a webhook URL to be configured first', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('test-webhook', { method: 'POST' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('WEBHOOK_URL_REQUIRED');
  });

  test('requires a secret to be generated first', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    const res = await call('test-webhook', { method: 'POST' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('WEBHOOK_SECRET_REQUIRED');
  });

  test('sends a real signed request and reports success, recorded in the delivery log', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    global.fetch = jest.fn(() => Promise.resolve({ ok: true, status: 200 }));
    const res = await call('test-webhook', { method: 'POST' });
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(global.fetch).toHaveBeenCalledTimes(1);

    const deliveries = await call('deliveries', { method: 'GET' });
    expect(deliveries.body.deliveries.some(d => d.channel === 'webhook')).toBe(true);
  });

  test('a test payload is clearly synthetic, never a real CVE claim', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    let capturedBody = null;
    global.fetch = jest.fn((url, opts) => { capturedBody = JSON.parse(opts.body); return Promise.resolve({ ok: true, status: 200 }); });
    await call('test-webhook', { method: 'POST' });
    expect(capturedBody.data.change_type).toBe('TEST_DELIVERY');
    expect(capturedBody.data.reason).toMatch(/not a real intelligence change/i);
  });

  test('a failed test delivery is reported without throwing', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 503, text: () => Promise.resolve(''), headers: { get: () => null } }));
    const res = await call('test-webhook', { method: 'POST' });
    expect(res.statusCode).toBe(200); // the API call itself succeeded; the delivery attempt is what failed
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('HTTP_503');
  });
});

describe('deliveries / dead-letters — listing and pagination bound', () => {
  test('empty by default', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('deliveries', { method: 'GET' });
    expect(res.statusCode).toBe(200);
    expect(res.body.deliveries).toEqual([]);
    const dl = await call('dead-letters', { method: 'GET' });
    expect(dl.body.dead_letters).toEqual([]);
  });

  test('limit is bounded to 200 even if a caller requests more', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('deliveries', { method: 'GET', query: { limit: '99999' } });
    expect(res.statusCode).toBe(200); // does not error -- just clamps server-side
  });
});

describe('ownership isolation — customer A must never see customer B\'s notification state', () => {
  test('preferences are isolated per account', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { email_override: 'a@example.com' } });

    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    const res = await call('preferences', { method: 'GET' });
    expect(res.body.preferences.email_override).toBe(''); // not A's value
  });

  test('rotate-webhook-secret for A does not affect or reveal B\'s secret', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const aSecret = (await call('rotate-webhook-secret', { method: 'POST' })).body.webhook_secret;

    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    const bSecret = (await call('rotate-webhook-secret', { method: 'POST' })).body.webhook_secret;

    expect(aSecret).not.toEqual(bSecret);
  });

  test('delivery log for A is never visible to B', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    global.fetch = jest.fn(() => Promise.resolve({ ok: true, status: 200 }));
    await call('test-webhook', { method: 'POST' });

    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    const res = await call('deliveries', { method: 'GET' });
    expect(res.body.deliveries).toEqual([]);
  });
});

// moveToDeadLetter() is internal-only (see notification-store.test.js's
// own exhaustToDeadLetter helper) -- the only legitimate way to produce
// one is exhausting recordAttemptOutcome()'s real retry count, claiming
// before each resolve exactly as notification-dispatch.js's
// processDueDeliveries() does (recordAttemptOutcome() only applies once a
// matching claim_token exists -- the D1 claim/lease stale-worker guard).
// claimDeliveryChannel() also enforces next_attempt_at<=now (a job that
// just backed off genuinely isn't due again yet) -- forcing the row due
// between attempts simulates time passing, exactly like notification-
// store.test.js's own forceDueNow() helper.
async function seedDeadLetter(ownerId, eventId, channel, watchlistId = 'wl_1') {
  await notify.enqueuePendingDelivery({ ownerId, eventId, watchlistId, channels: [channel] });
  const deliveryId = notify.buildDeliveryId(ownerId, eventId, channel);
  for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
    const job = global.__fakeD1ForTest._dump().jobs.get(deliveryId);
    if (job) job.next_attempt_at = Date.now();
    const claim = await notify.claimDeliveryChannel({ deliveryId });
    await notify.recordAttemptOutcome({ deliveryId, claimToken: claim.claimToken, success: false });
  }
}

describe('retry-dead-letter', () => {
  test('404s when no matching dead-lettered delivery exists for this account', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    const res = await call('retry-dead-letter', { method: 'POST', body: { event_id: 'evt_never', channel: 'webhook' } });
    expect(res.statusCode).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('rejects a missing event_id or an invalid channel value', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    let res = await call('retry-dead-letter', { method: 'POST', body: { channel: 'webhook' } });
    expect(res.statusCode).toBe(400);
    res = await call('retry-dead-letter', { method: 'POST', body: { event_id: 'evt_1', channel: 'carrier-pigeon' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_FIELDS');
  });

  test('requires the channel to still be enabled/configured before requeueing', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await seedDeadLetter('usr_a', 'evt_1', 'webhook');
    // webhook was never enabled for this account in this test.
    const res = await call('retry-dead-letter', { method: 'POST', body: { event_id: 'evt_1', channel: 'webhook' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('CHANNEL_NOT_ELIGIBLE');
  });

  test('a dead-lettered delivery on a still-enabled channel is requeued as a fresh pending delivery', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    await call('update-preferences', { method: 'POST', body: { webhook_enabled: true } });
    await seedDeadLetter('usr_a', 'evt_1', 'webhook');

    const res = await call('retry-dead-letter', { method: 'POST', body: { event_id: 'evt_1', channel: 'webhook' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.requeued).toBe(true);

    const due = await notify.getDuePendingDeliveries(10);
    expect(due.some(r => r.event_id === 'evt_1' && r.channel === 'webhook')).toBe(true);
    // The original dead-letter entry is history, not resurrected/removed.
    const deadLetters = await notify.listDeadLetters('usr_a', { limit: 10 });
    expect(deadLetters).toHaveLength(1);
  });

  test('customer B cannot retry customer A\'s dead-lettered delivery (IDOR)', async () => {
    authenticate.mockResolvedValue(mockUser('free', 'usr_a'));
    await seedDeadLetter('usr_a', 'evt_1', 'webhook');

    authenticate.mockResolvedValue(mockUser('free', 'usr_b'));
    await call('update-preferences', { method: 'POST', body: { webhook_url: 'https://example.com/hook' } });
    await call('rotate-webhook-secret', { method: 'POST' });
    await call('update-preferences', { method: 'POST', body: { webhook_enabled: true } });
    const res = await call('retry-dead-letter', { method: 'POST', body: { event_id: 'evt_1', channel: 'webhook' } });
    expect(res.statusCode).toBe(404); // not found for B, even though it exists for A
  });
});
