'use strict';

jest.mock('../redis', () => {
  const { createFakeRedis } = require('../__fixtures__/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});

const fakeResendState = { canSend: true, sendImpl: null };
jest.mock('../resend', () => ({
  canSendEmail: () => fakeResendState.canSend,
  sendEmail: (...args) => (fakeResendState.sendImpl ? fakeResendState.sendImpl(...args) : Promise.resolve({ id: 'email_test' })),
}));

// getEventById is the only change-engine surface notification-dispatch.js
// actually calls (lazily, to break the load-order cycle -- see that
// module's loadChangeEngine() docstring) -- mocked here so these tests
// don't need the full intel/watchable-state dependency chain just to
// produce a test event.
const fakeEvents = {};
jest.mock('../change-engine', () => ({
  getEventById: jest.fn((id) => Promise.resolve(fakeEvents[id] || null)),
}));

const dispatch = require('../notification-dispatch');
const notify = require('../notification-store');
const store = require('../watchlist-store');

function makeEvent(overrides = {}) {
  return {
    event_id: 'evt_1', entity_type: 'cve', entity_id: 'CVE-2026-1234',
    change_type: 'CVE_KEV_ADDED', importance: 'HIGH',
    before: { cisa_kev: false }, after: { cisa_kev: true },
    observed_at: new Date().toISOString(),
    source_refs: ['cisa_kev'], evidence_refs: ['CISA KEV catalog'],
    reason: 'This CVE was added to the CISA Known Exploited Vulnerabilities catalog.',
    recommended_action: 'Patch immediately per CISA federal mandate timelines.',
    ...overrides,
  };
}

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  Object.keys(fakeEvents).forEach(k => delete fakeEvents[k]);
  fakeResendState.canSend = true;
  fakeResendState.sendImpl = null;
  global.fetch = undefined;
});

afterEach(() => {
  global.fetch = undefined;
});

/* ───────────────────────── email content ───────────────────────── */

describe('buildWatchlistAlertEmail', () => {
  test('includes entity, importance, reason, and recommended action', () => {
    const email = dispatch.buildWatchlistAlertEmail({ event: makeEvent(), watchlistName: 'My Watchlist' });
    expect(email.subject).toContain('HIGH');
    expect(email.subject).toContain('CVE-2026-1234');
    expect(email.text).toContain('My Watchlist');
    expect(email.text).toContain('CISA Known Exploited Vulnerabilities');
    expect(email.html).toContain('CISA federal mandate');
  });

  test('escapes a malicious watchlist name in the html body but not the text body', () => {
    const malicious = '<script>alert(1)</script>My List';
    const email = dispatch.buildWatchlistAlertEmail({ event: makeEvent(), watchlistName: malicious });
    expect(email.html).not.toContain('<script>alert(1)</script>');
    expect(email.html).toContain('&lt;script&gt;');
    expect(email.text).toContain(malicious); // text body is never parsed as markup -- no escaping needed
  });

  test('escapes a malicious reason/recommended_action from upstream event data', () => {
    const event = makeEvent({
      reason: '<img src=x onerror=alert(1)>',
      recommended_action: '"><svg onload=alert(2)>',
    });
    const email = dispatch.buildWatchlistAlertEmail({ event, watchlistName: 'L' });
    expect(email.html).not.toContain('<img src=x onerror=alert(1)>');
    expect(email.html).not.toContain('<svg onload=alert(2)>');
  });

  test('campaign entities are labeled distinctly from CVEs', () => {
    const email = dispatch.buildWatchlistAlertEmail({
      event: makeEvent({ entity_type: 'campaign', entity_id: 'CAMP-001' }), watchlistName: 'L',
    });
    expect(email.text).toContain('Campaign: CAMP-001');
  });
});

/* ───────────────────────── per-channel delivery ───────────────────────── */

describe('deliverEmailChannel', () => {
  test('succeeds when resend is configured and an address is given', async () => {
    const result = await dispatch.deliverEmailChannel({ email: 'a@example.com', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(true);
  });

  test('fails with EMAIL_NOT_CONFIGURED when resend has no API key', async () => {
    fakeResendState.canSend = false;
    const result = await dispatch.deliverEmailChannel({ email: 'a@example.com', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(false);
    expect(result.error).toBe('EMAIL_NOT_CONFIGURED');
  });

  test('fails with NO_RECIPIENT when no address is resolvable', async () => {
    const result = await dispatch.deliverEmailChannel({ email: '', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(false);
    expect(result.error).toBe('NO_RECIPIENT');
  });

  test('a resend API error is caught and reported, not thrown', async () => {
    fakeResendState.sendImpl = () => Promise.reject(new Error('Resend error: invalid domain'));
    const result = await dispatch.deliverEmailChannel({ email: 'a@example.com', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(false);
    expect(result.error).toContain('invalid domain');
  });
});

describe('deliverWebhookChannel', () => {
  test('succeeds on a 2xx response and signs the request', async () => {
    let captured = null;
    global.fetch = jest.fn((url, opts) => {
      captured = { url, opts };
      return Promise.resolve({ ok: true, status: 200 });
    });
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 'test_secret', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(true);
    expect(captured.url).toBe('https://example.com/hook');
    expect(captured.opts.method).toBe('POST');
    expect(captured.opts.redirect).toBe('error');
    expect(captured.opts.headers['X-Sentinel-Signature']).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    const body = JSON.parse(captured.opts.body);
    expect(body.type).toBe('watchlist.change_event');
    expect(body.data.event_id).toBe('evt_1');
    expect(body.data.watchlist.id).toBe('wl_1');
  });

  test('rejects delivery to an unsafe URL before ever calling fetch', async () => {
    global.fetch = jest.fn();
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://169.254.169.254/latest/meta-data', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain('UNSAFE_URL');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('a non-2xx response is a failure carrying the status and a bounded error detail', async () => {
    global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 500, text: () => Promise.resolve('x'.repeat(10000)) }));
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain('HTTP_500');
    expect(result.error.length).toBeLessThan(4200);
  });

  test('a network error is caught and reported, not thrown', async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error('ECONNREFUSED')));
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toBe('ECONNREFUSED');
  });

  test('a hung request times out rather than blocking forever', async () => {
    global.fetch = jest.fn((url, opts) => new Promise((resolve, reject) => {
      opts.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    }));
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toBe('TIMEOUT');
  }, 15000);
});

/* ───────────────────────── orchestration ───────────────────────── */

describe('dispatchNewEvent — enqueue-only', () => {
  test('enqueues email when enabled and the owner has a resolvable account email', async () => {
    // user:id / user:key mirrors auth.js's real registration write shape.
    await global.__fakeRedisForTest.set('user:id:usr_a', 'hash123');
    await global.__fakeRedisForTest.hmset('user:key:hash123', { email: 'owner@example.com' });
    const result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    expect(result.enqueued).toBe(true);
    expect(result.channels).toEqual(['email']);
  });

  test('does not enqueue email when the account has no resolvable email and no override is set', async () => {
    const result = await dispatch.dispatchNewEvent({ ownerId: 'usr_no_account', watchlistId: 'wl_1', event: makeEvent() });
    expect(result.enqueued).toBe(false);
  });

  test('an explicit email_override enqueues email even with no resolvable account email', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'override@example.com' });
    const result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    expect(result.channels).toEqual(['email']);
  });

  test('enqueues webhook only when enabled, a URL is set, AND a secret exists', async () => {
    await notify.updatePreferences('usr_a', { email_enabled: false, webhook_enabled: true, webhook_url: 'https://example.com/hook' });
    // No secret yet -- webhook must not be enqueued.
    let result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent({ event_id: 'evt_a' }) });
    expect(result.enqueued).toBe(false);

    await notify.rotateWebhookSecret('usr_a');
    result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent({ event_id: 'evt_b' }) });
    expect(result.channels).toEqual(['webhook']);
  });

  test('enqueuing for the same event twice is idempotent (matches the underlying store guarantee)', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    const second = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    expect(second.enqueued).toBe(false);
  });
});

describe('processDueDeliveries — the sender (first attempt and retries share one path)', () => {
  test('delivers a due email successfully and records it in the delivery log', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    await store.createWatchlist({ ownerId: 'usr_a', name: 'My Watchlist' });
    const watchlists = await store.listWatchlists('usr_a');
    const wlId = watchlists[0].id;
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: wlId, event: fakeEvents['evt_1'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(1);
    expect(results.attempts).toBe(1);

    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log).toHaveLength(1);
    expect(log[0].status).toBe('delivered');
    expect(log[0].channel).toBe('email');
  });

  test('a failed delivery is scheduled for retry, not immediately dead-lettered', async () => {
    fakeResendState.sendImpl = () => Promise.reject(new Error('temporary failure'));
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(0);
    expect(results.retried).toBe(1);
    expect(await notify.listDeadLetters('usr_a', { limit: 10 })).toHaveLength(0);

    // Not due again immediately -- the next sweep finds nothing to do.
    const again = await dispatch.processDueDeliveries({ limit: 10 });
    expect(again.attempts).toBe(0);
  });

  test('an event deleted between enqueue and delivery fails cleanly instead of throwing', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    // Enqueue references an event_id that was never registered in fakeEvents.
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_missing', watchlistId: null, channels: ['email'] });
    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.attempts).toBe(1);
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log[0].error).toBe('EVENT_NOT_FOUND');
  });

  test('a watchlist deleted between enqueue and delivery falls back to a labeled placeholder name, not a crash', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    fakeEvents['evt_1'] = makeEvent();
    let capturedSubjectAndBody = null;
    fakeResendState.sendImpl = (args) => { capturedSubjectAndBody = args; return Promise.resolve({ id: 'x' }); };
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_does_not_exist', channels: ['email'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(1);
    expect(capturedSubjectAndBody.html).toContain('(deleted watchlist)');
  });

  test('respects the limit parameter across multiple due owners', async () => {
    for (const owner of ['usr_a', 'usr_b', 'usr_c']) {
      await notify.updatePreferences(owner, { email_override: `${owner}@example.com` });
      fakeEvents[`evt_${owner}`] = makeEvent({ event_id: `evt_${owner}` });
      await dispatch.dispatchNewEvent({ ownerId: owner, watchlistId: null, event: fakeEvents[`evt_${owner}`] });
    }
    const results = await dispatch.processDueDeliveries({ limit: 2 });
    expect(results.records_processed).toBe(2);
  });

  test('email and webhook channels on the same event are both attempted independently', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com', webhook_enabled: true, webhook_url: 'https://example.com/hook' });
    await notify.rotateWebhookSecret('usr_a');
    global.fetch = jest.fn(() => Promise.resolve({ ok: true, status: 200 }));
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(2);
    expect(global.fetch).toHaveBeenCalledTimes(1);
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log.map(d => d.channel).sort()).toEqual(['email', 'webhook']);
  });
});
