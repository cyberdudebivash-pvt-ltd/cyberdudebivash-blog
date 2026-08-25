'use strict';

jest.mock('../redis', () => {
  const { createFakeRedis } = require('../__fixtures__/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});

const notify = require('../notification-store');

beforeEach(() => {
  global.__fakeRedisForTest._reset();
});

describe('preferences — defaults and updates', () => {
  test('defaults: email on (no override), webhook off, no secret', async () => {
    const prefs = await notify.getPreferences('usr_a');
    expect(prefs.email_enabled).toBe(true);
    expect(prefs.email_override).toBe('');
    expect(prefs.webhook_enabled).toBe(false);
    expect(prefs.webhook_url).toBe('');
    expect(prefs.has_webhook_secret).toBe(false);
  });

  test('updatePreferences persists and getPreferences reflects it', async () => {
    await notify.updatePreferences('usr_a', { email_enabled: false, email_override: 'ops@example.com' });
    const prefs = await notify.getPreferences('usr_a');
    expect(prefs.email_enabled).toBe(false);
    expect(prefs.email_override).toBe('ops@example.com');
  });

  test('partial update does not clobber unrelated fields', async () => {
    await notify.updatePreferences('usr_a', { webhook_url: 'https://example.com/hook' });
    await notify.updatePreferences('usr_a', { email_enabled: false });
    const prefs = await notify.getPreferences('usr_a');
    expect(prefs.webhook_url).toBe('https://example.com/hook'); // preserved
    expect(prefs.email_enabled).toBe(false);
  });

  test('preferences are isolated per owner', async () => {
    await notify.updatePreferences('usr_a', { webhook_url: 'https://a.example.com/hook' });
    await notify.updatePreferences('usr_b', { webhook_url: 'https://b.example.com/hook' });
    expect((await notify.getPreferences('usr_a')).webhook_url).toBe('https://a.example.com/hook');
    expect((await notify.getPreferences('usr_b')).webhook_url).toBe('https://b.example.com/hook');
  });
});

describe('rotateWebhookSecret — show-once discipline', () => {
  test('returns the raw secret once, but getPreferences never includes it', async () => {
    const secret = await notify.rotateWebhookSecret('usr_a');
    expect(secret).toMatch(/^whsec_/);
    const prefs = await notify.getPreferences('usr_a');
    expect(prefs.has_webhook_secret).toBe(true);
    expect(prefs.webhook_secret).toBeUndefined();
    expect(JSON.stringify(prefs)).not.toContain(secret);
  });

  test('getWebhookSecret (internal-only accessor) returns the current raw secret for signing', async () => {
    const secret = await notify.rotateWebhookSecret('usr_a');
    expect(await notify.getWebhookSecret('usr_a')).toBe(secret);
  });

  test('rotating again invalidates the previous secret', async () => {
    const first = await notify.rotateWebhookSecret('usr_a');
    const second = await notify.rotateWebhookSecret('usr_a');
    expect(first).not.toEqual(second);
    expect(await notify.getWebhookSecret('usr_a')).toBe(second);
  });
});

describe('delivery log', () => {
  test('records and lists deliveries newest-first', async () => {
    await notify.recordDelivery('usr_a', { channel: 'email', eventId: 'evt_1', status: 'delivered' });
    await new Promise(r => setTimeout(r, 2));
    await notify.recordDelivery('usr_a', { channel: 'webhook', eventId: 'evt_2', status: 'failed', error: 'HTTP_500' });
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log).toHaveLength(2);
    expect(log[0].event_id).toBe('evt_2'); // newest first
    expect(log[1].event_id).toBe('evt_1');
    expect(log[0].error).toBe('HTTP_500');
    expect(log[1].error).toBeNull();
  });

  test('delivery log is isolated per owner (no cross-tenant leakage)', async () => {
    await notify.recordDelivery('usr_a', { channel: 'email', eventId: 'evt_1', status: 'delivered' });
    await notify.recordDelivery('usr_b', { channel: 'email', eventId: 'evt_2', status: 'delivered' });
    expect(await notify.listDeliveries('usr_a', { limit: 10 })).toHaveLength(1);
    expect(await notify.listDeliveries('usr_b', { limit: 10 })).toHaveLength(1);
  });

  test('a long error string is truncated, not stored unbounded', async () => {
    await notify.recordDelivery('usr_a', { channel: 'webhook', eventId: 'evt_1', status: 'failed', error: 'x'.repeat(5000) });
    const log = await notify.listDeliveries('usr_a', { limit: 1 });
    expect(log[0].error.length).toBeLessThanOrEqual(300);
  });
});

describe('dead letter', () => {
  // moveToDeadLetter() is intentionally not exported -- the only legitimate
  // path to a dead letter is exhausting recordAttemptOutcome()'s own
  // retry count, exercised here exactly as it would happen in production
  // (not a direct call into an internal helper).
  async function exhaustToDeadLetter(ownerId, eventId, channel) {
    await notify.enqueuePendingDelivery({ ownerId, eventId, watchlistId: 'wl_1', channels: [channel] });
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      await notify.recordAttemptOutcome({ ownerId, eventId, channel, success: false });
    }
  }

  test('lists dead-lettered records newest-first, with real timestamps', async () => {
    await exhaustToDeadLetter('usr_a', 'evt_1', 'webhook');
    await new Promise(r => setTimeout(r, 2));
    await exhaustToDeadLetter('usr_a', 'evt_2', 'email');
    const list = await notify.listDeadLetters('usr_a', { limit: 10 });
    expect(list).toHaveLength(2);
    expect(list[0].event_id).toBe('evt_2'); // newest first
    expect(list[1].event_id).toBe('evt_1');
    expect(list[0].dead_lettered_at).toBeDefined();
  });

  test('dead letters are isolated per owner', async () => {
    await exhaustToDeadLetter('usr_a', 'evt_1', 'webhook');
    await exhaustToDeadLetter('usr_b', 'evt_2', 'webhook');
    expect(await notify.listDeadLetters('usr_a', { limit: 10 })).toHaveLength(1);
    expect(await notify.listDeadLetters('usr_b', { limit: 10 })).toHaveLength(1);
  });
});

describe('pending-delivery queue — enqueue, due-query, idempotency', () => {
  test('enqueue creates a record with both channels due immediately', async () => {
    const result = await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    expect(result.created).toBe(true);
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channels_pending.sort()).toEqual(['email', 'webhook']);
  });

  test('enqueuing the same (owner, event) twice is a no-op (idempotent)', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    const second = await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    expect(second.created).toBe(false);
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channels_pending).toEqual(['email']); // unaffected by the second, ignored call
  });

  test('enqueuing with zero channels is a no-op', async () => {
    const result = await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: [] });
    expect(result.created).toBe(false);
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
  });

  test('getDuePendingDeliveries respects the limit', async () => {
    for (let i = 0; i < 5; i++) {
      await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: `evt_${i}`, watchlistId: 'wl_1', channels: ['email'] });
    }
    expect(await notify.getDuePendingDeliveries(3)).toHaveLength(3);
    expect(await notify.getDuePendingDeliveries(100)).toHaveLength(5);
  });
});

describe('recordAttemptOutcome — success/failure/backoff/dead-letter, per channel', () => {
  test('success on one channel removes it from channels_pending, leaves the other untouched', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    await notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'email', success: true });
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channels_pending).toEqual(['webhook']);
  });

  test('success on all channels removes the record entirely', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    await notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'email', success: true });
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
  });

  test('failure schedules a backoff — the failed channel is not immediately due again', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    await notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'webhook', success: false });
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0); // 2-minute backoff, not due yet
  });

  test('a still-pending sibling channel keeps the record queryable even while the other channel backs off', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    await notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'webhook', success: false });
    // email is still due now (score = min of both channels' next_attempt_at)
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channels_pending).toContain('email');
    expect(due[0].channels_pending).toContain('webhook');
  });

  test('exhausting MAX_RETRY_ATTEMPTS dead-letters that channel and removes it from pending', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      await notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'webhook', success: false });
    }
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0); // record fully resolved
    const deadLetters = await notify.listDeadLetters('usr_a', { limit: 10 });
    expect(deadLetters).toHaveLength(1);
    expect(deadLetters[0].channel).toBe('webhook');
    expect(deadLetters[0].attempts).toBe(notify.MAX_RETRY_ATTEMPTS);
  });

  test('a dead-lettered channel does not block a still-retrying sibling channel on the same event', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      await notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'webhook', success: false });
    }
    // webhook is dead-lettered; email was never attempted and is still due.
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channels_pending).toEqual(['email']);
    expect(await notify.listDeadLetters('usr_a', { limit: 10 })).toHaveLength(1);
  });

  test('an outcome for an already-resolved (owner, event, channel) is a safe no-op', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    await notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'email', success: true });
    // Record no longer exists -- a second, late outcome call must not throw.
    await expect(notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_1', channel: 'email', success: false })).resolves.toBeUndefined();
  });

  test('an outcome for a channel never enqueued (unknown record) is a safe no-op', async () => {
    await expect(notify.recordAttemptOutcome({ ownerId: 'usr_a', eventId: 'evt_never_existed', channel: 'email', success: true })).resolves.toBeUndefined();
  });
});
