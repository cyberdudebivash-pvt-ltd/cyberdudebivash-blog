'use strict';

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const notify = require('../notification-store');

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

// Mirrors the real production flow (notification-dispatch.js's
// processDueDeliveries() always claims before resolving) -- the new D1
// schema's recordAttemptOutcome() only applies once a matching claim_token
// exists (the stale-worker guard), so a test resolving an outcome without
// first claiming is testing something that can no longer happen in
// production, not a corner the old Redis design could skip either.
//
// claimDeliveryChannel() also enforces next_attempt_at<=now -- correct,
// real production behavior (a job that just backed off genuinely is not
// due again until its backoff elapses, matching how a real scheduler
// would behave), but it means a tight test loop of repeated failures
// needs to simulate time actually passing between attempts, exactly like
// the "stale lease" tests below already do for lease_expires_at. Poking
// the fake's in-memory row directly (rather than a real sleep) keeps
// these tests fast without weakening what they prove: this is advancing
// a clock the fake owns, not bypassing any claim/token check itself.
function forceDueNow(deliveryId) {
  const job = global.__fakeD1ForTest._dump().jobs.get(deliveryId);
  if (job) job.next_attempt_at = Date.now();
}

async function claimAndResolve(deliveryId, outcome) {
  forceDueNow(deliveryId);
  const claim = await notify.claimDeliveryChannel({ deliveryId });
  return notify.recordAttemptOutcome({ deliveryId, claimToken: claim.claimToken, ...outcome });
}

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
    await notify.recordDelivery('usr_a', { channel: 'webhook', eventId: 'evt_2', status: 'failed', error: 'HTTP_500' });
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log).toHaveLength(2);
    expect(log[0].event_id).toBe('evt_2'); // newest first (insertion order via autoincrement id)
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
  // (claim -> resolve, not a direct call into an internal helper).
  async function exhaustToDeadLetter(ownerId, eventId, channel) {
    await notify.enqueuePendingDelivery({ ownerId, eventId, watchlistId: 'wl_1', channels: [channel] });
    const deliveryId = notify.buildDeliveryId(ownerId, eventId, channel);
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      await claimAndResolve(deliveryId, { success: false });
    }
  }

  test('lists dead-lettered records newest-first, with real timestamps', async () => {
    await exhaustToDeadLetter('usr_a', 'evt_1', 'webhook');
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

describe('pending-delivery queue — enqueue, due-query, idempotency (one row per channel)', () => {
  test('enqueue creates one due job row per channel', async () => {
    const result = await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    expect(result.created).toBe(true);
    expect(result.channels_created.sort()).toEqual(['email', 'webhook']);
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(2);
    expect(due.map(d => d.channel).sort()).toEqual(['email', 'webhook']);
  });

  test('enqueuing the same (owner, event, channel) twice is idempotent per channel', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    const second = await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    expect(second.created).toBe(false);
    expect(second.channels_created).toEqual([]);
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
  });

  test('re-enqueuing with a NEW channel on an already-enqueued event adds only that channel (partial-race safety)', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    const second = await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    expect(second.created).toBe(true);
    expect(second.channels_created).toEqual(['webhook']); // email already existed, only webhook is new
    const due = await notify.getDuePendingDeliveries(10);
    expect(due.map(d => d.channel).sort()).toEqual(['email', 'webhook']);
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

describe('recordAttemptOutcome — success/failure/backoff/dead-letter, per channel job', () => {
  test('success on one channel removes only that job, leaves the sibling channel untouched', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    await claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_1', 'email'), { success: true });
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channel).toBe('webhook');
  });

  test('success on the only channel removes it entirely', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    await claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_1', 'email'), { success: true });
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
  });

  test('failure schedules a backoff — the failed channel is not immediately due again', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    await claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_1', 'webhook'), { success: false });
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0); // 2-minute backoff, not due yet
  });

  test('a still-pending sibling channel stays queryable even while the other channel backs off', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    await claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_1', 'webhook'), { success: false });
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channel).toBe('email'); // still due now; webhook backed off independently
  });

  test('exhausting MAX_RETRY_ATTEMPTS dead-letters that channel and removes its job', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      await claimAndResolve(deliveryId, { success: false });
    }
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
    const deadLetters = await notify.listDeadLetters('usr_a', { limit: 10 });
    expect(deadLetters).toHaveLength(1);
    expect(deadLetters[0].channel).toBe('webhook');
    expect(deadLetters[0].attempts).toBe(notify.MAX_RETRY_ATTEMPTS);
  });

  test('a dead-lettered channel does not block a still-retrying sibling channel on the same event', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    const webhookId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      await claimAndResolve(webhookId, { success: false });
    }
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channel).toBe('email'); // never attempted, still due
    expect(await notify.listDeadLetters('usr_a', { limit: 10 })).toHaveLength(1);
  });

  test('an outcome for an already-resolved job (no matching claim) is a safe no-op', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'email');
    const claim = await notify.claimDeliveryChannel({ deliveryId });
    await notify.recordAttemptOutcome({ deliveryId, claimToken: claim.claimToken, success: true });
    // Job no longer exists -- a second, late outcome call (stale token) must
    // not throw, and reports 'unresolved' rather than silently finalizing
    // an outcome that isn't its to finalize (stale-worker guard).
    await expect(notify.recordAttemptOutcome({ deliveryId, claimToken: claim.claimToken, success: false })).resolves.toBe('unresolved');
  });

  test('an outcome using a token that never claimed anything is a safe no-op', async () => {
    await expect(notify.recordAttemptOutcome({ deliveryId: 'dlv_never_existed', claimToken: 'bogus', success: true })).resolves.toBe('unresolved');
  });

  test('return value reflects the actual disposition: delivered / retrying / dead_lettered', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    await expect(claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_1', 'email'), { success: false })).resolves.toBe('retrying');

    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_2', watchlistId: 'wl_1', channels: ['email'] });
    await expect(claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_2', 'email'), { success: true })).resolves.toBe('delivered');

    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_3', watchlistId: 'wl_1', channels: ['email'] });
    const deliveryId3 = notify.buildDeliveryId('usr_a', 'evt_3', 'email');
    let last;
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      last = await claimAndResolve(deliveryId3, { success: false });
    }
    expect(last).toBe('dead_lettered');
  });

  test('retryable:false dead-letters immediately, on the very first failure', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const disposition = await claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_1', 'webhook'), { success: false, retryable: false });
    expect(disposition).toBe('dead_lettered');
    const deadLetters = await notify.listDeadLetters('usr_a', { limit: 10 });
    expect(deadLetters[0].reason).toBe('PERMANENT_FAILURE');
    expect(deadLetters[0].attempts).toBe(1); // did not burn through MAX_RETRY_ATTEMPTS first
  });

  test('MAX_RETRY_ATTEMPTS exhaustion (no explicit retryable:false) is labeled distinctly from a permanent failure', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    for (let i = 0; i < notify.MAX_RETRY_ATTEMPTS; i++) {
      await claimAndResolve(deliveryId, { success: false, retryable: true });
    }
    const deadLetters = await notify.listDeadLetters('usr_a', { limit: 10 });
    expect(deadLetters[0].reason).toBe('MAX_RETRY_ATTEMPTS_EXHAUSTED');
  });

  test('retryAfterSeconds overrides the normal backoff table, bounded by MAX_RETRY_AFTER_SECONDS', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    const before = Date.now();
    await claimAndResolve(deliveryId, { success: false, retryAfterSeconds: 999999 });
    const [job] = global.__fakeD1ForTest._dump().jobs.has(deliveryId) ? [global.__fakeD1ForTest._dump().jobs.get(deliveryId)] : [null];
    const delayMs = job.next_attempt_at - before;
    // Bounded to MAX_RETRY_AFTER_SECONDS even though a much larger value
    // was requested -- a malicious endpoint cannot defer delivery
    // indefinitely via Retry-After.
    expect(delayMs).toBeLessThanOrEqual(notify.MAX_RETRY_AFTER_SECONDS * 1000 + 50);
    expect(delayMs).toBeGreaterThan(notify.MAX_RETRY_AFTER_SECONDS * 1000 - 5000);
  });
});

describe('cancelDeliveryChannel — clean disable-mid-flight removal', () => {
  test('removes a channel job without dead-lettering or bumping its attempt count', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    await notify.cancelDeliveryChannel({ deliveryId: notify.buildDeliveryId('usr_a', 'evt_1', 'webhook') });
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channel).toBe('email');
    expect(await notify.listDeadLetters('usr_a', { limit: 10 })).toHaveLength(0);
  });

  test('cancelling the last pending channel leaves nothing due', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email'] });
    await notify.cancelDeliveryChannel({ deliveryId: notify.buildDeliveryId('usr_a', 'evt_1', 'email') });
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
  });

  test('cancelling an unknown delivery id is a safe no-op', async () => {
    await expect(notify.cancelDeliveryChannel({ deliveryId: 'dlv_never' })).resolves.toBeUndefined();
  });
});

describe('buildDeliveryId — stable identity, not a fresh ID per attempt', () => {
  test('same (owner, event, channel) always produces the same id', () => {
    const a = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    const b = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    expect(a).toBe(b);
    expect(a).toMatch(/^dlv_/);
  });

  test('differs by owner, event, or channel independently', () => {
    const base = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    expect(notify.buildDeliveryId('usr_b', 'evt_1', 'webhook')).not.toBe(base);
    expect(notify.buildDeliveryId('usr_a', 'evt_2', 'webhook')).not.toBe(base);
    expect(notify.buildDeliveryId('usr_a', 'evt_1', 'email')).not.toBe(base);
  });
});

describe('claimDeliveryChannel / releaseDeliveryChannel — atomic claim with lease + claim-token stale-worker guard', () => {
  test('first claim succeeds with a token; a concurrent second claim on the same delivery fails', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    const first = await notify.claimDeliveryChannel({ deliveryId });
    const second = await notify.claimDeliveryChannel({ deliveryId });
    expect(first.claimed).toBe(true);
    expect(first.claimToken).toEqual(expect.any(String));
    expect(second.claimed).toBe(false);
    expect(second.claimToken).toBeNull();
  });

  test('two concurrent claims issued via Promise.all — exactly one wins, proving the claim is genuinely atomic', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    const [a, b] = await Promise.all([
      notify.claimDeliveryChannel({ deliveryId }),
      notify.claimDeliveryChannel({ deliveryId }),
    ]);
    const claimedCount = [a, b].filter(r => r.claimed).length;
    expect(claimedCount).toBe(1);
  });

  test('claiming an unknown delivery id fails cleanly', async () => {
    const result = await notify.claimDeliveryChannel({ deliveryId: 'dlv_never' });
    expect(result.claimed).toBe(false);
  });

  test('releasing lets a subsequent claim succeed again', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    const claim = await notify.claimDeliveryChannel({ deliveryId });
    await notify.releaseDeliveryChannel({ deliveryId, claimToken: claim.claimToken });
    expect((await notify.claimDeliveryChannel({ deliveryId })).claimed).toBe(true);
  });

  test('releasing with the WRONG claim token is a safe no-op — does not release someone else\'s live claim', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    await notify.claimDeliveryChannel({ deliveryId }); // holder A
    await notify.releaseDeliveryChannel({ deliveryId, claimToken: 'not-the-real-token' });
    // Still claimed by holder A -- a stale/forged token must not release it.
    expect((await notify.claimDeliveryChannel({ deliveryId })).claimed).toBe(false);
  });

  test('releasing an unclaimed delivery is a safe no-op', async () => {
    await expect(notify.releaseDeliveryChannel({ deliveryId: 'dlv_never', claimToken: 'x' })).resolves.toBeUndefined();
  });

  test('claims on different channels of the same event are independent', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['email', 'webhook'] });
    expect((await notify.claimDeliveryChannel({ deliveryId: notify.buildDeliveryId('usr_a', 'evt_1', 'email') })).claimed).toBe(true);
    expect((await notify.claimDeliveryChannel({ deliveryId: notify.buildDeliveryId('usr_a', 'evt_1', 'webhook') })).claimed).toBe(true);
  });

  test('a stale claim (lease expired) is reclaimable by a new claim with a fresh token', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    const first = await notify.claimDeliveryChannel({ deliveryId });
    expect(first.claimed).toBe(true);
    // Simulate lease expiry directly on the fake's in-memory row (this
    // proves claimDeliveryChannel()'s own WHERE clause performs the
    // recovery, not a separate sweep -- exactly mirroring how the real D1
    // WHERE clause has no separate cleanup job either).
    global.__fakeD1ForTest._dump().jobs.get(deliveryId).lease_expires_at = Date.now() - 1;
    const second = await notify.claimDeliveryChannel({ deliveryId });
    expect(second.claimed).toBe(true);
    expect(second.claimToken).not.toBe(first.claimToken);
  });

  test('a worker holding an expired, reclaimed token can never finalize the newer claim\'s outcome (stale-worker guard)', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    const deliveryId = notify.buildDeliveryId('usr_a', 'evt_1', 'webhook');
    const staleClaim = await notify.claimDeliveryChannel({ deliveryId });
    global.__fakeD1ForTest._dump().jobs.get(deliveryId).lease_expires_at = Date.now() - 1; // simulate expiry
    const freshClaim = await notify.claimDeliveryChannel({ deliveryId });
    expect(freshClaim.claimToken).not.toBe(staleClaim.claimToken);

    // The original (now-stale) worker finally finishes and tries to
    // record its outcome -- must be rejected, not silently applied.
    const disposition = await notify.recordAttemptOutcome({ deliveryId, claimToken: staleClaim.claimToken, success: true });
    expect(disposition).toBe('unresolved');
    // The job is still legitimately claimed by the fresh holder.
    expect(global.__fakeD1ForTest._dump().jobs.get(deliveryId).claim_token).toBe(freshClaim.claimToken);
  });
});

describe('auditNotificationAction', () => {
  test('writes an entry to the audit log, never a secret value', async () => {
    await notify.auditNotificationAction('usr_a', 'WEBHOOK_SECRET_ROTATED');
    const entries = global.__fakeD1ForTest._dump().auditLog;
    expect(entries).toHaveLength(1);
    expect(entries[0].owner_id).toBe('usr_a');
    expect(entries[0].action).toBe('WEBHOOK_SECRET_ROTATED');
    expect(entries[0].ts).toBeDefined();
  });

  test('a logging failure never throws or blocks the caller', async () => {
    const original = global.__fakeD1ForTest.run;
    global.__fakeD1ForTest.run = () => { throw new Error('d1 down'); };
    await expect(notify.auditNotificationAction('usr_a', 'PREFERENCES_UPDATED')).resolves.toBeUndefined();
    global.__fakeD1ForTest.run = original;
  });
});

describe('getOldestPendingAgeSeconds — observability', () => {
  test('null when the queue is empty', async () => {
    expect(await notify.getOldestPendingAgeSeconds()).toBeNull();
  });

  test('0 (not negative) when the only pending item is not yet due', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] });
    await claimAndResolve(notify.buildDeliveryId('usr_a', 'evt_1', 'webhook'), { success: false }); // schedules a future backoff
    expect(await notify.getOldestPendingAgeSeconds()).toBe(0);
  });

  test('reflects how overdue the most-overdue item is once its next_attempt_at has passed', async () => {
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_1', channels: ['webhook'] }); // due immediately (now)
    await new Promise(r => setTimeout(r, 20));
    const age = await notify.getOldestPendingAgeSeconds();
    expect(age).toBeGreaterThanOrEqual(0);
  });
});
