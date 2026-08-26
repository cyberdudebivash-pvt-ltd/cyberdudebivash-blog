'use strict';

// Covers the Redis-shape-to-D1-shape mapping logic specifically -- the
// one part of this migration tool that is genuinely untested elsewhere
// (its D1 write calls reuse the exact same statement shapes notification-
// store.js's own tests already exercise; its Redis reads use the exact
// same redis.js client the fake-redis fixture already faithfully
// simulates). See jest.config.js's roots comment for why scripts/ is
// covered at all, unlike this repo's other CLI scripts.

jest.mock('../../api/_lib/redis', () => {
  const { createFakeRedis } = require('../../api/_lib/__fixtures__/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});
jest.mock('../../api/_lib/d1', () => {
  const { createFakeD1 } = require('../../api/_lib/__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const { migratePreferences, migratePendingDeliveries, migrateLogEntries } = require('../migrate-notifications-redis-to-d1');
const notify = require('../../api/_lib/notification-store');

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  global.__fakeD1ForTest._reset();
});

describe('migratePreferences', () => {
  test('dry run: counts what would migrate, writes nothing to D1', async () => {
    await global.__fakeRedisForTest.hmset('notify:prefs:usr_a', { email_enabled: 'false', webhook_url: 'https://example.com/hook' });
    const counts = { preferences_found: 0, preferences_migrated: 0 };
    await migratePreferences({ apply: false, verbose: false, counts });
    expect(counts.preferences_found).toBe(1);
    expect(counts.preferences_migrated).toBe(0);
    expect(await notify.getPreferences('usr_a')).toMatchObject({ email_enabled: true }); // untouched -- still the pre-migration default
  });

  test('apply: maps Redis hash string fields onto real D1 columns/types correctly', async () => {
    await global.__fakeRedisForTest.hmset('notify:prefs:usr_a', {
      email_enabled: 'false', email_override: 'ops@example.com',
      webhook_enabled: 'true', webhook_url: 'https://example.com/hook',
      webhook_secret: 'whsec_abc123', webhook_configured_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-02T00:00:00.000Z',
    });
    const counts = { preferences_found: 0, preferences_migrated: 0 };
    await migratePreferences({ apply: true, verbose: false, counts });
    expect(counts.preferences_migrated).toBe(1);

    const prefs = await notify.getPreferences('usr_a');
    expect(prefs.email_enabled).toBe(false); // 'false' string correctly becomes boolean false, not truthy
    expect(prefs.email_override).toBe('ops@example.com');
    expect(prefs.webhook_enabled).toBe(true);
    expect(prefs.webhook_url).toBe('https://example.com/hook');
    expect(prefs.has_webhook_secret).toBe(true);
    expect(await notify.getWebhookSecret('usr_a')).toBe('whsec_abc123');
  });

  test('apply: multiple owners are migrated independently, no cross-contamination', async () => {
    await global.__fakeRedisForTest.hmset('notify:prefs:usr_a', { webhook_url: 'https://a.example.com/hook' });
    await global.__fakeRedisForTest.hmset('notify:prefs:usr_b', { webhook_url: 'https://b.example.com/hook' });
    const counts = { preferences_found: 0, preferences_migrated: 0 };
    await migratePreferences({ apply: true, verbose: false, counts });
    expect(counts.preferences_found).toBe(2);
    expect((await notify.getPreferences('usr_a')).webhook_url).toBe('https://a.example.com/hook');
    expect((await notify.getPreferences('usr_b')).webhook_url).toBe('https://b.example.com/hook');
  });

  test('re-running apply is idempotent for preferences (D1 upsert, not a duplicate row)', async () => {
    await global.__fakeRedisForTest.hmset('notify:prefs:usr_a', { webhook_url: 'https://example.com/hook' });
    const counts = { preferences_found: 0, preferences_migrated: 0 };
    await migratePreferences({ apply: true, verbose: false, counts });
    await migratePreferences({ apply: true, verbose: false, counts });
    expect(global.__fakeD1ForTest._dump().preferences.size).toBe(1);
  });
});

describe('migratePendingDeliveries', () => {
  test('dry run: counts jobs found, writes nothing to D1', async () => {
    await global.__fakeRedisForTest.set('notify:pending:usr_a:evt_1', JSON.stringify({
      owner_id: 'usr_a', event_id: 'evt_1', watchlist_id: 'wl_1',
      channels_pending: ['email', 'webhook'],
      attempts: { email: { count: 0, next_attempt_at: Date.now() }, webhook: { count: 1, next_attempt_at: Date.now() + 60000 } },
      created_at: new Date().toISOString(),
    }));
    const counts = { pending_jobs_found: 0, pending_jobs_migrated: 0 };
    await migratePendingDeliveries({ apply: false, verbose: false, counts });
    expect(counts.pending_jobs_found).toBe(2);
    expect(counts.pending_jobs_migrated).toBe(0);
    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
  });

  test('apply: creates one D1 job row per pending channel, preserving each channel\'s own attempt count/schedule', async () => {
    const emailNextAttempt = Date.now(); // due now
    const webhookNextAttempt = Date.now() + 3600000; // not due for an hour
    await global.__fakeRedisForTest.set('notify:pending:usr_a:evt_1', JSON.stringify({
      owner_id: 'usr_a', event_id: 'evt_1', watchlist_id: 'wl_1',
      channels_pending: ['email', 'webhook'],
      attempts: {
        email: { count: 0, next_attempt_at: emailNextAttempt },
        webhook: { count: 2, next_attempt_at: webhookNextAttempt },
      },
      created_at: new Date().toISOString(),
    }));
    const counts = { pending_jobs_found: 0, pending_jobs_migrated: 0 };
    await migratePendingDeliveries({ apply: true, verbose: false, counts });
    expect(counts.pending_jobs_migrated).toBe(2);

    // Only email is due right now -- webhook's own backoff was preserved,
    // not reset to "due immediately" by the migration.
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(1);
    expect(due[0].channel).toBe('email');

    const webhookJob = global.__fakeD1ForTest._dump().jobs.get(notify.buildDeliveryId('usr_a', 'evt_1', 'webhook'));
    expect(webhookJob.attempt_count).toBe(2);
    expect(webhookJob.next_attempt_at).toBe(webhookNextAttempt);
  });

  test('re-running apply is idempotent per channel (INSERT...ON CONFLICT DO NOTHING, not a duplicate job)', async () => {
    await global.__fakeRedisForTest.set('notify:pending:usr_a:evt_1', JSON.stringify({
      owner_id: 'usr_a', event_id: 'evt_1', watchlist_id: 'wl_1',
      channels_pending: ['email'], attempts: { email: { count: 0, next_attempt_at: Date.now() } },
      created_at: new Date().toISOString(),
    }));
    const counts = { pending_jobs_found: 0, pending_jobs_migrated: 0 };
    await migratePendingDeliveries({ apply: true, verbose: false, counts });
    await migratePendingDeliveries({ apply: true, verbose: false, counts });
    expect(global.__fakeD1ForTest._dump().jobs.size).toBe(1);
  });

  test('a record with no channels_pending (already fully resolved) migrates nothing', async () => {
    await global.__fakeRedisForTest.set('notify:pending:usr_a:evt_1', JSON.stringify({
      owner_id: 'usr_a', event_id: 'evt_1', watchlist_id: 'wl_1', channels_pending: [], attempts: {},
    }));
    const counts = { pending_jobs_found: 0, pending_jobs_migrated: 0 };
    await migratePendingDeliveries({ apply: true, verbose: false, counts });
    expect(counts.pending_jobs_found).toBe(0);
  });
});

describe('migrateLogEntries — delivery log / dead letters / audit log', () => {
  test('migrates historical delivery-log entries with correct field mapping', async () => {
    await global.__fakeRedisForTest.zadd('notify:delivery_log:usr_a', Date.now(), JSON.stringify({
      channel: 'webhook', event_id: 'evt_1', watchlist_id: 'wl_1', status: 'delivered', error: null, attempt: 1, attempted_at: new Date().toISOString(),
    }));
    const counts = {};
    await migrateLogEntries({
      label: 'delivery_log', keyPattern: 'notify:delivery_log:*', keyPrefix: 'notify:delivery_log:',
      insertSql: `INSERT INTO notification_delivery_log (owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      buildParams: (ownerId, e) => [ownerId, e.channel, e.event_id, e.watchlist_id || null, e.status, e.error || null, e.attempt || 0, e.attempted_at],
      apply: true, verbose: false, counts,
    });
    expect(counts.delivery_log_migrated).toBe(1);
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log[0]).toMatchObject({ channel: 'webhook', event_id: 'evt_1', status: 'delivered' });
  });

  test('a second --apply run duplicates historical rows -- the disclosed, accepted limitation for log/audit history', async () => {
    await global.__fakeRedisForTest.zadd('notify:delivery_log:usr_a', Date.now(), JSON.stringify({
      channel: 'email', event_id: 'evt_1', status: 'delivered', attempt: 0, attempted_at: new Date().toISOString(),
    }));
    const run = () => migrateLogEntries({
      label: 'delivery_log', keyPattern: 'notify:delivery_log:*', keyPrefix: 'notify:delivery_log:',
      insertSql: `INSERT INTO notification_delivery_log (owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      buildParams: (ownerId, e) => [ownerId, e.channel, e.event_id, e.watchlist_id || null, e.status, e.error || null, e.attempt || 0, e.attempted_at],
      apply: true, verbose: false, counts: {},
    });
    await run();
    await run();
    // Documented behavior, not a bug: history entries have no natural
    // shared unique key, so a second apply run duplicates them. Contrast
    // with migratePreferences/migratePendingDeliveries above, which ARE
    // idempotent -- this test exists so that distinction stays true, not
    // to endorse re-running --apply twice in a real environment.
    expect((await notify.listDeliveries('usr_a', { limit: 10 })).length).toBe(2);
  });
});
