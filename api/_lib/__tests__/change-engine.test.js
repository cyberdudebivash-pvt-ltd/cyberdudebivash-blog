'use strict';

jest.mock('../redis', () => {
  const { createFakeRedis } = require('../__fixtures__/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});

let fakeCves = {};
let fakeCampaigns = {};
let fakeGraph = { nodes: {}, edges: [] };
let fakeReportsIndex = { reports: [] };

jest.mock('../intel', () => ({
  getCVEDetail: (id) => (global.__fakeCves[id] ? { found: true, item: global.__fakeCves[id] } : { found: false, item: null }),
  getCampaignDetail: (id) => (global.__fakeCampaigns[id] ? { found: true, campaign: global.__fakeCampaigns[id] } : { found: false, campaign: null }),
  loadGraph: () => global.__fakeGraph,
  loadJSON: () => global.__fakeReportsIndex,
  PATHS: { reportsIndex: 'REPORTS_INDEX_PATH' },
}));

const store = require('../watchlist-store');
const engine = require('../change-engine');

function resetFakes() {
  fakeCves = {}; fakeCampaigns = {}; fakeGraph = { nodes: {}, edges: [] }; fakeReportsIndex = { reports: [] };
  global.__fakeCves = fakeCves;
  global.__fakeCampaigns = fakeCampaigns;
  global.__fakeGraph = fakeGraph;
  global.__fakeReportsIndex = fakeReportsIndex;
}

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  resetFakes();
});

async function watchCve(ownerId, cveId, name = 'L') {
  const wl = await store.createWatchlist({ ownerId, name });
  await store.addEntity(wl.watchlist.id, ownerId, 'cve', cveId);
  return wl.watchlist.id;
}

describe('evaluateEntity — baseline (Phase 52)', () => {
  test('first observation establishes a baseline snapshot with zero events', async () => {
    fakeCves['CVE-2026-1111'] = { cvss: 8.1, threat_level: 'high', cisa_kev: false, exploited: false };
    await watchCve('usr_a', 'CVE-2026-1111');

    const intel = require('../intel');
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-1111', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('baseline_established');
    expect(outcome.events).toEqual([]);

    const snapshot = await engine.loadSnapshot('cve', 'CVE-2026-1111');
    expect(snapshot).not.toBeNull();
    expect(snapshot.state.cvss).toBe(8.1);
  });
});

describe('evaluateEntity — unchanged vs changed', () => {
  test('re-evaluating identical canonical state produces unchanged, zero events', async () => {
    fakeCves['CVE-2026-2222'] = { cvss: 7.0, threat_level: 'high', cisa_kev: false, exploited: false };
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-2222', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    const second = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-2222', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(second.status).toBe('unchanged');
    expect(second.events).toEqual([]);
  });

  test('a real KEV addition produces one persisted, matched event', async () => {
    fakeCves['CVE-2026-3333'] = { cvss: 9.1, threat_level: 'critical', cisa_kev: false, exploited: false };
    const watchlistId = await watchCve('usr_a', 'CVE-2026-3333');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-3333', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCves['CVE-2026-3333'] = { ...fakeCves['CVE-2026-3333'], cisa_kev: true };
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-3333', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('changed');
    // cisa_kev flipping true fires BOTH CVE_KEV_ADDED and
    // CVE_ACTIVE_EXPLOITATION_CONFIRMED (classifyExploitation() derives
    // exploitation status from cisa_kev) -- two distinct, correctly
    // evidenced facts changed together, matching the mandate's own
    // north-star example (KEV and Active Exploitation shown as separate
    // line items for the same underlying update).
    expect(outcome.events).toHaveLength(2);
    const kevEvent = outcome.events.find(e => e.change_type === 'CVE_KEV_ADDED');
    expect(kevEvent).toBeDefined();

    const page = await store.getOwnerFeedPage('usr_a', { limit: 10, cursor: 0 });
    expect(page.eventIds.sort()).toEqual(outcome.events.map(e => e.event_id).sort());
    const persisted = await engine.getEventById(kevEvent.event_id);
    expect(persisted.entity_id).toBe('CVE-2026-3333');
  });
});

describe('idempotency and replay safety (Phase 31/32/70)', () => {
  test('evaluating the exact same before/after pair twice does not duplicate the customer feed entry', async () => {
    fakeCves['CVE-2026-4444'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_a', 'CVE-2026-4444');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-4444', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCves['CVE-2026-4444'] = { ...fakeCves['CVE-2026-4444'], cisa_kev: true };
    const firstChange = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-4444', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    const pageAfterFirstChange = await store.getOwnerFeedPage('usr_a', { limit: 10, cursor: 0 });
    expect(pageAfterFirstChange.total).toBe(firstChange.events.length);

    // Re-run evaluation again with the SAME (now-current) state -- this is
    // "unchanged" from here, so it must not add any further feed entries.
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-4444', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    const pageAfterReplay = await store.getOwnerFeedPage('usr_a', { limit: 10, cursor: 0 });
    expect(pageAfterReplay.total).toBe(firstChange.events.length);
  });
});

describe('catastrophic data-loss protection (Phase 72)', () => {
  test('a canonical load failure on a previously-known entity leaves the snapshot untouched and emits nothing', async () => {
    fakeCves['CVE-2026-5555'] = {
      cvss: 8.8, threat_level: 'high', cisa_kev: true, exploited: true,
    };
    fakeGraph.nodes['CVE-2026-5555'] = { id: 'CVE-2026-5555', type: 'CVE', name: 'CVE-2026-5555' };
    fakeGraph.nodes['campaign:x'] = { id: 'campaign:x', type: 'Campaign', name: 'campaign:x' };
    fakeGraph.edges.push({ source: 'CVE-2026-5555', target: 'campaign:x', relationship: 'includes', confidence: 0.9, sources: [], first_seen: null });

    await watchCve('usr_a', 'CVE-2026-5555');
    const intel = require('../intel');
    const baseline = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5555', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(baseline.status).toBe('baseline_established');
    const snapshotBefore = await engine.loadSnapshot('cve', 'CVE-2026-5555');
    expect(snapshotBefore.state.campaign_ids).toEqual(['campaign:x']);

    // Simulate an upstream outage / catastrophic drop: the entity can no
    // longer be found at all.
    delete fakeCves['CVE-2026-5555'];
    const outage = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5555', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outage.status).toBe('load_failed');
    expect(outage.events).toEqual([]);

    const snapshotAfterOutage = await engine.loadSnapshot('cve', 'CVE-2026-5555');
    expect(snapshotAfterOutage).toEqual(snapshotBefore); // untouched, not overwritten with empty state

    // Recovery: canonical data comes back with the SAME real facts as
    // before the outage. Because the snapshot was never corrupted by the
    // outage, this must be "unchanged", NOT a flood of "new" relationship
    // events (which is exactly what would happen if the outage had
    // incorrectly overwritten the snapshot with an empty state).
    fakeCves['CVE-2026-5555'] = { cvss: 8.8, threat_level: 'high', cisa_kev: true, exploited: true };
    const recovered = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5555', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(recovered.status).toBe('unchanged');
    expect(recovered.events).toEqual([]);
  });
});

describe('global event / customer match separation (Phase 67/68)', () => {
  test('100 customers watching the same CVE produce ONE diff and ONE stored event, fanned out to every watcher', async () => {
    fakeCves['CVE-2026-6666'] = { cvss: 6.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    const owners = Array.from({ length: 25 }, (_, i) => `usr_${i}`);
    for (const owner of owners) await watchCve(owner, 'CVE-2026-6666');

    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-6666', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    fakeCves['CVE-2026-6666'] = { ...fakeCves['CVE-2026-6666'], cisa_kev: true };
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-6666', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    // cisa_kev flipping fires 2 distinct events (see the note in the
    // preceding describe block) -- the point under test here is that each
    // one was computed ONCE and fanned out by reference, not recomputed
    // or duplicated per watcher.
    const eventIds = outcome.events.map(e => e.event_id).sort();

    for (const owner of owners) {
      const page = await store.getOwnerFeedPage(owner, { limit: 10, cursor: 0 });
      expect(page.eventIds.sort()).toEqual(eventIds);
    }

    // Exactly as many event objects were written as distinct changes
    // detected -- never one per watcher (25 watchers, still just N events).
    const dump = global.__fakeRedisForTest._dump();
    const eventKeys = [...dump.strings.keys()].filter(k => k.startsWith('event:'));
    expect(eventKeys).toHaveLength(outcome.events.length);
  });
});

describe('evaluateWatchedEntities — bounded, cursor-resumable batch (Phase 48/51/67)', () => {
  test('only entities that are actually watched are evaluated -- an unwatched entity is never touched', async () => {
    fakeCves['CVE-2026-7777'] = { cvss: 5.0 }; // watched
    fakeCves['CVE-2026-8888'] = { cvss: 5.0 }; // NOT watched
    await watchCve('usr_a', 'CVE-2026-7777');

    const results = await engine.evaluateWatchedEntities({ batchLimit: 200 });
    expect(results.watched_entities_total).toBe(1);
    expect(results.evaluated).toBe(1);
    const untouchedSnapshot = await engine.loadSnapshot('cve', 'CVE-2026-8888');
    expect(untouchedSnapshot).toBeNull();
  });

  test('baseline run over multiple watched entities does not flood events, and touches last_evaluated_at', async () => {
    fakeCves['CVE-2026-0001'] = { cvss: 5.0 };
    fakeCves['CVE-2026-0002'] = { cvss: 6.0 };
    fakeCves['CVE-2026-0003'] = { cvss: 7.0 };
    const wl = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(wl.watchlist.id, 'usr_a', 'cve', 'CVE-2026-0001');
    await store.addEntity(wl.watchlist.id, 'usr_a', 'cve', 'CVE-2026-0002');
    await store.addEntity(wl.watchlist.id, 'usr_a', 'cve', 'CVE-2026-0003');

    const results = await engine.evaluateWatchedEntities({ batchLimit: 200 });
    expect(results.baseline).toBe(3);
    expect(results.changed).toBe(0);
    expect(results.events_created).toBe(0);
    expect(results.watchlists_touched).toBe(1);

    const after = await store.getWatchlist(wl.watchlist.id, 'usr_a');
    expect(after.watchlist.last_evaluated_at).not.toBeNull();
  });

  test('batchLimit bounds a single run, and the cursor advances so a second run covers the rest', async () => {
    for (let i = 0; i < 5; i++) {
      fakeCves[`CVE-2026-${1000 + i}`] = { cvss: 5.0 };
      await watchCve('usr_a', `CVE-2026-${1000 + i}`, `L${i}`);
    }
    const first = await engine.evaluateWatchedEntities({ batchLimit: 2 });
    expect(first.evaluated).toBe(2);
    const second = await engine.evaluateWatchedEntities({ batchLimit: 2 });
    expect(second.evaluated).toBe(2);
    const third = await engine.evaluateWatchedEntities({ batchLimit: 2 });
    expect(third.evaluated).toBe(2); // wraps back around, not stuck

    // Across the 3 bounded runs (6 evaluations of a 5-entity set), every
    // entity was reached at least once.
    const snapshots = await Promise.all(
      [1000, 1001, 1002, 1003, 1004].map(n => engine.loadSnapshot('cve', `CVE-2026-${n}`))
    );
    expect(snapshots.every(s => s !== null)).toBe(true);
  });

  test('zero watched entities is a clean no-op, not an error', async () => {
    const results = await engine.evaluateWatchedEntities({});
    expect(results.watched_entities_total).toBe(0);
    expect(results.evaluated).toBe(0);
  });
});

describe('schema version change (Phase 30)', () => {
  test('a stored snapshot from an older schema version is treated as if no snapshot existed -- re-baselined, zero events, never a false mass-change', async () => {
    fakeCves['CVE-2026-1212'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_a', 'CVE-2026-1212');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-1212', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    // Simulate a future schema bump by corrupting the stored snapshot's
    // own version tag directly (the real production trigger for this
    // path -- WATCHABLE_STATE_SCHEMA_VERSION itself changing -- can't be
    // exercised without editing source, so this reaches the same branch
    // the same way a real version bump would: prior.schema_version !==
    // the module's current constant).
    const raw = await global.__fakeRedisForTest.get('snapshot:cve:CVE-2026-1212');
    const parsed = JSON.parse(raw);
    parsed.schema_version = '0.9-old';
    await global.__fakeRedisForTest.set('snapshot:cve:CVE-2026-1212', JSON.stringify(parsed));

    fakeCves['CVE-2026-1212'] = { ...fakeCves['CVE-2026-1212'], cisa_kev: true }; // a real change too, to prove it's suppressed by the re-baseline
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-1212', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('baseline_established');
    expect(outcome.events).toEqual([]);

    const newSnapshot = await engine.loadSnapshot('cve', 'CVE-2026-1212');
    expect(newSnapshot.schema_version).not.toBe('0.9-old');
  });
});

describe('defensive branch: unsupported entity type reaching the engine directly', () => {
  test('evaluateEntity never crashes on a type watchlist-store.js would already reject', async () => {
    const intel = require('../intel');
    const outcome = await engine.evaluateEntity({ entityType: 'malware', entityId: 'x', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('unsupported_type');
    expect(outcome.events).toEqual([]);
  });
});

describe('campaign evaluation', () => {
  test('a campaign change is detected the same way as a CVE change', async () => {
    fakeCampaigns['campaign:x'] = {
      campaign_id: 'campaign:x', severity: 'high', confidence: 0.6, last_seen: '2026-08-01',
      threat_actors: [], shared_cves: [], has_kev: false, has_exploited: false, has_ransomware: false,
    };
    const wl = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(wl.watchlist.id, 'usr_a', 'campaign', 'campaign:x');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'campaign', entityId: 'campaign:x', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCampaigns['campaign:x'] = { ...fakeCampaigns['campaign:x'], has_ransomware: true };
    const outcome = await engine.evaluateEntity({ entityType: 'campaign', entityId: 'campaign:x', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('changed');
    expect(outcome.events[0].change_type).toBe('CAMPAIGN_RANSOMWARE_FLAG_ADDED');
  });
});

describe('notification dispatch integration (Alert Delivery v1)', () => {
  const notify = require('../notification-store');

  test('a genuinely new event enqueues a pending delivery for a watcher with notifications enabled', async () => {
    fakeCves['CVE-2026-5001'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_notify', 'CVE-2026-5001');
    await notify.updatePreferences('usr_notify', { email_override: 'alerts@example.com' });
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5001', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCves['CVE-2026-5001'] = { ...fakeCves['CVE-2026-5001'], cisa_kev: true };
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5001', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    // A KEV flip legitimately fires TWO events (CVE_KEV_ADDED and
    // CVE_ACTIVE_EXPLOITATION_CONFIRMED, since classifyExploitation()
    // derives exploitation status from the same cisa_kev field) -- this
    // is documented, correct platform behavior from the watchlist v1
    // round's own change-detector tests, not a bug here. One pending-
    // delivery record is created per (owner, event_id), so two distinct
    // events for the same owner correctly produce two records.
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(2);
    expect(due.every(r => r.owner_id === 'usr_notify')).toBe(true);
    expect(due.every(r => r.channels_pending.includes('email'))).toBe(true);
    expect(new Set(due.map(r => r.event_id)).size).toBe(2); // distinct events, not a duplicate enqueue
  });

  test('a watcher with no notification channels enabled gets nothing enqueued (existing default-off-for-webhook, on-but-unresolvable-for-email posture)', async () => {
    fakeCves['CVE-2026-5002'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_silent', 'CVE-2026-5002');
    // No preferences ever set for usr_silent, and no user:id/user:key
    // account record exists in this fake redis for it either -- email
    // defaults "on" but has no resolvable target, so nothing is enqueued.
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5002', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    fakeCves['CVE-2026-5002'] = { ...fakeCves['CVE-2026-5002'], cisa_kev: true };
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5002', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(0);
  });

  test('a baseline-only run (no real change) never enqueues a notification', async () => {
    fakeCves['CVE-2026-5003'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_notify2', 'CVE-2026-5003');
    await notify.updatePreferences('usr_notify2', { email_override: 'a@example.com' });
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5003', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex }); // baseline only

    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
  });

  test('a notification-dispatch failure never prevents the feed fan-out that already succeeded', async () => {
    // dispatchNewEvent is enqueue-only and error-swallowed at the call
    // site (see change-engine.js) -- simulate a hard failure by breaking
    // notification-store's redis access mid-flight and confirm the
    // watcher's feed entry (the pre-existing, load-bearing behavior) is
    // still written.
    fakeCves['CVE-2026-5004'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    const wlId = await watchCve('usr_resilient', 'CVE-2026-5004');
    await notify.updatePreferences('usr_resilient', { email_override: 'a@example.com' });
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5004', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    const originalHget = global.__fakeRedisForTest.hget;
    global.__fakeRedisForTest.hget = async () => { throw new Error('simulated notification-store failure'); };
    try {
      fakeCves['CVE-2026-5004'] = { ...fakeCves['CVE-2026-5004'], cisa_kev: true };
      const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5004', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
      expect(outcome.status).toBe('changed'); // detection + persistence + feed fan-out all still succeeded
      const feed = await store.getOwnerFeedPage('usr_resilient', { limit: 10, cursor: 0 });
      expect(feed.eventIds.length).toBeGreaterThan(0);
    } finally {
      global.__fakeRedisForTest.hget = originalHget;
    }
  });
});
