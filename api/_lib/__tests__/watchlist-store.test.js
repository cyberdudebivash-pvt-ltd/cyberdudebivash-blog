'use strict';

const { createFakeRedis } = require('./fixtures/fake-redis');

let fakeRedis;
jest.mock('../redis', () => {
  const { createFakeRedis } = require('./fixtures/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});

// payment-utils.js requires redis.js too (via other exports) and reads
// crypto/env at module load -- safe to require after the mock is set up.
const store = require('../watchlist-store');

beforeEach(() => {
  fakeRedis = global.__fakeRedisForTest;
  fakeRedis._reset();
});

describe('createWatchlist', () => {
  test('creates a watchlist owned by the caller, never exposing the owner field', async () => {
    const result = await store.createWatchlist({ ownerId: 'usr_a', name: 'My CVEs', description: 'tracked vulns' });
    expect(result.error).toBeUndefined();
    expect(result.watchlist.id).toMatch(/^wl_[0-9a-f]{24}$/);
    expect(result.watchlist.name).toBe('My CVEs');
    expect(result.watchlist.entity_count).toBe(0);
    expect(result.watchlist.owner).toBeUndefined();
  });

  test('rejects an empty name', async () => {
    const result = await store.createWatchlist({ ownerId: 'usr_a', name: '   ' });
    expect(result.error).toBe('INVALID_NAME');
  });

  test('strips HTML from name/description (Phase 60 XSS defense)', async () => {
    const result = await store.createWatchlist({ ownerId: 'usr_a', name: '<script>alert(1)</script>My List', description: '<img onerror=alert(1)>' });
    expect(result.watchlist.name).not.toMatch(/<script>/);
    expect(result.watchlist.description).not.toMatch(/<img/);
  });

  test('enforces MAX_WATCHLISTS_PER_OWNER', async () => {
    for (let i = 0; i < store.MAX_WATCHLISTS_PER_OWNER; i++) {
      const r = await store.createWatchlist({ ownerId: 'usr_a', name: `List ${i}` });
      expect(r.error).toBeUndefined();
    }
    const overLimit = await store.createWatchlist({ ownerId: 'usr_a', name: 'One too many' });
    expect(overLimit.error).toBe('LIMIT_REACHED');
  });

  test('per-owner limits are independent -- one customer hitting the cap does not affect another', async () => {
    for (let i = 0; i < store.MAX_WATCHLISTS_PER_OWNER; i++) {
      await store.createWatchlist({ ownerId: 'usr_a', name: `List ${i}` });
    }
    const otherOwner = await store.createWatchlist({ ownerId: 'usr_b', name: 'Fresh account' });
    expect(otherOwner.error).toBeUndefined();
  });
});

describe('ownership isolation (Phase 7 required invariant)', () => {
  test('customer B cannot read customer A watchlist -- identical NOT_FOUND as a nonexistent ID', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'A only' });
    const asOwner = await store.getWatchlist(created.watchlist.id, 'usr_a');
    const asOther = await store.getWatchlist(created.watchlist.id, 'usr_b');
    const asNonexistent = await store.getWatchlist('wl_doesnotexist000000000000', 'usr_b');
    expect(asOwner.error).toBeUndefined();
    expect(asOther.error).toBe('NOT_FOUND');
    expect(asNonexistent.error).toBe('NOT_FOUND');
    expect(asOther).toEqual(asNonexistent); // no distinguishing signal (IDOR enumeration guard)
  });

  test('customer B cannot update customer A watchlist', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'A only' });
    const result = await store.updateWatchlist(created.watchlist.id, 'usr_b', { name: 'hijacked' });
    expect(result.error).toBe('NOT_FOUND');
    const stillOwnedByA = await store.getWatchlist(created.watchlist.id, 'usr_a');
    expect(stillOwnedByA.watchlist.name).toBe('A only');
  });

  test('customer B cannot delete customer A watchlist', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'A only' });
    const result = await store.deleteWatchlist(created.watchlist.id, 'usr_b');
    expect(result.error).toBe('NOT_FOUND');
    const stillThere = await store.getWatchlist(created.watchlist.id, 'usr_a');
    expect(stillThere.error).toBeUndefined();
  });

  test('customer B cannot add an entity to customer A watchlist', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'A only' });
    const result = await store.addEntity(created.watchlist.id, 'usr_b', 'cve', 'CVE-2026-1234');
    expect(result.error).toBe('NOT_FOUND');
  });

  test('listWatchlists never returns another owner\'s watchlists', async () => {
    await store.createWatchlist({ ownerId: 'usr_a', name: 'A1' });
    await store.createWatchlist({ ownerId: 'usr_a', name: 'A2' });
    await store.createWatchlist({ ownerId: 'usr_b', name: 'B1' });
    const listA = await store.listWatchlists('usr_a');
    const listB = await store.listWatchlists('usr_b');
    expect(listA.map(w => w.name).sort()).toEqual(['A1', 'A2']);
    expect(listB.map(w => w.name)).toEqual(['B1']);
  });
});

describe('entity membership', () => {
  test('valid CVE ID is added and normalized to uppercase', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    const result = await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'cve-2026-1234');
    expect(result.error).toBeUndefined();
    expect(result.entity).toEqual({ type: 'cve', id: 'CVE-2026-1234' });
  });

  test('malformed CVE ID is rejected', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    const result = await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'not-a-cve');
    expect(result.error).toBe('INVALID_ENTITY_ID');
  });

  test('unsupported entity type is honestly rejected, including prototype-pollution keys', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    expect((await store.addEntity(created.watchlist.id, 'usr_a', 'malware', 'x')).error).toBe('UNSUPPORTED_ENTITY_TYPE');
    expect((await store.addEntity(created.watchlist.id, 'usr_a', 'actor', 'x')).error).toBe('UNSUPPORTED_ENTITY_TYPE');
    expect((await store.addEntity(created.watchlist.id, 'usr_a', '__proto__', 'x')).error).toBe('UNSUPPORTED_ENTITY_TYPE');
    expect((await store.addEntity(created.watchlist.id, 'usr_a', 'constructor', 'x')).error).toBe('UNSUPPORTED_ENTITY_TYPE');
  });

  test('adding the same entity twice is a no-op, not a duplicate (Phase 11)', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-1234');
    const second = await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-1234');
    expect(second.duplicate).toBe(true);
    const list = await store.listEntities(created.watchlist.id, 'usr_a');
    expect(list.entities).toHaveLength(1);
  });

  test('enforces MAX_ENTITIES_PER_WATCHLIST for genuinely new additions, but a duplicate re-add still succeeds at the cap', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    for (let i = 0; i < store.MAX_ENTITIES_PER_WATCHLIST; i++) {
      const id = `CVE-2026-${1000 + i}`;
      const r = await store.addEntity(created.watchlist.id, 'usr_a', 'cve', id);
      expect(r.error).toBeUndefined();
    }
    const overLimit = await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-9999');
    expect(overLimit.error).toBe('LIMIT_REACHED');

    const dupAtCap = await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-1000');
    expect(dupAtCap.error).toBeUndefined();
    expect(dupAtCap.duplicate).toBe(true);
  });

  test('removeEntity removes both the membership and the reverse index', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-1234');
    let watchers = await store.getWatchersForEntity('cve', 'CVE-2026-1234');
    expect(watchers).toHaveLength(1);

    await store.removeEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-1234');
    const list = await store.listEntities(created.watchlist.id, 'usr_a');
    expect(list.entities).toHaveLength(0);
    watchers = await store.getWatchersForEntity('cve', 'CVE-2026-1234');
    expect(watchers).toHaveLength(0);
  });
});

describe('deleteWatchlist', () => {
  test('deleting a watchlist removes it from the reverse index so future changes stop matching it', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-1234');
    await store.deleteWatchlist(created.watchlist.id, 'usr_a');

    const watchers = await store.getWatchersForEntity('cve', 'CVE-2026-1234');
    expect(watchers).toHaveLength(0);
    const gone = await store.getWatchlist(created.watchlist.id, 'usr_a');
    expect(gone.error).toBe('NOT_FOUND');
    const list = await store.listWatchlists('usr_a');
    expect(list).toHaveLength(0);
  });
});

describe('status / pause semantics', () => {
  test('a paused watchlist is excluded from getWatchersForEntity (stops new matches without deleting membership)', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(created.watchlist.id, 'usr_a', 'cve', 'CVE-2026-1234');
    await store.updateWatchlist(created.watchlist.id, 'usr_a', { status: 'paused' });

    const watchers = await store.getWatchersForEntity('cve', 'CVE-2026-1234');
    expect(watchers).toHaveLength(0);

    const list = await store.listEntities(created.watchlist.id, 'usr_a');
    expect(list.entities).toHaveLength(1); // membership itself is preserved
  });

  test('rejects an invalid status value', async () => {
    const created = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    const result = await store.updateWatchlist(created.watchlist.id, 'usr_a', { status: 'deleted-ish' });
    expect(result.error).toBe('INVALID_STATUS');
  });
});

describe('feed pagination (Phase 55/56)', () => {
  test('newest-first, stable ordering, bounded page size', async () => {
    for (let i = 0; i < 5; i++) {
      await store.appendToOwnerFeed('usr_a', `IEV-${i}`, 1000 + i);
    }
    const page = await store.getOwnerFeedPage('usr_a', { limit: 3, cursor: 0 });
    expect(page.eventIds).toEqual(['IEV-4', 'IEV-3', 'IEV-2']); // newest (highest score) first
    expect(page.total).toBe(5);
    expect(page.nextCursor).toBe(3);

    const page2 = await store.getOwnerFeedPage('usr_a', { limit: 3, cursor: page.nextCursor });
    expect(page2.eventIds).toEqual(['IEV-1', 'IEV-0']);
    expect(page2.nextCursor).toBeNull();
  });

  test('feed is bounded to FEED_MAX_PER_OWNER (Phase 54 retention)', async () => {
    for (let i = 0; i < 520; i++) {
      await store.appendToOwnerFeed('usr_a', `IEV-${i}`, i);
    }
    const page = await store.getOwnerFeedPage('usr_a', { limit: 1, cursor: 0 });
    expect(page.total).toBeLessThanOrEqual(500);
  });
});

describe('getWatchlistEntitlements', () => {
  test('returns a stable, documented shape regardless of tier (Phase 9: flat in v1)', () => {
    const free = store.getWatchlistEntitlements('free');
    const enterprise = store.getWatchlistEntitlements('enterprise');
    expect(free).toEqual(enterprise);
    expect(free.enabled).toBe(true);
    expect(free.max_watchlists).toBe(store.MAX_WATCHLISTS_PER_OWNER);
  });
});

describe('audit log', () => {
  test('mutating actions write to audit:watchlist:log, not the payment audit log', async () => {
    await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    const dump = fakeRedis._dump();
    expect(dump.zsets.has('audit:watchlist:log')).toBe(true);
    expect(dump.zsets.has('audit:payment:log')).toBe(false);
    const entries = [...dump.zsets.get('audit:watchlist:log').keys()];
    expect(entries.some(e => JSON.parse(e).action === 'WATCHLIST_CREATED')).toBe(true);
  });
});
