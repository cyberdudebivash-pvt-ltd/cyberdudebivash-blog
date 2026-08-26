-- SENTINEL APEX — Watchlists & Change-Detection State (D1)
--
-- Second migration against the same D1 database PR #138 introduced for
-- the alert-delivery control plane (0001_notification_delivery.sql).
-- Same database, not a separate one, deliberately: change-engine.js
-- already calls directly into notification-dispatch.js at fan-out time
-- (dispatchNewEvent()), and the Cloudflare-Only Runtime Completion v2
-- mandate's own Phase 14 anticipates a possible future atomic
-- "event + watchlist match + delivery outbox row" transaction -- D1
-- transactions cannot span two databases, so keeping this state in the
-- SAME database preserves that option without forcing it this round (no
-- such combined transaction is built here; watchlist-store.js/change-
-- engine.js/notification-store.js remain three separate modules making
-- separate D1 calls, exactly as their Redis-era predecessors did).
--
-- Because this database's role grew beyond "notification delivery" with
-- this migration, wrangler.jsonc's database_name changes from
-- sentinel-apex-notification-delivery to sentinel-apex-core in this same
-- round -- safe and costless: no real database has ever been created
-- against the old name (wrangler whoami still reports "not
-- authenticated" in every sandbox this platform's work has run in so
-- far), so this is a rename of an unprovisioned config pointer, not a
-- live resource.
--
-- Design departures from the Redis model, each deliberate, not
-- mechanical ports:
--
-- 1. watchlist_entities collapses TWO mirrored Redis structures
--    (watchlist:{id}:entities SET, forward; entity_watchers:{type}:{id}
--    SET, reverse) into ONE table with an index in each direction. The
--    Redis design needed two because a Set has no secondary index; a SQL
--    table's PRIMARY KEY (forward: WHERE watchlist_id=?) and a plain
--    index (reverse: WHERE entity_type=? AND entity_id=?) give both
--    lookups over one source of truth, removing the class of bug where
--    the two mirrored sets could theoretically drift (they never did in
--    the Redis code -- every write path updated both together -- but the
--    relational model makes that drift structurally impossible instead
--    of merely disciplined).
--
-- 2. getWatchersForEntity()'s old N+1 pattern (SMEMBERS the reverse set,
--    then GET each watchlist hash individually to check its status) is a
--    single JOIN in the D1 version -- see watchlist-store.js's rewrite.
--
-- 3. change_events stores each event's full JSON payload in one column
--    (payload), not decomposed into per-field columns. Deliberate, not
--    lazy: change-engine.js's own getEventById()/getEventsByIds() have
--    always treated an event as an opaque blob (JSON.parse the whole
--    thing, return it whole) and nothing in this codebase queries by an
--    individual event field (change_type, importance, etc.) -- decomposing
--    would add relational structure this system does not use, the
--    opposite of Principle 5 (Minimal Change Surface). entity_type/
--    entity_id/observed_at ARE extracted as real columns (see the index
--    below) because persistEventIfNew() already has them as local
--    variables at write time and a plain index costs nothing -- not
--    because anything queries them today (nothing does; the Redis
--    equivalent, events:by_entity:*, was write-only dead weight, a real
--    finding from this round's audit -- see the V2 inventory doc §7 note.
--    Kept here as a real, queryable index instead of reproducing that
--    same write-only waste).
--
-- 4. owner_feed's PRIMARY KEY (owner_id, event_id) reproduces a subtle
--    property the Redis ZADD-per-member design had for free: the SAME
--    owner can watch the SAME entity via two different watchlists
--    (getWatchersForEntity() returns one row per watchlist_id, not one
--    per distinct owner), so appendToOwnerFeed() can legitimately be
--    called twice for the same (owner, event) pair in one evaluation
--    cycle. ZADD naturally dedupes by member; here that's an explicit
--    INSERT ... ON CONFLICT(owner_id, event_id) DO NOTHING in
--    watchlist-store.js's rewrite, not a coincidence of the schema.

CREATE TABLE IF NOT EXISTS watchlists (
  id                  TEXT PRIMARY KEY,   -- wl_xxxxxxxxxxxxxxxxxxxxxxxx
  owner_id            TEXT NOT NULL,
  name                TEXT NOT NULL,
  description         TEXT NOT NULL DEFAULT '',
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
  schema_version      TEXT NOT NULL DEFAULT '1.0',
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL,
  last_evaluated_at   TEXT
);
-- listWatchlists()'s own access pattern (all of one owner's watchlists).
CREATE INDEX IF NOT EXISTS idx_watchlists_owner ON watchlists (owner_id);

CREATE TABLE IF NOT EXISTS watchlist_entities (
  watchlist_id  TEXT NOT NULL,
  entity_type   TEXT NOT NULL,
  entity_id     TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  PRIMARY KEY (watchlist_id, entity_type, entity_id)
);
-- Reverse lookup: getWatchersForEntity()/getAllWatchedEntityKeys() --
-- the sole reason this table's own PK ordering (watchlist_id first)
-- cannot serve both directions.
CREATE INDEX IF NOT EXISTS idx_watchlist_entities_reverse ON watchlist_entities (entity_type, entity_id);

CREATE TABLE IF NOT EXISTS watchlist_audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  action  TEXT NOT NULL,
  data    TEXT, -- JSON-encoded; owner_id/watchlist_id/etc live inside this blob,
                 -- matching auditWatchlistAction(action, data)'s existing signature
                 -- exactly (no separate ownerId parameter, unlike notification_audit_log)
  ts      TEXT NOT NULL
);
-- Global trim only (no per-owner index): the Redis version's own
-- ZREMRANGEBYRANK on audit:watchlist:log trims the WHOLE sorted set to
-- the newest AUDIT_LOG_MAX_ENTRIES, not per-owner -- reproduced exactly,
-- not changed to a per-owner bound.

CREATE TABLE IF NOT EXISTS entity_snapshots (
  entity_type     TEXT NOT NULL,
  entity_id       TEXT NOT NULL,
  schema_version  TEXT NOT NULL,
  fingerprint     TEXT NOT NULL,
  state           TEXT NOT NULL, -- JSON blob, opaque to this schema (watchable-state.js's shape)
  snapshotted_at  TEXT NOT NULL,
  PRIMARY KEY (entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS change_events (
  event_id      TEXT PRIMARY KEY,
  entity_type   TEXT NOT NULL,
  entity_id     TEXT NOT NULL,
  observed_at   TEXT NOT NULL,
  payload       TEXT NOT NULL, -- full JSON event object; see design note 3 above
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_events_entity ON change_events (entity_type, entity_id, observed_at);

CREATE TABLE IF NOT EXISTS owner_feed (
  owner_id        TEXT NOT NULL,
  event_id        TEXT NOT NULL,
  observed_at_ms  INTEGER NOT NULL,
  PRIMARY KEY (owner_id, event_id)
);
-- getOwnerFeedPage()'s newest-first pagination.
CREATE INDEX IF NOT EXISTS idx_owner_feed_page ON owner_feed (owner_id, observed_at_ms DESC);

-- Single-row table: the bounded batch driver's resumable sweep cursor
-- (evaluateWatchedEntities()'s old watchlist_eval:cursor Redis key).
CREATE TABLE IF NOT EXISTS watchlist_eval_state (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  cursor  INTEGER NOT NULL DEFAULT 0
);
