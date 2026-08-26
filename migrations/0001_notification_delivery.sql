-- SENTINEL APEX — Alert Delivery Control Plane (D1)
--
-- Additive-only, first migration for this database: no ALTER/DROP against
-- anything pre-existing, since this D1 database is new and dedicated to
-- the alert-delivery control plane specifically (see the Cloudflare
-- Runtime Dependency Inventory §0 for why watchlists/change-detection are
-- explicitly NOT part of this schema -- they remain Redis-backed,
-- out of scope for this tranche).
--
-- Design note vs. the prior Redis model: Redis stored one JSON record per
-- (owner_id, event_id) with a nested channels_pending array/attempts
-- object, because Redis has no native relational row concept. D1 is real
-- SQL, so the natural (and simpler) shape is one ROW per
-- (owner_id, event_id, channel) -- delivery_id (see notification-store.js's
-- buildDeliveryId, unchanged) is the primary key directly. This collapses
-- what used to be a "remove from array, delete record if array now empty"
-- bookkeeping helper into a plain DELETE of one row -- a real
-- simplification the relational model gives for free, not a cosmetic
-- rename.

CREATE TABLE IF NOT EXISTS notification_preferences (
  owner_id              TEXT PRIMARY KEY,
  email_enabled         INTEGER NOT NULL DEFAULT 1,
  email_override        TEXT NOT NULL DEFAULT '',
  webhook_enabled       INTEGER NOT NULL DEFAULT 0,
  webhook_url           TEXT NOT NULL DEFAULT '',
  -- Never returned by any read path outside getWebhookSecret() (internal-
  -- only, mirrors the Redis version's own show-once discipline). Not
  -- separately encrypted at the application layer -- D1 storage is
  -- Cloudflare-managed encryption-at-rest, the same trust boundary the
  -- prior Upstash-managed-encryption-at-rest model already relied on; see
  -- the certification doc's Secret Storage section for the explicit
  -- comparison.
  webhook_secret        TEXT,
  webhook_configured_at TEXT,
  updated_at             TEXT
);

CREATE TABLE IF NOT EXISTS notification_delivery_jobs (
  delivery_id       TEXT PRIMARY KEY, -- buildDeliveryId(owner_id, event_id, channel); stable across every retry
  event_id          TEXT NOT NULL,
  owner_id          TEXT NOT NULL,
  watchlist_id      TEXT,
  channel           TEXT NOT NULL CHECK (channel IN ('email', 'webhook')),
  state             TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'retry', 'claimed')),
  attempt_count     INTEGER NOT NULL DEFAULT 0,
  next_attempt_at   INTEGER NOT NULL, -- epoch ms; due when <= current time
  -- Claim/lease (Phase 9-12): a claim is a conditional UPDATE setting
  -- these three together, checked atomically via the affected-row count
  -- (see d1.js's runClaim()). claim_token is the stale-worker guard
  -- (Phase 10/56): completion requires BOTH delivery_id and a matching
  -- claim_token, so a worker whose lease already expired and was
  -- reclaimed by someone else can never finalize a newer claim's outcome.
  claim_token       TEXT,
  claimed_at        INTEGER,
  lease_expires_at  INTEGER,
  schema_version    TEXT NOT NULL DEFAULT '1.0',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);
-- The due-job query's own WHERE clause (state, next_attempt_at) --
-- the one index this table cannot function efficiently without.
CREATE INDEX IF NOT EXISTS idx_delivery_jobs_due ON notification_delivery_jobs (state, next_attempt_at);
-- Customer isolation queries (a given owner's own pending jobs).
CREATE INDEX IF NOT EXISTS idx_delivery_jobs_owner ON notification_delivery_jobs (owner_id);
-- Lease-expiry recovery scans.
CREATE INDEX IF NOT EXISTS idx_delivery_jobs_lease ON notification_delivery_jobs (lease_expires_at);

CREATE TABLE IF NOT EXISTS notification_delivery_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id      TEXT NOT NULL,
  channel       TEXT NOT NULL,
  event_id      TEXT NOT NULL,
  watchlist_id  TEXT,
  status        TEXT NOT NULL, -- 'delivered' | 'failed' | 'cancelled'
  error         TEXT,          -- bounded to 300 chars at the application layer, same cap as the Redis version
  attempt       INTEGER NOT NULL DEFAULT 0,
  attempted_at  TEXT NOT NULL
);
-- Newest-first per-owner listing is the only real access pattern
-- (listDeliveries()) -- id DESC on an autoincrement PK is a correct,
-- cheap proxy for "newest first" without a separate timestamp index.
CREATE INDEX IF NOT EXISTS idx_delivery_log_owner ON notification_delivery_log (owner_id, id DESC);

CREATE TABLE IF NOT EXISTS notification_dead_letters (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id          TEXT NOT NULL,
  event_id          TEXT NOT NULL,
  watchlist_id      TEXT,
  channel           TEXT NOT NULL,
  attempts          INTEGER NOT NULL,
  reason            TEXT NOT NULL, -- 'PERMANENT_FAILURE' | 'MAX_RETRY_ATTEMPTS_EXHAUSTED'
  dead_lettered_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dead_letters_owner ON notification_dead_letters (owner_id, id DESC);

CREATE TABLE IF NOT EXISTS notification_audit_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id  TEXT NOT NULL,
  action    TEXT NOT NULL,
  data      TEXT, -- JSON-encoded, field NAMES only per the existing privacy-minimization discipline -- never secret/PII values
  ts        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_owner ON notification_audit_log (owner_id, id DESC);
