-- SENTINEL APEX — Customer Defense Profiles (D1)
--
-- Third migration against the same `sentinel-apex-core` D1 database
-- (0001_notification_delivery.sql, 0002_watchlists_change_detection.sql).
-- Same database, not a separate one, for the same reason 0002's header
-- gives: no cross-database transaction capability in D1, and this state is
-- conceptually part of the same "customer-owned control plane" the
-- watchlist tables already live in.
--
-- One profile per owner in v1 (UNIQUE on owner_id) -- mandate's own
-- instruction (Phase 52): "If customer/workspace supports one profile in
-- v1: implement one. Do not build arbitrary unlimited environments unless
-- commercial need exists." A dedicated reuse-before-build audit (see
-- docs/audits/SENTINEL-APEX-CUSTOMER-DEFENSE-CONTEXT-INVENTORY-V1.md §2)
-- confirmed no multi-workspace/tenant foundation exists anywhere in this
-- codebase, so there is no "workspace" to scope multiple profiles under --
-- inventing one now would be exactly the premature MSSP architecture
-- Phase 53 says not to build. Extending to multiple profiles per owner
-- later only requires dropping the UNIQUE constraint and adding a
-- profile_id to the caller's requests; the owner_id-keyed shape below does
-- not need to change.
--
-- Telemetry status storage encodes the mandate's UNKNOWN-vs-NOT_AVAILABLE
-- distinction (Phase 16/23) structurally, not just in application code: a
-- data source the customer has never declared simply has NO ROW in
-- defense_profile_telemetry (== UNKNOWN at the API layer), rather than a
-- row whose status column happens to say 'UNKNOWN' -- setting a data
-- source back to "not configured" in the UI deletes its row instead of
-- writing a third status value, so "missing" and "explicitly unknown" can
-- never drift into two different representations of the same fact.

CREATE TABLE IF NOT EXISTS defense_profiles (
  id                TEXT PRIMARY KEY,          -- dp_xxxxxxxxxxxxxxxxxxxxxxxx
  owner_id          TEXT NOT NULL UNIQUE,      -- one profile per owner (v1)
  name              TEXT NOT NULL DEFAULT 'My Defense Environment',
  schema_version    TEXT NOT NULL DEFAULT '1.0',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS defense_profile_technologies (
  profile_id      TEXT NOT NULL,
  category        TEXT NOT NULL,   -- siem | edr_xdr | cloud | endpoint_telemetry | os
  technology_id   TEXT NOT NULL,   -- normalized id from defense-taxonomy.js, or 'other' (CUSTOM_UNMAPPED)
  custom_label    TEXT,            -- only set when technology_id = 'other'; sanitized free text
  created_at      TEXT NOT NULL,
  PRIMARY KEY (profile_id, category, technology_id)
);
-- listTechnologies()'s own access pattern (all of one profile's stack).
CREATE INDEX IF NOT EXISTS idx_dpt_profile ON defense_profile_technologies (profile_id);

CREATE TABLE IF NOT EXISTS defense_profile_telemetry (
  profile_id      TEXT NOT NULL,
  data_source     TEXT NOT NULL,   -- process_creation | process_access | registry_set | network
  status          TEXT NOT NULL CHECK (status IN ('AVAILABLE', 'PARTIALLY_AVAILABLE', 'NOT_AVAILABLE')),
  updated_at      TEXT NOT NULL,
  PRIMARY KEY (profile_id, data_source)
);

CREATE TABLE IF NOT EXISTS defense_profile_audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  action  TEXT NOT NULL,
  data    TEXT,   -- JSON-encoded; owner_id/profile_id/etc live inside this blob,
                   -- matching watchlist_audit_log's existing convention exactly
  ts      TEXT NOT NULL
);
