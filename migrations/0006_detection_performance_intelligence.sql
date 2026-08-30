-- SENTINEL APEX — Detection Performance Intelligence, Defensive Efficacy
-- Fabric, Privacy-Safe Analyst Feedback Aggregation, Detection Review
-- Prioritization & Closed-Loop Defense Quality Engine v1 (D1)
--
-- Sixth migration against the same `sentinel-apex-core` D1 database.
-- Same reasoning as every prior migration: this is control-plane state
-- (a content-integrity record for a canonical detection, not a second
-- domain needing isolation).
--
-- ONE new table. Everything else this tranche needs (tenant-scoped
-- performance counts, the privacy-safe global aggregate signal, the
-- deterministic Quality State) is computed on demand from tables that
-- already exist (detection_feedback from migrations/0005, detection-
-- rules.js's canonical store, detection_deployments from migrations/0004)
-- — matching this platform's recurring "coverage/signal is never
-- persisted, only recomputed" discipline (see hunt-engine.js's own header
-- comments and the Source-of-Truth Matrix). A detection_performance_
-- aggregates table and a detection_quality_history table were both
-- evaluated and deliberately NOT added: no evidence (high read volume,
-- expensive joins, or a genuine need for point-in-time quality-state
-- history) justifies materializing either at this platform's current
-- scale (a handful of canonical detections), and both would be a second,
-- driftable copy of state this platform already knows how to derive
-- fresh from detection_feedback + the canonical rule store. See
-- docs/audits/SENTINEL-APEX-DETECTION-PERFORMANCE-INTELLIGENCE-V1-
-- CERTIFICATION.md for the full evidence-based rationale.
--
-- WHY detection_versions exists (the one real, provable defect this
-- tranche closes): api/_lib/detection-rules.js#storeRule() overwrites a
-- detection's content fields (platforms/suricata/title/description/etc.)
-- in place on every version bump — history[] has only ever recorded
-- metadata (version number, timestamp, change note, author), never
-- content. Confirmed against the real canonical store before writing this
-- migration: rule 65b906336880ed01 carries 12 history entries up to
-- version 1.0.9 with ZERO recoverable content for versions 1.0.0-1.0.8 —
-- this has already caused real, permanent data loss for 3 of the
-- platform's 5 real detection rules. A platform that pins operational
-- feedback to (detection_id, detection_version) cannot honestly call that
-- pinning meaningful if a past version's actual query content is
-- unrecoverable. This table is an immutable, append-only, content-
-- addressed snapshot store: one row per (detection_id, version) that has
-- ever been captured, written once and never updated or deleted at the
-- application layer. Editing version 4 must never modify version 3's row
-- — enforced by the store layer's INSERT ... WHERE NOT EXISTS pattern
-- (idempotent no-op if that exact version already has a row), never an
-- UPDATE.
--
-- Honest limitation, disclosed here and in the certification doc: this
-- table can only ever contain content for versions captured from the
-- moment this migration's backfill ran forward (BACKFILL_CURRENT_STATE
-- snapshots the CURRENT content of each existing rule at migration time)
-- plus every version stored live from here on (LIVE_CAPTURE). Content for
-- versions 1.0.0-1.0.8 of a rule now at 1.0.9, for example, was already
-- destroyed by the pre-existing overwrite behavior long before this
-- migration existed and cannot be reconstructed — this migration does not
-- and cannot invent that content. The live history[] array (unchanged,
-- still the only record of those versions having existed at all) remains
-- the source for version *metadata* (number/timestamp/author/change note)
-- even where this table has no matching content row; the version-history
-- API/UI reads both and explicitly marks pre-migration content as
-- unavailable rather than fabricating it.
CREATE TABLE IF NOT EXISTS detection_versions (
  detection_id                    TEXT NOT NULL,   -- detection-rules.js's stable rule id
  version                         TEXT NOT NULL,   -- e.g. '1.0.3' -- matches governance.version at snapshot time
  title                           TEXT NOT NULL,
  technique_id                    TEXT NOT NULL,
  level                           TEXT,
  description                     TEXT,
  data_source                     TEXT,
  platforms_json                  TEXT NOT NULL,   -- JSON snapshot of {sigma,kql,splunk,osquery} content as it existed at this version
  suricata_json                   TEXT,             -- JSON snapshot of suricata[] content as it existed at this version
  governance_status_at_snapshot   TEXT NOT NULL,    -- point-in-time capture only -- NOT live-tracking; a later status change does not retroactively update this row
  confidence_at_snapshot          TEXT,
  content_hash                    TEXT NOT NULL,    -- SHA-256 over a canonical (sorted-key) JSON serialization of the content fields above
  snapshot_source                 TEXT NOT NULL CHECK (snapshot_source IN ('LIVE_CAPTURE', 'BACKFILL_CURRENT_STATE')),
  snapshot_reason                 TEXT,             -- sourceMetadata.change at storeRule() time, when available
  snapshot_author                 TEXT,             -- sourceMetadata.author at storeRule() time, when available
  snapshotted_at                  TEXT NOT NULL,
  PRIMARY KEY (detection_id, version)
);
CREATE INDEX IF NOT EXISTS idx_detection_versions_detection ON detection_versions (detection_id);
