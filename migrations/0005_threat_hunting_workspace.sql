-- SENTINEL APEX — Threat Hunting Workspace, Analyst Investigation Fabric,
-- Detection Feedback Intelligence & Defensive Outcome Loop v1 (D1)
--
-- Fifth migration against the same `sentinel-apex-core` D1 database
-- (0001 notification delivery, 0002 watchlists/change-detection,
-- 0003 defense profiles, 0004 SIEM deployment gateway). Same database,
-- same reason every prior migration gives: this is customer-owned control
-- plane state, not a new domain needing isolation.
--
-- Why NOT the existing Redis-backed Investigation/Case/Evidence system
-- (api/_lib/investigation-manager.js and friends, api/v1/workbench/*):
-- see docs/audits/SENTINEL-APEX-HUNTING-WORKSPACE-CAPABILITY-INVENTORY-V1.md
-- §1. Two independent reasons: (1) that system has zero owner_id/customer-
-- tenancy concept — it is gated by an internal X-Analyst-Key, not
-- authenticate()'s customer userId; (2) docs/architecture/
-- PRODUCTION-RUNTIME-POLICY.md §1 bars new Upstash Redis dependency for
-- new capability. A hunt is customer-owned, so it goes on D1 with every
-- other customer-owned store, matching siem_connectors/detection_deployments/
-- watchlists/defense_profiles exactly.
--
-- Ownership: owner_id is always re-derived server-side from authenticate()'s
-- userId, never trusted from a request body — matching every prior table.
-- Child tables (hunt_refs/hunt_queries/hunt_observations/hunt_evidence_links/
-- hunt_findings/hunt_timeline) deliberately do NOT carry their own owner_id
-- column: ownership is enforced once, at the store layer, by resolving the
-- parent hunt row first (mirrors deployment_attempts/deployment_audit_log's
-- existing precedent of omitting owner_id from child rows). detection_feedback
-- is the one exception — it carries owner_id directly because feedback can
-- be submitted standalone against a deployment, with no parent hunt to
-- resolve through.
--
-- Deliberately absent from this migration (computed, not stored — matching
-- this platform's recurring "coverage is never persisted" discipline, see
-- the Source-of-Truth Matrix): a hunt_telemetry_requirements table (readiness
-- is computed live from defense-compatibility.js on every read) and any
-- persisted "REVIEW_REQUIRED" flag on a detection (computed live by scanning
-- detection_feedback for the detection_id/detection_version in question).
-- Neither is a second, driftable copy of state this platform already knows
-- how to derive fresh.
--
-- Additive-only: CREATE TABLE IF NOT EXISTS throughout, matching 0001-0004.

CREATE TABLE IF NOT EXISTS hunts (
  hunt_id               TEXT PRIMARY KEY,        -- hunt_xxxxxxxxxxxxxxxxxxxxxxxx
  owner_id              TEXT NOT NULL,
  title                 TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'DRAFT'
                          CHECK (status IN ('DRAFT','READY','ACTIVE','PAUSED','AWAITING_EVIDENCE','ANALYSIS_COMPLETE','CLOSED')),
  priority              TEXT NOT NULL DEFAULT 'MEDIUM'
                          CHECK (priority IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  hypothesis            TEXT NOT NULL,           -- specific, defensively testable statement — never framed as established fact
  hypothesis_source     TEXT NOT NULL
                          CHECK (hypothesis_source IN ('ANALYST_CREATED','INTELLIGENCE_DERIVED','DETECTION_DERIVED','ALERT_DERIVED')),
  linked_case_reference TEXT,                    -- analyst-entered free-text pointer into the existing internal Workbench case system
                                                   -- (case-manager.js) -- a manual reference, not an automated cross-tenancy promotion;
                                                   -- see the capability inventory §6 for why no automated bridge was built.
  disposition           TEXT
                          CHECK (disposition IN ('CONFIRMED_THREAT','BENIGN_ACTIVITY','FALSE_POSITIVE','INCONCLUSIVE','NO_EVIDENCE','MONITORING_REQUIRED') OR disposition IS NULL),
  disposition_summary   TEXT,                    -- required at the application layer whenever disposition is set
  disposition_by        TEXT,                    -- analyst identity; required whenever disposition is set
  disposition_at        TEXT,
  created_by            TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL,
  closed_at             TEXT
);
CREATE INDEX IF NOT EXISTS idx_hunts_owner ON hunts (owner_id);
CREATE INDEX IF NOT EXISTS idx_hunts_status ON hunts (status);

-- Polymorphic entity linkage: threat_refs[]/attack_refs[]/detection_refs[]/
-- deployment_refs[] from the mandate's canonical Hunt model, collapsed into
-- one table with a ref_kind discriminator rather than four parallel join
-- tables -- mirrors watchlist_entities' already-proven entity_type/entity_id
-- polymorphic pattern (Section 0 Level 5: minimal change surface).
CREATE TABLE IF NOT EXISTS hunt_refs (
  hunt_id     TEXT NOT NULL,
  ref_kind    TEXT NOT NULL CHECK (ref_kind IN ('threat_actor','cve','campaign','ioc','attack_technique','detection','deployment')),
  ref_id      TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (hunt_id, ref_kind, ref_id)
);
CREATE INDEX IF NOT EXISTS idx_hunt_refs_lookup ON hunt_refs (ref_kind, ref_id);

-- A hunt's approved defensive queries. query_snapshot captures the query
-- CONTENT as it existed at the moment it was added to the hunt -- the same
-- reason detection_deployments.deployed_intent_snapshot exists
-- (detection-rules.js#storeRule() overwrites format content in place on
-- every version bump, so the canonical store cannot answer "what did this
-- query say" once a later version is stored; this table is the only place
-- that survives). Query is DATA (view/copy/download) by default -- there is
-- no execution state here because remote read-only query execution is
-- deferred this tranche (see the certification doc's query-execution
-- section) -- validation_status is a snapshot of the source detection's own
-- release-gate status at add-time, not a live re-check.
CREATE TABLE IF NOT EXISTS hunt_queries (
  query_id                TEXT PRIMARY KEY,      -- hq_xxxxxxxxxxxxxxxxxxxxxxxx
  hunt_id                 TEXT NOT NULL,
  source_detection_id     TEXT NOT NULL,
  source_detection_version TEXT NOT NULL,
  format                  TEXT NOT NULL,         -- 'kql' | 'splunk' | 'sigma' | ...
  query_snapshot          TEXT NOT NULL,
  validation_status       TEXT NOT NULL,          -- snapshot of the source detection's status at add-time (e.g. 'RELEASED')
  added_by                TEXT NOT NULL,
  created_at              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_queries_hunt ON hunt_queries (hunt_id);

-- A structured, analyst/customer-entered result relevant to a hunt --
-- NOT raw telemetry ingestion (explicitly out of scope per the mandate's
-- safety boundary). summary is bounded prose/structured text a human typed
-- or pasted, never a bulk data feed.
CREATE TABLE IF NOT EXISTS hunt_observations (
  observation_id  TEXT PRIMARY KEY,      -- hob_xxxxxxxxxxxxxxxxxxxxxxxx
  hunt_id         TEXT NOT NULL,
  query_id        TEXT,                  -- optional: which hunt_queries row this observation resulted from
  summary         TEXT NOT NULL,
  created_by      TEXT NOT NULL,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_observations_hunt ON hunt_observations (hunt_id);

-- Intentionally minimal (description + reference URL), NOT the full
-- 13-type/graph-linked model evidence-manager.js implements internally --
-- see the capability inventory for why that richer system isn't reusable
-- here. Richer evidence tooling is a disclosed future item.
CREATE TABLE IF NOT EXISTS hunt_evidence_links (
  evidence_id     TEXT PRIMARY KEY,      -- hev_xxxxxxxxxxxxxxxxxxxxxxxx
  hunt_id         TEXT NOT NULL,
  observation_id  TEXT,                  -- optional: the observation this evidence supports
  description     TEXT NOT NULL,
  reference_url   TEXT,
  created_by      TEXT NOT NULL,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_evidence_links_hunt ON hunt_evidence_links (hunt_id);

-- An analyst-classified conclusion. Never auto-created from an observation --
-- application layer enforces a human created_by on every insert. confidence
-- reuses intelligence-object.js's existing HIGH/MEDIUM/LOW vocabulary
-- (already platform-wide) rather than inventing a third one; classification
-- is a distinct, new security-disposition taxonomy (see the capability
-- inventory for why analysis-models.js's CONFIRMED/LIKELY/POSSIBLE/UNLIKELY/
-- UNSUBSTANTIATED vocabulary answers a different question and isn't reused).
CREATE TABLE IF NOT EXISTS hunt_findings (
  finding_id      TEXT PRIMARY KEY,      -- hfd_xxxxxxxxxxxxxxxxxxxxxxxx
  hunt_id         TEXT NOT NULL,
  classification  TEXT NOT NULL
                    CHECK (classification IN ('CONFIRMED_MALICIOUS','LIKELY_MALICIOUS','BENIGN','EXPECTED_ACTIVITY','INCONCLUSIVE','FALSE_POSITIVE','NO_EVIDENCE_FOUND')),
  confidence      TEXT NOT NULL CHECK (confidence IN ('HIGH','MEDIUM','LOW')),
  summary         TEXT NOT NULL,
  evidence_refs   TEXT,                  -- JSON array of hunt_evidence_links.evidence_id -- required at the application layer
                                          -- whenever classification is CONFIRMED_MALICIOUS (mandate: strong outcomes require linked evidence)
  created_by      TEXT NOT NULL,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_hunt ON hunt_findings (hunt_id);

-- Append-only, mirrors the already-proven siem_connector_audit_log /
-- deployment_audit_log / watchlist_audit_log shape exactly -- capped/trimmed
-- at the application layer the same way.
CREATE TABLE IF NOT EXISTS hunt_timeline (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  hunt_id     TEXT NOT NULL,
  event_type  TEXT NOT NULL,   -- HUNT_CREATED | STATUS_CHANGED | QUERY_ADDED | OBSERVATION_ADDED | EVIDENCE_ADDED |
                                -- FINDING_ADDED | FEEDBACK_SUBMITTED | DISPOSITION_SET | HUNT_REOPENED
  summary     TEXT NOT NULL,
  actor       TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_timeline_hunt ON hunt_timeline (hunt_id);

-- Detection feedback: pinned to (detection_id, detection_version), always
-- tenant-scoped (owner_id), NEVER automatically globalized -- one customer's
-- FALSE_POSITIVE does not mean a detection is globally invalid (mandate's
-- own explicit instruction). hunt_id/deployment_id are both optional and
-- independent: feedback may arise from an active hunt, from a standalone
-- reaction to a deployed detection with no hunt involved, or both.
-- "REVIEW_REQUIRED" is deliberately NOT a column here -- see this file's
-- header for why that signal is computed live, not stored.
CREATE TABLE IF NOT EXISTS detection_feedback (
  feedback_id       TEXT PRIMARY KEY,      -- dfb_xxxxxxxxxxxxxxxxxxxxxxxx
  owner_id          TEXT NOT NULL,
  detection_id      TEXT NOT NULL,
  detection_version TEXT NOT NULL,
  hunt_id           TEXT,
  deployment_id     TEXT,
  classification    TEXT NOT NULL
                      CHECK (classification IN ('TRUE_POSITIVE','FALSE_POSITIVE','USEFUL_SIGNAL','TOO_BROAD','TOO_NARROW','TELEMETRY_MISMATCH','QUERY_ERROR','TUNING_REQUIRED','NO_SIGNAL')),
  summary           TEXT,
  created_by        TEXT NOT NULL,
  created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detection_feedback_owner ON detection_feedback (owner_id);
CREATE INDEX IF NOT EXISTS idx_detection_feedback_detection ON detection_feedback (detection_id, detection_version);
CREATE INDEX IF NOT EXISTS idx_detection_feedback_hunt ON detection_feedback (hunt_id);
