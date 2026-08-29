-- SENTINEL APEX — Controlled SIEM Deployment Gateway v1 (D1)
--
-- Fourth migration against the same `sentinel-apex-core` D1 database
-- (0001_notification_delivery.sql, 0002_watchlists_change_detection.sql,
-- 0003_defense_profiles.sql). Same database, not a separate one, for the
-- same reason every prior migration's header gives: no cross-database
-- transaction capability in D1, and this state is conceptually part of the
-- same "customer-owned control plane" the watchlist/defense-profile tables
-- already live in.
--
-- Ownership: every table below is scoped by `owner_id`, always re-derived
-- server-side from authenticate()'s userId (matching watchlist-store.js /
-- defense-profile-store.js's exact precedent) — never trusted from a
-- request body.
--
-- Additive-only: CREATE TABLE IF NOT EXISTS throughout, matching 0001-0003.
--
-- APPROVED and DEPLOYED are deliberately never compressed into one state
-- (mandate requirement): a deployment can be APPROVED and not yet
-- DEPLOYING/DEPLOYED (e.g. a transient failure before the first remote
-- call), and DEPLOYED without a live APPROVED record once an approval is
-- superseded by a new one after a configuration change.

CREATE TABLE IF NOT EXISTS siem_connectors (
  id                    TEXT PRIMARY KEY,          -- conn_xxxxxxxxxxxxxxxxxxxxxxxx
  owner_id              TEXT NOT NULL,             -- one owner may have multiple connectors/targets
  platform              TEXT NOT NULL,             -- siem-connector-taxonomy.js KNOWN_PLATFORMS key, e.g. 'microsoft-sentinel'
  name                  TEXT NOT NULL,             -- customer-chosen label, e.g. "Production SOC"
  target_config         TEXT NOT NULL,             -- JSON: NON-secret target identifiers only (tenant_id, subscription_id,
                                                    -- resource_group, workspace_name, client_id for Sentinel — never a secret)
  credential_ciphertext TEXT,                      -- "v<keyVersion>:<ivHex>:<authTagHex>:<ciphertextHex>", or NULL if untested/no credential yet
  credential_configured INTEGER NOT NULL DEFAULT 0, -- 0/1 -- lets GET responses report a boolean without ever touching credential_ciphertext
  health_status         TEXT NOT NULL DEFAULT 'NEVER_TESTED'
                          CHECK (health_status IN ('NEVER_TESTED','CONNECTED','AUTH_EXPIRED','PERMISSION_CHANGED','UNAVAILABLE','DISABLED')),
  last_connection_check_at TEXT,
  last_connection_result TEXT,                     -- JSON: { result, checked_at } — never a credential value
  disabled_at           TEXT,                      -- set on customer disconnect; deployments through this connector are blocked, history preserved
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_siem_connectors_owner ON siem_connectors (owner_id);

CREATE TABLE IF NOT EXISTS siem_connector_audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  action  TEXT NOT NULL,   -- CONNECTOR_CREATED | CONNECTION_TESTED | CREDENTIAL_ROTATED | CONNECTOR_DISABLED | CONNECTOR_DELETED
  data    TEXT,            -- JSON-encoded; owner_id/connector_id/result live inside this blob. NEVER a credential value.
  ts      TEXT NOT NULL
);

-- One canonical deployment record per (connector, detection, target) intent.
-- `state` is the explicit lifecycle (Section 12 of the mandate) — APPROVED
-- and DEPLOYED are never the same row value.
CREATE TABLE IF NOT EXISTS detection_deployments (
  deployment_id       TEXT PRIMARY KEY,        -- dep_xxxxxxxxxxxxxxxxxxxxxxxx
  owner_id            TEXT NOT NULL,
  connector_id        TEXT NOT NULL,           -- FK (app-level) -> siem_connectors.id, always re-checked for owner_id match
  detection_id        TEXT NOT NULL,           -- detection-rules.js stable rule id
  detection_version    TEXT NOT NULL,           -- pinned at preview time; never re-read as "latest" after approval
  entity_type         TEXT NOT NULL CHECK (entity_type IN ('cve','campaign')),
  entity_id           TEXT NOT NULL,           -- the CVE/campaign this deployment was initiated from (drives compatibility recheck)
  format              TEXT NOT NULL,           -- 'kql' | 'splunk' | ... — the matched format at preview time
  remote_resource_name TEXT NOT NULL,          -- deterministic, derived from (connector_id, detection_id) — the idempotency key
  -- APPROVED and DEPLOYED are deliberately never the same value (mandate
  -- requirement). ROLLBACK_AVAILABLE/ROLLED_BACK are deliberately NOT
  -- states here: this table uses one row per (connector,detection,entity)
  -- triple for its entire lifecycle, rotating deployed_intent_snapshot /
  -- previous_intent_snapshot in place on UPDATE/ROLLBACK rather than
  -- spawning a sibling row per version — so "rollback available" is the
  -- derived boolean !!previous_intent_snapshot (deployment-store.js
  -- #toPublicDeployment), and a completed rollback simply returns the row
  -- to VERIFIED with the restored content, not a distinct terminal state
  -- (Section 12: "do not create unnecessary states").
  state               TEXT NOT NULL
                        CHECK (state IN (
                          'DRAFT','PREVIEWED','APPROVAL_REQUIRED','APPROVED','DEPLOYING','DEPLOYED',
                          'VERIFYING','VERIFIED','DRIFTED','UPDATE_REQUIRED','FAILED_RETRYABLE',
                          'FAILED_TERMINAL','DISABLED'
                        )),
  desired_hash         TEXT,                    -- sha256 over the approved deployment intent (see deployment-engine.js#computeApprovalHash)
  observed_hash        TEXT,                    -- sha256 over the canonicalized remote-read-back state; NULL until first read-back
  remote_resource_id   TEXT,                    -- full ARM resource ID (or connector-specific remote ID) once created
  remote_etag          TEXT,                    -- optimistic-concurrency token, when the connector supports one
  enabled_desired      INTEGER NOT NULL DEFAULT 0, -- 0/1 -- safe-default DISABLED unless explicitly approved with enabled=true
  deployed_intent_snapshot TEXT,               -- JSON: the full connector-agnostic intent object as actually deployed (query/severity_raw/technique_id/title/description/enabled).
                                                 -- CAPTURED HERE because detection-rules.js#storeRule() overwrites a rule's `platforms` content in place on
                                                 -- each new version (its history[] records only version/timestamp/change metadata, never a content snapshot) —
                                                 -- so this table, not the canonical store, is the only place a prior deployed version's exact content survives
                                                 -- for rollback (see deployment-engine.js's header for the full reasoning).
  previous_intent_snapshot TEXT,               -- JSON: ONE level of undo — the intent that was deployed immediately before the current
                                                 -- deployed_intent_snapshot. Set when an UPDATE overwrites a previously-VERIFIED deployment;
                                                 -- consumed (cleared) by a successful ROLLBACK (Section 53: "restore prior version", singular).
  pending_action       TEXT CHECK (pending_action IN ('DEPLOY','UPDATE','ROLLBACK') OR pending_action IS NULL),
                                                 -- set by previewDeployment()/previewRollback(), read by executeDeployment() to decide
                                                 -- whether the intent comes from live canonical sources or from previous_intent_snapshot.
  last_error           TEXT,                    -- JSON: { code, message } for the most recent FAILED_* transition; never a credential value
  previous_deployment_id TEXT,                  -- reserved for a future multi-workspace/target migration path; unused by the single-row update/rollback model above
  created_at           TEXT NOT NULL,
  approved_at          TEXT,
  deployed_at          TEXT,
  verified_at          TEXT,
  updated_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deployments_owner ON detection_deployments (owner_id);
CREATE INDEX IF NOT EXISTS idx_deployments_connector ON detection_deployments (connector_id);
CREATE INDEX IF NOT EXISTS idx_deployments_state ON detection_deployments (state);
CREATE INDEX IF NOT EXISTS idx_deployments_detection ON detection_deployments (detection_id);
-- Idempotency/uniqueness: at most one non-terminal deployment per
-- (connector, detection, entity) triple — a second PREVIEW/APPROVE for the
-- same triple reuses the existing row rather than creating a sibling.
-- Terminal states (ROLLED_BACK/DISABLED/FAILED_TERMINAL) are excluded from
-- the uniqueness scope at the application layer (deployment-store.js),
-- since SQLite partial-unique-index predicates on non-deterministic
-- CHECK-constrained text columns are avoided here for portability; the
-- application layer enforces "reuse the latest non-terminal row" instead.

CREATE TABLE IF NOT EXISTS deployment_approvals (
  approval_id         TEXT PRIMARY KEY,        -- appr_xxxxxxxxxxxxxxxxxxxxxxxx
  deployment_id       TEXT NOT NULL,
  owner_id            TEXT NOT NULL,           -- the approving identity — always re-derived from authenticate(), never request body
  detection_version    TEXT NOT NULL,
  connector_id        TEXT NOT NULL,
  target_config_hash   TEXT NOT NULL,          -- hash of the connector's target_config at approval time (detects target drift)
  approved_hash        TEXT NOT NULL,          -- == desired_hash on detection_deployments at the moment of approval
  enabled_requested    INTEGER NOT NULL DEFAULT 0,
  created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_deployment ON deployment_approvals (deployment_id);

CREATE TABLE IF NOT EXISTS deployment_attempts (
  attempt_id    TEXT PRIMARY KEY,       -- att_xxxxxxxxxxxxxxxxxxxxxxxx
  deployment_id TEXT NOT NULL,
  action        TEXT NOT NULL CHECK (action IN ('DEPLOY','UPDATE','READBACK','DISABLE','ROLLBACK','RECONCILE')),
  result        TEXT NOT NULL CHECK (result IN ('SUCCESS','FAILED_RETRYABLE','FAILED_TERMINAL')),
  error_code    TEXT,
  http_status   INTEGER,
  started_at    TEXT NOT NULL,
  finished_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_deployment ON deployment_attempts (deployment_id);

CREATE TABLE IF NOT EXISTS deployment_audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  action  TEXT NOT NULL,   -- PREVIEW_CREATED | DEPLOYMENT_APPROVED | DEPLOYMENT_STARTED | DEPLOYMENT_VERIFIED |
                            -- DEPLOYMENT_FAILED | DRIFT_DETECTED | ROLLBACK_APPROVED | ROLLBACK_COMPLETED | DEPLOYMENT_DISABLED
  data    TEXT,            -- JSON-encoded; actor/owner_id/deployment_id/detection_id/version/target/result live inside this blob
  ts      TEXT NOT NULL
);

-- Backing store for the deterministic mock/test SIEM connector
-- (api/_lib/connectors/mock-siem-connector.js, Section 91 of the mandate).
-- A real, D1-persisted "fake remote system" — not merely an in-memory
-- object — because preview/approve/execute/read-back are separate HTTP
-- requests (and, on Cloudflare Workers, potentially separate isolates),
-- so the simulated remote state must survive across requests exactly
-- like a real SIEM's state would. This also gives contract tests a real
-- way to simulate "an administrator changed the rule out of band"
-- (UPDATE this table directly) to prove drift detection without touching
-- any live vendor API.
CREATE TABLE IF NOT EXISTS mock_siem_resources (
  connector_id    TEXT NOT NULL,
  resource_name   TEXT NOT NULL,
  payload         TEXT NOT NULL,   -- JSON: the simulated remote rule's controlled fields
  etag            TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  PRIMARY KEY (connector_id, resource_name)
);
