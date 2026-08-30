-- SENTINEL APEX — Controlled Read-Only SIEM Hunting Connectors & Remote
-- Observation Ingestion v1 (D1)
--
-- Seventh migration against the same `sentinel-apex-core` D1 database. ONE
-- new table. Everything else this tranche needs already exists:
--
--   - hunt_queries (migrations/0005) IS the trusted query template/
--     registry a hunt query executes -- one row per (source_detection_id,
--     source_detection_version), content snapshotted at add-time, format
--     and validation_status already captured. No separate
--     hunt_query_templates table is added: a hunt_queries row already is
--     exactly that, for the one query source this tranche supports
--     (a RELEASED canonical detection's own format-specific content).
--     "Trusted internal query template" (not detection-derived) is
--     deliberately NOT built this round -- no such template exists yet,
--     and inventing one would be exactly the fabrication this platform's
--     governance forbids without real evidence driving it.
--   - hunt_observations (migrations/0005) IS where an analyst-selected
--     remote result row becomes a hunt observation -- no separate
--     "selected result" table. query_id already links an observation back
--     to the hunt_queries row it came from.
--   - hunt_timeline (migrations/0005) IS the append-only audit trail for
--     QUERY_EXECUTED events, matching every other hunt lifecycle event.
--   - detection_feedback (migrations/0005) IS where a genuine QUERY_ERROR
--     signal from a failed remote execution lands -- via the existing,
--     unmodified hunt-engine.js#submitDetectionFeedback().
--
-- Deliberately absent: any raw-telemetry/result-row storage table.
-- Remote query results are bounded and returned directly in the API
-- response (ephemeral -- never persisted), matching the mandate's own
-- "do not become a telemetry lake" requirement. An analyst who wants a
-- specific result to survive must explicitly select it, which persists it
-- as a hunt_observations row (already-existing table, already-existing
-- function) -- never automatically.
--
-- Additive-only: CREATE TABLE IF NOT EXISTS, matching 0001-0006.
CREATE TABLE IF NOT EXISTS hunt_query_executions (
  execution_id          TEXT PRIMARY KEY,      -- hqx_xxxxxxxxxxxxxxxxxxxxxxxx
  owner_id              TEXT NOT NULL,
  hunt_id               TEXT NOT NULL,
  query_id              TEXT NOT NULL,         -- hunt_queries.query_id -- the exact query content executed
  connector_id          TEXT NOT NULL,
  detection_id          TEXT NOT NULL,         -- denormalized from hunt_queries for fast feedback-routing without a join
  detection_version     TEXT NOT NULL,
  format                TEXT NOT NULL,
  time_start            TEXT NOT NULL,         -- explicit, customer/analyst-supplied bounds -- never an unbounded historical query
  time_end              TEXT NOT NULL,
  row_limit             INTEGER NOT NULL,
  state                 TEXT NOT NULL
                          CHECK (state IN ('RUNNING','SUCCEEDED','PARTIAL','TIMED_OUT','RATE_LIMITED','FAILED')),
  result_row_count       INTEGER,               -- count only -- never the rows themselves
  error_code             TEXT,                  -- ConnectorError.code (connector-contract.js) when state is a failure state
  error_classification   TEXT
                          CHECK (error_classification IN ('QUERY_DEFECT','PROVIDER_ISSUE','AUTH_ISSUE') OR error_classification IS NULL),
                          -- QUERY_DEFECT is the ONLY classification that ever
                          -- drives a QUERY_ERROR detection-feedback signal
                          -- (Section 50/105) -- PROVIDER_ISSUE/AUTH_ISSUE
                          -- never do, however many times they occur.
  started_at             TEXT NOT NULL,
  completed_at           TEXT,
  created_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunt_query_executions_hunt ON hunt_query_executions (hunt_id);
CREATE INDEX IF NOT EXISTS idx_hunt_query_executions_owner ON hunt_query_executions (owner_id);
CREATE INDEX IF NOT EXISTS idx_hunt_query_executions_query ON hunt_query_executions (query_id);

-- Two nullable, additive columns on the EXISTING hunt_observations table
-- (migrations/0005) -- never a new observations table -- so an
-- analyst-selected remote result row carries real provenance (Section:
-- observation provenance = connector/query execution/remote timestamp/
-- source/field subset/analyst identity/creation time). created_by +
-- created_at already satisfy analyst identity + creation time;
-- execution_id (joins to hunt_query_executions above) supplies connector +
-- time bounds + remote timestamp context; selected_fields_json is the
-- ONE normalized row's `fields` object the analyst explicitly chose to
-- keep -- already sanitized (primitives only, dangerous keys stripped,
-- each value capped) by connector-contract.js#normalizeObservationRows
-- before it ever reaches here, and hunt-store.js#addObservation() bounds
-- its serialized size again on top of that. Both columns are NULL for
-- every pre-existing and every manually-authored (non-query-derived)
-- observation -- backward compatible by construction, no existing row or
-- caller is affected.
ALTER TABLE hunt_observations ADD COLUMN execution_id TEXT;
ALTER TABLE hunt_observations ADD COLUMN selected_fields_json TEXT;
