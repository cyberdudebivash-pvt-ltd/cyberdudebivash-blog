'use strict';
/**
 * SENTINEL APEX — Deterministic Mock/Test SIEM Connector (Section 91)
 *
 * A real, D1-persisted "fake remote system" (migrations/0004_siem_
 * deployment_gateway.sql#mock_siem_resources) — not an in-memory object —
 * so its simulated remote state survives across the separate HTTP
 * requests a real deployment lifecycle spans (preview -> approve ->
 * execute -> read-back are never one request). This is also a first-
 * class, customer-selectable "Sandbox / Test Connector" platform (safe:
 * it never touches any real customer infrastructure), which is what lets
 * a customer — and this platform's own browser QA — exercise the full
 * approve/deploy/verify/drift/rollback workflow with zero live vendor
 * dependency (mandate Sections 90-93).
 *
 * Failure/edge-case simulation is driven entirely by
 * connector.target_config.simulate, a string a connector owner sets
 * explicitly when creating a *test* connector (never present on a real
 * platform's target_config shape) — Section 91's required behaviors:
 *   'AUTH_FAILED'          -> testConnection() returns AUTH_FAILED
 *   'PERMISSION_DENIED'    -> testConnection() returns INSUFFICIENT_PERMISSION
 *   'TARGET_NOT_FOUND'     -> testConnection() returns TARGET_NOT_FOUND
 *   'UNAVAILABLE'          -> testConnection() returns UNAVAILABLE
 *   'RATE_LIMITED'         -> deploy()/readBack() throw a retryable 429 ConnectorError
 *   'SERVER_ERROR'         -> deploy()/readBack() throw a retryable 500 ConnectorError
 *   'TIMEOUT'              -> deploy() throws a retryable TIMEOUT before writing anything
 *   'TIMEOUT_AFTER_CREATE' -> deploy() WRITES the resource, then throws TIMEOUT — proves
 *                             the ambiguous-create-then-retry reconciliation path (Section 43/99)
 * Any other/absent value -> normal, successful behavior.
 *
 * Controlled Read-Only SIEM Hunting Connectors v1 (Section 56) reuses the
 * exact same connector.target_config.simulate values above for
 * testHuntQueryConnection()/executeHuntQuery()'s connector-level failure
 * modes (AUTH_FAILED/PERMISSION_DENIED/UNAVAILABLE/RATE_LIMITED/
 * SERVER_ERROR/TIMEOUT) — a connector-wide simulated condition applies to
 * every operation the connector performs, hunting included, never a
 * second parallel simulate vocabulary. Result-SHAPE scenarios (row count,
 * malformed schema, hostile field values), being per-query rather than
 * per-connector, are driven instead by a `__SIMULATE_HUNT__:MARKER`
 * substring embedded directly in the query text a test passes to
 * executeHuntQuery() — this needs no new connector schema/table, and
 * mirrors reality exactly (a hunt query already IS just query text, see
 * hunt_queries#query_snapshot). Absent any marker: zero rows (NO_SIGNAL),
 * never fabricated activity.
 */

const d1 = require('../d1');
const crypto = require('crypto');
const { ConnectorError, normalizeObservationRows } = require('./connector-contract');

const PLATFORM_ID = 'mock-siem';

function simulateOf(connector) {
  return (connector.target_config && connector.target_config.simulate) || null;
}

const HUNT_SIMULATE_MARKER = '__SIMULATE_HUNT__:';
const HUNT_SIMULATE = Object.freeze({
  ZERO_RESULTS: 'ZERO_RESULTS',
  ONE_RESULT: 'ONE_RESULT',
  HUNDRED_RESULTS: 'HUNDRED_RESULTS',
  OVER_LIMIT: 'OVER_LIMIT',
  MALFORMED_SCHEMA: 'MALFORMED_SCHEMA',
  HOSTILE_FIELDS: 'HOSTILE_FIELDS',
  QUERY_ERROR: 'QUERY_ERROR', // a genuine query/field defect the remote SIEM itself rejects -- mirrors microsoft-sentinel-connector.js's real 400 handling, never reachable via the engine's own pre-flight bounds checks alone
});

function huntSimulateOf(query) {
  if (typeof query !== 'string') return null;
  const idx = query.indexOf(HUNT_SIMULATE_MARKER);
  if (idx === -1) return null;
  const match = query.slice(idx + HUNT_SIMULATE_MARKER.length).match(/^[A-Z_]+/);
  return match ? match[0] : null;
}

async function testConnection(connector) {
  const sim = simulateOf(connector);
  if (sim === 'AUTH_FAILED') return { result: 'AUTH_FAILED', detail: 'Simulated authentication failure.' };
  if (sim === 'PERMISSION_DENIED') return { result: 'INSUFFICIENT_PERMISSION', detail: 'Simulated insufficient-permission response.' };
  if (sim === 'TARGET_NOT_FOUND') return { result: 'TARGET_NOT_FOUND', detail: 'Simulated target-not-found response.' };
  if (sim === 'UNAVAILABLE') return { result: 'UNAVAILABLE', detail: 'Simulated service-unavailable response.' };
  return { result: 'CONNECTED', detail: 'Sandbox connector — no real SIEM contacted.' };
}

function mapIntent(_connector, intent) {
  return {
    nativePayload: {
      name: intent.remote_resource_name,
      title: intent.title,
      description: intent.description,
      query: intent.query,
      severity: intent.severity_raw,
      enabled: !!intent.enabled,
      techniques: [intent.technique_id],
    },
  };
}

/** The canonical {query,severity,enabled,techniques} shape this intent
 *  WOULD produce if deployed — same shape readBack() returns, so
 *  deployment-engine.js can hash both sides identically (Section 46/47).
 *  The mock stores severity_raw verbatim (no vendor remapping). */
function toCanonicalObserved(intent) {
  return {
    query: intent.query,
    severity: intent.severity_raw,
    enabled: !!intent.enabled,
    techniques: [intent.technique_id].sort(),
  };
}

function maybeThrowPreDeploy(sim) {
  if (sim === 'RATE_LIMITED') throw new ConnectorError('RATE_LIMITED', 'Simulated 429 from mock SIEM.', { retryable: true, httpStatus: 429 });
  if (sim === 'SERVER_ERROR') throw new ConnectorError('REMOTE_ERROR', 'Simulated 500 from mock SIEM.', { retryable: true, httpStatus: 500 });
  if (sim === 'TIMEOUT') throw new ConnectorError('TIMEOUT', 'Simulated request timeout (no resource created).', { retryable: true });
}

async function upsertResource(connector, intent) {
  const nowIso = new Date().toISOString();
  const { nativePayload } = mapIntent(connector, intent);
  const existing = await d1.query(
    'SELECT etag FROM mock_siem_resources WHERE connector_id = ? AND resource_name = ?',
    [connector.id, intent.remote_resource_name]
  );
  const etag = crypto.randomBytes(8).toString('hex');
  if (existing.length) {
    await d1.run(
      'UPDATE mock_siem_resources SET payload = ?, etag = ?, updated_at = ? WHERE connector_id = ? AND resource_name = ?',
      [JSON.stringify(nativePayload), etag, nowIso, connector.id, intent.remote_resource_name]
    );
  } else {
    await d1.run(
      `INSERT INTO mock_siem_resources (connector_id, resource_name, payload, etag, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [connector.id, intent.remote_resource_name, JSON.stringify(nativePayload), etag, nowIso, nowIso]
    );
  }
  return { remote_resource_id: `mock://${connector.id}/${intent.remote_resource_name}`, remote_etag: etag, raw: nativePayload };
}

/** Idempotent upsert — calling twice with the same intent updates the same row, never creates a sibling. */
async function deploy(connector, intent) {
  const sim = simulateOf(connector);
  maybeThrowPreDeploy(sim);
  const result = await upsertResource(connector, intent);
  if (sim === 'TIMEOUT_AFTER_CREATE') {
    // The write above already committed -- this simulates the real-world
    // ambiguous case where the remote mutation succeeded but the response
    // never reached the caller. Reconciliation (readBack by
    // remote_resource_name) must discover this on retry, not create a
    // duplicate (Section 43/99).
    throw new ConnectorError('TIMEOUT', 'Simulated timeout after the remote resource was actually created.', { retryable: true });
  }
  return result;
}

async function readBack(connector, remoteResourceName) {
  const sim = simulateOf(connector);
  if (sim === 'RATE_LIMITED') throw new ConnectorError('RATE_LIMITED', 'Simulated 429 from mock SIEM.', { retryable: true, httpStatus: 429 });
  if (sim === 'SERVER_ERROR') throw new ConnectorError('REMOTE_ERROR', 'Simulated 500 from mock SIEM.', { retryable: true, httpStatus: 500 });

  const rows = await d1.query(
    'SELECT payload, etag FROM mock_siem_resources WHERE connector_id = ? AND resource_name = ?',
    [connector.id, remoteResourceName]
  );
  if (!rows.length) return { found: false, observed: null, etag: null, raw: null };
  const raw = JSON.parse(rows[0].payload);
  return {
    found: true,
    observed: {
      query: raw.query,
      severity: raw.severity,
      enabled: !!raw.enabled,
      techniques: [...(raw.techniques || [])].sort(),
    },
    etag: rows[0].etag,
    raw,
  };
}

async function disable(connector, remoteResourceName) {
  const rows = await d1.query(
    'SELECT payload FROM mock_siem_resources WHERE connector_id = ? AND resource_name = ?',
    [connector.id, remoteResourceName]
  );
  if (!rows.length) return { ok: false };
  const raw = JSON.parse(rows[0].payload);
  raw.enabled = false;
  const etag = crypto.randomBytes(8).toString('hex');
  await d1.run(
    'UPDATE mock_siem_resources SET payload = ?, etag = ?, updated_at = ? WHERE connector_id = ? AND resource_name = ?',
    [JSON.stringify(raw), etag, new Date().toISOString(), connector.id, remoteResourceName]
  );
  return { ok: true };
}

async function deleteRemote(connector, remoteResourceName) {
  await d1.run(
    'DELETE FROM mock_siem_resources WHERE connector_id = ? AND resource_name = ?',
    [connector.id, remoteResourceName]
  );
  return { ok: true };
}

/** Same connector-level simulate values testConnection() honors — a
 *  real, separate call (never inferred from testConnection()'s result),
 *  but the mock's simulate semantics are connector-wide by design, so the
 *  same simulate value legitimately drives both. */
async function testHuntQueryConnection(connector) {
  const sim = simulateOf(connector);
  if (sim === 'AUTH_FAILED') return { result: 'AUTH_FAILED', detail: 'Simulated authentication failure (hunt query path).' };
  if (sim === 'PERMISSION_DENIED') return { result: 'INSUFFICIENT_PERMISSION', detail: 'Simulated insufficient-permission response (hunt query path).' };
  if (sim === 'TARGET_NOT_FOUND') return { result: 'TARGET_NOT_FOUND', detail: 'Simulated target-not-found response (hunt query path).' };
  if (sim === 'UNAVAILABLE') return { result: 'UNAVAILABLE', detail: 'Simulated service-unavailable response (hunt query path).' };
  return { result: 'CONNECTED', detail: 'Sandbox connector — no real SIEM contacted.' };
}

function sandboxRow(i) {
  return {
    host: `sandbox-host-${i}`,
    user: `sandbox-user-${i}`,
    process: 'powershell.exe',
    timestamp: new Date(Date.now() - i * 60000).toISOString(),
    detail: `Simulated sandbox observation #${i}`,
  };
}

/** Read-only. Never creates/modifies/deletes any mock_siem_resources row —
 *  hunting and deployment are deliberately fully independent data paths. */
async function executeHuntQuery(connector, { query, format, timeStart, timeEnd, rowLimit }) {
  const sim = simulateOf(connector);
  if (sim === 'AUTH_FAILED') throw new ConnectorError('AUTH_FAILED', 'Simulated authentication failure.', { retryable: false, httpStatus: 401 });
  if (sim === 'PERMISSION_DENIED') throw new ConnectorError('PERMISSION_DENIED', 'Simulated insufficient-permission response.', { retryable: false, httpStatus: 403 });
  if (sim === 'RATE_LIMITED') throw new ConnectorError('RATE_LIMITED', 'Simulated 429 from mock SIEM.', { retryable: true, httpStatus: 429 });
  if (sim === 'SERVER_ERROR') throw new ConnectorError('REMOTE_ERROR', 'Simulated 500 from mock SIEM.', { retryable: true, httpStatus: 500 });
  if (sim === 'TIMEOUT') throw new ConnectorError('TIMEOUT', 'Simulated request timeout.', { retryable: true });

  if (!Number.isInteger(rowLimit) || rowLimit < 1) {
    throw new ConnectorError('QUERY_REJECTED', 'rowLimit must be a positive integer.', { retryable: false });
  }
  if (!timeStart || !timeEnd) {
    throw new ConnectorError('QUERY_REJECTED', 'timeStart and timeEnd are required.', { retryable: false });
  }

  const huntSim = huntSimulateOf(query);

  if (huntSim === HUNT_SIMULATE.QUERY_ERROR) {
    // Simulates the ONE realistic query-defect path a real vendor rejects
    // at execution time (mirrors microsoft-sentinel-connector.js's 400 ->
    // QUERY_REJECTED handling) -- never reachable via rowLimit/time-bounds
    // pre-flight rejection alone, so this is the deterministic fixture
    // that lets hunt-query-engine.js's QUERY_DEFECT -> QUERY_ERROR
    // detection-feedback routing be exercised end-to-end in CI/QA without
    // a live SIEM.
    throw new ConnectorError('QUERY_REJECTED', 'Simulated: the query references an unknown field/table.', { retryable: false });
  }

  if (huntSim === HUNT_SIMULATE.MALFORMED_SCHEMA) {
    // A vendor response whose row shapes don't match anything a real SIEM
    // would send -- proves normalizeResults() fails closed (drops what it
    // can't safely interpret) rather than crashing or passing shapes
    // through unexamined.
    return { rows: [{ unexpected_nested: { a: 1 } }, 'not-an-object', null], truncated: false, raw: { simulate: 'MALFORMED_SCHEMA' } };
  }

  if (huntSim === HUNT_SIMULATE.HOSTILE_FIELDS) {
    return {
      rows: [{
        host: '<script>alert(1)</script>',
        user: '__proto__',
        process: 'constructor',
        timestamp: new Date().toISOString(),
        detail: '"; DROP TABLE hunt_observations; --',
        // Computed key (not the literal `__proto__:` token) is required so
        // this creates a genuine OWN property named "__proto__", matching
        // what JSON.parse() of a hostile remote payload actually produces
        // -- the literal object-literal syntax would instead set this
        // object's real prototype (Annex B.3.1), which would not
        // reproduce the vulnerability class this fixture exists to test.
        ['__proto__']: { polluted: true },
      }],
      truncated: false,
      raw: { simulate: 'HOSTILE_FIELDS' },
    };
  }

  let count;
  if (huntSim === HUNT_SIMULATE.ZERO_RESULTS) count = 0;
  else if (huntSim === HUNT_SIMULATE.ONE_RESULT) count = 1;
  else if (huntSim === HUNT_SIMULATE.HUNDRED_RESULTS) count = 100;
  else if (huntSim === HUNT_SIMULATE.OVER_LIMIT) count = rowLimit + 250;
  else count = 0; // no marker present -> zero results (NO_SIGNAL), never fabricated activity

  const truncated = count > rowLimit;
  const rows = Array.from({ length: truncated ? rowLimit : count }, (_, i) => sandboxRow(i));

  return { rows, truncated, raw: { simulated_total: count, format, timeStart, timeEnd } };
}

/** Pure, no I/O — delegates to connector-contract.js's single shared
 *  implementation (every connector's normalizeResults shares it) rather
 *  than re-deriving the same primitive-only/dangerous-key sanitization
 *  logic here. */
function normalizeResults(_connector, rawRows) {
  return normalizeObservationRows(rawRows);
}

/** Test-only helper: simulates an out-of-band remote change (an admin
 *  editing the rule directly in the SIEM), used exclusively by the drift
 *  contract test (Section 100) -- never called from any customer-facing
 *  code path. */
async function _simulateOutOfBandChange(connectorId, remoteResourceName, patch) {
  const rows = await d1.query(
    'SELECT payload FROM mock_siem_resources WHERE connector_id = ? AND resource_name = ?',
    [connectorId, remoteResourceName]
  );
  if (!rows.length) throw new Error('No mock resource to mutate.');
  const raw = { ...JSON.parse(rows[0].payload), ...patch };
  const etag = crypto.randomBytes(8).toString('hex');
  await d1.run(
    'UPDATE mock_siem_resources SET payload = ?, etag = ?, updated_at = ? WHERE connector_id = ? AND resource_name = ?',
    [JSON.stringify(raw), etag, new Date().toISOString(), connectorId, remoteResourceName]
  );
}

module.exports = {
  platformId: PLATFORM_ID,
  testConnection,
  mapIntent,
  toCanonicalObserved,
  deploy,
  readBack,
  disable,
  deleteRemote,
  testHuntQueryConnection,
  executeHuntQuery,
  normalizeResults,
  _simulateOutOfBandChange,
  HUNT_SIMULATE_MARKER,
  HUNT_SIMULATE,
};
