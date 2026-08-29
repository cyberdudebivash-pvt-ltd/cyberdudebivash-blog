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
 */

const d1 = require('../d1');
const crypto = require('crypto');
const { ConnectorError } = require('./connector-contract');

const PLATFORM_ID = 'mock-siem';

function simulateOf(connector) {
  return (connector.target_config && connector.target_config.simulate) || null;
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
  _simulateOutOfBandChange,
};
