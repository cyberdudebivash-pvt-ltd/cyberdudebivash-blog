'use strict';
/**
 * SENTINEL APEX — Controlled Read-Only SIEM Hunting: Query Execution
 * Persistence
 *
 * D1-backed metadata for hunt_query_executions (migrations/0007). Pure
 * persistence + identity derivation only, mirroring hunt-store.js's exact
 * conventions — bounds/safety/readiness/connector orchestration lives in
 * hunt-query-engine.js, which composes this module with hunt-store.js,
 * siem-connector-store.js, and connector-registry.js rather than
 * re-implementing any of them.
 *
 * Deliberately stores metadata ONLY — never a raw result row (see
 * migrations/0007_readonly_siem_hunting.sql's header for why no such
 * table exists at all: this is never allowed to become a telemetry lake).
 */

const crypto = require('crypto');
const d1 = require('./d1');

const EXECUTION_STATES = ['RUNNING', 'SUCCEEDED', 'PARTIAL', 'TIMED_OUT', 'RATE_LIMITED', 'FAILED'];
const ERROR_CLASSIFICATIONS = ['QUERY_DEFECT', 'PROVIDER_ISSUE', 'AUTH_ISSUE'];

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;

function generateExecutionId() {
  return `hqx_${crypto.randomBytes(12).toString('hex')}`;
}

function boundedLimit(requested) {
  const n = Number(requested);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_LIST_LIMIT;
  return Math.min(Math.floor(n), MAX_LIST_LIMIT);
}

function toPublicExecution(row) {
  return {
    execution_id: row.execution_id,
    hunt_id: row.hunt_id,
    query_id: row.query_id,
    connector_id: row.connector_id,
    detection_id: row.detection_id,
    detection_version: row.detection_version,
    format: row.format,
    time_start: row.time_start,
    time_end: row.time_end,
    row_limit: row.row_limit,
    state: row.state,
    result_row_count: (row.result_row_count === null || row.result_row_count === undefined) ? null : Number(row.result_row_count),
    error_code: row.error_code || null,
    error_classification: row.error_classification || null,
    started_at: row.started_at,
    completed_at: row.completed_at || null,
    created_at: row.created_at,
  };
}

async function createExecution(ownerId, { huntId, queryId, connectorId, detectionId, detectionVersion, format, timeStart, timeEnd, rowLimit }) {
  const executionId = generateExecutionId();
  const nowIso = new Date().toISOString();
  await d1.run(
    `INSERT INTO hunt_query_executions
      (execution_id, owner_id, hunt_id, query_id, connector_id, detection_id, detection_version, format, time_start, time_end, row_limit, state, started_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RUNNING', ?, ?)`,
    [executionId, ownerId, huntId, queryId, connectorId, detectionId, String(detectionVersion), format, timeStart, timeEnd, rowLimit, nowIso, nowIso]
  );
  return executionId;
}

/** The one mutation after creation — moves a RUNNING row to its terminal
 *  state. Never called twice for the same execution_id in normal
 *  operation, but idempotent if it ever were (a later call simply
 *  overwrites with the same or a corrected outcome, never throws). */
async function completeExecution(executionId, { state, resultRowCount, errorCode, errorClassification }) {
  await d1.run(
    `UPDATE hunt_query_executions
     SET state = ?, result_row_count = ?, error_code = ?, error_classification = ?, completed_at = ?
     WHERE execution_id = ?`,
    [
      state,
      (resultRowCount === undefined || resultRowCount === null) ? null : Number(resultRowCount),
      errorCode || null,
      errorClassification || null,
      new Date().toISOString(),
      executionId,
    ]
  );
}

async function getExecution(ownerId, executionId) {
  const rows = await d1.query('SELECT * FROM hunt_query_executions WHERE execution_id = ? AND owner_id = ?', [executionId, ownerId]);
  return rows[0] ? toPublicExecution(rows[0]) : null;
}

/** Ownership is always re-derived from ownerId here, never trusted from
 *  huntId alone — a hunt_id belonging to another tenant simply returns no
 *  rows (Section: customer ownership/IDOR/BOLA P0 gate). */
async function listExecutionsForHunt(ownerId, huntId, { limit } = {}) {
  const boundedN = boundedLimit(limit);
  const rows = await d1.query(
    'SELECT * FROM hunt_query_executions WHERE owner_id = ? AND hunt_id = ? ORDER BY created_at DESC LIMIT ?',
    [ownerId, huntId, boundedN]
  );
  return rows.map(toPublicExecution);
}

module.exports = {
  EXECUTION_STATES,
  ERROR_CLASSIFICATIONS,
  generateExecutionId,
  toPublicExecution,
  createExecution,
  completeExecution,
  getExecution,
  listExecutionsForHunt,
};
