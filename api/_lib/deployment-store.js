'use strict';
/**
 * SENTINEL APEX — Detection Deployment Persistence (Controlled SIEM
 * Deployment Gateway v1)
 *
 * D1-backed lifecycle state for detection_deployments / deployment_
 * approvals / deployment_attempts / deployment_audit_log
 * (migrations/0004_siem_deployment_gateway.sql). Ownership always
 * re-derived from the caller's authenticate()-issued userId, matching
 * every other customer-owned store in this codebase.
 *
 * This module is pure persistence + identity derivation — the actual
 * state-machine transitions, approval-hash computation, and connector
 * dispatch live in deployment-engine.js, which is the only caller of the
 * mutating functions below.
 */

const crypto = require('crypto');
const d1 = require('./d1');

const AUDIT_LOG_MAX_ENTRIES = 10000;
const NON_TERMINAL_STATES = [
  'DRAFT', 'PREVIEWED', 'APPROVAL_REQUIRED', 'APPROVED', 'DEPLOYING', 'DEPLOYED',
  'VERIFYING', 'VERIFIED', 'DRIFTED', 'UPDATE_REQUIRED', 'FAILED_RETRYABLE', 'ROLLBACK_AVAILABLE',
];

function generateId(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

/**
 * Deterministic, not random (Section 39/41 idempotency + Section 41
 * "no sensitive customer metadata in rule names"): the same
 * (connector, detection) pair always derives the same remote resource
 * name, which is the idempotency key every connector's deploy() upserts
 * against. Includes a stable SENTINEL APEX marker prefix (Section 39).
 */
function deriveRemoteResourceName(connectorId, detectionId) {
  const hash = crypto.createHash('sha256').update(`${connectorId}:${detectionId}`).digest('hex');
  return `sentinelapex-${hash.slice(0, 32)}`;
}

async function appendDeploymentAudit(action, data = {}) {
  try {
    await d1.run(
      'INSERT INTO deployment_audit_log (action, data, ts) VALUES (?, ?, ?)',
      [action, JSON.stringify(data), new Date().toISOString()]
    );
    await d1.run(
      `DELETE FROM deployment_audit_log WHERE id NOT IN
       (SELECT id FROM deployment_audit_log ORDER BY id DESC LIMIT ?)`,
      [AUDIT_LOG_MAX_ENTRIES]
    ).catch(() => {});
  } catch (_) {
    // Audit failure must never break the main deployment flow.
  }
}

function toPublicDeployment(row) {
  return {
    deployment_id: row.deployment_id,
    connector_id: row.connector_id,
    detection_id: row.detection_id,
    detection_version: row.detection_version,
    entity_type: row.entity_type,
    entity_id: row.entity_id,
    format: row.format,
    remote_resource_name: row.remote_resource_name,
    state: row.state,
    remote_resource_id: row.remote_resource_id,
    enabled_desired: !!row.enabled_desired,
    pending_action: row.pending_action || null,
    rollback_available: !!row.previous_intent_snapshot,
    last_error: row.last_error ? JSON.parse(row.last_error) : null,
    created_at: row.created_at,
    approved_at: row.approved_at,
    deployed_at: row.deployed_at,
    verified_at: row.verified_at,
    updated_at: row.updated_at,
  };
}

async function getDeploymentRaw(ownerId, deploymentId) {
  const rows = await d1.query('SELECT * FROM detection_deployments WHERE deployment_id = ? AND owner_id = ?', [deploymentId, ownerId]);
  return rows[0] || null;
}

async function getDeployment(ownerId, deploymentId) {
  const row = await getDeploymentRaw(ownerId, deploymentId);
  if (!row) return { error: 'NOT_FOUND', message: 'No deployment found.' };
  return { deployment: toPublicDeployment(row) };
}

async function listDeployments(ownerId) {
  const rows = await d1.query('SELECT * FROM detection_deployments WHERE owner_id = ? ORDER BY created_at DESC', [ownerId]);
  return rows.map(toPublicDeployment);
}

// Mirrors hunt-engine.js's own (unexported) LIVE_DEPLOYMENT_STATES exactly
// -- "currently deployed in some customer's environment," not "has ever
// had a deployment record" (a long-removed/failed attempt shouldn't count
// toward how many customers presently run this detection).
const LIVE_DEPLOYMENT_STATES = ['DEPLOYED', 'VERIFYING', 'VERIFIED', 'DRIFTED', 'UPDATE_REQUIRED'];

/**
 * Detection Performance Intelligence v1: GLOBAL (cross-tenant) count of
 * how many distinct customers currently have a live deployment of this
 * detection -- a Review Priority input ("number of affected deployments").
 * Safe to compute cross-tenant because it returns only a count, never an
 * owner_id, connector_id, or any other identifying field -- same
 * aggregate-only contract as detection-feedback-store.js's
 * computeFeedbackSignal()/computeGlobalReviewMetrics().
 */
async function countDeploymentsByDetection(detectionId) {
  const placeholders = LIVE_DEPLOYMENT_STATES.map(() => '?').join(',');
  const rows = await d1.query(
    `SELECT COUNT(*) AS total, COUNT(DISTINCT owner_id) AS distinct_owners
     FROM detection_deployments WHERE detection_id = ? AND state IN (${placeholders})`,
    [detectionId, ...LIVE_DEPLOYMENT_STATES]
  );
  const row = rows[0] || {};
  return { total: Number(row.total) || 0, distinct_owners: Number(row.distinct_owners) || 0 };
}

/** Finds the current non-terminal deployment for this exact (connector,
 *  detection, entity) triple, if one exists — the idempotency check that
 *  keeps repeated PREVIEW calls from spawning sibling rows (Section 41). */
async function findActiveDeployment(ownerId, connectorId, detectionId, entityType, entityId) {
  const placeholders = NON_TERMINAL_STATES.map(() => '?').join(',');
  const rows = await d1.query(
    `SELECT * FROM detection_deployments
     WHERE owner_id = ? AND connector_id = ? AND detection_id = ? AND entity_type = ? AND entity_id = ?
       AND state IN (${placeholders})
     ORDER BY created_at DESC LIMIT 1`,
    [ownerId, connectorId, detectionId, entityType, entityId, ...NON_TERMINAL_STATES]
  );
  return rows[0] || null;
}

async function createDraftDeployment(ownerId, { connectorId, detectionId, detectionVersion, entityType, entityId, format }) {
  const deploymentId = generateId('dep');
  const remoteResourceName = deriveRemoteResourceName(connectorId, detectionId);
  const nowIso = new Date().toISOString();
  await d1.run(
    `INSERT INTO detection_deployments
      (deployment_id, owner_id, connector_id, detection_id, detection_version, entity_type, entity_id,
       format, remote_resource_name, state, enabled_desired, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'DRAFT', 0, ?, ?)`,
    [deploymentId, ownerId, connectorId, detectionId, detectionVersion, entityType, entityId, format, remoteResourceName, nowIso, nowIso]
  );
  return getDeploymentRaw(ownerId, deploymentId);
}

/**
 * Atomic claim (Section 98: two concurrent execute requests must produce
 * one semantic remote deployment) — mirrors the notification_delivery_jobs
 * claim pattern (`d1.js#runMutationWithChanges()`'s own header) rather
 * than a plain SELECT-then-branch, which would race under real
 * concurrency. Only the caller that actually flips the row from an
 * executable state to 'DEPLOYING' proceeds; a losing concurrent caller
 * gets `claimed: false` and must not touch the connector at all.
 */
async function claimForExecution(deploymentId) {
  const affected = await d1.runMutationWithChanges(
    `UPDATE detection_deployments SET state = 'DEPLOYING', updated_at = ?
     WHERE deployment_id = ? AND state IN ('APPROVED', 'FAILED_RETRYABLE')`,
    [new Date().toISOString(), deploymentId]
  );
  return { claimed: affected === 1 };
}

/** Generic field/state updater — the only mutation primitive every
 *  deployment-engine.js transition goes through, so `updated_at` and
 *  audit-log symmetry can never be forgotten in one call site but not
 *  another. */
async function updateDeployment(deploymentId, fields) {
  const columns = Object.keys(fields);
  if (!columns.length) return;
  const setClause = columns.map(c => `${c} = ?`).join(', ');
  const values = columns.map(c => fields[c]);
  await d1.run(
    `UPDATE detection_deployments SET ${setClause}, updated_at = ? WHERE deployment_id = ?`,
    [...values, new Date().toISOString(), deploymentId]
  );
}

async function recordApproval(deploymentId, ownerId, { detectionVersion, connectorId, targetConfigHash, approvedHash, enabledRequested }) {
  const approvalId = generateId('appr');
  const nowIso = new Date().toISOString();
  await d1.run(
    `INSERT INTO deployment_approvals
      (approval_id, deployment_id, owner_id, detection_version, connector_id, target_config_hash, approved_hash, enabled_requested, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [approvalId, deploymentId, ownerId, detectionVersion, connectorId, targetConfigHash, approvedHash, enabledRequested ? 1 : 0, nowIso]
  );
  return approvalId;
}

async function getLatestApproval(deploymentId) {
  const rows = await d1.query(
    'SELECT * FROM deployment_approvals WHERE deployment_id = ? ORDER BY created_at DESC LIMIT 1',
    [deploymentId]
  );
  return rows[0] || null;
}

async function recordAttempt(deploymentId, { action, result, errorCode, httpStatus, startedAt, finishedAt }) {
  const attemptId = generateId('att');
  await d1.run(
    `INSERT INTO deployment_attempts (attempt_id, deployment_id, action, result, error_code, http_status, started_at, finished_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [attemptId, deploymentId, action, result, errorCode || null, httpStatus || null, startedAt, finishedAt]
  );
  return attemptId;
}

async function listAttempts(deploymentId) {
  return d1.query('SELECT * FROM deployment_attempts WHERE deployment_id = ? ORDER BY started_at DESC', [deploymentId]);
}

module.exports = {
  NON_TERMINAL_STATES,
  deriveRemoteResourceName,
  appendDeploymentAudit,
  toPublicDeployment,
  getDeploymentRaw,
  getDeployment,
  listDeployments,
  countDeploymentsByDetection,
  findActiveDeployment,
  createDraftDeployment,
  claimForExecution,
  updateDeployment,
  recordApproval,
  getLatestApproval,
  recordAttempt,
  listAttempts,
};
