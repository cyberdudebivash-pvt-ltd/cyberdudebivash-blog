/**
 * SENTINEL APEX — Controlled Detection Deployments (Controlled SIEM
 * Deployment Gateway v1)
 * Single serverless function handling the preview -> approve -> execute ->
 * verify -> rollback lifecycle, matching the established api/v1/watchlists.js
 * / api/v1/defense-profile.js router convention exactly.
 *
 * Routing: /api/v1/deployments?action={action}
 *
 *  action=list                    GET   The caller's own deployment history
 *  action=get&id=                 GET   One deployment's current state
 *  action=history&id=              GET   Attempt log for one deployment (no credentials, no stack traces)
 *  action=preview                  POST  Body: {connector_id, detection_id, entity_type, entity_id, enabled?}
 *  action=approve&id=                  POST  Body: {enabled?} -- server-side approval; a client "approved: true" flag alone is never sufficient
 *  action=execute&id=                  POST  Recomputes eligibility + approval hash, dispatches to the connector, reads back, verifies
 *  action=verify&id=                   POST  On-demand read-back / drift check for an already-deployed row
 *  action=preview-rollback&id=              POST  Shows the restore-to-previous-version diff; still requires a fresh approve+execute
 *  action=disable&id=                  POST  Disables the remote rule (never deletes) and marks this deployment DISABLED
 *
 * Every action requires authenticate() -- ownership is always re-derived
 * from the authenticated caller's userId. Detection content, customer
 * compatibility, and connector credentials are never accepted from the
 * request body — the server always derives them from canonical sources
 * (deployment-engine.js's header explains why this is a stronger
 * approval-hash guarantee than hashing a client-supplied payload).
 */
'use strict';

const sec = require('../_lib/security');
const { authenticate, successResponse, apiError } = require('../_lib/middleware');
const { parseBody } = require('../_lib/payment-utils');
const deploymentStore = require('../_lib/deployment-store');
const engine = require('../_lib/deployment-engine');

const VALID_ACTIONS = 'list, get, history, preview, approve, execute, verify, preview-rollback, disable';
const FIELDS = {
  preview: ['connector_id', 'detection_id', 'entity_type', 'entity_id', 'enabled'],
  approve: ['enabled'],
  execute: [],
  verify: [],
  'preview-rollback': [],
  disable: [],
};

const BLOCK_STATUS = {
  NOT_FOUND: 404,
  CONNECTOR_DISABLED: 409,
  PLATFORM_NOT_IMPLEMENTED: 400,
  CREDENTIAL_NOT_CONFIGURED: 409,
  CREDENTIAL_DECRYPT_FAILED: 500,
  DETECTION_NOT_FOUND: 404,
  UNSUPPORTED_ENTITY_TYPE: 400,
  ENTITY_NOT_FOUND: 404,
  DETECTION_NOT_RELEASED: 409,
  COMPATIBILITY_NOT_READY: 409,
  INVALID_STATE_FOR_APPROVAL: 409,
  INVALID_STATE_FOR_EXECUTE: 409,
  INVALID_STATE_FOR_DISABLE: 409,
  NO_APPROVAL_ON_RECORD: 409,
  APPROVAL_HASH_MISMATCH: 409,
  TARGET_CONFIG_CHANGED: 409,
  NOT_YET_DEPLOYED: 409,
  NO_ROLLBACK_TARGET: 409,
  NO_ROLLBACK_SNAPSHOT: 409,
  DETECTION_REVOKED: 409,
  DISABLE_NOT_SUPPORTED: 400,
};

module.exports = async (req, res) => {
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes: 10240,
  });
  if (!ok_guard) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  if (!action) return apiError(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);

  switch (action) {
    case 'list': return handleList(req, res);
    case 'get': return handleGet(req, res);
    case 'history': return handleHistory(req, res);
    case 'preview': return handlePreview(req, res);
    case 'approve': return handleApprove(req, res);
    case 'execute': return handleExecute(req, res);
    case 'verify': return handleVerify(req, res);
    case 'preview-rollback': return handlePreviewRollback(req, res);
    case 'disable': return handleDisable(req, res);
    default:
      return apiError(res, 400, 'INVALID_ACTION', `Unknown action: "${action}". Valid: ${VALID_ACTIONS}`);
  }
};

async function readValidatedBody(req, res, action) {
  if (req.method !== 'POST') {
    apiError(res, 405, 'METHOD_NOT_ALLOWED', `POST required for action=${action}`);
    return null;
  }
  let body;
  try {
    body = await parseBody(req);
  } catch (_) {
    apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON.');
    return null;
  }
  const whitelistErr = sec.assertFieldWhitelist(body || {}, FIELDS[action] || []);
  if (whitelistErr) {
    apiError(res, 400, 'INVALID_FIELDS', whitelistErr);
    return null;
  }
  return body || {};
}

function respondBlocked(res, result) {
  const status = BLOCK_STATUS[result.reason] || 409;
  return apiError(res, status, result.reason || 'BLOCKED', blockMessage(result.reason), {
    'X-Deployment-Block-Reason': result.reason || 'BLOCKED',
  });
}

function blockMessage(reason) {
  const messages = {
    DETECTION_NOT_RELEASED: 'This detection is not currently in a RELEASED (fully validated) state.',
    COMPATIBILITY_NOT_READY: "This detection is not READY for your Defense Profile (format or telemetry gap).",
    APPROVAL_HASH_MISMATCH: 'The approved deployment intent no longer matches current detection/connector state. A new preview and approval is required.',
    TARGET_CONFIG_CHANGED: 'The connector target configuration changed after approval. A new preview and approval is required.',
    DETECTION_REVOKED: 'This detection has been revoked and cannot be (re)deployed.',
    INVALID_STATE_FOR_EXECUTE: 'This deployment is not in a state that can be executed right now (it may already be executing).',
    NO_ROLLBACK_TARGET: 'No prior deployed version is available to roll back to.',
  };
  return messages[reason] || 'This action is currently blocked. See X-Deployment-Block-Reason for the specific reason.';
}

async function handleList(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const deployments = await deploymentStore.listDeployments(user.userId);
  return successResponse(res, { deployments });
}

async function handleGet(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Deployment id required.');
  const result = await deploymentStore.getDeployment(user.userId, id);
  if (result.error) return apiError(res, 404, result.error, result.message);
  return successResponse(res, { deployment: result.deployment });
}

async function handleHistory(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Deployment id required.');
  // Ownership check first -- listAttempts()/getLatestApproval() are not
  // themselves owner-scoped (attempts/approvals are keyed only by
  // deployment_id), so a customer must never reach them for a deployment
  // they don't own.
  const owned = await deploymentStore.getDeployment(user.userId, id);
  if (owned.error) return apiError(res, 404, owned.error, owned.message);
  const attempts = await deploymentStore.listAttempts(id);
  return successResponse(res, {
    deployment: owned.deployment,
    attempts: attempts.map(a => ({
      attempt_id: a.attempt_id, action: a.action, result: a.result,
      error_code: a.error_code, http_status: a.http_status,
      started_at: a.started_at, finished_at: a.finished_at,
    })),
  });
}

async function handlePreview(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'preview');
  if (body === null) return;
  const connectorId = String(body.connector_id || '').trim();
  const detectionId = String(body.detection_id || '').trim();
  const entityType = String(body.entity_type || '').trim().toLowerCase();
  const entityId = String(body.entity_id || '').trim();
  if (!connectorId || !detectionId || !entityType || !entityId) {
    return apiError(res, 400, 'MISSING_PARAMETERS', 'connector_id, detection_id, entity_type, and entity_id are all required.');
  }
  const result = await engine.previewDeployment({
    ownerId: user.userId, tier: user.tier, connectorId, detectionId, entityType, entityId, enabledRequested: !!body.enabled,
  });
  if (result.blocked) return respondBlocked(res, result);
  return successResponse(res, { preview: result });
}

async function handleApprove(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Deployment id required.');
  const body = await readValidatedBody(req, res, 'approve');
  if (body === null) return;
  const result = await engine.approveDeployment({
    ownerId: user.userId, tier: user.tier, deploymentId: id,
    enabledRequested: body.enabled === undefined ? undefined : !!body.enabled,
  });
  if (result.blocked) return respondBlocked(res, result);
  return successResponse(res, { deployment: result.deployment });
}

async function handleExecute(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Deployment id required.');
  const body = await readValidatedBody(req, res, 'execute');
  if (body === null) return;
  const result = await engine.executeDeployment({ ownerId: user.userId, tier: user.tier, deploymentId: id });
  if (result.blocked) return respondBlocked(res, result);
  return successResponse(res, { deployment: result.deployment });
}

async function handleVerify(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Deployment id required.');
  const body = await readValidatedBody(req, res, 'verify');
  if (body === null) return;
  const result = await engine.verifyDeployment({ ownerId: user.userId, deploymentId: id });
  if (result.blocked) return respondBlocked(res, result);
  return successResponse(res, { deployment: result.deployment });
}

async function handlePreviewRollback(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Deployment id required.');
  const body = await readValidatedBody(req, res, 'preview-rollback');
  if (body === null) return;
  const result = await engine.previewRollback({ ownerId: user.userId, deploymentId: id });
  if (result.blocked) return respondBlocked(res, result);
  return successResponse(res, { preview: result });
}

async function handleDisable(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'Deployment id required.');
  const body = await readValidatedBody(req, res, 'disable');
  if (body === null) return;
  const result = await engine.disableDeployment({ ownerId: user.userId, deploymentId: id });
  if (result.blocked) return respondBlocked(res, result);
  if (result.error) return apiError(res, 502, 'REMOTE_DISABLE_FAILED', sec.safeError(new Error(result.message), 'Could not disable the remote rule.'));
  return successResponse(res, { deployment: result.deployment });
}
