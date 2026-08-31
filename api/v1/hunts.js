/**
 * SENTINEL APEX — Threat Hunting Workspace & Detection Feedback Intelligence v1
 * Single serverless function handling the hunt lifecycle and detection
 * feedback, matching the established api/v1/deployments.js router
 * convention exactly.
 *
 * Routing: /api/v1/hunts?action={action}
 *
 *  action=list                       GET   The caller's own hunts (optional status filter)
 *  action=get&id=                    GET   One hunt + resolved refs, telemetry readiness, deployment linkage
 *  action=queries&id=                GET   A hunt's approved defensive queries (data — view/copy/download only)
 *  action=observations&id=           GET   A hunt's recorded observations
 *  action=evidence&id=               GET   A hunt's linked evidence
 *  action=findings&id=               GET   A hunt's analyst-classified findings
 *  action=timeline&id=               GET   A hunt's append-only event history
 *  action=feedback-list              GET   The caller's own submitted detection feedback (optional detection_id filter)
 *  action=feedback-signal            GET   Aggregate, cross-tenant REVIEW_REQUIRED signal for a detection/version (no per-tenant data returned)
 *  action=detection-maturity         GET   Coverage maturity ladder for one detection (query: detection_id, entity_type?, entity_id?)
 *  action=create                     POST  Body: {title?, entity_type?, entity_id?, detection_id?, priority?}
 *  action=update&id=                 POST  Body: {title?, priority?} -- status transitions go through close/reopen only
 *  action=close&id=                  POST  Body: {disposition, summary} -- server-side terminal act; CONFIRMED_THREAT requires linked evidence
 *  action=reopen&id=                 POST  Body: {reason?}
 *  action=add-ref&id=                POST  Body: {ref_kind, ref_id}
 *  action=add-query&id=              POST  Body: {source_detection_id, format?} -- snapshots a RELEASED detection's query content; data, never executed
 *  action=add-observation&id=        POST  Body: {query_id?, summary, execution_id?, selected_fields?} -- selected_fields is the ONE analyst-selected result row, never a bulk capture
 *  action=add-evidence&id=           POST  Body: {observation_id?, description, reference_url?}
 *  action=add-finding&id=            POST  Body: {classification, confidence, summary, evidence_refs?}
 *  action=feedback-submit            POST  Body: {detection_id, hunt_id?, deployment_id?, classification, summary?}
 *
 *  Controlled Read-Only SIEM Hunting Connectors v1 (bounded, explicit,
 *  read-only remote execution against a customer-authorized connector --
 *  never auto-run):
 *  action=query-preview&id=          GET   query: {query_id, connector_id} -- VIEW QUERY / PREVIEW PARAMETERS; no remote call, no execution record
 *  action=query-run&id=              POST  Body: {query_id, connector_id, time_start, time_end, row_limit?} -- the explicit RUN QUERY action
 *  action=query-executions&id=       GET   Bounded execution history (metadata only, never raw telemetry) for this hunt
 *
 * Every action requires authenticate() -- ownership is always re-derived
 * from the authenticated caller's userId, never trusted from the request
 * body. A hunt_id/deployment_id supplied to feedback-submit, and a
 * query_id/connector_id supplied to query-preview/query-run, are all
 * independently ownership-verified by hunt-engine.js/hunt-query-engine.js
 * before any row is read or written -- a queryId or connectorId belonging
 * to another tenant is NOT_FOUND here, never partial cross-tenant access.
 *
 * No autonomous investigation authority is exposed here: nothing in this
 * file can classify a finding, set a disposition, close a hunt, or select
 * which remote result becomes an observation without an explicit,
 * authenticated, human-attributed call -- this router only ever forwards
 * the caller's own explicit action.
 */
'use strict';

const sec = require('../_lib/security');
const { authenticate, successResponse, apiError } = require('../_lib/middleware');
const { parseBody } = require('../_lib/payment-utils');
const huntStore = require('../_lib/hunt-store');
const feedbackStore = require('../_lib/detection-feedback-store');
const engine = require('../_lib/hunt-engine');
const huntQueryEngine = require('../_lib/hunt-query-engine');

const VALID_ACTIONS =
  'list, get, queries, observations, evidence, findings, timeline, feedback-list, feedback-signal, detection-maturity, ' +
  'create, update, close, reopen, add-ref, add-query, add-observation, add-evidence, add-finding, feedback-submit, ' +
  'query-preview, query-run, query-executions';

const FIELDS = {
  create: ['title', 'entity_type', 'entity_id', 'detection_id', 'priority'],
  update: ['title', 'priority'],
  close: ['disposition', 'summary'],
  reopen: ['reason'],
  'add-ref': ['ref_kind', 'ref_id'],
  'add-query': ['source_detection_id', 'format'],
  'add-observation': ['query_id', 'summary', 'execution_id', 'selected_fields'],
  'add-evidence': ['observation_id', 'description', 'reference_url'],
  'add-finding': ['classification', 'confidence', 'summary', 'evidence_refs'],
  'feedback-submit': ['detection_id', 'hunt_id', 'deployment_id', 'classification', 'summary'],
  'query-run': ['query_id', 'connector_id', 'time_start', 'time_end', 'row_limit'],
};

const BLOCK_STATUS = {
  NOT_FOUND: 404,
  EVIDENCE_REQUIRED: 409,
  DISPOSITION_INCOMPLETE: 400,
  NOT_CLOSED: 409,
  ACTOR_REQUIRED: 400,
  DETECTION_NOT_RELEASED: 409,
  FORMAT_NOT_AVAILABLE: 400,
  MISSING_PARAMETERS: 400,
  HUNT_QUERY_NOT_SUPPORTED: 400,
  FORMAT_MISMATCH: 400,
  NOT_READY: 409,
  INVALID_TIME_RANGE: 400,
  QUERY_ALREADY_RUNNING: 409,
  CONNECTOR_DISABLED: 409,
};

module.exports = async (req, res) => {
  const ok_guard = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'POST', 'OPTIONS'], maxBodyBytes: 20480 });
  if (!ok_guard) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  if (!action) return apiError(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);

  switch (action) {
    case 'list': return handleList(req, res);
    case 'get': return handleGet(req, res);
    case 'queries': return handleChildList(req, res, huntStore.listQueries);
    case 'observations': return handleChildList(req, res, huntStore.listObservations);
    case 'evidence': return handleChildList(req, res, huntStore.listEvidence);
    case 'findings': return handleChildList(req, res, huntStore.listFindings);
    case 'timeline': return handleChildList(req, res, huntStore.listTimeline);
    case 'feedback-list': return handleFeedbackList(req, res);
    case 'feedback-signal': return handleFeedbackSignal(req, res);
    case 'detection-maturity': return handleDetectionMaturity(req, res);
    case 'create': return handleCreate(req, res);
    case 'update': return handleUpdate(req, res);
    case 'close': return handleClose(req, res);
    case 'reopen': return handleReopen(req, res);
    case 'add-ref': return handleAddRef(req, res);
    case 'add-query': return handleAddQuery(req, res);
    case 'add-observation': return handleAddObservation(req, res);
    case 'add-evidence': return handleAddEvidence(req, res);
    case 'add-finding': return handleAddFinding(req, res);
    case 'feedback-submit': return handleFeedbackSubmit(req, res);
    case 'query-preview': return handleQueryPreview(req, res);
    case 'query-run': return handleQueryRun(req, res);
    case 'query-executions': return handleQueryExecutions(req, res);
    default:
      return apiError(res, 400, 'INVALID_ACTION', `Unknown action: "${action}". Valid: ${VALID_ACTIONS}`);
  }
};

async function readValidatedBody(req, res, action) {
  if (req.method !== 'POST') { apiError(res, 405, 'METHOD_NOT_ALLOWED', `POST required for action=${action}`); return null; }
  let body;
  try { body = await parseBody(req); } catch (_) { apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON.'); return null; }
  const whitelistErr = sec.assertFieldWhitelist(body || {}, FIELDS[action] || []);
  if (whitelistErr) { apiError(res, 400, 'INVALID_FIELDS', whitelistErr); return null; }
  return body || {};
}

function respondBlocked(res, result) {
  const status = BLOCK_STATUS[result.error] || 409;
  return apiError(res, status, result.error || 'BLOCKED', result.message || 'This action is currently blocked.');
}

async function requireOwnedHunt(req, res, userId) {
  const id = String(req.query.id || '').trim();
  if (!id) { apiError(res, 400, 'MISSING_ID', 'Hunt id required.'); return null; }
  const { hunt, error, message } = await huntStore.getHunt(userId, id);
  if (error) { apiError(res, 404, error, message); return null; }
  return { id, hunt };
}

async function handleList(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const status = req.query.status ? String(req.query.status).toUpperCase().trim() : undefined;
  if (status && !huntStore.HUNT_STATUSES.includes(status)) return apiError(res, 400, 'INVALID_STATUS', `status must be one of: ${huntStore.HUNT_STATUSES.join(', ')}`);
  const hunts = await huntStore.listHunts(user.userId, { status, limit: req.query.limit });
  return successResponse(res, { hunts });
}

async function handleGet(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const [refs, readiness, deploymentLinkage] = await Promise.all([
    huntStore.listRefs(owned.id),
    engine.computeHuntReadiness(user.userId, owned.id),
    engine.resolveDeploymentLinkage(user.userId, owned.id),
  ]);
  return successResponse(res, { hunt: owned.hunt, refs, telemetry_readiness: readiness, deployment_linkage: deploymentLinkage });
}

async function handleChildList(req, res, listFn) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const items = await listFn(owned.id);
  return successResponse(res, { items });
}

async function handleFeedbackList(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const detectionId = req.query.detection_id ? String(req.query.detection_id).trim() : undefined;
  const feedback = await feedbackStore.listFeedbackForOwner(user.userId, { detectionId, limit: req.query.limit });
  return successResponse(res, { feedback });
}

async function handleFeedbackSignal(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const detectionId = String(req.query.detection_id || '').trim();
  const detectionVersion = String(req.query.detection_version || '').trim();
  if (!detectionId || !detectionVersion) return apiError(res, 400, 'MISSING_PARAMETERS', 'detection_id and detection_version are both required.');
  const signal = await feedbackStore.computeFeedbackSignal(detectionId, detectionVersion);
  return successResponse(res, { signal });
}

async function handleDetectionMaturity(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const detectionId = String(req.query.detection_id || '').trim();
  if (!detectionId) return apiError(res, 400, 'MISSING_PARAMETERS', 'detection_id is required.');
  const entityType = req.query.entity_type ? String(req.query.entity_type).toLowerCase().trim() : undefined;
  const entityId = req.query.entity_id ? String(req.query.entity_id).trim() : undefined;
  const entityRef = entityType && entityId ? { entityType, entityId } : undefined;
  const maturity = await engine.computeDetectionMaturity(user.userId, detectionId, entityRef);
  return successResponse(res, { detection_id: detectionId, maturity });
}

async function handleCreate(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'create');
  if (body === null) return;
  const priority = body.priority ? String(body.priority).toUpperCase().trim() : undefined;
  if (priority && !huntStore.HUNT_PRIORITIES.includes(priority)) return apiError(res, 400, 'INVALID_PRIORITY', `priority must be one of: ${huntStore.HUNT_PRIORITIES.join(', ')}`);
  const entityType = body.entity_type ? String(body.entity_type).toLowerCase().trim() : undefined;
  if (entityType && !huntStore.REF_KINDS.includes(entityType)) return apiError(res, 400, 'INVALID_ENTITY_TYPE', `entity_type must be one of: ${huntStore.REF_KINDS.join(', ')}`);
  const hunt = await engine.createHuntFromContext(user.userId, {
    title: body.title ? String(body.title).trim() : undefined,
    entityType,
    entityId: body.entity_id ? String(body.entity_id).trim() : undefined,
    detectionId: body.detection_id ? String(body.detection_id).trim() : undefined,
    priority,
    createdBy: user.userId,
  });
  return successResponse(res, { hunt });
}

async function handleUpdate(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'update');
  if (body === null) return;
  const fields = {};
  if (body.title !== undefined) fields.title = String(body.title).trim();
  if (body.priority !== undefined) {
    const priority = String(body.priority).toUpperCase().trim();
    if (!huntStore.HUNT_PRIORITIES.includes(priority)) return apiError(res, 400, 'INVALID_PRIORITY', `priority must be one of: ${huntStore.HUNT_PRIORITIES.join(', ')}`);
    fields.priority = priority;
  }
  if (Object.keys(fields).length) await huntStore.updateHunt(owned.id, fields);
  const result = await huntStore.getHunt(user.userId, owned.id);
  return successResponse(res, { hunt: result.hunt });
}

async function handleClose(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'close');
  if (body === null) return;
  const disposition = String(body.disposition || '').toUpperCase().trim();
  if (!huntStore.DISPOSITIONS.includes(disposition)) return apiError(res, 400, 'INVALID_DISPOSITION', `disposition must be one of: ${huntStore.DISPOSITIONS.join(', ')}`);
  const result = await engine.setDisposition(user.userId, owned.id, { disposition, summary: body.summary, actor: user.userId });
  if (result.error) return respondBlocked(res, result);
  return successResponse(res, { hunt: result.hunt });
}

async function handleReopen(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'reopen');
  if (body === null) return;
  const result = await engine.reopenHunt(user.userId, owned.id, { reason: body.reason, actor: user.userId });
  if (result.error) return respondBlocked(res, result);
  return successResponse(res, { hunt: result.hunt });
}

async function handleAddRef(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'add-ref');
  if (body === null) return;
  const refKind = String(body.ref_kind || '').toLowerCase().trim();
  const refId = String(body.ref_id || '').trim();
  if (!huntStore.REF_KINDS.includes(refKind) || !refId) return apiError(res, 400, 'INVALID_REF', `ref_kind must be one of: ${huntStore.REF_KINDS.join(', ')}, and ref_id is required.`);
  await huntStore.addRef(owned.id, refKind, refId);
  await huntStore.appendTimeline(owned.id, 'REF_ADDED', `Linked ${refKind}:${refId}.`, user.userId);
  const refs = await huntStore.listRefs(owned.id);
  return successResponse(res, { refs });
}

async function handleAddQuery(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'add-query');
  if (body === null) return;
  const sourceDetectionId = String(body.source_detection_id || '').trim();
  if (!sourceDetectionId) return apiError(res, 400, 'MISSING_PARAMETERS', 'source_detection_id is required.');
  const attackContextTechniques = await engine.resolveHuntAttackContext(owned.id);
  const canonical = engine.resolveCanonicalDetection(sourceDetectionId, attackContextTechniques);
  if (!canonical) return apiError(res, 404, 'NOT_FOUND', 'No detection found.');
  if (canonical.status !== 'RELEASED') return apiError(res, 409, 'DETECTION_NOT_RELEASED', 'Only a RELEASED detection can be added as a hunt query.');
  const format = body.format ? String(body.format).toLowerCase().trim() : Object.keys(canonical.formats)[0];
  const formatEntry = canonical.formats[format];
  if (!formatEntry) return apiError(res, 400, 'FORMAT_NOT_AVAILABLE', `Format "${format}" is not available for this detection.`);
  const queryId = await huntStore.addQuery(owned.id, {
    sourceDetectionId, sourceDetectionVersion: canonical.version, format, querySnapshot: formatEntry.content,
    validationStatus: canonical.status, addedBy: user.userId,
  });
  await huntStore.addRef(owned.id, 'detection', sourceDetectionId);
  await huntStore.appendTimeline(owned.id, 'QUERY_ADDED', `Query added from detection ${sourceDetectionId} (${format}).`, user.userId);
  return successResponse(res, { query_id: queryId });
}

async function handleAddObservation(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'add-observation');
  if (body === null) return;
  const summary = String(body.summary || '').trim();
  if (!summary) return apiError(res, 400, 'MISSING_PARAMETERS', 'summary is required.');
  const selectedFields = (body.selected_fields && typeof body.selected_fields === 'object' && !Array.isArray(body.selected_fields))
    ? body.selected_fields : undefined;
  const observationId = await huntStore.addObservation(owned.id, {
    queryId: body.query_id, summary, createdBy: user.userId,
    executionId: body.execution_id ? String(body.execution_id).trim() : undefined,
    selectedFields,
  });
  await huntStore.appendTimeline(owned.id, 'OBSERVATION_ADDED', 'Observation recorded.', user.userId);
  return successResponse(res, { observation_id: observationId });
}

async function handleAddEvidence(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'add-evidence');
  if (body === null) return;
  const description = String(body.description || '').trim();
  if (!description) return apiError(res, 400, 'MISSING_PARAMETERS', 'description is required.');
  const evidenceId = await huntStore.addEvidence(owned.id, {
    observationId: body.observation_id, description, referenceUrl: body.reference_url, createdBy: user.userId,
  });
  await huntStore.appendTimeline(owned.id, 'EVIDENCE_ADDED', 'Evidence recorded.', user.userId);
  return successResponse(res, { evidence_id: evidenceId });
}

async function handleAddFinding(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'add-finding');
  if (body === null) return;
  const classification = String(body.classification || '').toUpperCase().trim();
  const confidence = String(body.confidence || '').toUpperCase().trim();
  if (!huntStore.FINDING_CLASSIFICATIONS.includes(classification)) return apiError(res, 400, 'INVALID_CLASSIFICATION', `classification must be one of: ${huntStore.FINDING_CLASSIFICATIONS.join(', ')}`);
  if (!huntStore.CONFIDENCE_LEVELS.includes(confidence)) return apiError(res, 400, 'INVALID_CONFIDENCE', `confidence must be one of: ${huntStore.CONFIDENCE_LEVELS.join(', ')}`);
  const summary = String(body.summary || '').trim();
  if (!summary) return apiError(res, 400, 'MISSING_PARAMETERS', 'summary is required.');
  const result = await engine.addFindingWithValidation(user.userId, owned.id, {
    classification, confidence, summary, evidenceRefs: Array.isArray(body.evidence_refs) ? body.evidence_refs : [], createdBy: user.userId,
  });
  if (result.error) return respondBlocked(res, result);
  return successResponse(res, { finding_id: result.finding_id });
}

async function handleFeedbackSubmit(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'feedback-submit');
  if (body === null) return;
  const detectionId = String(body.detection_id || '').trim();
  const classification = String(body.classification || '').toUpperCase().trim();
  if (!detectionId) return apiError(res, 400, 'MISSING_PARAMETERS', 'detection_id is required.');
  if (!feedbackStore.FEEDBACK_CLASSIFICATIONS.includes(classification)) return apiError(res, 400, 'INVALID_CLASSIFICATION', `classification must be one of: ${feedbackStore.FEEDBACK_CLASSIFICATIONS.join(', ')}`);
  const result = await engine.submitDetectionFeedback(user.userId, {
    detectionId,
    huntId: body.hunt_id ? String(body.hunt_id).trim() : undefined,
    deploymentId: body.deployment_id ? String(body.deployment_id).trim() : undefined,
    classification,
    summary: body.summary,
    createdBy: user.userId,
  });
  if (result.error) return respondBlocked(res, result);
  return successResponse(res, { feedback_id: result.feedback_id, detection_version: result.detection_version });
}

/** VIEW QUERY / PREVIEW PARAMETERS -- read-only, no remote call, no
 *  execution record created. query_id/connector_id ownership is
 *  re-verified inside hunt-query-engine.js, never trusted here. */
async function handleQueryPreview(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const queryId = String(req.query.query_id || '').trim();
  const connectorId = String(req.query.connector_id || '').trim();
  if (!queryId || !connectorId) return apiError(res, 400, 'MISSING_PARAMETERS', 'query_id and connector_id are required.');
  const result = await huntQueryEngine.previewQuery(user.userId, owned.id, queryId, connectorId);
  if (result.error) return respondBlocked(res, result);
  return successResponse(res, { preview: result });
}

/** The explicit RUN QUERY action -- never auto-run. A remote-execution
 *  OUTCOME (TIMED_OUT/RATE_LIMITED/FAILED, an expected result of a
 *  bounded read-only hunt query) is still a successful API call and
 *  returns 200 with the outcome in the body; only a request-level
 *  rejection (not ready, bad bounds, ownership failure, unsupported
 *  connector) maps to an HTTP error status via respondBlocked. */
async function handleQueryRun(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const body = await readValidatedBody(req, res, 'query-run');
  if (body === null) return;
  const queryId = String(body.query_id || '').trim();
  const connectorId = String(body.connector_id || '').trim();
  if (!queryId || !connectorId) return apiError(res, 400, 'MISSING_PARAMETERS', 'query_id and connector_id are required.');
  const result = await huntQueryEngine.runQuery(user.userId, owned.id, queryId, connectorId, {
    timeStart: body.time_start, timeEnd: body.time_end, rowLimit: body.row_limit, actor: user.userId,
  });
  if (result.error && result.error !== 'QUERY_EXECUTION_FAILED') return respondBlocked(res, result);
  if (result.error === 'QUERY_EXECUTION_FAILED') {
    return successResponse(res, {
      execution_id: result.execution_id, state: result.state,
      error_code: result.error_code, error_classification: result.error_classification, message: result.message,
    });
  }
  return successResponse(res, { execution_id: result.execution_id, state: result.state, truncated: result.truncated, results: result.results });
}

/** Bounded execution history (metadata only -- never raw telemetry) for
 *  this hunt, matching the mandate's "bounded query history" requirement. */
async function handleQueryExecutions(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const owned = await requireOwnedHunt(req, res, user.userId);
  if (!owned) return;
  const result = await huntQueryEngine.listExecutions(user.userId, owned.id, { limit: req.query.limit });
  if (result.error) return respondBlocked(res, result);
  return successResponse(res, { executions: result.executions });
}
