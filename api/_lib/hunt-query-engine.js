'use strict';
/**
 * SENTINEL APEX — Controlled Read-Only SIEM Hunting: Query Execution Engine
 *
 * Orchestrates hunt-query-store.js (execution metadata persistence),
 * hunt-store.js (hunt/query ownership + the immutable query snapshot
 * itself), siem-connector-store.js (connector ownership + decrypted-
 * credential access), connector-registry.js (the platform-specific
 * executeHuntQuery/testHuntQueryConnection/normalizeResults
 * implementation), hunt-engine.js (canonical detection resolution +
 * telemetry-compatibility readiness + deployment linkage), and
 * detection-feedback-store.js (query-defect feedback routing, via
 * hunt-engine.js#submitDetectionFeedback, unchanged) — never
 * re-implements any of them.
 *
 * Every entry point re-derives ownership of hunt_id/query_id/connector_id
 * from the caller's authenticated ownerId before touching anything else
 * (Section: customer ownership/IDOR/BOLA P0 gate) — a queryId or
 * connectorId belonging to another tenant is NOT_FOUND here, identical to
 * every other store in this platform. VIEW QUERY / PREVIEW PARAMETERS
 * (previewQuery) never contacts the remote SIEM; only the explicit RUN
 * QUERY action (runQuery) does — there is no auto-run on page open.
 */

const huntStore = require('./hunt-store');
const huntEngine = require('./hunt-engine');
const huntQueryStore = require('./hunt-query-store');
const siemConnectorStore = require('./siem-connector-store');
const connectorRegistry = require('./connectors/connector-registry');
const taxonomy = require('./siem-connector-taxonomy');
const defenseProfileStore = require('./defense-profile-store');
const defenseCompatibility = require('./defense-compatibility');
const { ConnectorError } = require('./connectors/connector-contract');

const DEFAULT_ROW_LIMIT = 100;
const MAX_ROW_LIMIT = 1000; // technical ceiling for v1 -- no commercial entitlement tiering exists yet for hunt result size; document any future tier limit separately rather than inventing one here
const MAX_TIME_RANGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days -- v1's conservative bound against an unlimited historical query
const RUNNING_STALE_AFTER_MS = 60000; // comfortably longer than any connector's own internal timeout (15s for microsoft-sentinel)

function isIsoDate(value) {
  return typeof value === 'string' && !!value && Number.isFinite(Date.parse(value));
}

/** Resolves + ownership-checks hunt, query, and connector together — the
 *  one shared precondition every hunt-query action requires. Returns
 *  {error} on any tenant-isolation or not-found failure, never partial
 *  access to another tenant's row. */
async function resolveContext(ownerId, huntId, queryId, connectorId) {
  const { error: huntError } = await huntStore.getHunt(ownerId, huntId);
  if (huntError) return { error: 'NOT_FOUND', message: 'No hunt found.' };

  const queries = await huntStore.listQueries(huntId);
  const query = queries.find((q) => q.query_id === queryId);
  if (!query) return { error: 'NOT_FOUND', message: 'No query found on this hunt.' };

  const connectorResult = await siemConnectorStore.getConnectorWithCredential(ownerId, connectorId);
  if (connectorResult.error) return { error: connectorResult.error, message: connectorResult.message };

  return { query, connector: connectorResult.connector };
}

/** A query's format must match its target connector's platform format --
 *  the sandbox connector is exempt (it accepts any format for QA
 *  purposes, see mock-siem-connector.js's header) since it never actually
 *  parses query text. Checked here, upfront, so a mismatch is a clear
 *  FORMAT_MISMATCH before any execution record is even created — the
 *  connector's own executeHuntQuery() also rejects it independently
 *  (defense in depth), never trusted from this pre-check alone. */
function formatMismatch(platform, query) {
  if (!platform || platform.is_sandbox) return null;
  if (platform.detection_format && query.format !== platform.detection_format) {
    return `Connector platform "${platform.label}" requires ${platform.detection_format} queries; this query is in ${query.format} format.`;
  }
  return null;
}

/** Read-only readiness/eligibility check for ONE query, computed fresh --
 *  never cached, matching computeHuntReadiness's own discipline (Source-
 *  of-Truth Matrix: coverage is never persisted). Blocks (ready:false)
 *  whenever ANY required telemetry is missing -- status must be exactly
 *  READY (defense-compatibility.js's own zero-missing-telemetry state),
 *  never PARTIALLY_READY/TELEMETRY_GAP/UNSUPPORTED_PLATFORM/UNKNOWN/
 *  NO_VALIDATED_DETECTION (v1 preference: BLOCK whenever there is any
 *  doubt, rather than allow a partially-blind hunt query). */
async function checkDetectionReadiness(ownerId, huntId, query) {
  const attackContextTechniques = await huntEngine.resolveHuntAttackContext(huntId);
  const canonical = huntEngine.resolveCanonicalDetection(query.source_detection_id, attackContextTechniques);
  if (!canonical || canonical.status !== 'RELEASED') {
    return { ready: false, reason: 'DETECTION_NOT_RELEASED', detail: 'The source detection for this query is not currently RELEASED.' };
  }
  const { profile } = await defenseProfileStore.getProfile(ownerId);
  const compat = defenseCompatibility.evaluateDetectionCompatibility(canonical, profile);
  if (compat.status !== 'READY') {
    return {
      ready: false,
      reason: 'TELEMETRY_NOT_READY',
      detail: compat.explanation || `Required telemetry is not fully available (status: ${compat.status}).`,
      compat_status: compat.status,
    };
  }
  return {
    ready: true,
    canonical_version: canonical.version,
    query_version_matches_current_released: String(canonical.version) === String(query.source_detection_version),
  };
}

/**
 * VIEW QUERY / PREVIEW PARAMETERS step — no remote call, no execution
 * record created. Surfaces everything the customer-safe Hunt Query UI
 * needs before the explicit RUN QUERY action: the query text/format,
 * connector/read-only status, default+max row limit, max time range,
 * telemetry readiness, and (Section: deployment linkage) the source
 * detection's current deployment state for this owner, so a DRIFTED
 * deployment is visible before running, never hidden.
 */
async function previewQuery(ownerId, huntId, queryId, connectorId) {
  const ctx = await resolveContext(ownerId, huntId, queryId, connectorId);
  if (ctx.error) return ctx;
  const { query, connector } = ctx;

  const platform = taxonomy.KNOWN_PLATFORMS[connector.platform];
  if (!platform || !platform.capabilities.hunt_query_supported) {
    return { error: 'HUNT_QUERY_NOT_SUPPORTED', message: `Platform "${connector.platform}" does not support hunt query execution.` };
  }
  const mismatch = formatMismatch(platform, query);
  if (mismatch) return { error: 'FORMAT_MISMATCH', message: mismatch };

  const readiness = await checkDetectionReadiness(ownerId, huntId, query);
  const deploymentLinkage = await huntEngine.resolveDeploymentLinkage(ownerId, huntId);
  const detectionLinkage = deploymentLinkage.find((d) => d.detection_id === query.source_detection_id) || null;

  return {
    query: {
      query_id: query.query_id,
      format: query.format,
      query_snapshot: query.query_snapshot,
      source_detection_id: query.source_detection_id,
      source_detection_version: query.source_detection_version,
      validation_status: query.validation_status,
    },
    connector: { connector_id: connector.id, platform: connector.platform, platform_label: platform.label },
    read_only: true, // every hunt_query_supported connector is read-only by construction (connector-contract.js's executeHuntQuery contract)
    default_row_limit: DEFAULT_ROW_LIMIT,
    max_row_limit: MAX_ROW_LIMIT,
    max_time_range_ms: MAX_TIME_RANGE_MS,
    readiness,
    detection_linkage: detectionLinkage,
  };
}

/**
 * Maps a thrown ConnectorError onto this platform's execution state +
 * feedback-routing classification. QUERY_REJECTED (the connector itself
 * refused an unsupported/malformed query before any remote call) is the
 * one case unambiguous enough to classify as a genuine query defect
 * automatically — everything remote-side (auth/permission/rate-limit/
 * timeout/generic remote error) is a PROVIDER_ISSUE or AUTH_ISSUE, NEVER
 * auto-classified as a detection defect (Section: never treat a provider
 * error/outage/rate limit as a query defect or telemetry mismatch).
 */
function classifyExecutionFailure(connectorError) {
  switch (connectorError.code) {
    case 'QUERY_REJECTED':
      return { state: 'FAILED', errorClassification: 'QUERY_DEFECT' };
    case 'AUTH_FAILED':
    case 'PERMISSION_DENIED':
      return { state: 'FAILED', errorClassification: 'AUTH_ISSUE' };
    case 'RATE_LIMITED':
      return { state: 'RATE_LIMITED', errorClassification: 'PROVIDER_ISSUE' };
    case 'TIMEOUT':
      return { state: 'TIMED_OUT', errorClassification: 'PROVIDER_ISSUE' };
    default:
      return { state: 'FAILED', errorClassification: 'PROVIDER_ISSUE' };
  }
}

/**
 * Explicit RUN QUERY action — never auto-run. Creates a RUNNING execution
 * row first (so a crash mid-call still leaves an honest audit trail),
 * then calls the connector's real executeHuntQuery(), then completes the
 * row with the outcome. Bounded, normalized results are returned directly
 * in the response (ephemeral — never persisted); only the row COUNT is
 * stored. The caller (the API layer) is responsible for the analyst's
 * subsequent, explicit addObservation() call for whichever rows they
 * select — this function never selects one automatically.
 */
async function runQuery(ownerId, huntId, queryId, connectorId, { timeStart, timeEnd, rowLimit, actor }) {
  if (!actor) return { error: 'ACTOR_REQUIRED', message: 'Running a hunt query requires an attributed analyst identity.' };

  const ctx = await resolveContext(ownerId, huntId, queryId, connectorId);
  if (ctx.error) return ctx;
  const { query, connector } = ctx;

  const platform = taxonomy.KNOWN_PLATFORMS[connector.platform];
  if (!platform || !platform.capabilities.hunt_query_supported) {
    return { error: 'HUNT_QUERY_NOT_SUPPORTED', message: `Platform "${connector.platform}" does not support hunt query execution.` };
  }
  const mismatch = formatMismatch(platform, query);
  if (mismatch) return { error: 'FORMAT_MISMATCH', message: mismatch };

  const readiness = await checkDetectionReadiness(ownerId, huntId, query);
  if (!readiness.ready) {
    return { error: 'NOT_READY', message: readiness.detail || 'Required telemetry is not available for this query.', reason: readiness.reason };
  }

  if (!isIsoDate(timeStart) || !isIsoDate(timeEnd)) {
    return { error: 'INVALID_TIME_RANGE', message: 'timeStart and timeEnd must be valid dates.' };
  }
  const startMs = Date.parse(timeStart);
  const endMs = Date.parse(timeEnd);
  if (endMs <= startMs) {
    return { error: 'INVALID_TIME_RANGE', message: 'timeEnd must be after timeStart.' };
  }
  if (endMs - startMs > MAX_TIME_RANGE_MS) {
    return { error: 'INVALID_TIME_RANGE', message: `Time range exceeds the maximum of ${Math.floor(MAX_TIME_RANGE_MS / 86400000)} days.` };
  }

  const requestedLimit = Number(rowLimit);
  const boundedRowLimit = (Number.isFinite(requestedLimit) && requestedLimit > 0)
    ? Math.min(Math.floor(requestedLimit), MAX_ROW_LIMIT)
    : DEFAULT_ROW_LIMIT;

  const connectorModule = connectorRegistry.getConnectorModule(connector.platform);
  if (!connectorModule || typeof connectorModule.executeHuntQuery !== 'function') {
    return { error: 'HUNT_QUERY_NOT_SUPPORTED', message: `No hunt query implementation registered for platform "${connector.platform}".` };
  }

  // One in-flight execution per hunt at a time (v1 concurrency bound) -- a
  // stale RUNNING row (older than any connector's own internal timeout)
  // never permanently deadlocks the hunt.
  const recent = await huntQueryStore.listExecutionsForHunt(ownerId, huntId, { limit: 5 });
  const runningNow = recent.find((e) => e.state === 'RUNNING' && (Date.now() - Date.parse(e.started_at)) < RUNNING_STALE_AFTER_MS);
  if (runningNow) {
    return { error: 'QUERY_ALREADY_RUNNING', message: 'Another query is already running for this hunt. Wait for it to complete.' };
  }

  const executionId = await huntQueryStore.createExecution(ownerId, {
    huntId, queryId, connectorId, detectionId: query.source_detection_id, detectionVersion: query.source_detection_version,
    format: query.format, timeStart, timeEnd, rowLimit: boundedRowLimit,
  });

  let result;
  try {
    result = await connectorModule.executeHuntQuery(connector, {
      query: query.query_snapshot, format: query.format, timeStart, timeEnd, rowLimit: boundedRowLimit,
    });
  } catch (e) {
    const connectorError = e instanceof ConnectorError ? e : new ConnectorError('REMOTE_ERROR', e.message, { retryable: false });
    const { state, errorClassification } = classifyExecutionFailure(connectorError);
    await huntQueryStore.completeExecution(executionId, { state, resultRowCount: null, errorCode: connectorError.code, errorClassification });
    await huntStore.appendTimeline(huntId, 'QUERY_EXECUTED', `Hunt query execution failed via connector ${connector.id}: ${state} (${connectorError.code}).`, actor);

    if (errorClassification === 'QUERY_DEFECT') {
      await huntEngine.submitDetectionFeedback(ownerId, {
        detectionId: query.source_detection_id,
        huntId,
        classification: 'QUERY_ERROR',
        summary: `Hunt query execution against connector ${connector.id} failed with a query-format/field defect: ${connectorError.message}`,
        createdBy: actor,
      });
    }

    return {
      error: 'QUERY_EXECUTION_FAILED', message: connectorError.message, execution_id: executionId,
      state, error_code: connectorError.code, error_classification: errorClassification,
    };
  }

  const normalized = typeof connectorModule.normalizeResults === 'function' ? connectorModule.normalizeResults(connector, result.rows) : [];
  const state = result.truncated ? 'PARTIAL' : 'SUCCEEDED';
  await huntQueryStore.completeExecution(executionId, { state, resultRowCount: normalized.length });
  await huntStore.appendTimeline(huntId, 'QUERY_EXECUTED', `Hunt query executed via connector ${connector.id}: ${state}, ${normalized.length} row(s).`, actor);

  return { execution_id: executionId, state, truncated: !!result.truncated, results: normalized };
}

async function listExecutions(ownerId, huntId, { limit } = {}) {
  const { error } = await huntStore.getHunt(ownerId, huntId);
  if (error) return { error: 'NOT_FOUND', message: 'No hunt found.' };
  return { executions: await huntQueryStore.listExecutionsForHunt(ownerId, huntId, { limit }) };
}

module.exports = {
  DEFAULT_ROW_LIMIT,
  MAX_ROW_LIMIT,
  MAX_TIME_RANGE_MS,
  previewQuery,
  runQuery,
  listExecutions,
  checkDetectionReadiness,
  formatMismatch,
  classifyExecutionFailure,
};
