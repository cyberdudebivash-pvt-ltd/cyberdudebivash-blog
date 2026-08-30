/**
 * SENTINEL APEX — Detection Performance Intelligence & Quality Review v1
 * Single serverless function, matching the established api/v1/hunts.js /
 * api/v1/deployments.js action-router convention exactly.
 *
 * Routing: /api/v1/detections/performance?action={action}
 *
 *  action=quality             GET   Deterministic Quality State + Evidence Sufficiency for one
 *                                   detection (query: detection_id, detection_version?) --
 *                                   defaults to the CURRENT version when detection_version is omitted.
 *                                   Cross-tenant aggregate-only; no customer-private data returned.
 *  action=version-history     GET   Version metadata (always available) joined with immutable
 *                                   content-snapshot availability per version (query: detection_id).
 *  action=my-performance      GET   The CALLER'S OWN operational feedback counts for one detection
 *                                   version (query: detection_id, detection_version) -- tenant-private.
 *  action=review-queue        GET   Internal-only: every canonical detection's current quality state,
 *                                   deterministic review priority, and factors. Requires a valid
 *                                   X-Admin-Key header (same gate as api/v1/admin.js). No customer-
 *                                   private content anywhere in the response.
 *
 * Every customer-facing action requires authenticate() (any authenticated
 * tier -- this capability is not tier-gated, matching hunts.js's own
 * precedent). review-queue requires the operator admin key instead --
 * it exposes cross-detection prioritization, not a per-customer resource.
 *
 * No automatic rule modification lives here: this file only ever reads
 * and composes existing, unmodified systems (detection-performance-
 * engine.js) -- nothing in this router can change a detection's content,
 * release a new version, or alter its canonical status.
 */
'use strict';

const sec = require('../../_lib/security');
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');
const { auditLog } = require('../../_lib/payment-utils');
const feedbackStore = require('../../_lib/detection-feedback-store');
const performanceEngine = require('../../_lib/detection-performance-engine');

const VALID_ACTIONS = 'quality, version-history, my-performance, review-queue';

module.exports = async (req, res) => {
  const ok_guard = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'], maxBodyBytes: 2048 });
  if (!ok_guard) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  if (!action) return apiError(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);

  switch (action) {
    case 'quality': return handleQuality(req, res);
    case 'version-history': return handleVersionHistory(req, res);
    case 'my-performance': return handleMyPerformance(req, res);
    case 'review-queue': return handleReviewQueue(req, res);
    default:
      return apiError(res, 400, 'INVALID_ACTION', `Unknown action: "${action}". Valid: ${VALID_ACTIONS}`);
  }
};

async function handleQuality(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const detectionId = String(req.query.detection_id || '').trim();
  if (!detectionId) return apiError(res, 400, 'MISSING_PARAMETERS', 'detection_id is required.');
  const detectionVersion = req.query.detection_version ? String(req.query.detection_version).trim() : undefined;
  const quality = await performanceEngine.computeDetectionQuality(detectionId, detectionVersion);
  if (!quality) return apiError(res, 404, 'NOT_FOUND', 'No detection found.');
  return successResponse(res, { quality });
}

async function handleVersionHistory(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const detectionId = String(req.query.detection_id || '').trim();
  if (!detectionId) return apiError(res, 400, 'MISSING_PARAMETERS', 'detection_id is required.');
  const history = await performanceEngine.getVersionHistory(detectionId);
  if (!history) return apiError(res, 404, 'NOT_FOUND', 'No detection found.');
  return successResponse(res, { history });
}

async function handleMyPerformance(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const detectionId = String(req.query.detection_id || '').trim();
  const detectionVersion = String(req.query.detection_version || '').trim();
  if (!detectionId || !detectionVersion) return apiError(res, 400, 'MISSING_PARAMETERS', 'detection_id and detection_version are both required.');
  const performance = await feedbackStore.computeTenantPerformance(user.userId, detectionId, detectionVersion);
  return successResponse(res, { performance });
}

async function handleReviewQueue(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  if (!(await sec.adminIpRateLimit(req, res))) return;
  if (!sec.verifyAdminKey(req)) {
    await auditLog('ADMIN_AUTH_FAIL', { ip: sec.getIp(req), action: 'review-queue', endpoint: 'detections/performance' });
    return apiError(res, 401, 'UNAUTHORIZED', 'Valid X-Admin-Key header required.');
  }
  const queue = await performanceEngine.computeReviewQueue();
  return successResponse(res, { queue });
}
