'use strict';
/**
 * Legacy compatibility endpoint: GET /api/v1/detections/rules/:id[/history]
 * Canonical successor: /api/v1/intel?action=detection&id=...
 *
 * Historical comments referenced PATCH/admin behavior, but this handler has
 * never implemented mutation. The compatibility contract is therefore
 * intentionally GET-only; every other method is rejected by guardRequest.
 */

const detectionRules = require('../../../_lib/detection-rules');
const sec = require('../../../_lib/security');
const { authenticate, apiError } = require('../../../_lib/middleware');

function markDeprecated(res, id) {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Link', `</api/v1/intel?action=detection&id=${encodeURIComponent(id || '')}>; rel="successor-version"`);
  res.setHeader('X-Sentinel-Deprecated-Endpoint', '/api/v1/detections/rules/:id');
}

module.exports = async (req, res) => {
  const ok = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'], maxBodyBytes: 2048 });
  if (!ok) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const user = await authenticate(req, res);
  if (!user) return;

  const id = String((req.query && req.query.id) || '').trim();
  if (!id || id.length > 128) return apiError(res, 400, 'INVALID_RULE_ID', 'A valid detection rule ID is required.');
  markDeprecated(res, id);

  try {
    const rule = detectionRules.getRule(id);
    if (!rule) return apiError(res, 404, 'DETECTION_NOT_FOUND', 'Detection rule not found.');

    const path = String(req.url || '').split('?')[0];
    if (path.endsWith('/history')) {
      return res.status(200).json({
        success: true,
        rule_id: id,
        title: rule.title,
        technique_id: rule.technique_id,
        history: Array.isArray(rule.history) ? rule.history : [],
        current_version: rule.governance && rule.governance.version,
        deprecated: true,
        successor: `/api/v1/intel?action=detection&id=${encodeURIComponent(id)}`,
      });
    }

    return res.status(200).json({
      success: true,
      rule,
      deploymentInfo: {
        sigma_status: rule.platforms && rule.platforms.sigma ? 'READY' : 'NOT_AVAILABLE',
        kql_status: rule.platforms && rule.platforms.kql ? 'READY' : 'NOT_AVAILABLE',
        splunk_status: rule.platforms && rule.platforms.splunk ? 'READY' : 'NOT_AVAILABLE',
        osquery_status: rule.platforms && rule.platforms.osquery ? 'READY' : 'NOT_AVAILABLE',
        suricata_status: Array.isArray(rule.suricata) && rule.suricata.length > 0 ? 'READY' : 'NOT_AVAILABLE',
      },
      deprecated: true,
      successor: `/api/v1/intel?action=detection&id=${encodeURIComponent(id)}`,
    });
  } catch (e) {
    console.error('[DETECTION API] legacy detail failed:', e && e.message ? e.message : 'unknown');
    return apiError(res, 500, 'DETECTION_DETAIL_FAILED', 'Detection detail is temporarily unavailable.');
  }
};
