'use strict';
/**
 * Legacy compatibility endpoint: GET /api/v1/detections/rules
 *
 * Canonical customer API lives under /api/v1/intel?action=detections.
 * This path remains for backwards compatibility, but it MUST carry the
 * same authentication, request guard, rate limiting and bounded-input
 * guarantees as the canonical API.
 */

const detectionRules = require('../../_lib/detection-rules');
const sec = require('../../_lib/security');
const { authenticate, apiError } = require('../../_lib/middleware');

const ALLOWED_FORMATS = new Set(['json', 'sigma', 'kql', 'suricata', 'csv']);
const MAX_QUERY_LENGTH = 200;
const MAX_RESULTS = 100;

function markDeprecated(res) {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Link', '</api/v1/intel?action=detections>; rel="successor-version"');
  res.setHeader('X-Sentinel-Deprecated-Endpoint', '/api/v1/detections/rules');
}

module.exports = async (req, res) => {
  const ok = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'], maxBodyBytes: 2048 });
  if (!ok) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const user = await authenticate(req, res);
  if (!user) return;
  markDeprecated(res);

  try {
    const filters = {};
    if (req.query.technique_id) filters.technique_id = String(req.query.technique_id).trim().slice(0, 64);
    if (req.query.level) filters.level = String(req.query.level).trim().toLowerCase().slice(0, 16);
    if (req.query.status) filters.status = String(req.query.status).trim().toUpperCase().slice(0, 32);
    if (req.query.platform) filters.platform = String(req.query.platform).trim().toLowerCase().slice(0, 32);
    if (req.query.confidence) filters.confidence = String(req.query.confidence).trim().toUpperCase().slice(0, 16);
    if (req.query.query) {
      const q = String(req.query.query).trim();
      if (q.length > MAX_QUERY_LENGTH) return apiError(res, 400, 'QUERY_TOO_LONG', `query must not exceed ${MAX_QUERY_LENGTH} characters.`);
      filters.query = q;
    }

    const format = String(req.query.format || 'json').toLowerCase().trim();
    if (!ALLOWED_FORMATS.has(format)) {
      return apiError(res, 400, 'INVALID_FORMAT', `format must be one of: ${[...ALLOWED_FORMATS].join(', ')}.`);
    }

    const allRules = detectionRules.searchRules(filters);
    const rules = allRules.slice(0, MAX_RESULTS);

    if (format !== 'json') {
      // exportRules is retained for compatibility. The canonical store is
      // currently small, but refuse unbounded export if it grows beyond the
      // compatibility endpoint's hard ceiling; callers should then move to
      // the paginated canonical API/download action.
      if (allRules.length > MAX_RESULTS) {
        return apiError(res, 413, 'LEGACY_EXPORT_TOO_LARGE', `Legacy export is limited to ${MAX_RESULTS} rules. Use /api/v1/intel?action=detections and action=detection-download.`);
      }
      const exported = detectionRules.exportRules(format, filters);
      const mimeTypes = { sigma: 'text/plain; charset=utf-8', kql: 'text/plain; charset=utf-8', suricata: 'text/plain; charset=utf-8', csv: 'text/csv; charset=utf-8' };
      res.setHeader('Content-Type', mimeTypes[format]);
      res.setHeader('Content-Disposition', `attachment; filename="sentinel-apex-detection-rules.${format === 'csv' ? 'csv' : 'txt'}"`);
      return res.status(200).send(exported);
    }

    return res.status(200).json({
      success: true,
      count: rules.length,
      total: allRules.length,
      truncated: allRules.length > rules.length,
      rules,
      stats: detectionRules.getStats(),
      filters,
      deprecated: true,
      successor: '/api/v1/intel?action=detections',
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error('[DETECTION API] legacy catalogue failed:', e && e.message ? e.message : 'unknown');
    return apiError(res, 500, 'DETECTION_LIST_FAILED', 'Detection catalogue is temporarily unavailable.');
  }
};
