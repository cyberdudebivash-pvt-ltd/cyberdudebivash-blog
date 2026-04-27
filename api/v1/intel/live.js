/**
 * GET /api/v1/intel/live
 * Live threat intelligence feed — all tiers, tier-gated content depth.
 * Query: page, limit, severity, type, exploited, cisa_kev, min_cvss, from_date, vendor
 */
'use strict';
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');
const { getIntel } = require('../../_lib/intel');

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const result = getIntel('live', user.tier, req.query);
    successResponse(res, result, {
      endpoint:    '/api/v1/intel/live',
      tier:        user.tier,
      requests_used:  user.requestsUsed,
      requests_limit: user.requestsLimit,
    });
  } catch (e) {
    apiError(res, 500, 'INTERNAL_ERROR', `Intel fetch failed: ${e.message}`);
  }
};
