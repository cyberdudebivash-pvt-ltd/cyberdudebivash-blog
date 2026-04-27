/**
 * GET /api/v1/intel/ransomware
 * Ransomware-specific threat intelligence feed.
 */
'use strict';
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');
const { getIntel } = require('../../_lib/intel');

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const result = getIntel('ransomware', user.tier, req.query);
    successResponse(res, result, {
      endpoint:       '/api/v1/intel/ransomware',
      description:    'Active ransomware campaigns, actor TTPs, and IOC feeds',
      tier:           user.tier,
      requests_used:  user.requestsUsed,
      requests_limit: user.requestsLimit,
    });
  } catch (e) {
    apiError(res, 500, 'INTERNAL_ERROR', e.message);
  }
};
