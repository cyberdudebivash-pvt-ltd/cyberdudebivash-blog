/**
 * GET /api/v1/intel/top-threats
 * Highest-priority threats (score ≥ 65). All tiers — depth gated.
 */
'use strict';
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');
const { getIntel } = require('../../_lib/intel');

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const result = getIntel('topThreats', user.tier, req.query);
    successResponse(res, result, {
      endpoint:       '/api/v1/intel/top-threats',
      description:    'Top priority threats (priority score ≥ 65/100)',
      tier:           user.tier,
      requests_used:  user.requestsUsed,
      requests_limit: user.requestsLimit,
    });
  } catch (e) {
    apiError(res, 500, 'INTERNAL_ERROR', e.message);
  }
};
