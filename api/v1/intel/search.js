/**
 * GET /api/v1/intel/search?q={query}
 * Full-text search across all intel. Free tier gets first 5 results only.
 */
'use strict';
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');
const { searchIntel } = require('../../_lib/intel');

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  const q = String(req.query.q || '').trim();
  if (!q || q.length < 2) {
    return apiError(res, 400, 'INVALID_QUERY', 'Search query (q) is required and must be at least 2 characters.');
  }
  if (q.length > 200) {
    return apiError(res, 400, 'QUERY_TOO_LONG', 'Search query must be under 200 characters.');
  }

  try {
    // Free tier: max 5 results, limited fields
    const effectiveTier = user.tier;
    const result = searchIntel(q, effectiveTier, req.query);

    if (user.tier === 'free' && result.items.length > 5) {
      result.items = result.items.slice(0, 5);
      result._free_limit = `Showing 5 of ${result.total} results. Upgrade to Pro for full search — https://blog.cyberdudebivash.in/pricing.html`;
    }

    successResponse(res, result, {
      endpoint:       '/api/v1/intel/search',
      requests_used:  user.requestsUsed,
      requests_limit: user.requestsLimit,
    });
  } catch (e) {
    apiError(res, 500, 'INTERNAL_ERROR', e.message);
  }
};
