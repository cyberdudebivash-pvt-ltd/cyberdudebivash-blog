/**
 * GET /api/v1/intel/cve/{id}
 * Deep CVE intelligence — full technical detail. Free: summary only.
 */
'use strict';
const { authenticate, successResponse, apiError } = require('../../../_lib/middleware');
const { getCVEDetail } = require('../../../_lib/intel');

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  const { id } = req.query;
  if (!id) return apiError(res, 400, 'MISSING_ID', 'CVE ID is required in the URL path.');

  // Validate CVE format
  const cvePattern = /^CVE-\d{4}-\d{4,7}$/i;
  if (!cvePattern.test(id)) {
    return apiError(res, 400, 'INVALID_CVE_ID',
      `Invalid CVE ID format: '${id}'. Expected format: CVE-YYYY-NNNN (e.g. CVE-2025-12345)`);
  }

  try {
    const { found, item } = getCVEDetail(id, user.tier);
    if (!found) {
      return apiError(res, 404, 'CVE_NOT_FOUND',
        `${id.toUpperCase()} not found in SENTINEL APEX intelligence database. ` +
        `It may not meet the minimum severity threshold (CVSS ≥ 7.0) or may not have been ingested yet. ` +
        `Check NVD directly: https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`);
    }

    successResponse(res, {
      cve_id:    id.toUpperCase(),
      item,
      report_url: item.report_url || null,
    }, {
      endpoint:       `/api/v1/intel/cve/${id}`,
      tier:           user.tier,
      requests_used:  user.requestsUsed,
      requests_limit: user.requestsLimit,
    });
  } catch (e) {
    apiError(res, 500, 'INTERNAL_ERROR', e.message);
  }
};
