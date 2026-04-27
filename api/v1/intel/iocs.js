/**
 * GET /api/v1/intel/iocs
 * Enriched IOC feed with confidence scoring. PRO+ ONLY.
 * Query: type (ipv4|domain|url|sha256|md5), min_confidence, page, limit
 */
'use strict';
const { authenticate, successResponse, apiError } = require('../../_lib/middleware');
const { getIntel } = require('../../_lib/intel');

module.exports = async (req, res) => {
  const user = await authenticate(req, res);
  if (!user) return;

  // IOC data requires Pro or higher
  if (user.tier === 'free') {
    return apiError(res, 403, 'TIER_RESTRICTED',
      'IOC feed requires Pro or Enterprise plan. Upgrade at https://blog.cyberdudebivash.in/pricing.html — $49/month includes full IOC access, enriched indicators, and STIX export.',
      { 'X-Upgrade-URL': 'https://blog.cyberdudebivash.in/pricing.html' }
    );
  }

  try {
    const raw = getIntel('iocs', user.tier, {});
    let items = raw.items || [];

    // Additional filters
    if (req.query.type) {
      const t = req.query.type.toLowerCase();
      items = items.filter(i => (i.type || '').toLowerCase() === t);
    }
    if (req.query.min_confidence) {
      const mc = parseFloat(req.query.min_confidence);
      items = items.filter(i => (i.confidence_score || 0) >= mc);
    }
    if (req.query.related_id) {
      const rid = req.query.related_id.toUpperCase();
      items = items.filter(i => (i.related_id || '').toUpperCase() === rid);
    }

    // Pagination
    const page  = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.min(200, parseInt(req.query.limit || '50', 10));
    const offset = (page - 1) * limit;
    const paged = items.slice(offset, offset + limit);

    // Enterprise gets STIX 2.1 bundle option
    let stixBundle = null;
    if (user.tier === 'enterprise' && req.query.format === 'stix') {
      stixBundle = buildSTIXBundle(paged);
    }

    successResponse(res, {
      iocs:    paged,
      stix:    stixBundle,
      pagination: {
        page, limit, total: items.length,
        total_pages: Math.ceil(items.length / limit),
        has_next: offset + limit < items.length,
      },
      ioc_types: [...new Set(items.map(i => i.type).filter(Boolean))],
      intel_meta: raw.intel_meta,
      tier_info:  raw.tier_info,
    }, {
      endpoint:       '/api/v1/intel/iocs',
      requests_used:  user.requestsUsed,
      requests_limit: user.requestsLimit,
    });
  } catch (e) {
    apiError(res, 500, 'INTERNAL_ERROR', e.message);
  }
};

// Build minimal STIX 2.1 bundle for enterprise export
function buildSTIXBundle(iocs) {
  return {
    type: 'bundle',
    id:   `bundle--${require('crypto').randomUUID()}`,
    spec_version: '2.1',
    created: new Date().toISOString(),
    objects: iocs.map(ioc => {
      const typeMap = { ipv4: 'ipv4-addr', domain: 'domain-name', url: 'url', sha256: 'file', md5: 'file', sha1: 'file' };
      return {
        type: 'indicator',
        spec_version: '2.1',
        id:   `indicator--${require('crypto').randomUUID()}`,
        created: ioc.first_seen || new Date().toISOString(),
        modified: new Date().toISOString(),
        name: `${ioc.type}: ${ioc.value}`,
        description: `SENTINEL APEX IOC — ${ioc.related_id || ''} | Confidence: ${Math.round((ioc.confidence_score || 0.8) * 100)}%`,
        indicator_types: [ioc.related_type === 'RANSOMWARE' ? 'malicious-activity' : 'compromised'],
        pattern: `[${typeMap[ioc.type] || 'artifact'}:value = '${ioc.value}']`,
        pattern_type: 'stix',
        valid_from: ioc.first_seen || new Date().toISOString(),
        confidence: Math.round((ioc.confidence_score || 0.8) * 100),
        labels: ['cyberdudebivash-sentinel-apex', ioc.type, ioc.related_type || 'threat'].filter(Boolean),
      };
    }),
    extensions: { 'x-sentinel-apex': { version: '4.0', platform: 'blog.cyberdudebivash.in' } },
  };
}
