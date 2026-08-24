/**
 * SENTINEL APEX — Consolidated Intel Router
 * Single serverless function handling ALL intelligence endpoints.
 *
 * Routing: GET /api/v1/intel?action={action}
 *
 *  action=live         GET  All live threat intelligence (tier-gated depth)
 *  action=top          GET  Top-priority threats (priority_score >= 65)
 *  action=cve          GET  CVE detail lookup  (?id=CVE-2024-xxxx)
 *  action=iocs         GET  IOC feed — PRO+ only, STIX export for Enterprise
 *  action=ransomware   GET  Ransomware campaign feed
 *  action=search       GET  Full-text search across all intel (?q=query)
 *  action=stats        GET  Platform stats — no auth required
 *  action=graph        GET  Threat actor relationship graph (tier-gated)
 *  action=campaigns    GET  Campaign clusters (?severity=&has_kev=)
 *  action=campaign     GET  Single campaign detail (?id=campaign:...)
 *  action=top-actors   GET  Most active threat actors ranked by activity
 *  action=unified-search GET Cross-entity search: CVE/campaign/actor/IOC/report (?q=query&type=)
 *  action=actor        GET  Single threat actor detail + relationships (?id=actor:...)
 *  action=ioc          GET  Single IOC detail + linked intel — PRO+ only (?id=ioc:...)
 *  action=report       GET  Single published intelligence report detail (?id=SA-YYYY-NNNN)
 *
 * Backward-compat rewrites in vercel.json map old paths to ?action= params.
 */
'use strict';
const crypto = require('crypto');
const { authenticate, successResponse, apiError, corsHeaders } = require('../_lib/middleware');
const { getIntel, getCVEDetail, searchIntel, getPlatformStats,
        getGraph, getCampaigns, getCampaignDetail, getTopActorsAPI,
        unifiedSearch, getActorDetailAPI, getIocDetailAPI, getReportDetailAPI } = require('../_lib/intel');
const sec = require('../_lib/security');

/* ─── Main Router ────────────────────────────────────────────── */
module.exports = async (req, res) => {
  /* Phase 1: global guard — security headers + method check + size limit */
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes:   10240,
  });
  if (!ok_guard) return;

  /* Phase 4: global IP rate limit (10 req/min) */
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();

  /* ── Public: stats — no API key required ───────────────────── */
  if (action === 'stats') {
    try {
      const stats = getPlatformStats();
      return res.status(200).json({
        success: true,
        stats,
        meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      });
    } catch (e) {
      return res.status(500).json({ success: false, error: 'Stats unavailable' });
    }
  }

  /* ── All other actions require authentication ───────────────── */
  if (req.method !== 'GET') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required for intel endpoints');
  }

  if (!action) {
    return apiError(res, 400, 'MISSING_ACTION',
      'action parameter required. Valid: live, top, cve, iocs, ransomware, search, stats. ' +
      'Example: GET /api/v1/intel?action=live');
  }

  const user = await authenticate(req, res);
  if (!user) return;

  /* ─── Route Dispatcher ───────────────────────────────────────── */
  try {
    switch (action) {

      /* ── GET ?action=live ──────────────────────────────────── */
      case 'live': {
        const result = getIntel('live', user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=live',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=top ───────────────────────────────────── */
      case 'top': {
        const result = getIntel('topThreats', user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=top',
          description:    'Top priority threats (priority score ≥ 65/100)',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=cve&id=CVE-YYYY-NNNN ─────────────────── */
      case 'cve': {
        const id = String(req.query.id || '').trim().toUpperCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_CVE_ID',
            'CVE ID required. Example: GET /api/v1/intel?action=cve&id=CVE-2024-12345');
        }
        if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) {
          return apiError(res, 400, 'INVALID_CVE_ID',
            `Invalid CVE ID format: "${id}". Expected: CVE-YYYY-NNNNN`);
        }
        const { found, item } = getCVEDetail(id, user.tier);
        if (!found) {
          return apiError(res, 404, 'CVE_NOT_FOUND',
            `${id} not found in SENTINEL APEX database. ` +
            `May not meet CVSS ≥ 7.0 threshold or not yet ingested. ` +
            `Check: https://nvd.nist.gov/vuln/detail/${id}`);
        }
        return successResponse(res, {
          cve_id:     id,
          item,
          report_url: item.report_url || null,
        }, {
          endpoint:       `/api/v1/intel?action=cve&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=iocs ──────────────────────────────────── */
      case 'iocs': {
        if (user.tier !== 'pro' && user.tier !== 'enterprise') {
          return apiError(res, 403, 'TIER_RESTRICTED',
            'IOC feed requires Pro or Enterprise plan. Upgrade at https://blog.cyberdudebivash.in/pricing.html',
            { 'X-Upgrade-URL': 'https://blog.cyberdudebivash.in/pricing.html' });
        }
        const raw   = getIntel('iocs', user.tier, {});
        let items   = raw.items || [];

        // Additional filters
        if (req.query.type) {
          const t = req.query.type.toLowerCase();
          items = items.filter(i => (i.type || '').toLowerCase() === t);
        }
        if (req.query.min_confidence) {
          const mc = parseFloat(req.query.min_confidence);
          if (!isNaN(mc)) items = items.filter(i => (i.confidence_score || 0) >= mc);
        }
        if (req.query.related_id) {
          const rid = req.query.related_id.toUpperCase();
          items = items.filter(i => (i.related_id || '').toUpperCase() === rid);
        }

        // Pagination
        const page   = Math.max(1, parseInt(req.query.page  || '1',  10));
        const limit  = Math.min(200, parseInt(req.query.limit || '50', 10));
        const offset = (page - 1) * limit;
        const paged  = items.slice(offset, offset + limit);

        // Enterprise STIX 2.1 export
        let stixBundle = null;
        if (user.tier === 'enterprise' && req.query.format === 'stix') {
          stixBundle = buildSTIXBundle(paged);
        }

        return successResponse(res, {
          iocs: paged,
          stix: stixBundle,
          pagination: {
            page, limit, total: items.length,
            total_pages: Math.ceil(items.length / limit),
            has_next: offset + limit < items.length,
          },
          ioc_types:  [...new Set(items.map(i => i.type).filter(Boolean))],
          intel_meta: raw.intel_meta,
          tier_info:  raw.tier_info,
        }, {
          endpoint:       '/api/v1/intel?action=iocs',
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=ransomware ────────────────────────────── */
      case 'ransomware': {
        const result = getIntel('ransomware', user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=ransomware',
          description:    'Active ransomware campaigns, actor TTPs, and IOC feeds',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=search&q=query ────────────────────────── */
      case 'search': {
        const q = String(req.query.q || '').trim();
        if (!q || q.length < 2) {
          return apiError(res, 400, 'INVALID_QUERY',
            'Search query (q) required and must be ≥ 2 characters. Example: ?action=search&q=log4j');
        }
        if (q.length > 200) {
          return apiError(res, 400, 'QUERY_TOO_LONG', 'Search query must be under 200 characters.');
        }
        const result = searchIntel(q, user.tier, req.query);
        if (user.tier === 'free' && result.items.length > 5) {
          result.items = result.items.slice(0, 5);
          result._free_limit = `Showing 5 of ${result.total} results. Upgrade to Pro for full search.`;
        }
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=search',
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=graph ────────────────────────────────────── */
      case 'graph': {
        const result = getGraph(user.tier);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=graph',
          description:    'Threat actor relationship graph — nodes (CVE/Actor/Campaign/IOC) and edges',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=campaigns ────────────────────────────────── */
      case 'campaigns': {
        const result = getCampaigns(user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=campaigns',
          description:    'Threat campaign clusters grouped by shared IOCs, CVEs, and actor TTPs',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=campaign&id=campaign:... ─────────────────── */
      case 'campaign': {
        const campaignId = String(req.query.id || '').trim();
        if (!campaignId || campaignId.length < 3) {
          return apiError(res, 400, 'MISSING_CAMPAIGN_ID',
            'Campaign ID required. Example: GET /api/v1/intel?action=campaign&id=campaign:cve-2024-27199');
        }
        const { found, campaign } = getCampaignDetail(campaignId, user.tier);
        if (!found) {
          return apiError(res, 404, 'CAMPAIGN_NOT_FOUND',
            `Campaign "${campaignId}" not found. List all at GET /api/v1/intel?action=campaigns`);
        }
        return successResponse(res, { campaign }, {
          endpoint:       `/api/v1/intel?action=campaign&id=${campaignId}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=top-actors ───────────────────────────────── */
      case 'top-actors': {
        const actorLimit = Math.min(20, parseInt(req.query.limit || '10', 10));
        const result     = getTopActorsAPI(user.tier, actorLimit);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=top-actors',
          description:    'Most active threat actors ranked by graph connectivity and CVE exploitation count',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=unified-search&q=query&type=cve,campaign ─── */
      case 'unified-search': {
        const q = String(req.query.q || '').trim();
        const result = unifiedSearch(q, user.tier, {
          type:     req.query.type,
          severity: req.query.severity,
          from:     req.query.from_date,
          to:       req.query.to_date,
          limit:    req.query.limit,
          offset:   req.query.offset,
        });
        if (!result.ok) {
          return apiError(res, 400, result.error, result.message);
        }
        if (user.tier === 'free' && result.results.length > 5) {
          result.results = result.results.slice(0, 5);
          result._free_limit = `Showing 5 of ${result.pagination.total} results. Upgrade to Pro for full search.`;
        }
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=unified-search',
          description:    'Cross-entity search across CVE, campaign, threat actor, IOC, and published-report intelligence',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=actor&id=actor:... ───────────────────────── */
      case 'actor': {
        const id = String(req.query.id || '').trim().toLowerCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_ACTOR_ID',
            'Actor ID required. Example: GET /api/v1/intel?action=actor&id=actor:lockbit');
        }
        const { found, actor } = getActorDetailAPI(id);
        if (!found) {
          return apiError(res, 404, 'ACTOR_NOT_FOUND',
            `Actor "${id}" not found. List all at GET /api/v1/intel?action=top-actors`);
        }
        // Free/starter: identity only, no relationships/timeline — mirrors
        // getGraphForTier()'s own free/starter node-detail restriction.
        const payload = (user.tier === 'free' || user.tier === 'starter') ? {
          id: actor.id, type: actor.type, name: actor.name,
          attributes: {
            aliases: actor.attributes.aliases, category: actor.attributes.category,
            motivation: actor.attributes.motivation, active: actor.attributes.active,
          },
          _upgrade: 'Full relationships, timeline, and TTP detail available on Pro plan',
        } : actor;
        return successResponse(res, { actor: payload }, {
          endpoint:       `/api/v1/intel?action=actor&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=ioc&id=ioc:... — PRO+ only ───────────────── */
      case 'ioc': {
        if (user.tier !== 'pro' && user.tier !== 'enterprise') {
          return apiError(res, 403, 'TIER_RESTRICTED',
            'IOC detail requires Pro or Enterprise plan. Upgrade at https://blog.cyberdudebivash.in/pricing.html',
            { 'X-Upgrade-URL': 'https://blog.cyberdudebivash.in/pricing.html' });
        }
        const id = String(req.query.id || '').trim().toLowerCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_IOC_ID',
            'IOC ID required. Example: GET /api/v1/intel?action=ioc&id=ioc:domain:example.com');
        }
        const { found, ioc } = getIocDetailAPI(id);
        if (!found) {
          return apiError(res, 404, 'IOC_NOT_FOUND', `IOC "${id}" not found.`);
        }
        return successResponse(res, { ioc }, {
          endpoint:       `/api/v1/intel?action=ioc&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=report&id=SA-YYYY-NNNN ───────────────────── */
      case 'report': {
        const id = String(req.query.id || '').trim().toUpperCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_REPORT_ID',
            'Report ID required. Example: GET /api/v1/intel?action=report&id=SA-2026-0001');
        }
        const { found, report } = getReportDetailAPI(id);
        if (!found) {
          return apiError(res, 404, 'REPORT_NOT_FOUND', `Report "${id}" not found.`);
        }
        return successResponse(res, { report }, {
          endpoint:       `/api/v1/intel?action=report&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── Unknown action ────────────────────────────────────── */
      default:
        return apiError(res, 400, 'INVALID_ACTION',
          `Unknown action: "${action}". Valid actions: live, top, cve, iocs, ransomware, search, stats, graph, campaigns, campaign, top-actors, unified-search, actor, ioc, report`);
    }
  } catch (e) {
    return apiError(res, 500, 'INTERNAL_ERROR',
      sec.safeError(e, 'Intel service temporarily unavailable. Please retry.'));
  }
};

/* ─── STIX 2.1 Bundle Builder (Enterprise only) ──────────────── */
function buildSTIXBundle(iocs) {
  const typeMap = {
    ipv4: 'ipv4-addr', domain: 'domain-name', url: 'url',
    sha256: 'file', md5: 'file', sha1: 'file',
  };
  return {
    type:         'bundle',
    id:           `bundle--${crypto.randomUUID()}`,
    spec_version: '2.1',
    created:      new Date().toISOString(),
    objects:      iocs.map(ioc => ({
      type:            'indicator',
      spec_version:    '2.1',
      id:              `indicator--${crypto.randomUUID()}`,
      created:         ioc.first_seen || new Date().toISOString(),
      modified:        new Date().toISOString(),
      name:            `${ioc.type}: ${ioc.value}`,
      description:     `SENTINEL APEX IOC — ${ioc.related_id || ''} | Confidence: ${Math.round((ioc.confidence_score || 0.8) * 100)}%`,
      indicator_types: [ioc.related_type === 'RANSOMWARE' ? 'malicious-activity' : 'compromised'],
      pattern:         `[${typeMap[ioc.type] || 'artifact'}:value = '${ioc.value}']`,
      pattern_type:    'stix',
      valid_from:      ioc.first_seen || new Date().toISOString(),
      confidence:      Math.round((ioc.confidence_score || 0.8) * 100),
      labels:          ['cyberdudebivash-sentinel-apex', ioc.type, ioc.related_type || 'threat'].filter(Boolean),
    })),
    extensions: { 'x-sentinel-apex': { version: '4.0', platform: 'blog.cyberdudebivash.in' } },
  };
}
