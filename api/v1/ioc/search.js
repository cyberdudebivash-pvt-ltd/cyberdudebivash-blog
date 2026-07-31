'use strict';
/**
 * GET /api/v1/ioc/search
 *
 * Search the canonical IOC store
 *
 * Query Parameters:
 *   type         — IOC type: ipv4, ipv6, domain, url, file_hash_md5, file_hash_sha1, file_hash_sha256, file_name, registry_key, mitre_technique
 *   value        — IOC value (will be normalized)
 *   confidence   — HIGH, MEDIUM, LOW
 *   severity     — CRITICAL, HIGH, MEDIUM, LOW
 *   classification — malware, c2, phishing, ransomware, etc.
 *   campaign     — campaign name
 *   actor        — threat actor name
 *   min_corroboration — minimum number of sources (2, 3, etc.)
 *   status       — ACTIVE, INACTIVE, RETIRED
 *   query        — free-text search
 *   format       — json (default), csv, stix
 *   limit        — results per page (default 100)
 *   offset       — pagination offset
 *
 * Examples:
 *   /api/v1/ioc/search?type=ipv4&value=192.168.1.1
 *   /api/v1/ioc/search?type=domain&value=evil.com
 *   /api/v1/ioc/search?severity=CRITICAL&confidence=HIGH
 *   /api/v1/ioc/search?campaign=darkside&format=stix
 *   /api/v1/ioc/search?min_corroboration=3
 */

const iocCanonical = require('../../_lib/ioc-canonical');

module.exports = async (req, res) => {
  try {
    const filters = {
      type: req.query.type,
      value: req.query.value,
      confidence: req.query.confidence,
      severity: req.query.severity,
      classification: req.query.classification,
      campaign: req.query.campaign,
      actor: req.query.actor,
      status: req.query.status,
      min_corroboration: req.query.min_corroboration ? parseInt(req.query.min_corroboration) : undefined,
      query: req.query.query,
      limit: req.query.limit ? parseInt(req.query.limit) : 100,
      offset: req.query.offset ? parseInt(req.query.offset) : 0,
    };

    // Remove undefined filters
    Object.keys(filters).forEach(k => filters[k] === undefined && delete filters[k]);

    const format = req.query.format || 'json';

    // Export format handling
    if (['csv', 'stix'].includes(format)) {
      const exported = iocCanonical.exportIOCs(format, filters);
      const mimeTypes = { csv: 'text/csv', stix: 'application/stix+json' };
      res.setHeader('Content-Type', mimeTypes[format]);
      res.setHeader('Content-Disposition', `attachment; filename="iocs-${Date.now()}.${format}"`);
      return res.send(exported);
    }

    // JSON response
    const iocs = iocCanonical.searchIOCs(filters);
    const stats = iocCanonical.getStats();

    res.setHeader('Content-Type', 'application/json');
    res.json({
      count: iocs.length,
      iocs,
      stats,
      filters,
      timestamp: new Date().toISOString(),
    });

  } catch (e) {
    console.error('[IOC API] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
};
