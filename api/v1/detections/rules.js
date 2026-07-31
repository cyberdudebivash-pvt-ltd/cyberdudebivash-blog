'use strict';
/**
 * GET /api/v1/detections/rules
 *
 * Query the canonical detection rule store.
 * Returns rules with governance metadata, versioning, and source tracking.
 *
 * Query Parameters:
 *   technique_id  — filter by MITRE ATT&CK technique (e.g., T1059.001)
 *   level         — filter by severity: critical, high, medium, low
 *   status        — filter by governance status: GENERATED, REVIEW, APPROVED, PUBLISHED
 *   platform      — filter by platform: sigma, kql, splunk, osquery, suricata
 *   confidence    — filter by confidence: HIGH, MEDIUM, LOW
 *   query         — search title/description/technique_id
 *   format        — export format: json (default), sigma, kql, suricata, csv
 *
 * Examples:
 *   /api/v1/detections/rules?status=PUBLISHED
 *   /api/v1/detections/rules?platform=sigma&level=high
 *   /api/v1/detections/rules?technique_id=T1059.001
 *   /api/v1/detections/rules?query=powershell&format=sigma
 */

const detectionRules = require('../../_lib/detection-rules');

module.exports = async (req, res) => {
  try {
    const filters = {};

    // Parse query parameters
    if (req.query.technique_id) filters.technique_id = req.query.technique_id;
    if (req.query.level) filters.level = req.query.level;
    if (req.query.status) filters.status = req.query.status;
    if (req.query.platform) filters.platform = req.query.platform;
    if (req.query.confidence) filters.confidence = req.query.confidence;
    if (req.query.query) filters.query = req.query.query;

    const format = req.query.format || 'json';

    // Export format handling
    if (['sigma', 'kql', 'suricata', 'csv'].includes(format)) {
      const exported = detectionRules.exportRules(format, filters);
      const mimeTypes = {
        sigma: 'text/plain',
        kql: 'text/plain',
        suricata: 'text/plain',
        csv: 'text/csv',
      };
      res.setHeader('Content-Type', mimeTypes[format]);
      res.setHeader('Content-Disposition', `attachment; filename="detection-rules-${Date.now()}.${format === 'csv' ? 'csv' : 'txt'}"`);
      return res.send(exported);
    }

    // JSON response
    const rules = detectionRules.searchRules(filters);
    const stats = detectionRules.getStats();

    res.setHeader('Content-Type', 'application/json');
    res.json({
      count: rules.length,
      rules,
      stats,
      filters,
      timestamp: new Date().toISOString(),
    });

  } catch (e) {
    console.error('[DETECTION API] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
};
