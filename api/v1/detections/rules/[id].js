'use strict';
/**
 * GET /api/v1/detections/rules/[id]
 * GET /api/v1/detections/rules/[id]/history
 * PATCH /api/v1/detections/rules/[id] (admin only)
 *
 * Get individual detection rule with full governance metadata and version history
 */

const detectionRules = require('../../../_lib/detection-rules');

module.exports = async (req, res) => {
  try {
    const { id } = req.query;

    if (!id) {
      return res.status(400).json({ error: 'Rule ID required' });
    }

    // GET /api/v1/detections/rules/[id]/history
    if (req.url.includes('/history')) {
      const rule = detectionRules.getRule(id);
      if (!rule) {
        return res.status(404).json({ error: 'Rule not found' });
      }
      return res.json({
        rule_id: id,
        title: rule.title,
        technique_id: rule.technique_id,
        history: rule.history,
        current_version: rule.governance.version,
      });
    }

    // GET /api/v1/detections/rules/[id]
    const rule = detectionRules.getRule(id);
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    res.json({
      rule,
      deploymentInfo: {
        sigma_status: rule.platforms.sigma ? 'READY' : 'NOT_AVAILABLE',
        kql_status: rule.platforms.kql ? 'READY' : 'NOT_AVAILABLE',
        splunk_status: rule.platforms.splunk ? 'READY' : 'NOT_AVAILABLE',
        osquery_status: rule.platforms.osquery ? 'READY' : 'NOT_AVAILABLE',
        suricata_status: rule.suricata?.length > 0 ? 'READY' : 'NOT_AVAILABLE',
      },
    });

  } catch (e) {
    console.error('[DETECTION API] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
};
