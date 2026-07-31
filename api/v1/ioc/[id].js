'use strict';
/**
 * GET /api/v1/ioc/[id]
 * GET /api/v1/ioc/[id]/history
 * GET /api/v1/ioc/[id]/mentions
 * GET /api/v1/ioc/[id]/correlations
 *
 * Get individual IOC with full metadata, history, and related IOCs
 */

const iocCanonical = require('../../_lib/ioc-canonical');

module.exports = async (req, res) => {
  try {
    const { id } = req.query;

    if (!id) {
      return res.status(400).json({ error: 'IOC ID required' });
    }

    // GET /api/v1/ioc/[id]/history
    if (req.url.includes('/history')) {
      const ioc = iocCanonical.getIOC(id);
      if (!ioc) return res.status(404).json({ error: 'IOC not found' });
      return res.json({
        ioc_id: id,
        type: ioc.type,
        value: ioc.value,
        history: ioc.history,
        first_seen: ioc.first_seen,
        last_seen: ioc.last_seen,
      });
    }

    // GET /api/v1/ioc/[id]/mentions
    if (req.url.includes('/mentions')) {
      const mentions = iocCanonical.getIOCMentions(id);
      if (!mentions) return res.status(404).json({ error: 'IOC not found' });
      return res.json(mentions);
    }

    // GET /api/v1/ioc/[id]/correlations
    if (req.url.includes('/correlations')) {
      const ioc = iocCanonical.getIOC(id);
      if (!ioc) return res.status(404).json({ error: 'IOC not found' });
      const correlated = iocCanonical.getCorrelatedIOCs(id);
      return res.json({
        ioc_id: id,
        type: ioc.type,
        value: ioc.value,
        correlations: correlated,
        related_count: correlated.length,
      });
    }

    // GET /api/v1/ioc/[id] — full IOC details
    const ioc = iocCanonical.getIOC(id);
    if (!ioc) {
      return res.status(404).json({ error: 'IOC not found' });
    }

    res.json({
      ioc,
      sources_count: {
        articles: ioc.sources.articles.length,
        detections: ioc.sources.detections.length,
        campaigns: ioc.sources.campaigns.length,
        total_mentions: ioc.sources.articles.length + ioc.sources.detections.length + ioc.sources.campaigns.length,
      },
      related_iocs: iocCanonical.getCorrelatedIOCs(id).length,
    });

  } catch (e) {
    console.error('[IOC API] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
};
