'use strict';
/**
 * GET /api/v1/intelligence/confidence
 *
 * Query intelligence with confidence filtering
 * Returns articles, reports, and CVEs enriched with confidence scores
 *
 * Query Parameters:
 *   type         — article, cve, malware, threat_actor, campaign
 *   min_confidence — HIGH, MEDIUM, LOW (default: MEDIUM)
 *   include_confidence_breakdown — true/false (include multidimensional scoring)
 *   include_explanation — true/false (include confidence explanation)
 *   sort_by      — confidence, date, severity
 *   limit        — results per page
 *
 * Example Response:
 * {
 *   "count": 10,
 *   "items": [
 *     {
 *       "id": "CVE-2024-001",
 *       "title": "Critical RCE in OpenSSL",
 *       "severity": "CRITICAL",
 *       "confidence": {
 *         "level": "HIGH",
 *         "aggregate": 88,
 *         "multidimensional": {
 *           "source_reliability": 99,
 *           "evidence_quality": 92,
 *           "analyst_assessment": 95,
 *           "temporal_relevance": 100,
 *           "corroboration": 85
 *         }
 *       },
 *       "governance": {
 *         "status": "PUBLISHED",
 *         "version": "1.0.2",
 *         "reviewed_by": ["analyst-1", "analyst-2"],
 *         "reviewed_at": "2026-07-31T10:00:00Z"
 *       },
 *       "explanation": "Sourced from official vendor advisories. Evidence is detailed and verifiable. Reviewed and approved by security analyst. Recently published. Suitable for enterprise threat intake and automated response."
 *     }
 *   ]
 * }
 */

const confidenceExposure = require('../../_lib/confidence-exposure');

module.exports = async (req, res) => {
  try {
    const minConfidence = req.query.min_confidence || 'MEDIUM';
    const includeBreakdown = req.query.include_confidence_breakdown === 'true';
    const includeExplanation = req.query.include_explanation === 'true';
    const sortBy = req.query.sort_by || 'confidence';

    // Mock data for demonstration
    // In production, this would query the actual intelligence database
    const mockIntelligence = [
      {
        id: 'CVE-2024-42857',
        type: 'CVE_REPORT',
        title: 'Critical RCE in OpenSSL 3.0.0 through 3.0.7',
        severity: 'CRITICAL',
        cvss: 9.8,
        published_at: new Date().toISOString(),
        sources: ['nvd.nist.gov', 'cisa.gov', 'openssl.org'],
      },
      {
        id: 'MALWARE-2024-DARKSIDE',
        type: 'MALWARE_REPORT',
        title: 'DarkSide Ransomware Campaign Update',
        severity: 'CRITICAL',
        published_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        sources: ['crowdstrike.com', 'mandiant.com'],
      },
      {
        id: 'ADVISORY-2024-001',
        type: 'ADVISORY',
        title: 'Supply Chain Attack in Popular PyPI Package',
        severity: 'HIGH',
        published_at: new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString(),
        sources: ['bleepingcomputer.com', 'github.com'],
      },
    ];

    // Enrich with confidence
    let enriched = mockIntelligence.map(item => {
      const context = {
        governance: {
          status: 'PUBLISHED',
          version: '1.0.0',
          reviewed_at: item.published_at,
        },
        ioc_mentions: Math.floor(Math.random() * 5) + 1,
        detection_rules: [],
        source_type: item.type,
        analyst_reviewed: Math.random() > 0.3, // 70% are analyst-reviewed
      };

      return confidenceExposure.enrichConfidence(item, context);
    });

    // Filter by confidence
    enriched = confidenceExposure.filterByConfidence(enriched, minConfidence);

    // Add explanations if requested
    if (includeExplanation) {
      enriched = enriched.map(item => ({
        ...item,
        confidence_explanation: confidenceExposure.explainConfidence(
          item.confidence,
          { sources: item.sources, ioc_count: item.intelligence_quality.ioc_count }
        ),
      }));
    }

    // Remove breakdown if not requested
    if (!includeBreakdown) {
      enriched = enriched.map(item => ({
        ...item,
        confidence: {
          level: item.confidence.level,
          aggregate: item.confidence.aggregate,
        },
      }));
    }

    // Sort
    if (sortBy === 'confidence') {
      enriched.sort((a, b) => b.confidence.aggregate - a.confidence.aggregate);
    } else if (sortBy === 'date') {
      enriched.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
    } else if (sortBy === 'severity') {
      const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      enriched.sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0));
    }

    res.json({
      count: enriched.length,
      items: enriched,
      filters: {
        min_confidence: minConfidence,
        include_breakdown: includeBreakdown,
        include_explanation: includeExplanation,
        sort_by: sortBy,
      },
      timestamp: new Date().toISOString(),
    });

  } catch (e) {
    console.error('[CONFIDENCE API] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
};
