'use strict';
/**
 * Confidence Exposure Engine (Stage 3.1)
 * Surfaces confidence scoring and governance metadata to customer-facing APIs
 *
 * The governance, IOC, and detection engines all calculate confidence internally.
 * This module standardizes how confidence is exposed to API consumers:
 * - Multidimensional confidence breakdown (source reliability, evidence quality, analyst assessment)
 * - Editorial approval status (GENERATED, REVIEW, APPROVED, PUBLISHED)
 * - Version tracking (customers know exact rule/report version)
 * - Temporal freshness (when last reviewed)
 *
 * API consumers can build risk scoring models on top of confidence scores.
 * Enterprises can filter by confidence thresholds in their threat intake workflows.
 */

/**
 * Calculate multidimensional confidence from multiple signal sources
 * Returns confidence object suitable for API response
 */
function calculateConfidence(signals = {}) {
  // Signal sources: (each 0-1 scale)
  const sourceReliability = signals.source_reliability || 0.7;      // Is the source trustworthy?
  const evidenceQuality = signals.evidence_quality || 0.7;          // How solid is the evidence?
  const analystAssessment = signals.analyst_assessment || undefined; // Did a human verify this?
  const temporalRelevance = signals.temporal_relevance || 0.8;      // Is this fresh or stale?
  const corroboration = signals.corroboration || 0.6;               // How many independent sources?

  // Aggregate: weighted average
  const components = { source_reliability: sourceReliability, evidence_quality: evidenceQuality, temporal_relevance: temporalRelevance, corroboration };
  if (analystAssessment !== undefined) components.analyst_assessment = analystAssessment;

  const weights = { source_reliability: 0.2, evidence_quality: 0.2, analyst_assessment: 0.25, temporal_relevance: 0.15, corroboration: 0.2 };
  let weightedSum = 0;
  let totalWeight = 0;

  for (const [key, value] of Object.entries(components)) {
    if (value !== undefined) {
      weightedSum += value * (weights[key] || 0.2);
      totalWeight += weights[key] || 0.2;
    }
  }

  const aggregate = totalWeight > 0 ? weightedSum / totalWeight : 0.5;

  // Normalize to confidence level
  let level = 'MEDIUM';
  if (aggregate >= 0.75) level = 'HIGH';
  else if (aggregate <= 0.4) level = 'LOW';

  return {
    level,
    aggregate: parseFloat((aggregate * 100).toFixed(0)),
    multidimensional: {
      source_reliability: parseFloat((sourceReliability * 100).toFixed(0)),
      evidence_quality: parseFloat((evidenceQuality * 100).toFixed(0)),
      analyst_assessment: analystAssessment ? parseFloat((analystAssessment * 100).toFixed(0)) : undefined,
      temporal_relevance: parseFloat((temporalRelevance * 100).toFixed(0)),
      corroboration: parseFloat((corroboration * 100).toFixed(0)),
    },
    factors: Object.entries(components).map(([key, value]) => ({
      factor: key,
      score: parseFloat((value * 100).toFixed(0)),
      weight: weights[key] || 0.2,
    })),
  };
}

/**
 * Enrich API response with confidence and governance metadata
 * Called for each intelligence object returned by API
 *
 * Example usage:
 *   const article = await getArticle('CVE-2024-001');
 *   return enrichConfidence(article, { governance, ioc_mentions, detection_rules });
 */
function enrichConfidence(item, context = {}) {
  const {
    governance = {},
    ioc_mentions = 0,
    detection_rules = [],
    source_type = 'article',
    analyst_reviewed = false,
  } = context;

  // Calculate confidence from multiple signals
  const signals = {
    source_reliability: calculateSourceReliability(item.sources || []),
    evidence_quality: calculateEvidenceQuality(item.type || 'article'),
    analyst_assessment: analyst_reviewed ? 0.95 : undefined,
    temporal_relevance: calculateFreshness(item.published_at || item.date),
    corroboration: Math.min(1.0, 0.5 + (ioc_mentions * 0.1)), // Each IOC mention increases confidence
  };

  const confidence = calculateConfidence(signals);

  return {
    ...item,
    confidence,
    governance: {
      status: governance.status || 'PUBLISHED',
      version: governance.version || '1.0.0',
      reviewed_by: governance.reviewed_by || [],
      reviewed_at: governance.reviewed_at,
      created_at: governance.created_at,
      updated_at: governance.updated_at || governance.reviewed_at,
      confidence_level: confidence.level,
    },
    intelligence_quality: {
      ioc_count: ioc_mentions,
      detection_rule_count: (detection_rules || []).length,
      analyst_assessed: analyst_reviewed,
      version_history_available: !!governance.version_history,
    },
  };
}

/**
 * Calculate source reliability score (0-1)
 * Official sources (NVD, CISA, vendors) score higher
 */
function calculateSourceReliability(sources = []) {
  const sourceScores = {
    'nvd.nist.gov': 0.99,
    'cisa.gov': 0.98,
    'microsoft.com': 0.95,
    'google.com': 0.95,
    'apache.org': 0.95,
    'linux.org': 0.94,
    'securityweek.com': 0.80,
    'bleepingcomputer.com': 0.80,
    'krebsonsecurity.com': 0.85,
    'crowdstrike.com': 0.85,
    'paloaltonetworks.com': 0.85,
    'reddit.com': 0.50,
    'twitter.com': 0.55,
  };

  if (!sources.length) return 0.7;

  const scores = sources.map(s => {
    for (const [domain, score] of Object.entries(sourceScores)) {
      if (s.includes(domain)) return score;
    }
    return 0.65; // Unknown source default
  });

  return scores.reduce((a, b) => a + b, 0) / scores.length;
}

/**
 * Calculate evidence quality (0-1)
 * Different article types have different baseline quality
 */
function calculateEvidenceQuality(type = 'article') {
  const typeScores = {
    'CVE_REPORT': 0.95,       // Official CVE records are high quality
    'ZERO_DAY': 0.90,         // Zero-day reports are carefully vetted
    'MALWARE_REPORT': 0.85,   // Malware analysis is detailed
    'RANSOMWARE': 0.85,
    'THREAT_ACTOR': 0.80,
    'CAMPAIGN': 0.80,
    'ADVISORY': 0.88,
    'BREAKING_NEWS': 0.75,
    'ARTICLE': 0.70,
    'BLOG': 0.65,
  };

  return typeScores[type] || 0.70;
}

/**
 * Calculate temporal relevance (0-1)
 * Recent intel scores higher; stale intel scores lower
 */
function calculateFreshness(publishedAt) {
  if (!publishedAt) return 0.8;

  const published = new Date(publishedAt);
  const now = new Date();
  const ageHours = (now - published) / (1000 * 60 * 60);

  if (ageHours < 1) return 1.0;           // Fresh (< 1 hour)
  if (ageHours < 24) return 0.95;         // Recent (< 1 day)
  if (ageHours < 7 * 24) return 0.90;     // 1 week
  if (ageHours < 30 * 24) return 0.80;    // 1 month
  if (ageHours < 90 * 24) return 0.70;    // 3 months
  if (ageHours < 365 * 24) return 0.50;   // 1 year
  return 0.30;                             // Stale (> 1 year)
}

/**
 * Create confidence explanation for customer communication
 * Explain WHY confidence is at this level
 */
function explainConfidence(confidence, context = {}) {
  const { sources = [], ioc_count = 0, analyst_reviewed = false } = context;
  const explanations = [];

  if (confidence.multidimensional.source_reliability >= 90) {
    explanations.push('Sourced from official vendor/government advisories');
  } else if (confidence.multidimensional.source_reliability >= 75) {
    explanations.push('Sourced from established security research organizations');
  } else {
    explanations.push('Sourced from community and independent researchers');
  }

  if (confidence.multidimensional.evidence_quality >= 85) {
    explanations.push('Evidence is detailed and verifiable');
  } else if (confidence.multidimensional.evidence_quality >= 70) {
    explanations.push('Evidence is reasonably detailed');
  } else {
    explanations.push('Evidence is preliminary or limited');
  }

  if (analyst_reviewed) {
    explanations.push('Reviewed and approved by security analyst');
  }

  if (ioc_count >= 3) {
    explanations.push(`Corroborated by ${ioc_count} independent indicators of compromise`);
  } else if (ioc_count > 0) {
    explanations.push(`Includes ${ioc_count} indicator(s) of compromise`);
  }

  if (confidence.multidimensional.temporal_relevance >= 90) {
    explanations.push('Recently published or updated');
  } else if (confidence.multidimensional.temporal_relevance >= 70) {
    explanations.push('Reasonably recent intelligence');
  } else {
    explanations.push('Note: this intelligence is aging, verify freshness');
  }

  return {
    confidence_level: confidence.level,
    confidence_score: confidence.aggregate,
    explanation: explanations.join('. '),
    recommendation: confidence.level === 'HIGH'
      ? 'Suitable for enterprise threat intake and automated response'
      : confidence.level === 'MEDIUM'
        ? 'Suitable for human analyst review and investigation'
        : 'Should be corroborated with additional sources before action',
  };
}

/**
 * Filter intelligence by confidence threshold
 * Enterprises can request only HIGH confidence intelligence
 */
function filterByConfidence(items = [], minConfidence = 'MEDIUM') {
  const confidenceRank = { LOW: 1, MEDIUM: 2, HIGH: 3 };
  const minRank = confidenceRank[minConfidence] || 2;

  return items.filter(item => {
    const itemConfidence = item.confidence?.level || 'MEDIUM';
    const itemRank = confidenceRank[itemConfidence] || 2;
    return itemRank >= minRank;
  });
}

module.exports = {
  calculateConfidence,
  enrichConfidence,
  explainConfidence,
  filterByConfidence,
  calculateSourceReliability,
  calculateEvidenceQuality,
  calculateFreshness,
};
