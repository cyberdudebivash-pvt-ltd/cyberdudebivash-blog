/**
 * SENTINEL APEX — AI Threat Scoring Engine v2.0
 * Phase 3 Hardening: Normalized scoring + data confidence layer.
 *
 * NORMALIZED SCORING FORMULA:
 *   score = (cvss_norm*0.20) + (kev_flag*0.20) + (exploit_flag*0.15)
 *         + (ioc_density*0.10) + (actor_confidence*0.15)
 *         + (campaign_size_norm*0.10) + (recency*0.10)
 *
 *   All features normalized to [0, 1] before weighting.
 *   Final priority_score = normalized_score × 100.
 *   Every output includes reasoning[] explaining each component.
 *
 * DATA CONFIDENCE LAYER:
 *   data_confidence = (source_count*0.40) + (structured_data*0.30) + (ioc_presence*0.30)
 *   < 0.40 → LOW (suppress from top threats)
 *   0.40–0.69 → MEDIUM
 *   ≥ 0.70 → HIGH
 *
 * All weights are explicit and auditable. No black-box scoring.
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';
const { boundConfidence } = require('./threat-graph');

/* ═══════════════════════════════════════════════════════════════════════
   DATA CONFIDENCE LAYER
   data_confidence = (source_count*0.40) + (structured_data*0.30) + (ioc_presence*0.30)
═══════════════════════════════════════════════════════════════════════ */

/**
 * Compute data confidence score for a single intel item.
 * Items below 0.40 are flagged for suppression from top threats.
 *
 * @param {Object} item - Intel item
 * @returns {{ score, tier, suppressed, factors }}
 */
function computeDataConfidence(item) {
  // ── Factor 1: source_count (weight 0.40) ──────────────────────────
  // Normalized: min(1.0, sourceCount / 3)
  // 1 source → 0.33, 2 sources → 0.67, 3+ sources → 1.0
  const sourceCount = Math.max(1,
    parseInt(item.sourceCount || item.sources_confirmed || 1, 10)
  );
  const sourceNorm  = Math.min(1.0, sourceCount / 3);

  // ── Factor 2: structured_data_presence (weight 0.30) ──────────────
  // Check 6 expected structured fields: cvss, pubDate/published, title, type, vendor, exploited
  const structuredFields = [
    !!parseFloat(item.cvss || item.cvssScore || 0),
    !!(item.pubDate || item.published),
    !!(item.title && item.title.length > 5),
    !!(item.type),
    !!(item.vendor || item.product),
    (item.exploited !== undefined && item.exploited !== null),
  ];
  const populatedCount   = structuredFields.filter(Boolean).length;
  const structuredNorm   = populatedCount / 6;

  // ── Factor 3: ioc_presence (weight 0.30) ──────────────────────────
  // Normalized: min(1.0, iocCount / 5)
  // 0 IOCs → 0, 1 → 0.2, 3 → 0.6, 5+ → 1.0
  const iocCount   = Math.max(
    (item.iocs || []).length,
    parseInt(item.ioc_count || 0, 10)
  );
  const iocNorm    = Math.min(1.0, iocCount / 5);

  // ── Composite ────────────────────────────────────────────────────
  const rawScore   = (sourceNorm * 0.40) + (structuredNorm * 0.30) + (iocNorm * 0.30);
  const score      = Math.round(rawScore * 1000) / 1000;

  // ── Tier assignment ──────────────────────────────────────────────
  let tier;
  if (score >= 0.70)      tier = 'HIGH';
  else if (score >= 0.40) tier = 'MEDIUM';
  else                    tier = 'LOW';

  const suppressed = score < 0.40;

  return {
    score,
    tier,
    suppressed,
    factors: {
      source_count:           { raw: sourceCount, normalized: Math.round(sourceNorm * 1000) / 1000, weight: 0.40 },
      structured_data:        { populated: populatedCount, of: 6, normalized: Math.round(structuredNorm * 1000) / 1000, weight: 0.30 },
      ioc_presence:           { raw: iocCount, normalized: Math.round(iocNorm * 1000) / 1000, weight: 0.30 },
    },
  };
}

/* ═══════════════════════════════════════════════════════════════════════
   PHASE 3 HARDENING: NORMALIZED SCORING ENGINE
   score = (cvss_norm*0.20) + (kev_flag*0.20) + (exploit_flag*0.15)
         + (ioc_density*0.10) + (actor_confidence*0.15)
         + (campaign_size_norm*0.10) + (recency*0.10)
═══════════════════════════════════════════════════════════════════════ */

/**
 * Compute normalized threat score for a single intel item.
 * Replaces computeEnhancedScore with fully normalized [0,1] features.
 *
 * @param {Object} item         - Intel item (from live.json schema)
 * @param {Object} graphContext - Optional context from graph + clustering layer
 *   @param {number}  graphContext.actorCount       - # of linked threat actors
 *   @param {number}  graphContext.actorConfidence  - primary actor confidence (0–1)
 *   @param {boolean} graphContext.inCampaign       - part of a campaign?
 *   @param {number}  graphContext.campaignSize     - items in associated campaign
 *   @param {string}  graphContext.campaignSeverity - CRITICAL/HIGH/MEDIUM/LOW
 * @returns {Object} Normalized scoring result with reasoning[]
 */
function computeNormalizedScore(item, graphContext) {
  graphContext = graphContext || {};
  const {
    actorCount       = 0,
    actorConfidence  = 0,
    inCampaign       = false,
    campaignSize     = 0,
    campaignSeverity = null,
  } = graphContext;

  const reasoning  = [];
  const breakdown  = {};

  // ── Feature 1: cvss_norm (weight 0.20) ──────────────────────────────
  // CVSS 0–10 → normalized 0–1
  const cvss     = Math.min(10, Math.max(0, parseFloat(item.cvss || item.cvssScore || 0)));
  const cvssNorm = cvss / 10;
  breakdown.cvss = { raw: cvss, normalized: cvssNorm, weight: 0.20, contribution: cvssNorm * 0.20 };
  if (cvss >= 9.0)      reasoning.push(`Critical CVSS ${cvss} (cvss_norm=${cvssNorm.toFixed(2)}, weight=0.20)`);
  else if (cvss >= 7.0) reasoning.push(`High CVSS ${cvss} (cvss_norm=${cvssNorm.toFixed(2)}, weight=0.20)`);
  else if (cvss > 0)    reasoning.push(`CVSS ${cvss} (cvss_norm=${cvssNorm.toFixed(2)}, weight=0.20)`);
  else                  reasoning.push(`No CVSS data (cvss_norm=0.00, weight=0.20)`);

  // ── Feature 2: kev_flag (weight 0.20) ───────────────────────────────
  // Binary: on CISA KEV → 1.0
  const hasKev  = !!(item.cisaKev || item.cisa_kev);
  const kevNorm = hasKev ? 1.0 : 0.0;
  breakdown.kev = { present: hasKev, normalized: kevNorm, weight: 0.20, contribution: kevNorm * 0.20 };
  reasoning.push(hasKev
    ? `CISA KEV confirmed — highest exploitation priority (kev_flag=1.0, weight=0.20)`
    : `Not on CISA KEV list (kev_flag=0.0, weight=0.20)`
  );

  // ── Feature 3: exploit_flag (weight 0.15) ────────────────────────────
  // exploited = 1.0; zero_day (not yet patched) = 0.85; neither = 0
  const exploited    = !!(item.exploited);
  const isZeroDay    = item.type === 'ZERO_DAY';
  const exploitNorm  = exploited ? 1.0 : isZeroDay ? 0.85 : 0.0;
  breakdown.exploit  = { exploited, is_zero_day: isZeroDay, normalized: exploitNorm, weight: 0.15, contribution: exploitNorm * 0.15 };
  if (exploited)      reasoning.push(`Exploited in the wild (exploit_flag=1.0, weight=0.15)`);
  else if (isZeroDay) reasoning.push(`Zero-day — unpatched at publication (exploit_flag=0.85, weight=0.15)`);
  else                reasoning.push(`No confirmed exploitation (exploit_flag=0.0, weight=0.15)`);

  // ── Feature 4: ioc_density (weight 0.10) ────────────────────────────
  // IOC count normalized: min(1.0, iocCount / 5)
  const iocCount    = Math.max(
    (item.iocs || []).length,
    parseInt(item.ioc_count || 0, 10)
  );
  const iocNorm     = Math.min(1.0, iocCount / 5);
  breakdown.ioc     = { count: iocCount, normalized: iocNorm, weight: 0.10, contribution: iocNorm * 0.10 };
  if (iocCount > 0) reasoning.push(`${iocCount} IOC(s) present (ioc_density=${iocNorm.toFixed(2)}, weight=0.10)`);
  else              reasoning.push(`No IOCs (ioc_density=0.0, weight=0.10)`);

  // ── Feature 5: actor_confidence (weight 0.15) ───────────────────────
  // From actor attribution. 0 actors = 0.0; actor_confidence from attribution.
  // If actorCount ≥ 1 but no confidence passed, use 0.5 as default.
  let actorConf = 0.0;
  if (item.actor_attribution && !item.actor_attribution.unattributed) {
    actorConf = boundConfidence(item.actor_attribution.primary_confidence || actorConfidence);
  } else if (actorCount > 0) {
    actorConf = boundConfidence(actorConfidence || 0.5);
  }
  const actorNorm = actorConf;
  breakdown.actor = { actor_count: actorCount, confidence: actorConf, normalized: actorNorm, weight: 0.15, contribution: actorNorm * 0.15 };
  if (actorNorm > 0) {
    const actorName = item.actor_attribution?.primary_actor || `${actorCount} actor(s)`;
    reasoning.push(`Actor attribution: ${actorName} (actor_confidence=${actorNorm.toFixed(2)}, weight=0.15)`);
  } else {
    reasoning.push(`No actor attribution (actor_confidence=0.0, weight=0.15)`);
  }

  // ── Feature 6: campaign_size_norm (weight 0.10) ─────────────────────
  // campaignSize normalized: min(1.0, campaignSize / 5)
  // Not in campaign = 0; campaign with 5+ items = 1.0
  const campNorm  = inCampaign ? Math.min(1.0, (campaignSize || 1) / 5) : 0.0;
  breakdown.campaign = {
    member: inCampaign, size: campaignSize, severity: campaignSeverity,
    normalized: campNorm, weight: 0.10, contribution: campNorm * 0.10,
  };
  if (inCampaign) reasoning.push(`Part of ${campaignSeverity || 'active'} campaign (${campaignSize} items; campaign_size_norm=${campNorm.toFixed(2)}, weight=0.10)`);
  else            reasoning.push(`Not associated with a campaign (campaign_size_norm=0.0, weight=0.10)`);

  // ── Feature 7: recency (weight 0.10) ────────────────────────────────
  // recency = exp(-daysOld / 14)
  // Same-day → 1.0; 14 days → ~0.37; 28 days → ~0.14
  const pubDate  = item.pubDate || item.published || null;
  const daysOld  = item.daysOld != null
    ? Math.max(0, item.daysOld)
    : pubDate
      ? Math.max(0, Math.floor((Date.now() - new Date(pubDate).getTime()) / 86400000))
      : 7; // default unknown = 7 days
  const recencyNorm = Math.exp(-daysOld / 14);
  breakdown.recency = { days_old: daysOld, normalized: Math.round(recencyNorm * 1000) / 1000, weight: 0.10, contribution: recencyNorm * 0.10 };
  reasoning.push(`Published ${daysOld} day(s) ago (recency=exp(-${daysOld}/14)=${recencyNorm.toFixed(3)}, weight=0.10)`);

  // ── Composite normalized score ────────────────────────────────────────
  const normalizedScore = boundConfidence(
    (cvssNorm    * 0.20) +
    (kevNorm     * 0.20) +
    (exploitNorm * 0.15) +
    (iocNorm     * 0.10) +
    (actorNorm   * 0.15) +
    (campNorm    * 0.10) +
    (recencyNorm * 0.10)
  );

  const priorityScore = Math.min(100, Math.max(0, Math.round(normalizedScore * 100)));

  // ── Threat level ────────────────────────────────────────────────────
  const threatLevel = priorityScore >= 85 ? 'CRITICAL'
                    : priorityScore >= 65 ? 'HIGH'
                    : priorityScore >= 45 ? 'MEDIUM' : 'LOW';

  // ── Confidence score (data quality × scoring richness) ──────────────
  // Confidence in the score itself: based on features with real data
  const featuresWithData    = [cvss > 0, hasKev, exploited || isZeroDay, iocCount > 0, actorNorm > 0, inCampaign].filter(Boolean).length;
  const scoringConfidence   = boundConfidence(0.40 + (featuresWithData / 6) * 0.55 + (hasKev ? 0.05 : 0));

  reasoning.push(`Composite: normalized_score=${normalizedScore.toFixed(4)} → priority_score=${priorityScore} (${threatLevel})`);

  return {
    priority_score:   priorityScore,
    normalized_score: Math.round(normalizedScore * 10000) / 10000,
    threat_level:     threatLevel,
    confidence_score: Math.round(scoringConfidence * 100) / 100,
    reasoning,
    breakdown,
    scoring_model:    'SENTINEL_APEX_v4.2_NORMALIZED',
  };
}

/**
 * Legacy alias — backward compatibility for any callers using computeEnhancedScore.
 * Maps old graphContext shape to new one.
 */
function computeEnhancedScore(item, graphContext) {
  graphContext = graphContext || {};
  // Old signature had actorCount; new has actorConfidence too
  return computeNormalizedScore(item, {
    actorCount:       graphContext.actorCount      || 0,
    actorConfidence:  graphContext.actorConfidence || 0,
    inCampaign:       graphContext.inCampaign      || false,
    campaignSize:     graphContext.campaignSize    || 0,
    campaignSeverity: graphContext.campaignSeverity || null,
  });
}

/**
 * Recompute score for items that already have actor_attribution + campaign embedded.
 */
function rescoreEnrichedItem(item) {
  const attr = item.actor_attribution || {};
  const graphContext = {
    actorCount:       attr.unattributed ? 0 : 1,
    actorConfidence:  attr.primary_confidence || 0,
    inCampaign:       !!(item._intelligence?.campaign_id),
    campaignSize:     item._intelligence?.campaign_item_count || 0,
    campaignSeverity: item._intelligence?.campaign_severity   || null,
  };
  return computeNormalizedScore(item, graphContext);
}

/**
 * Batch score: returns delta fields to update stored items.
 */
function batchScore(items, graphContextMap) {
  graphContextMap = graphContextMap || {};
  return items.map(item => {
    const ctx     = graphContextMap[item.id] || {};
    const scoring = computeNormalizedScore(item, ctx);
    return {
      id:               item.id,
      priority_score:   scoring.priority_score,
      normalized_score: scoring.normalized_score,
      threat_level:     scoring.threat_level,
      confidence_score: scoring.confidence_score,
      breakdown:        scoring.breakdown,
      reasoning:        scoring.reasoning,
    };
  });
}

module.exports = {
  computeDataConfidence,
  computeNormalizedScore,
  computeEnhancedScore,  // legacy alias
  rescoreEnrichedItem,
  batchScore,
};
