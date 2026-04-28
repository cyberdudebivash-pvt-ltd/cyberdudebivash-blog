/**
 * SENTINEL APEX — AI Threat Scoring Engine v1.0
 * Phase 3: Deterministic weighted scoring model.
 *
 * INPUT FEATURES (11 dimensions):
 *   CVSS score · KEV presence · Exploitation status · Ransomware flag
 *   IOC richness · Source count · Threat actor linkage · Campaign membership
 *   Campaign size · Recency · Critical infrastructure flag
 *
 * OUTPUT:
 *   { priority_score: 0–100, threat_level: CRITICAL/HIGH/MEDIUM/LOW,
 *     confidence_score: 0–1, score_breakdown: {...}, scoring_model: string }
 *
 * All weights are explicit and auditable. No black-box scoring.
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';

/* ═══════════════════════════════════════════════════════════════════════
   WEIGHT CONFIGURATION
   Total maximum raw score ≈ 115 (capped at 100).
   Over-capacity allows differentiation at the top end.
═══════════════════════════════════════════════════════════════════════ */
const WEIGHTS = {
  CVSS_MAX:             25,  // CVSS 10.0 → 25 pts (linear: cvss * 2.5)
  KEV_BONUS:            20,  // CISA KEV confirmed
  EXPLOITATION_BONUS:   15,  // Active exploitation in wild
  RANSOMWARE_BONUS:     10,  // Ransomware campaign association
  IOC_MAX:               8,  // IOC count ≥ 6 → full 8 pts
  SOURCE_MAX:            7,  // 4+ corroborating sources → full 7 pts
  ACTOR_KNOWN:           8,  // Known threat actor(s) linked (2+ actors → max)
  CAMPAIGN_MEMBER:       5,  // Part of active campaign
  RECENCY_MAX:           7,  // Published today → 7 pts, fades over 14 days
  ZERO_DAY_BONUS:        5,  // Type === 'ZERO_DAY'
  CRITICAL_INFRA_BONUS:  5,  // SCADA/ICS/federal/nuclear context
};

/* ═══════════════════════════════════════════════════════════════════════
   SCORING ENGINE
═══════════════════════════════════════════════════════════════════════ */

/**
 * Compute enhanced threat score for a single intel item.
 *
 * @param {Object} item         — Intel item (from live.json schema)
 * @param {Object} graphContext — Optional context from the graph + clustering layer
 *   @param {number} graphContext.actorCount    — # of linked threat actors
 *   @param {boolean} graphContext.inCampaign   — is this item part of a campaign?
 *   @param {number} graphContext.campaignSize  — # of items in associated campaign
 *   @param {string} graphContext.campaignSeverity — CRITICAL/HIGH/MEDIUM/LOW
 * @returns {Object} Scoring result with full breakdown
 */
function computeEnhancedScore(item, graphContext = {}) {
  const {
    actorCount      = 0,
    inCampaign      = false,
    campaignSize    = 0,
    campaignSeverity = null,
  } = graphContext;

  const breakdown = {};

  /* ── 1. CVSS Base Score (0–25 pts) ─────────────────────────────── */
  const cvss = Math.min(10, Math.max(0, parseFloat(item.cvss || item.cvssScore || 0)));
  const cvssScore = Math.min(WEIGHTS.CVSS_MAX, Math.round(cvss * (WEIGHTS.CVSS_MAX / 10)));
  breakdown.cvss = { raw: cvss, max: WEIGHTS.CVSS_MAX, contribution: cvssScore };

  /* ── 2. CISA KEV Confirmation (0 or 20 pts) ─────────────────────── */
  const hasKev     = !!(item.cisaKev || item.cisa_kev);
  const kevScore   = hasKev ? WEIGHTS.KEV_BONUS : 0;
  breakdown.kev    = { present: hasKev, max: WEIGHTS.KEV_BONUS, contribution: kevScore };

  /* ── 3. Active Exploitation (0 or 15 pts) ───────────────────────── */
  const exploited      = !!(item.exploited);
  const exploitScore   = exploited ? WEIGHTS.EXPLOITATION_BONUS : 0;
  breakdown.exploitation = {
    status: exploited ? 'confirmed_in_wild' : 'not_confirmed',
    max: WEIGHTS.EXPLOITATION_BONUS,
    contribution: exploitScore,
  };

  /* ── 4. Ransomware Association (0 or 10 pts) ────────────────────── */
  const hasRansomware    = !!(item.ransomware || item.type === 'RANSOMWARE');
  const ransomwareScore  = hasRansomware ? WEIGHTS.RANSOMWARE_BONUS : 0;
  breakdown.ransomware   = { present: hasRansomware, max: WEIGHTS.RANSOMWARE_BONUS, contribution: ransomwareScore };

  /* ── 5. IOC Richness (0–8 pts) ──────────────────────────────────── */
  const iocCount    = Math.max(
    (item.iocs || []).length,
    parseInt(item.ioc_count || 0, 10)
  );
  // 1 IOC = 1pt, 2 = 3pt, 4 = 6pt, 6+ = 8pt
  const iocScore    = iocCount >= 6 ? 8 : iocCount >= 4 ? 6 : iocCount >= 2 ? 3 : iocCount >= 1 ? 1 : 0;
  breakdown.ioc_richness = { count: iocCount, max: WEIGHTS.IOC_MAX, contribution: iocScore };

  /* ── 6. Multi-Source Corroboration (0–7 pts) ────────────────────── */
  const sourceCount = Math.max(1,
    parseInt(item.sourceCount || item.sources_confirmed || 1, 10)
  );
  // 1 source = 0pt, 2 = 3pt, 3 = 5pt, 4+ = 7pt
  const sourceScore = sourceCount >= 4 ? 7 : sourceCount >= 3 ? 5 : sourceCount >= 2 ? 3 : 0;
  breakdown.sources = { count: sourceCount, max: WEIGHTS.SOURCE_MAX, contribution: sourceScore };

  /* ── 7. Known Threat Actor Linkage (0–8 pts) ────────────────────── */
  // 0 actors = 0pt, 1 actor = 5pt, 2+ actors = 8pt
  const actorScore  = actorCount >= 2 ? WEIGHTS.ACTOR_KNOWN
                    : actorCount === 1 ? 5 : 0;
  breakdown.threat_actor = {
    count: actorCount,
    max: WEIGHTS.ACTOR_KNOWN,
    contribution: actorScore,
    note: actorCount > 0 ? `${actorCount} known actor(s) linked via SENTINEL APEX graph` : 'No known actor attribution',
  };

  /* ── 8. Campaign Membership (0–5 pts) ───────────────────────────── */
  // Not in campaign = 0pt, in campaign (small) = 3pt, large campaign = 5pt
  const campaignScore = inCampaign
    ? (campaignSize >= 5 ? WEIGHTS.CAMPAIGN_MEMBER : campaignSize >= 3 ? 4 : 3)
    : 0;
  breakdown.campaign = {
    member:   inCampaign,
    size:     campaignSize,
    severity: campaignSeverity,
    max:      WEIGHTS.CAMPAIGN_MEMBER,
    contribution: campaignScore,
  };

  /* ── 9. Recency (0–7 pts) ───────────────────────────────────────── */
  const pubDate  = item.pubDate || item.published || null;
  const daysOld  = item.daysOld != null ? item.daysOld
                  : pubDate ? Math.floor((Date.now() - new Date(pubDate).getTime()) / 86400000)
                  : 7; // default to 7 days if unknown
  const safeAge  = Math.max(0, daysOld);
  const recencyScore = safeAge <= 0  ? 7
                     : safeAge <= 1  ? 6
                     : safeAge <= 3  ? 4
                     : safeAge <= 7  ? 2
                     : safeAge <= 14 ? 1 : 0;
  breakdown.recency = { days_old: safeAge, max: WEIGHTS.RECENCY_MAX, contribution: recencyScore };

  /* ── 10. Zero-Day Bonus (0 or 5 pts) ───────────────────────────── */
  const isZeroDay   = item.type === 'ZERO_DAY';
  const zeroDayScore = isZeroDay ? WEIGHTS.ZERO_DAY_BONUS : 0;
  breakdown.zero_day = { present: isZeroDay, max: WEIGHTS.ZERO_DAY_BONUS, contribution: zeroDayScore };

  /* ── 11. Critical Infrastructure Context (0 or 5 pts) ──────────── */
  const critText        = `${item.title || ''} ${item.desc || item.description || ''}`;
  const isCritInfra     = /federal|critical\s+infra|scada|ics|ot\s+|nuclear|power\s+grid|water\s+treatment|pipeline|election/i.test(critText);
  const critInfraScore  = isCritInfra ? WEIGHTS.CRITICAL_INFRA_BONUS : 0;
  breakdown.critical_infra = { present: isCritInfra, max: WEIGHTS.CRITICAL_INFRA_BONUS, contribution: critInfraScore };

  /* ── COMPOSITE SCORE ─────────────────────────────────────────────── */
  const rawScore  = cvssScore + kevScore + exploitScore + ransomwareScore +
                    iocScore + sourceScore + actorScore + campaignScore +
                    recencyScore + zeroDayScore + critInfraScore;
  const finalScore = Math.min(100, Math.max(0, Math.round(rawScore)));

  /* ── CONFIDENCE SCORE (0–1) ──────────────────────────────────────── */
  // Based on: how many features have data, source count, and KEV presence
  const featuresWithData = Object.values(breakdown).filter(v => v.contribution > 0).length;
  const baseConfidence   = 0.40 + (featuresWithData / 11) * 0.40;
  const sourceBonus      = sourceCount >= 3 ? 0.12 : sourceCount >= 2 ? 0.06 : 0;
  const kevBonus         = hasKev ? 0.08 : 0;
  const confidence       = Math.min(0.99, baseConfidence + sourceBonus + kevBonus);

  /* ── THREAT LEVEL ────────────────────────────────────────────────── */
  const threatLevel = finalScore >= 85 ? 'CRITICAL'
                    : finalScore >= 65 ? 'HIGH'
                    : finalScore >= 45 ? 'MEDIUM' : 'LOW';

  return {
    priority_score:   finalScore,
    threat_level:     threatLevel,
    confidence_score: Math.round(confidence * 100) / 100,
    score_breakdown:  breakdown,
    raw_score:        rawScore,
    scoring_model:    'SENTINEL_APEX_v4.1_ENHANCED_DETERMINISTIC',
  };
}

/**
 * Recompute score for items that already have graph/campaign context embedded.
 * Convenience wrapper for batch re-scoring after enrichment.
 */
function rescoreEnrichedItem(item) {
  const graphContext = {
    actorCount:       (item._intelligence?.linked_actors || []).length,
    inCampaign:       !!(item._intelligence?.campaign_id),
    campaignSize:     item._intelligence?.campaign_item_count || 0,
    campaignSeverity: item._intelligence?.campaign_severity || null,
  };
  return computeEnhancedScore(item, graphContext);
}

/**
 * Batch score: returns only the delta fields needed to update stored items.
 */
function batchScore(items, graphContext = {}) {
  return items.map(item => {
    const ctx = graphContext[item.id] || {};
    const scoring = computeEnhancedScore(item, ctx);
    return {
      id:               item.id,
      priority_score:   scoring.priority_score,
      threat_level:     scoring.threat_level,
      confidence_score: scoring.confidence_score,
      score_breakdown:  scoring.score_breakdown,
    };
  });
}

module.exports = { computeEnhancedScore, rescoreEnrichedItem, batchScore, WEIGHTS };
