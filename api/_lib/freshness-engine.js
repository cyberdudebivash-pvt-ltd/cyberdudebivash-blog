'use strict';

const redis = require('./redis');

class FreshnessEngine {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async scoreFreshness(intelligence) {
    const type = intelligence.type;
    const lastSeen = intelligence.lastSeen || intelligence.createdAt;
    const daysSinceLastSeen = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60 * 24);

    let freshnessScore = 1.0;
    let status = 'fresh';
    let recommendation = 'Current intelligence';

    if (type === 'IOC' || type === 'INDICATOR') {
      freshnessScore = this.scoreIOCFreshness(daysSinceLastSeen);
      status = this.getIOCFreshnessStatus(daysSinceLastSeen);
      recommendation = this.getIOCFreshnessRecommendation(daysSinceLastSeen, freshnessScore);
    } else if (type === 'MALWARE') {
      freshnessScore = this.scoreMalwareFreshness(daysSinceLastSeen);
      status = this.getMalwareFreshnessStatus(daysSinceLastSeen);
      recommendation = this.getMalwareFreshnessRecommendation(daysSinceLastSeen, freshnessScore);
    } else if (type === 'CAMPAIGN') {
      freshnessScore = this.scoreCampaignFreshness(daysSinceLastSeen);
      status = this.getCampaignFreshnessStatus(daysSinceLastSeen);
      recommendation = this.getCampaignFreshnessRecommendation(daysSinceLastSeen, freshnessScore);
    } else if (type === 'THREAT_ACTOR') {
      freshnessScore = this.scoreThreatActorFreshness(daysSinceLastSeen);
      status = this.getThreatActorFreshnessStatus(daysSinceLastSeen);
      recommendation = this.getThreatActorFreshnessRecommendation(daysSinceLastSeen, freshnessScore);
    } else if (type === 'INFRASTRUCTURE') {
      freshnessScore = this.scoreInfrastructureFreshness(daysSinceLastSeen);
      status = this.getInfrastructureFreshnessStatus(daysSinceLastSeen);
      recommendation = this.getInfrastructureFreshnessRecommendation(daysSinceLastSeen, freshnessScore);
    }

    return {
      type,
      daysSinceLastSeen: Math.round(daysSinceLastSeen),
      freshnessScore: Math.round(freshnessScore * 100) / 100,
      status,
      recommendation,
      confidenceImpact: this.getConfidenceImpact(freshnessScore),
    };
  }

  scoreIOCFreshness(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 7) return 1.0;
    if (daysSinceLastSeen <= 30) return 0.9;
    if (daysSinceLastSeen <= 60) return 0.7;
    if (daysSinceLastSeen <= 90) return 0.5;
    if (daysSinceLastSeen <= 180) return 0.25;
    return 0.05;
  }

  scoreMalwareFreshness(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 30) return 1.0;
    if (daysSinceLastSeen <= 90) return 0.8;
    if (daysSinceLastSeen <= 180) return 0.6;
    if (daysSinceLastSeen <= 365) return 0.4;
    if (daysSinceLastSeen <= 730) return 0.2;
    return 0.05;
  }

  scoreCampaignFreshness(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 30) return 1.0;
    if (daysSinceLastSeen <= 90) return 0.85;
    if (daysSinceLastSeen <= 180) return 0.7;
    if (daysSinceLastSeen <= 365) return 0.5;
    if (daysSinceLastSeen <= 730) return 0.3;
    return 0.1;
  }

  scoreThreatActorFreshness(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 90) return 1.0;
    if (daysSinceLastSeen <= 180) return 0.9;
    if (daysSinceLastSeen <= 365) return 0.7;
    if (daysSinceLastSeen <= 730) return 0.5;
    return 0.3;
  }

  scoreInfrastructureFreshness(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 14) return 1.0;
    if (daysSinceLastSeen <= 60) return 0.8;
    if (daysSinceLastSeen <= 120) return 0.6;
    if (daysSinceLastSeen <= 180) return 0.4;
    return 0.1;
  }

  getIOCFreshnessStatus(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 7) return 'hot';
    if (daysSinceLastSeen <= 30) return 'active';
    if (daysSinceLastSeen <= 90) return 'aging';
    if (daysSinceLastSeen <= 180) return 'stale';
    return 'expired';
  }

  getMalwareFreshnessStatus(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 30) return 'active';
    if (daysSinceLastSeen <= 180) return 'ongoing';
    if (daysSinceLastSeen <= 365) return 'legacy';
    return 'archived';
  }

  getCampaignFreshnessStatus(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 30) return 'active';
    if (daysSinceLastSeen <= 180) return 'ongoing';
    if (daysSinceLastSeen <= 365) return 'dormant';
    return 'historical';
  }

  getThreatActorFreshnessStatus(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 90) return 'active';
    if (daysSinceLastSeen <= 365) return 'recent';
    if (daysSinceLastSeen <= 730) return 'historical';
    return 'archived';
  }

  getInfrastructureFreshnessStatus(daysSinceLastSeen) {
    if (daysSinceLastSeen <= 14) return 'current';
    if (daysSinceLastSeen <= 60) return 'recent';
    if (daysSinceLastSeen <= 180) return 'aging';
    return 'deprecated';
  }

  getIOCFreshnessRecommendation(daysSinceLastSeen, score) {
    if (score >= 0.9) return 'IOC is actively being used. High detection priority.';
    if (score >= 0.7) return 'IOC recently active. Monitor for resurgence.';
    if (score >= 0.5) return 'IOC aging. Verify status before detection deployment.';
    if (score >= 0.25) return 'IOC stale. Unlikely still active. Remove from active detection.';
    return 'IOC expired. Archive or remove from all detection systems.';
  }

  getMalwareFreshnessRecommendation(daysSinceLastSeen, score) {
    if (score >= 0.9) return 'Malware actively circulating. Prioritize detection.';
    if (score >= 0.7) return 'Malware recent activity. Maintain detection posture.';
    if (score >= 0.4) return 'Malware historical. Update detection rules if samples available.';
    return 'Malware legacy. Archive analysis for reference.';
  }

  getCampaignFreshnessRecommendation(daysSinceLastSeen, score) {
    if (score >= 0.85) return 'Campaign actively ongoing. Prioritize intelligence updates.';
    if (score >= 0.7) return 'Campaign recent activity. Monitor for escalation.';
    if (score >= 0.5) return 'Campaign dormant. Reactivation risk if threat actor active.';
    return 'Campaign historical. Archive for reference.';
  }

  getThreatActorFreshnessRecommendation(daysSinceLastSeen, score) {
    if (score >= 0.95) return 'Threat actor recently active. Maintain targeting focus.';
    if (score >= 0.8) return 'Threat actor recent activity. Continue monitoring.';
    if (score >= 0.5) return 'Threat actor historical activity. Archive profile.';
    return 'Threat actor inactive. Low immediate risk.';
  }

  getInfrastructureFreshnessRecommendation(daysSinceLastSeen, score) {
    if (score >= 0.9) return 'Infrastructure currently operational. High blocking priority.';
    if (score >= 0.7) return 'Infrastructure recent activity. Maintain blocking rules.';
    if (score >= 0.4) return 'Infrastructure aging. Verify status before blocking.';
    return 'Infrastructure deprecated. Remove from active blocking.';
  }

  getConfidenceImpact(freshnessScore) {
    if (freshnessScore >= 0.9) return { impact: 'positive', adjustment: 0.1, message: 'Fresh intelligence increases confidence' };
    if (freshnessScore >= 0.7) return { impact: 'neutral', adjustment: 0, message: 'Current intelligence confidence appropriate' };
    if (freshnessScore >= 0.5) return { impact: 'negative', adjustment: -0.1, message: 'Aging intelligence may reduce confidence' };
    if (freshnessScore >= 0.25) return { impact: 'negative', adjustment: -0.2, message: 'Stale intelligence significantly reduces confidence' };
    return { impact: 'negative', adjustment: -0.3, message: 'Expired intelligence should be archived' };
  }

  async evaluateInvestigationFreshness(investigationId) {
    const analysisReport = await this.redis.hgetall(`analysis:${investigationId}`);
    const technicalAssessment = await this.redis.hgetall(`technical:${investigationId}`);

    const iocs = [];
    if (technicalAssessment && technicalAssessment.length > 0) {
      for (let i = 0; i < technicalAssessment.length; i += 2) {
        if (technicalAssessment[i] === 'iocs' && technicalAssessment[i + 1]) {
          try {
            const parsedIOCs = JSON.parse(technicalAssessment[i + 1]);
            iocs.push(...parsedIOCs);
          } catch (e) {
            // Skip if not parseable
          }
        }
      }
    }

    const freshnessScores = [];
    for (const ioc of iocs) {
      const score = await this.scoreFreshness({ type: 'IOC', lastSeen: ioc.lastSeen || new Date().toISOString() });
      freshnessScores.push(score);
    }

    const avgFreshness = freshnessScores.length > 0
      ? freshnessScores.reduce((sum, s) => sum + s.freshnessScore, 0) / freshnessScores.length
      : 0.5;

    const staleness = freshnessScores.filter(s => s.status === 'stale' || s.status === 'expired').length;

    return {
      investigationId,
      evaluatedAt: new Date().toISOString(),
      iocCount: iocs.length,
      averageFreshnessScore: Math.round(avgFreshness * 100) / 100,
      staleCount: staleness,
      freshnessScores: freshnessScores.slice(0, 10),
      overallRecommendation: this.getInvestigationFreshnessRecommendation(avgFreshness, staleness),
    };
  }

  getInvestigationFreshnessRecommendation(avgFreshness, staleCount) {
    if (avgFreshness >= 0.85) return 'Investigation intelligence is current. Ready for publication.';
    if (avgFreshness >= 0.7) return 'Investigation intelligence is mostly current. Ready for publication with notes.';
    if (avgFreshness >= 0.5) return 'Investigation has aging intelligence. Consider updates before publication.';
    return `Investigation has ${staleCount} stale/expired IOCs. Update or remove before publication.`;
  }
}

module.exports = { FreshnessEngine };
