'use strict';

const redis = require('./redis');
const crypto = require('crypto');
const { EvidenceValidator } = require('./evidence-validator');
const { ConfidenceScorer } = require('./confidence-scorer');
const { GapAnalyzer } = require('./gap-analyzer');
const {
  AnalyticalFinding,
  SituationAssessment,
  ThreatActorAssessment,
  TechnicalAssessment,
  ExecutiveAssessment,
  InformationGap,
  CONFIDENCE_LEVELS,
  FINDING_STATUS,
} = require('./analysis-models');

class AnalysisManager {
  constructor(redisClient = redis) {
    this.redis = redisClient;
    this.validator = new EvidenceValidator(redisClient);
    this.scorer = new ConfidenceScorer(redisClient);
    this.gapAnalyzer = new GapAnalyzer(redisClient);
  }

  async createAnalyticalFinding(investigationId, data) {
    const finding = new AnalyticalFinding({
      ...data,
      investigationId,
    });

    const validation = await this.validator.validateFinding(finding);
    if (!validation.isValid) {
      return {
        success: false,
        finding: null,
        validation,
        error: 'Finding validation failed',
      };
    }

    const scoring = await this.scorer.scoreFinding(finding);

    const key = `finding:${finding.id}`;
    const findingData = {
      ...finding.toJSON(),
      confidenceScore: scoring.confidenceScore,
      confidenceFactors: JSON.stringify(scoring.factors),
    };

    await this.redis.hset(key, Object.entries(findingData).flat());
    await this.redis.zadd(`findings:investigation:${investigationId}`, Date.now(), finding.id);
    await this.redis.zadd('findings:all', Date.now(), finding.id);

    return {
      success: true,
      finding: finding.toJSON(),
      validation,
      scoring,
    };
  }

  async reviewFinding(findingId, reviewerName, approved, feedback = '') {
    const key = `finding:${findingId}`;
    const finding = await this.redis.hgetall(key);

    if (!finding || finding.length === 0) {
      return { success: false, error: `Finding not found: ${findingId}` };
    }

    const updatedFinding = {};
    for (let i = 0; i < finding.length; i += 2) {
      updatedFinding[finding[i]] = finding[i + 1];
    }

    updatedFinding.status = approved ? FINDING_STATUS.APPROVED : FINDING_STATUS.REVIEWED;
    updatedFinding.reviewedAt = new Date().toISOString();
    updatedFinding.reviewedBy = reviewerName;
    updatedFinding.reviewFeedback = feedback;
    updatedFinding.version = (parseInt(updatedFinding.version) || 1) + 1;

    await this.redis.hset(key, Object.entries(updatedFinding).flat());

    return {
      success: true,
      finding: updatedFinding,
      reviewedAt: updatedFinding.reviewedAt,
      reviewedBy: reviewerName,
    };
  }

  async publishFinding(findingId, publisherName) {
    const key = `finding:${findingId}`;
    const finding = await this.redis.hgetall(key);

    if (!finding || finding.length === 0) {
      return { success: false, error: `Finding not found: ${findingId}` };
    }

    const updatedFinding = {};
    for (let i = 0; i < finding.length; i += 2) {
      updatedFinding[finding[i]] = finding[i + 1];
    }

    if (updatedFinding.status !== FINDING_STATUS.APPROVED) {
      return {
        success: false,
        error: 'Finding must be approved before publishing',
      };
    }

    updatedFinding.status = FINDING_STATUS.PUBLISHED;
    updatedFinding.publishedAt = new Date().toISOString();
    updatedFinding.publishedBy = publisherName;

    await this.redis.hset(key, Object.entries(updatedFinding).flat());
    await this.redis.zadd('findings:published', Date.now(), findingId);

    return {
      success: true,
      finding: updatedFinding,
      publishedAt: updatedFinding.publishedAt,
      publishedBy: publisherName,
    };
  }

  async createSituationAssessment(investigationId, data) {
    const assessment = new SituationAssessment(investigationId);

    if (data.overview) assessment.setOverview(data.overview);
    if (data.scope) assessment.setScope(data.scope);
    if (data.affectedSectors) {
      for (const sector of data.affectedSectors) {
        assessment.addAffectedSector(sector);
      }
    }
    if (data.geographicContext) {
      for (const location of data.geographicContext) {
        assessment.addGeographicContext(location);
      }
    }
    if (data.estimatedImpact) assessment.setEstimatedImpact(data.estimatedImpact);
    if (data.timelineEvents) {
      for (const event of data.timelineEvents) {
        assessment.addTimelineEvent(event.timestamp, event.event);
      }
    }

    const validation = await this.validator.validateSituationAssessment(assessment);
    if (!validation.isValid) {
      return {
        success: false,
        assessment: null,
        validation,
        error: 'Situation assessment validation failed',
      };
    }

    const key = `situation:${investigationId}`;
    await this.redis.hset(key, Object.entries(assessment.toJSON()).flat());
    await this.redis.zadd('assessments:situations', Date.now(), investigationId);

    return {
      success: true,
      assessment: assessment.toJSON(),
      validation,
    };
  }

  async createThreatActorAssessment(investigationId, actorId, data) {
    const assessment = new ThreatActorAssessment(investigationId, actorId);

    if (data.attribution && data.attributionConfidence) {
      assessment.setAttribution(data.attribution, data.attributionConfidence);
    }

    if (data.supportingEvidence) {
      for (const evidence of data.supportingEvidence) {
        assessment.addSupportingEvidence(evidence.evidenceId, evidence.reasoning);
      }
    }

    if (data.contradictoryEvidence) {
      for (const evidence of data.contradictoryEvidence) {
        assessment.addContradictoryEvidence(evidence.evidenceId, evidence.contradiction);
      }
    }

    if (data.aliases) {
      for (const alias of data.aliases) {
        assessment.addAlias(alias);
      }
    }

    if (data.attributionGaps) {
      for (const gap of data.attributionGaps) {
        assessment.addAttributionGap(gap);
      }
    }

    const validation = await this.validator.validateThreatActorAssessment(assessment);
    if (!validation.isValid) {
      return {
        success: false,
        assessment: null,
        validation,
        error: 'Threat actor assessment validation failed',
      };
    }

    const key = `actor:${actorId}`;
    await this.redis.hset(key, Object.entries(assessment.toJSON()).flat());
    await this.redis.zadd(`assessments:actors:${investigationId}`, Date.now(), actorId);

    return {
      success: true,
      assessment: assessment.toJSON(),
      validation,
    };
  }

  async createTechnicalAssessment(investigationId, data) {
    const assessment = new TechnicalAssessment(investigationId);

    if (data.iocs) {
      for (const ioc of data.iocs) {
        assessment.addIOC(ioc.ioc, ioc.type, ioc.reliability, ioc.context);
      }
    }

    if (data.malwareFindings) {
      for (const malware of data.malwareFindings) {
        assessment.addMalwareAnalysis(malware.malwareName, malware.hash, malware.analysis);
      }
    }

    if (data.techniques) {
      for (const technique of data.techniques) {
        assessment.addTechnique(technique.techniqueId, technique.description, technique.evidence);
      }
    }

    if (data.infrastructure) {
      for (const infra of data.infrastructure) {
        assessment.addInfrastructure(infra.hostname, infra.ip, infra.provider, infra.purpose);
      }
    }

    if (data.detectionOpportunities) {
      for (const opportunity of data.detectionOpportunities) {
        assessment.addDetectionOpportunity(opportunity.opportunity, opportunity.detectability, opportunity.priority);
      }
    }

    const validation = await this.validator.validateTechnicalAssessment(assessment);
    if (!validation.isValid) {
      return {
        success: false,
        assessment: null,
        validation,
        error: 'Technical assessment validation failed',
      };
    }

    const key = `technical:${investigationId}`;
    await this.redis.hset(key, Object.entries(assessment.toJSON()).flat());
    await this.redis.zadd('assessments:technical', Date.now(), investigationId);

    return {
      success: true,
      assessment: assessment.toJSON(),
      validation,
    };
  }

  async createExecutiveAssessment(investigationId, data) {
    const assessment = new ExecutiveAssessment(investigationId);

    if (data.businessImpact) assessment.setBusinessImpact(data.businessImpact);
    if (data.operationalImpact) assessment.setOperationalImpact(data.operationalImpact);
    if (data.priorityLevel) assessment.setPriorityLevel(data.priorityLevel);

    if (data.strategicImplications) {
      for (const implication of data.strategicImplications) {
        assessment.addStrategicImplication(implication);
      }
    }

    if (data.recommendedActions) {
      for (const action of data.recommendedActions) {
        assessment.addRecommendedAction(action.action, action.rationale, action.priority);
      }
    }

    const validation = await this.validator.validateExecutiveAssessment(assessment);
    if (!validation.isValid) {
      return {
        success: false,
        assessment: null,
        validation,
        error: 'Executive assessment validation failed',
      };
    }

    const key = `executive:${investigationId}`;
    await this.redis.hset(key, Object.entries(assessment.toJSON()).flat());
    await this.redis.zadd('assessments:executive', Date.now(), investigationId);

    return {
      success: true,
      assessment: assessment.toJSON(),
      validation,
    };
  }

  async generateInformationGaps(investigationId, investigation) {
    const gapAnalysis = await this.gapAnalyzer.analyzeInvestigationGaps(investigation);

    const gaps = [];
    for (const gapData of gapAnalysis.gaps) {
      const gap = new InformationGap(gapData.description, gapData.category, gapData.priority);
      gap.setCollectionRecommendation(gapData.collectingRecommendation);

      const key = `gap:${gap.id}`;
      await this.redis.hset(key, Object.entries(gap.toJSON()).flat());
      await this.redis.zadd(`gaps:investigation:${investigationId}`, Date.now(), gap.id);

      gaps.push(gap.toJSON());
    }

    return {
      investigationId,
      totalGaps: gaps.length,
      gaps,
      collectionPlan: this.gapAnalyzer.getGapCollectionPlan(gapAnalysis.gaps, investigationId),
    };
  }

  async getFinding(findingId) {
    const key = `finding:${findingId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return null;
    }

    const finding = {};
    for (let i = 0; i < data.length; i += 2) {
      finding[data[i]] = data[i + 1];
    }

    return finding;
  }

  async getInvestigationFindings(investigationId, limit = 50) {
    const findingIds = await this.redis.zrevrange(`findings:investigation:${investigationId}`, 0, limit - 1);
    const findings = [];

    for (const findingId of findingIds) {
      const finding = await this.getFinding(findingId);
      if (finding) findings.push(finding);
    }

    return findings;
  }

  async getAnalysisReport(investigationId) {
    const findings = await this.getInvestigationFindings(investigationId, 100);

    const situationKey = `situation:${investigationId}`;
    const situationData = await this.redis.hgetall(situationKey);
    const situation = {};
    for (let i = 0; i < (situationData?.length || 0); i += 2) {
      situation[situationData[i]] = situationData[i + 1];
    }

    const technicalKey = `technical:${investigationId}`;
    const technicalData = await this.redis.hgetall(technicalKey);
    const technical = {};
    for (let i = 0; i < (technicalData?.length || 0); i += 2) {
      technical[technicalData[i]] = technicalData[i + 1];
    }

    const executiveKey = `executive:${investigationId}`;
    const executiveData = await this.redis.hgetall(executiveKey);
    const executive = {};
    for (let i = 0; i < (executiveData?.length || 0); i += 2) {
      executive[executiveData[i]] = executiveData[i + 1];
    }

    const gapIds = await this.redis.zrevrange(`gaps:investigation:${investigationId}`, 0, 99);
    const gaps = [];
    for (const gapId of gapIds) {
      const gapKey = `gap:${gapId}`;
      const gapData = await this.redis.hgetall(gapKey);
      const gap = {};
      for (let i = 0; i < (gapData?.length || 0); i += 2) {
        gap[gapData[i]] = gapData[i + 1];
      }
      gaps.push(gap);
    }

    return {
      investigationId,
      reportGeneratedAt: new Date().toISOString(),
      findings: {
        total: findings.length,
        draft: findings.filter(f => f.status === FINDING_STATUS.DRAFT).length,
        reviewed: findings.filter(f => f.status === FINDING_STATUS.REVIEWED).length,
        approved: findings.filter(f => f.status === FINDING_STATUS.APPROVED).length,
        published: findings.filter(f => f.status === FINDING_STATUS.PUBLISHED).length,
        items: findings,
      },
      assessments: {
        situation: Object.keys(situation).length > 0 ? situation : null,
        technical: Object.keys(technical).length > 0 ? technical : null,
        executive: Object.keys(executive).length > 0 ? executive : null,
      },
      gaps: {
        total: gaps.length,
        items: gaps,
      },
      completeness: this.calculateAnalysisCompleteness(findings, situation, technical, executive, gaps),
    };
  }

  calculateAnalysisCompleteness(findings, situation, technical, executive, gaps) {
    let score = 0;

    if (Object.keys(findings).length > 0 && findings.length > 0) score += 25;
    if (Object.keys(situation).length > 10) score += 20;
    if (Object.keys(technical).length > 10) score += 20;
    if (Object.keys(executive).length > 10) score += 20;
    if (gaps.length > 0) score += 15;

    return {
      score: Math.min(score, 100),
      hasFinding: findings.length > 0,
      hasSituation: Object.keys(situation).length > 0,
      hasTechnical: Object.keys(technical).length > 0,
      hasExecutive: Object.keys(executive).length > 0,
      hasGaps: gaps.length > 0,
    };
  }
}

module.exports = { AnalysisManager };
