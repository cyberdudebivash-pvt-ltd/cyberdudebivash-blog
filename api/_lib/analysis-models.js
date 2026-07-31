'use strict';

const crypto = require('crypto');

const CONFIDENCE_LEVELS = {
  CONFIRMED: 'confirmed',
  LIKELY: 'likely',
  POSSIBLE: 'possible',
  UNLIKELY: 'unlikely',
  UNSUBSTANTIATED: 'unsubstantiated',
};

const CONFIDENCE_SCORES = {
  confirmed: 0.95,
  likely: 0.70,
  possible: 0.40,
  unlikely: 0.15,
  unsubstantiated: 0,
};

const FINDING_STATUS = {
  DRAFT: 'draft',
  REVIEWED: 'reviewed',
  APPROVED: 'approved',
  PUBLISHED: 'published',
};

class AnalyticalFinding {
  constructor(data = {}) {
    this.id = data.id || crypto.randomBytes(16).toString('hex');
    this.investigationId = data.investigationId;
    this.type = data.type; // situation, threat_actor, campaign, technical, executive
    this.statement = data.statement;
    this.confidence = data.confidence || CONFIDENCE_LEVELS.POSSIBLE;
    this.confidenceScore = CONFIDENCE_SCORES[this.confidence];
    this.evidence = data.evidence || [];
    this.reasoning = data.reasoning || '';
    this.assumptions = data.assumptions || [];
    this.limitations = data.limitations || [];
    this.alternativeHypotheses = data.alternativeHypotheses || [];
    this.status = data.status || FINDING_STATUS.DRAFT;
    this.createdAt = data.createdAt || new Date().toISOString();
    this.createdBy = data.createdBy || 'analyst';
    this.reviewedAt = data.reviewedAt || null;
    this.reviewedBy = data.reviewedBy || null;
    this.publishedAt = data.publishedAt || null;
    this.tags = data.tags || [];
    this.version = data.version || 1;
  }

  addEvidence(evidenceId, reliability, strength, context) {
    this.evidence.push({
      id: crypto.randomBytes(8).toString('hex'),
      evidenceId,
      reliability, // high, medium, low
      strength, // strong, moderate, weak
      context,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addAlternativeHypothesis(hypothesis, reasoning, confidence) {
    this.alternativeHypotheses.push({
      id: crypto.randomBytes(8).toString('hex'),
      hypothesis,
      reasoning,
      confidence,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addAssumption(assumption) {
    this.assumptions.push({
      id: crypto.randomBytes(8).toString('hex'),
      text: assumption,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addLimitation(limitation) {
    this.limitations.push({
      id: crypto.randomBytes(8).toString('hex'),
      text: limitation,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  isEvidenceBacked() {
    return this.evidence.length > 0;
  }

  getEvidenceStrengthScore() {
    if (this.evidence.length === 0) return 0;

    const strengthScores = { strong: 1.0, moderate: 0.6, weak: 0.3 };
    const reliabilityScores = { high: 1.0, medium: 0.6, low: 0.3 };

    let total = 0;
    for (const evid of this.evidence) {
      const strengthScore = strengthScores[evid.strength] || 0;
      const reliabilityScore = reliabilityScores[evid.reliability] || 0;
      total += strengthScore * reliabilityScore;
    }

    return Math.min(total / this.evidence.length, 1.0);
  }

  toJSON() {
    return {
      id: this.id,
      investigationId: this.investigationId,
      type: this.type,
      statement: this.statement,
      confidence: this.confidence,
      confidenceScore: this.confidenceScore,
      evidenceCount: this.evidence.length,
      evidence: this.evidence,
      reasoning: this.reasoning,
      assumptions: this.assumptions,
      limitations: this.limitations,
      alternativeHypothesesCount: this.alternativeHypotheses.length,
      alternativeHypotheses: this.alternativeHypotheses,
      status: this.status,
      createdAt: this.createdAt,
      createdBy: this.createdBy,
      reviewedAt: this.reviewedAt,
      reviewedBy: this.reviewedBy,
      publishedAt: this.publishedAt,
      tags: this.tags,
      version: this.version,
      isEvidenceBacked: this.isEvidenceBacked(),
      evidenceStrengthScore: this.getEvidenceStrengthScore(),
    };
  }
}

class SituationAssessment {
  constructor(investigationId) {
    this.investigationId = investigationId;
    this.overview = null;
    this.scope = null;
    this.affectedSectors = [];
    this.geographicContext = [];
    this.timelineEvents = [];
    this.estimatedImpact = null;
    this.createdAt = new Date().toISOString();
    this.version = 1;
  }

  setOverview(overview) {
    this.overview = overview;
    return this;
  }

  setScope(scope) {
    this.scope = scope;
    return this;
  }

  addAffectedSector(sector) {
    if (!this.affectedSectors.includes(sector)) {
      this.affectedSectors.push(sector);
    }
    return this;
  }

  addGeographicContext(location) {
    if (!this.geographicContext.includes(location)) {
      this.geographicContext.push(location);
    }
    return this;
  }

  addTimelineEvent(timestamp, event) {
    this.timelineEvents.push({
      timestamp,
      event,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  setEstimatedImpact(impact) {
    this.estimatedImpact = impact;
    return this;
  }

  toJSON() {
    return {
      investigationId: this.investigationId,
      overview: this.overview,
      scope: this.scope,
      affectedSectors: this.affectedSectors,
      geographicContext: this.geographicContext,
      timelineEvents: this.timelineEvents,
      estimatedImpact: this.estimatedImpact,
      createdAt: this.createdAt,
      version: this.version,
    };
  }
}

class ThreatActorAssessment {
  constructor(investigationId, actorId) {
    this.investigationId = investigationId;
    this.actorId = actorId;
    this.attribution = null;
    this.attributionConfidence = CONFIDENCE_LEVELS.UNSUBSTANTIATED;
    this.supportingEvidence = [];
    this.contradictoryEvidence = [];
    this.aliases = [];
    this.historicalTargets = [];
    this.attributionGaps = [];
    this.createdAt = new Date().toISOString();
    this.version = 1;
  }

  setAttribution(attribution, confidence) {
    this.attribution = attribution;
    this.attributionConfidence = confidence;
    return this;
  }

  addSupportingEvidence(evidenceId, reasoning) {
    this.supportingEvidence.push({
      id: crypto.randomBytes(8).toString('hex'),
      evidenceId,
      reasoning,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addContradictoryEvidence(evidenceId, contradiction) {
    this.contradictoryEvidence.push({
      id: crypto.randomBytes(8).toString('hex'),
      evidenceId,
      contradiction,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addAlias(alias) {
    if (!this.aliases.includes(alias)) {
      this.aliases.push(alias);
    }
    return this;
  }

  addAttributionGap(gap) {
    this.attributionGaps.push({
      id: crypto.randomBytes(8).toString('hex'),
      gap,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  toJSON() {
    return {
      investigationId: this.investigationId,
      actorId: this.actorId,
      attribution: this.attribution,
      attributionConfidence: this.attributionConfidence,
      supportingEvidenceCount: this.supportingEvidence.length,
      supportingEvidence: this.supportingEvidence,
      contradictoryEvidenceCount: this.contradictoryEvidence.length,
      contradictoryEvidence: this.contradictoryEvidence,
      aliases: this.aliases,
      historicalTargets: this.historicalTargets,
      attributionGaps: this.attributionGaps,
      createdAt: this.createdAt,
      version: this.version,
    };
  }
}

class TechnicalAssessment {
  constructor(investigationId) {
    this.investigationId = investigationId;
    this.iocs = [];
    this.malwareFindings = [];
    this.techniques = [];
    this.infrastructure = [];
    this.attackFlow = [];
    this.detectionOpportunities = [];
    this.createdAt = new Date().toISOString();
    this.version = 1;
  }

  addIOC(ioc, type, reliability, context) {
    this.iocs.push({
      id: crypto.randomBytes(8).toString('hex'),
      ioc,
      type, // hash, domain, ip, url
      reliability,
      context,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addMalwareAnalysis(malwareName, hash, analysis) {
    this.malwareFindings.push({
      id: crypto.randomBytes(8).toString('hex'),
      malwareName,
      hash,
      analysis,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addTechnique(techniqueId, techniqueDescription, evidence) {
    this.techniques.push({
      id: crypto.randomBytes(8).toString('hex'),
      techniqueId, // MITRE ID
      description: techniqueDescription,
      evidence,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addInfrastructure(hostname, ip, provider, purpose) {
    this.infrastructure.push({
      id: crypto.randomBytes(8).toString('hex'),
      hostname,
      ip,
      provider,
      purpose,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addDetectionOpportunity(opportunity, detectability, priority) {
    this.detectionOpportunities.push({
      id: crypto.randomBytes(8).toString('hex'),
      opportunity,
      detectability, // high, medium, low
      priority, // critical, high, medium, low
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  toJSON() {
    return {
      investigationId: this.investigationId,
      iocCount: this.iocs.length,
      iocs: this.iocs,
      malwareFindingsCount: this.malwareFindings.length,
      malwareFindings: this.malwareFindings,
      techniqueCount: this.techniques.length,
      techniques: this.techniques,
      infrastructureCount: this.infrastructure.length,
      infrastructure: this.infrastructure,
      detectionOpportunitiesCount: this.detectionOpportunities.length,
      detectionOpportunities: this.detectionOpportunities,
      createdAt: this.createdAt,
      version: this.version,
    };
  }
}

class ExecutiveAssessment {
  constructor(investigationId) {
    this.investigationId = investigationId;
    this.businessImpact = null;
    this.operationalImpact = null;
    this.strategicImplications = [];
    this.recommendedActions = [];
    this.priorityLevel = 'medium'; // critical, high, medium, low
    this.createdAt = new Date().toISOString();
    this.version = 1;
  }

  setBusinessImpact(impact) {
    this.businessImpact = impact;
    return this;
  }

  setOperationalImpact(impact) {
    this.operationalImpact = impact;
    return this;
  }

  addStrategicImplication(implication) {
    this.strategicImplications.push({
      id: crypto.randomBytes(8).toString('hex'),
      implication,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  addRecommendedAction(action, rationale, priority) {
    this.recommendedActions.push({
      id: crypto.randomBytes(8).toString('hex'),
      action,
      rationale,
      priority,
      addedAt: new Date().toISOString(),
    });
    return this;
  }

  setPriorityLevel(level) {
    this.priorityLevel = level;
    return this;
  }

  toJSON() {
    return {
      investigationId: this.investigationId,
      businessImpact: this.businessImpact,
      operationalImpact: this.operationalImpact,
      strategicImplications: this.strategicImplications,
      recommendedActionsCount: this.recommendedActions.length,
      recommendedActions: this.recommendedActions,
      priorityLevel: this.priorityLevel,
      createdAt: this.createdAt,
      version: this.version,
    };
  }
}

class InformationGap {
  constructor(description, category, impact) {
    this.id = crypto.randomBytes(8).toString('hex');
    this.description = description;
    this.category = category; // evidence, attribution, ioc, malware, campaign, techniques, detection
    this.impact = impact; // critical, high, medium, low
    this.collectionRecommendation = null;
    this.status = 'open'; // open, in_progress, resolved
    this.createdAt = new Date().toISOString();
  }

  setCollectionRecommendation(recommendation) {
    this.collectionRecommendation = recommendation;
    return this;
  }

  resolve() {
    this.status = 'resolved';
    return this;
  }

  toJSON() {
    return {
      id: this.id,
      description: this.description,
      category: this.category,
      impact: this.impact,
      collectionRecommendation: this.collectionRecommendation,
      status: this.status,
      createdAt: this.createdAt,
    };
  }
}

module.exports = {
  AnalyticalFinding,
  SituationAssessment,
  ThreatActorAssessment,
  TechnicalAssessment,
  ExecutiveAssessment,
  InformationGap,
  CONFIDENCE_LEVELS,
  CONFIDENCE_SCORES,
  FINDING_STATUS,
};
