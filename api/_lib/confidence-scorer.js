'use strict';

const redis = require('./redis');

class ConfidenceScorer {
  constructor(redisClient = redis) {
    this.redis = redisClient;
    this.confidenceMap = {
      confirmed: 0.95,
      likely: 0.70,
      possible: 0.40,
      unlikely: 0.15,
      unsubstantiated: 0,
    };
  }

  calculateFindingConfidence(evidence, reasoning) {
    if (!evidence || evidence.length === 0) {
      return { level: 'unsubstantiated', score: 0, factors: [] };
    }

    const factors = [];

    const evidenceQuality = this.calculateEvidenceQuality(evidence);
    factors.push({
      name: 'evidence_quality',
      weight: 0.5,
      score: evidenceQuality.score,
      detail: evidenceQuality.detail,
    });

    const evidenceQuantity = this.calculateEvidenceQuantity(evidence);
    factors.push({
      name: 'evidence_quantity',
      weight: 0.2,
      score: evidenceQuantity.score,
      detail: evidenceQuantity.detail,
    });

    const reasoningQuality = this.calculateReasoningQuality(reasoning, evidence);
    factors.push({
      name: 'reasoning_quality',
      weight: 0.2,
      score: reasoningQuality.score,
      detail: reasoningQuality.detail,
    });

    const corroboration = this.calculateCorroboration(evidence);
    factors.push({
      name: 'corroboration',
      weight: 0.1,
      score: corroboration.score,
      detail: corroboration.detail,
    });

    const totalScore = factors.reduce((sum, f) => sum + (f.score * f.weight), 0);

    let level = 'unsubstantiated';
    if (totalScore >= 0.92) level = 'confirmed';
    else if (totalScore >= 0.65) level = 'likely';
    else if (totalScore >= 0.35) level = 'possible';
    else if (totalScore >= 0.10) level = 'unlikely';

    return {
      level,
      score: Math.round(totalScore * 100) / 100,
      numericScore: this.confidenceMap[level],
      factors,
      recommendation: this.getConfidenceRecommendation(level, totalScore, factors),
    };
  }

  calculateEvidenceQuality(evidence) {
    const reliabilityScores = { high: 1.0, medium: 0.6, low: 0.3 };
    const strengthScores = { strong: 1.0, moderate: 0.6, weak: 0.3 };

    let totalQuality = 0;
    for (const evid of evidence) {
      const reliability = reliabilityScores[evid.reliability] || 0;
      const strength = strengthScores[evid.strength] || 0;
      totalQuality += (reliability * 0.6 + strength * 0.4);
    }

    const avgQuality = evidence.length > 0 ? totalQuality / evidence.length : 0;

    return {
      score: avgQuality,
      detail: {
        highReliabilityCount: evidence.filter(e => e.reliability === 'high').length,
        strongStrengthCount: evidence.filter(e => e.strength === 'strong').length,
        totalEvidenceCount: evidence.length,
        avgReliability: this.calculateAvgReliability(evidence),
        avgStrength: this.calculateAvgStrength(evidence),
      },
    };
  }

  calculateEvidenceQuantity(evidence) {
    let quantityScore = 0;
    if (evidence.length >= 5) quantityScore = 1.0;
    else if (evidence.length >= 3) quantityScore = 0.8;
    else if (evidence.length >= 2) quantityScore = 0.6;
    else if (evidence.length >= 1) quantityScore = 0.4;

    return {
      score: quantityScore,
      detail: {
        evidenceCount: evidence.length,
        threshold: evidence.length >= 3 ? 'sufficient' : 'minimal',
      },
    };
  }

  calculateReasoningQuality(reasoning, evidence) {
    if (!reasoning || reasoning.trim().length === 0) {
      return { score: 0, detail: { hasReasoning: false, reasoning: '' } };
    }

    const wordCount = reasoning.split(/\s+/).length;
    let qualityScore = 0;

    if (wordCount >= 100) qualityScore = 1.0;
    else if (wordCount >= 50) qualityScore = 0.8;
    else if (wordCount >= 20) qualityScore = 0.6;
    else qualityScore = 0.4;

    const mentionsEvidence = evidence.some(e => reasoning.toLowerCase().includes((e.evidenceId || '').slice(0, 10)));

    if (mentionsEvidence) qualityScore = Math.min(qualityScore * 1.1, 1.0);

    return {
      score: qualityScore,
      detail: {
        hasReasoning: true,
        wordCount,
        mentionsEvidence,
        lengthQuality: wordCount >= 100 ? 'comprehensive' : wordCount >= 50 ? 'detailed' : 'brief',
      },
    };
  }

  calculateCorroboration(evidence) {
    if (evidence.length < 2) {
      return {
        score: evidence.length === 1 ? 0.5 : 0,
        detail: { independentSources: evidence.length, corroborationLevel: 'none' },
      };
    }

    const sourceTypes = new Set();
    for (const evid of evidence) {
      if (evid.evidenceId) {
        const source = evid.evidenceId.split(':')[0];
        sourceTypes.add(source);
      }
    }

    let corroborationScore = 0;
    if (sourceTypes.size >= 3) corroborationScore = 1.0;
    else if (sourceTypes.size === 2) corroborationScore = 0.8;
    else corroborationScore = 0.4;

    return {
      score: corroborationScore,
      detail: {
        independentSources: sourceTypes.size,
        sourceTypes: Array.from(sourceTypes),
        corroborationLevel: sourceTypes.size >= 3 ? 'strong' : sourceTypes.size === 2 ? 'moderate' : 'weak',
      },
    };
  }

  calculateAvgReliability(evidence) {
    const reliabilityScores = { high: 1.0, medium: 0.6, low: 0.3 };
    const total = evidence.reduce((sum, e) => sum + (reliabilityScores[e.reliability] || 0), 0);
    return evidence.length > 0 ? Math.round((total / evidence.length) * 100) / 100 : 0;
  }

  calculateAvgStrength(evidence) {
    const strengthScores = { strong: 1.0, moderate: 0.6, weak: 0.3 };
    const total = evidence.reduce((sum, e) => sum + (strengthScores[e.strength] || 0), 0);
    return evidence.length > 0 ? Math.round((total / evidence.length) * 100) / 100 : 0;
  }

  getConfidenceRecommendation(level, score, factors) {
    const recs = [];

    const qualityFactor = factors.find(f => f.name === 'evidence_quality');
    if (qualityFactor && qualityFactor.score < 0.6) {
      recs.push('Improve evidence quality by including higher-reliability sources');
    }

    const quantityFactor = factors.find(f => f.name === 'evidence_quantity');
    if (quantityFactor && quantityFactor.score < 0.7) {
      recs.push('Gather additional evidence to strengthen confidence level');
    }

    const reasoningFactor = factors.find(f => f.name === 'reasoning_quality');
    if (reasoningFactor && reasoningFactor.score < 0.6) {
      recs.push('Provide more detailed reasoning connecting evidence to conclusion');
    }

    const corroborationFactor = factors.find(f => f.name === 'corroboration');
    if (corroborationFactor && corroborationFactor.score < 0.6) {
      recs.push('Corroborate findings with evidence from independent sources');
    }

    if (level === 'unsubstantiated') {
      recs.push('This finding lacks supporting evidence and cannot be published. Gather evidence before finalizing.');
    }

    if (level === 'unlikely') {
      recs.push('Evidence quality is low. Consider marked as a hypothesis rather than a finding.');
    }

    return recs.length > 0 ? recs : ['Confidence level is appropriate for current evidence quality.'];
  }

  async scoreFinding(finding) {
    const confidence = this.calculateFindingConfidence(finding.evidence, finding.reasoning);

    return {
      findingId: finding.id,
      statement: finding.statement,
      confidenceLevel: confidence.level,
      confidenceScore: confidence.score,
      numericScore: confidence.numericScore,
      factors: confidence.factors,
      recommendations: confidence.recommendation,
      timestamp: new Date().toISOString(),
    };
  }

  async scoreAssessment(assessment, assessmentType) {
    if (assessmentType === 'threat_actor') {
      return this.scoreThreatActorAssessment(assessment);
    } else if (assessmentType === 'technical') {
      return this.scoreTechnicalAssessment(assessment);
    } else if (assessmentType === 'executive') {
      return this.scoreExecutiveAssessment(assessment);
    }

    return { error: 'Unknown assessment type' };
  }

  scoreThreatActorAssessment(assessment) {
    const confidence = this.calculateFindingConfidence(assessment.supportingEvidence || [], assessment.attribution || '');

    return {
      assessmentId: assessment.actorId,
      attribution: assessment.attribution,
      attributionConfidence: assessment.attributionConfidence,
      calculatedConfidence: confidence,
      supportingEvidenceCount: (assessment.supportingEvidence || []).length,
      contradictoryEvidenceCount: (assessment.contradictoryEvidence || []).length,
      attributionGaps: assessment.attributionGaps || [],
      timestamp: new Date().toISOString(),
    };
  }

  scoreTechnicalAssessment(assessment) {
    const techniqueConfidence = this.calculateTechniqueConfidence(assessment.techniques || []);

    return {
      assessmentId: assessment.investigationId,
      iocCount: (assessment.iocs || []).length,
      techniqueCount: (assessment.techniques || []).length,
      techniqueConfidence,
      infrastructureCount: (assessment.infrastructure || []).length,
      detectionOpportunitiesCount: (assessment.detectionOpportunities || []).length,
      timestamp: new Date().toISOString(),
    };
  }

  calculateTechniqueConfidence(techniques) {
    if (!techniques || techniques.length === 0) return { level: 'unsubstantiated', score: 0 };

    const avgEvidenceQuality = techniques.reduce((sum, t) => {
      const quality = (t.evidence && t.evidence.length > 0) ? 0.8 : 0.2;
      return sum + quality;
    }, 0) / techniques.length;

    let level = 'unsubstantiated';
    if (avgEvidenceQuality >= 0.8) level = 'likely';
    else if (avgEvidenceQuality >= 0.5) level = 'possible';

    return {
      level,
      score: avgEvidenceQuality,
      techniqueCount: techniques.length,
      techniquesCoverage: techniques.map(t => t.techniqueId).join(', '),
    };
  }

  scoreExecutiveAssessment(assessment) {
    const actionScores = (assessment.recommendedActions || []).map(action => ({
      action: action.action,
      priority: action.priority,
      rationale: action.rationale,
      actionability: this.calculateActionability(action),
    }));

    return {
      assessmentId: assessment.investigationId,
      businessImpact: assessment.businessImpact,
      operationalImpact: assessment.operationalImpact,
      priorityLevel: assessment.priorityLevel,
      recommendedActionsCount: actionScores.length,
      recommendedActions: actionScores,
      avgActionability: actionScores.reduce((sum, a) => sum + a.actionability, 0) / (actionScores.length || 1),
      timestamp: new Date().toISOString(),
    };
  }

  calculateActionability(action) {
    const hasRationale = action.rationale && action.rationale.trim().length > 20;
    const hasTimeline = /day|hour|week|month|immediate|urgent/i.test(action.rationale || '');
    const hasMeasurable = /reduce|prevent|detect|block|contain|isolate/i.test(action.action || '');

    let score = 0;
    if (hasRationale) score += 0.4;
    if (hasTimeline) score += 0.3;
    if (hasMeasurable) score += 0.3;

    return Math.round(score * 100) / 100;
  }
}

module.exports = { ConfidenceScorer };
