'use strict';

const { GoldStandardEIPCCertificationEngine } = require('./gs-eipc-certification-engine');
const { CertificationMetricsTracker } = require('./certification-metrics-tracker');

class GoldStandardPublicationGate {
  constructor() {
    this.certificationEngine = new GoldStandardEIPCCertificationEngine();
    this.metricsTracker = new CertificationMetricsTracker();
    this.publicationLog = [];
    this.blockedProducts = [];
  }

  async evaluateProductForPublication(product, investigation, report) {
    const evaluation = {
      productId: product.id,
      productType: product.productType,
      timestamp: new Date().toISOString(),
      certified: false,
      approved: false,
      certification: null,
      gateResults: [],
      blockers: [],
      warnings: [],
      recommendations: [],
    };

    // Step 1: Run Gold Standard Certification
    const certification = await this.certificationEngine.certifyProduct(product, investigation, report);
    evaluation.certification = this.certificationEngine.generateScorecard(certification);

    // Record in metrics tracker
    this.metricsTracker.recordCertification(certification);

    // Step 2: Check certification status
    const certificationGate = this.validateCertificationStatus(certification);
    evaluation.gateResults.push(certificationGate);

    if (!certificationGate.passed) {
      evaluation.blockers.push(certificationGate.issue);
    }

    // Step 3: Validate evidence integrity
    const evidenceGate = this.validateEvidenceIntegrity(product, investigation);
    evaluation.gateResults.push(evidenceGate);

    if (!evidenceGate.passed) {
      evaluation.blockers.push(evidenceGate.issue);
    }

    // Step 4: Validate confidence preservation
    const confidenceGate = this.validateConfidencePreservation(product, investigation);
    evaluation.gateResults.push(confidenceGate);

    if (!confidenceGate.passed) {
      evaluation.blockers.push(confidenceGate.issue);
    }

    // Step 5: Validate analytical rigor
    const analyticalGate = this.validateAnalyticalRigor(product, investigation);
    evaluation.gateResults.push(analyticalGate);

    if (!analyticalGate.passed) {
      evaluation.blockers.push(analyticalGate.issue);
    } else if (analyticalGate.warning) {
      evaluation.warnings.push(analyticalGate.warning);
    }

    // Step 6: Validate commercial readiness
    const commercialGate = this.validateCommercialReadiness(product, investigation);
    evaluation.gateResults.push(commercialGate);

    if (!commercialGate.passed) {
      evaluation.blockers.push(commercialGate.issue);
    } else if (commercialGate.warning) {
      evaluation.warnings.push(commercialGate.warning);
    }

    // Determine overall publication approval
    evaluation.approved = evaluation.blockers.length === 0;
    evaluation.certified = certification.certificationStatus === 'GOLD' || certification.certificationStatus === 'SILVER';

    // Generate recommendations for improvement
    if (!evaluation.approved) {
      evaluation.recommendations = this.generatePublicationRecommendations(evaluation, certification);
      this.blockedProducts.push({
        productId: product.id,
        timestamp: evaluation.timestamp,
        blockers: evaluation.blockers,
      });
    } else {
      this.publicationLog.push({
        productId: product.id,
        timestamp: evaluation.timestamp,
        certificationStatus: evaluation.certification.overallCertification,
      });
    }

    return evaluation;
  }

  validateCertificationStatus(certification) {
    const status = certification.certificationStatus;
    const approved = status === 'GOLD' || status === 'SILVER';

    return {
      gate: 'gold-standard-certification',
      passed: approved,
      issue: approved ? null : `Certification status ${status} below publication threshold (requires GOLD or SILVER)`,
      details: {
        status,
        overallScore: certification.overallScore,
        passedCategories: certification.passedCategories,
        failedCategories: certification.failedCategories,
      },
    };
  }

  validateEvidenceIntegrity(product, investigation) {
    const findings = investigation.findings || [];
    const iocs = investigation.iocs || [];
    const infrastructure = investigation.infrastructure || [];

    const hasEvidence = findings.length > 0 || iocs.length > 0 || infrastructure.length > 0;
    const evidenceCount = findings.length + iocs.length + infrastructure.length;

    return {
      gate: 'evidence-integrity',
      passed: hasEvidence && evidenceCount >= 3,
      issue: !hasEvidence ? 'No evidence found in investigation' :
             evidenceCount < 3 ? `Insufficient evidence (${evidenceCount} items, minimum 3 required)` : null,
      details: {
        findings: findings.length,
        iocs: iocs.length,
        infrastructure: infrastructure.length,
        total: evidenceCount,
      },
    };
  }

  validateConfidencePreservation(product, investigation) {
    const confidence = investigation.confidence || 0;
    const confidenceReasoning = investigation.confidenceReasoning;

    const validated = confidence > 0 && confidence <= 1 && !!confidenceReasoning;

    return {
      gate: 'confidence-preservation',
      passed: validated === true ? true : false,
      issue: validated ? null : 'Confidence level not properly documented or out of valid range (0-1)',
      details: {
        confidence: Math.round(confidence * 100) + '%',
        reasoningPresent: !!confidenceReasoning,
        reasoning: confidenceReasoning ? confidenceReasoning.substring(0, 100) + '...' : 'None',
      },
    };
  }

  validateAnalyticalRigor(product, investigation) {
    const modules = product.modules || {};
    const hasKeyElements = {
      evidence: !!modules.evidence,
      narrative: !!modules.narratives,
      assumptions: !!modules.assumptions || !!investigation.assumptionsDocumented,
      alternatives: !!modules.alternativeHypotheses,
      confidence: !!investigation.confidenceReasoning,
    };

    const rigorScore = Object.values(hasKeyElements).filter(v => v).length;
    const passed = rigorScore >= 3;

    return {
      gate: 'analytical-rigor',
      passed,
      warning: rigorScore >= 3 && rigorScore < 5 ? `Analytical rigor could be improved (${rigorScore}/5 elements present)` : null,
      issue: rigorScore < 3 ? `Insufficient analytical rigor (${rigorScore}/5 required elements present)` : null,
      details: hasKeyElements,
    };
  }

  validateCommercialReadiness(product, investigation) {
    const modules = product.modules || {};
    const hasCommercialElements = {
      executiveSummary: !!modules.executiveSummary,
      recommendations: !!modules.recommendations,
      actions: !!modules.immediateActions,
      detection: !!modules.detectionRules,
      completeness: Object.keys(modules).length >= 6,
    };

    const readinessScore = Object.values(hasCommercialElements).filter(v => v).length;
    const passed = readinessScore >= 3;

    return {
      gate: 'commercial-readiness',
      passed,
      warning: readinessScore >= 3 && readinessScore < 5 ? `Commercial readiness could be improved (${readinessScore}/5 elements present)` : null,
      issue: readinessScore < 3 ? `Insufficient commercial readiness (${readinessScore}/5 required elements present)` : null,
      details: hasCommercialElements,
    };
  }

  generatePublicationRecommendations(evaluation, certification) {
    const recommendations = [];

    // Add recommendations from certification failures
    for (const failedCategory of Object.entries(certification.categories)) {
      const [categoryName, categoryData] = failedCategory;
      if (!categoryData.passed) {
        recommendations.push({
          category: this.humanizeCategory(categoryName),
          findings: categoryData.findings.slice(0, 2),
          priority: categoryData.score < 70 ? 'Critical' : 'High',
        });
      }
    }

    // Add recommendations from gate failures
    for (const blocker of evaluation.blockers) {
      if (blocker.includes('Certification status')) {
        recommendations.push({
          gate: 'Certification Status',
          recommendation: 'Improve scores in failed certification categories',
          priority: 'Critical',
        });
      } else if (blocker.includes('evidence')) {
        recommendations.push({
          gate: 'Evidence Integrity',
          recommendation: 'Extract and validate additional IOCs and findings',
          priority: 'High',
        });
      } else if (blocker.includes('Confidence')) {
        recommendations.push({
          gate: 'Confidence',
          recommendation: 'Document confidence reasoning and adjust confidence levels',
          priority: 'High',
        });
      }
    }

    return recommendations;
  }

  humanizeCategory(categoryName) {
    const humanized = {
      executiveIntelligence: 'Executive Intelligence',
      technicalIntelligence: 'Technical Intelligence',
      analyticalTradecraft: 'Analytical Tradecraft',
      campaignIntelligence: 'Campaign Intelligence',
      intelligenceCorrelation: 'Intelligence Correlation',
      originalAnalyticalValue: 'Original Analytical Value',
      detectionEngineering: 'Detection Engineering',
      multiAudienceDecisionSupport: 'Multi-Audience Decision Support',
      editorialExcellence: 'Editorial Excellence',
      commercialProductExcellence: 'Commercial Product Excellence',
    };
    return humanized[categoryName] || categoryName;
  }

  getPublicationMetrics() {
    return {
      publishedProducts: this.publicationLog.length,
      blockedProducts: this.blockedProducts.length,
      publishingRate: this.publicationLog.length + this.blockedProducts.length > 0
        ? Math.round((this.publicationLog.length / (this.publicationLog.length + this.blockedProducts.length)) * 100)
        : 0,
      recentPublications: this.publicationLog.slice(-10),
      recentBlockages: this.blockedProducts.slice(-10),
    };
  }

  getGateMetrics() {
    return {
      metricsSnapshot: this.metricsTracker.getAggregateMetrics(),
      publishingGateStatus: this.metricsTracker.getPublishingGateStatus(),
      regressionReport: this.metricsTracker.getRegressionReport(),
      improvementReport: this.metricsTracker.getImprovementReport(),
      executiveSummary: this.metricsTracker.generateExecutiveSummary(),
    };
  }
}

module.exports = { GoldStandardPublicationGate };
