'use strict';

class QualityGatesEngine {
  validateProductForPublication(product, investigation, report) {
    const gates = [];

    gates.push(this.validateEvidenceExists(product, investigation));
    gates.push(this.validateConfidenceCalculated(product, investigation));
    gates.push(this.validateMITREMapping(product, investigation));
    gates.push(this.validateIOCsValidated(product, investigation));
    gates.push(this.validateRecommendationsGenerated(product, investigation));
    gates.push(this.validateDetectionContentGenerated(product, investigation));
    gates.push(this.validateExecutiveSummaryGenerated(product, investigation));
    gates.push(this.validateQualityScoreThreshold(product, investigation));

    const allPassed = gates.every(gate => gate.passed);
    const qualityScore = this.calculateQualityScore(gates);

    return {
      approvedForPublication: allPassed,
      qualityScore: qualityScore,
      gatesResult: gates,
      publishingReady: allPassed && qualityScore >= 0.8,
      reviewRequired: !allPassed || qualityScore < 0.8,
      blockers: gates.filter(g => !g.passed).map(g => g.issue),
      warnings: gates.filter(g => g.warning).map(g => g.warning),
      validatedAt: new Date().toISOString(),
    };
  }

  validateEvidenceExists(product, investigation) {
    const findings = investigation.findings || [];
    const iocs = investigation.iocs || [];
    const infrastructure = investigation.infrastructure || [];

    const hasEvidence = findings.length > 0 || iocs.length > 0 || infrastructure.length > 0;

    return {
      gate: 'evidence-exists',
      passed: hasEvidence,
      issue: hasEvidence ? null : 'No evidence found in investigation',
      details: {
        findings: findings.length,
        iocs: iocs.length,
        infrastructure: infrastructure.length,
        total: findings.length + iocs.length + infrastructure.length,
      },
    };
  }

  validateConfidenceCalculated(product, investigation) {
    const confidence = investigation.confidence || 0;
    const hasConfidence = confidence > 0 && investigation.confidenceReasoning;

    return {
      gate: 'confidence-calculated',
      passed: hasConfidence,
      issue: hasConfidence ? null : 'Confidence level not calculated or documented',
      details: {
        confidence: parseFloat((confidence * 100).toFixed(0)) + '%',
        reasoning: investigation.confidenceReasoning || 'Not provided',
      },
    };
  }

  validateMITREMapping(product, investigation) {
    const techniques = investigation.mitreTechniques || [];
    const hasTechniques = techniques.length > 0;

    return {
      gate: 'mitre-mapping',
      passed: hasTechniques,
      issue: hasTechniques ? null : 'No MITRE techniques mapped',
      warning: techniques.length > 0 && techniques.length < 3 ? 'Limited MITRE coverage' : null,
      details: {
        techniquesCount: techniques.length,
        tactics: [...new Set(techniques.map(t => t.tactic).filter(Boolean))].length,
      },
    };
  }

  validateIOCsValidated(product, investigation) {
    const iocs = investigation.iocs || [];
    const validatedIOCs = iocs.filter(i => i.validated || i.validation);

    const validationRate = iocs.length > 0 ? validatedIOCs.length / iocs.length : 1;
    const passed = validationRate >= 0.8;

    return {
      gate: 'iocs-validated',
      passed: passed,
      issue: passed ? null : `Only ${Math.floor(validationRate * 100)}% of IOCs validated (minimum 80%)`,
      details: {
        totalIOCs: iocs.length,
        validatedIOCs: validatedIOCs.length,
        validationRate: parseFloat((validationRate * 100).toFixed(1)) + '%',
      },
    };
  }

  validateRecommendationsGenerated(product, investigation) {
    const modules = product.modules || {};
    const hasRecommendations = modules.recommendations || modules.enterpriseRecommendations;

    return {
      gate: 'recommendations-generated',
      passed: !!hasRecommendations,
      issue: hasRecommendations ? null : 'No recommendations module found',
      details: {
        recommendationSections: hasRecommendations ? Object.keys(hasRecommendations).length : 0,
      },
    };
  }

  validateDetectionContentGenerated(product, investigation) {
    const modules = product.modules || {};
    const hasDetection = modules.detectionRules || modules.detectionContent;

    const techniques = investigation.mitreTechniques || [];
    const techniqueCount = techniques.length;

    return {
      gate: 'detection-generated',
      passed: !!hasDetection,
      issue: hasDetection ? null : 'No detection content generated',
      warning: hasDetection && techniqueCount < modules.detectionRules?.length ? null : 'Detection coverage < technique count',
      details: {
        detectionFormats: hasDetection ? Object.keys(hasDetection).length : 0,
        techniquesCount: techniqueCount,
      },
    };
  }

  validateExecutiveSummaryGenerated(product, investigation) {
    const modules = product.modules || {};
    const hasSummary = modules.executiveSummary || modules.summary;

    return {
      gate: 'executive-summary-generated',
      passed: !!hasSummary,
      issue: hasSummary ? null : 'No executive summary found',
      details: {
        summaryLength: hasSummary ? JSON.stringify(hasSummary).length : 0,
      },
    };
  }

  validateQualityScoreThreshold(product, investigation) {
    const qualityScore = this.calculateProductQualityScore(product, investigation);
    const minimumThreshold = 0.7;
    const passed = qualityScore >= minimumThreshold;

    return {
      gate: 'quality-score-threshold',
      passed: passed,
      issue: passed ? null : `Quality score ${parseFloat((qualityScore * 100).toFixed(0))} below minimum threshold ${minimumThreshold * 100}`,
      details: {
        score: parseFloat((qualityScore * 100).toFixed(0)),
        threshold: minimumThreshold * 100,
      },
    };
  }

  calculateQualityScore(gates) {
    if (gates.length === 0) return 0;

    const passedCount = gates.filter(g => g.passed).length;
    const warningCount = gates.filter(g => g.warning).length;

    let score = passedCount / gates.length;
    score = score * 0.9 - (warningCount * 0.05);

    return Math.max(0, Math.min(1, score));
  }

  calculateProductQualityScore(product, investigation) {
    let score = 0;

    // Evidence quality
    const evidenceCount = (investigation.findings || []).length + (investigation.iocs || []).length;
    score += Math.min(evidenceCount / 50, 0.2);

    // Confidence level
    const confidence = investigation.confidence || 0;
    score += confidence * 0.2;

    // MITRE coverage
    const techniqueCount = (investigation.mitreTechniques || []).length;
    score += Math.min(techniqueCount / 20, 0.2);

    // Module completeness
    const modules = product.modules || {};
    const moduleCount = Object.keys(modules).length;
    score += Math.min(moduleCount / 8, 0.2);

    // Analytical depth
    const analysisDepth = this.assessAnalyticalDepth(product, investigation);
    score += analysisDepth * 0.2;

    return Math.min(score, 1.0);
  }

  assessAnalyticalDepth(product, investigation) {
    const modules = product.modules || {};
    let depth = 0;

    if (modules.narratives || modules.threatNarrative) depth += 0.3;
    if (modules.keyJudgements || modules.judgements) depth += 0.3;
    if (modules.evidence || modules.evidenceAnalysis) depth += 0.2;
    if (modules.recommendations) depth += 0.2;

    return Math.min(depth, 1.0);
  }

  addQualityMetadata(product, validationResult) {
    product.qualityAssurance = {
      validated: true,
      approvedForPublication: validationResult.approvedForPublication,
      qualityScore: validationResult.qualityScore,
      publishingReady: validationResult.publishingReady,
      gates: validationResult.gatesResult.map(g => ({
        name: g.gate,
        passed: g.passed,
        issue: g.issue,
      })),
      validatedAt: validationResult.validatedAt,
      validationVersion: '1.0',
    };
    return product;
  }

  generateQualityReport(product, validationResult) {
    return {
      productId: product.id,
      productType: product.productType,
      publicationStatus: validationResult.approvedForPublication ? 'Approved' : 'Blocked',
      qualityScore: parseFloat((validationResult.qualityScore * 100).toFixed(1)),
      summary: this.generateSummary(validationResult),
      details: validationResult.gatesResult,
      recommendations: this.generateRecommendations(validationResult),
      reportedAt: new Date().toISOString(),
    };
  }

  generateSummary(validationResult) {
    const passedGates = validationResult.gatesResult.filter(g => g.passed).length;
    const totalGates = validationResult.gatesResult.length;

    return `${passedGates}/${totalGates} quality gates passed. Quality score: ${parseFloat((validationResult.qualityScore * 100).toFixed(0))}. ${validationResult.approvedForPublication ? 'Product ready for publication.' : 'Product requires review before publication.'}`;
  }

  generateRecommendations(validationResult) {
    return validationResult.gatesResult
      .filter(g => !g.passed || g.warning)
      .map(g => ({
        gate: g.gate,
        recommendation: this.recommendationForGate(g.gate),
        priority: !g.passed ? 'High' : 'Medium',
      }));
  }

  recommendationForGate(gateName) {
    const recommendations = {
      'evidence-exists': 'Ensure investigation includes findings, IOCs, and infrastructure data',
      'confidence-calculated': 'Calculate and document confidence reasoning',
      'mitre-mapping': 'Map additional MITRE ATT&CK techniques',
      'iocs-validated': 'Validate additional IOCs against known data',
      'recommendations-generated': 'Develop enterprise and technical recommendations',
      'detection-generated': 'Generate Sigma, YARA, and SIEM detection rules',
      'executive-summary-generated': 'Create executive summary with key findings',
      'quality-score-threshold': 'Address quality issues to meet publication standard',
    };
    return recommendations[gateName] || 'Review and improve this section';
  }
}

module.exports = { QualityGatesEngine };
