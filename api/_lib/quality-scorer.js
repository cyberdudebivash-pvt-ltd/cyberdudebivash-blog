'use strict';

const redis = require('./redis');

class QualityScorer {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async scoreReport(report, validationResults = {}) {
    const analyticalScore = this.scoreAnalyticalQuality(report, validationResults.analyticalQuality);
    const evidenceScore = this.scoreEvidenceQuality(report);
    const confidenceScore = this.scoreConfidenceIntegrity(report);
    const completenessScore = this.scoreCompleteness(report);
    const technicalScore = this.scoreTechnicalCoverage(report);
    const editorialScore = this.scoreEditorialQuality(report, validationResults.editorialQuality);
    const detectionScore = this.scoreDetectionCoverage(report);

    const overallScore = (
      (analyticalScore * 0.25) +
      (evidenceScore * 0.20) +
      (confidenceScore * 0.15) +
      (completenessScore * 0.15) +
      (technicalScore * 0.10) +
      (editorialScore * 0.10) +
      (detectionScore * 0.05)
    );

    const certification = this.determineCertification(overallScore, validationResults);

    return {
      reportId: report.id,
      overallScore: Math.round(overallScore * 100) / 100,
      scoreBreakdown: {
        analyticalQuality: Math.round(analyticalScore * 100) / 100,
        evidenceQuality: Math.round(evidenceScore * 100) / 100,
        confidenceIntegrity: Math.round(confidenceScore * 100) / 100,
        completeness: Math.round(completenessScore * 100) / 100,
        technicalCoverage: Math.round(technicalScore * 100) / 100,
        editorialQuality: Math.round(editorialScore * 100) / 100,
        detectionCoverage: Math.round(detectionScore * 100) / 100,
      },
      certification,
      recommendation: this.getPublicationRecommendation(overallScore, certification),
      qualityGaps: this.identifyQualityGaps(
        analyticalScore,
        evidenceScore,
        confidenceScore,
        completenessScore,
        technicalScore,
        editorialScore
      ),
    };
  }

  scoreAnalyticalQuality(report, validationResults) {
    let score = 0.5;

    const criticalIssues = validationResults?.criticalIssues || [];
    const totalIssues = validationResults?.issues || [];

    if (criticalIssues.length === 0) score += 0.3;
    if (totalIssues.length === 0) score += 0.2;

    const evidenceRatio = validationResults?.evidenceBackingRatio || 50;
    score += (evidenceRatio / 100) * 0.3;

    return Math.min(score, 1.0);
  }

  scoreEvidenceQuality(report) {
    let score = 0;

    const findings = report.findings || [];
    let totalEvidenceQuality = 0;
    let evidenceBackedCount = 0;

    for (const finding of findings) {
      const evidence = finding.evidence || [];
      if (evidence.length > 0) {
        evidenceBackedCount += 1;

        const reliabilityScores = { high: 1.0, medium: 0.6, low: 0.3 };
        const strengthScores = { strong: 1.0, moderate: 0.6, weak: 0.3 };

        for (const evid of evidence) {
          const reliability = reliabilityScores[evid.reliability] || 0;
          const strength = strengthScores[evid.strength] || 0;
          totalEvidenceQuality += (reliability * 0.5 + strength * 0.5);
        }
      }
    }

    if (findings.length > 0) {
      const avgEvidenceQuality = totalEvidenceQuality / (evidenceBackedCount || 1);
      const evidenceRatio = evidenceBackedCount / findings.length;
      score = (avgEvidenceQuality * 0.6) + (evidenceRatio * 0.4);
    }

    return Math.min(score, 1.0);
  }

  scoreConfidenceIntegrity(report) {
    let score = 0.5;

    const findings = report.findings || [];
    let confidenceAlignmentCount = 0;

    for (const finding of findings) {
      const confidence = finding.confidence || 'possible';
      const evidence = finding.evidence || [];
      const confidenceValues = { confirmed: 4, likely: 3, possible: 2, unlikely: 1, unsubstantiated: 0 };
      const confidenceLevel = confidenceValues[confidence] || 2;
      const requiredEvidenceCount = confidenceLevel + 1;

      if (evidence.length >= requiredEvidenceCount) {
        confidenceAlignmentCount += 1;
      }
    }

    if (findings.length > 0) {
      score = confidenceAlignmentCount / findings.length;
    }

    return Math.min(score, 1.0);
  }

  scoreCompleteness(report) {
    let score = 0;

    const sections = report.sections || [];
    const minSectionCount = 5;

    if (sections.length >= minSectionCount) score += 0.3;
    else score += (sections.length / minSectionCount) * 0.3;

    const findings = report.findings || [];
    if (findings.length >= 3) score += 0.3;
    else score += (findings.length / 3) * 0.3;

    const hasAssessments = (report.assessments?.situation || report.assessments?.technical || report.assessments?.executive);
    if (hasAssessments) score += 0.2;

    const hasMetadata = report.classification && report.audience && report.version;
    if (hasMetadata) score += 0.2;

    return Math.min(score, 1.0);
  }

  scoreTechnicalCoverage(report) {
    let score = 0;

    const technical = report.assessments?.technical || {};
    const iocCount = (technical.iocs || []).length;
    const techniqueCount = (technical.techniques || []).length;
    const infrastructureCount = (technical.infrastructure || []).length;

    if (iocCount > 0) score += 0.3;
    if (techniqueCount > 0) score += 0.3;
    if (infrastructureCount > 0) score += 0.2;

    const detectionOpportunities = (technical.detectionOpportunities || []).length;
    if (detectionOpportunities > 0) score += 0.2;

    return Math.min(score, 1.0);
  }

  scoreEditorialQuality(report, validationResults) {
    let score = 0.5;

    const contentQuality = validationResults?.contentQuality || {};
    const wordCount = contentQuality.wordCount || 0;
    const sectionCount = contentQuality.sectionCount || 0;
    const evidenceBackedSections = contentQuality.evidenceBackedSections || 0;

    if (wordCount >= 500) score += 0.25;
    else score += (wordCount / 500) * 0.25;

    if (sectionCount >= 5) score += 0.25;
    else score += (sectionCount / 5) * 0.25;

    if (evidenceBackedSections >= sectionCount) score += 0.25;
    else if (sectionCount > 0) score += (evidenceBackedSections / sectionCount) * 0.25;

    const issueCount = validationResults?.issues?.length || 0;
    if (issueCount === 0) score += 0.25;
    else if (issueCount <= 3) score += 0.15;

    return Math.min(score, 1.0);
  }

  scoreDetectionCoverage(report) {
    let score = 0;

    const technical = report.assessments?.technical || {};
    const detectionOpportunities = (technical.detectionOpportunities || []).length;

    if (detectionOpportunities >= 5) score = 1.0;
    else if (detectionOpportunities >= 3) score = 0.7;
    else if (detectionOpportunities > 0) score = 0.4;
    else score = 0.1;

    return Math.min(score, 1.0);
  }

  determineCertification(overallScore, validationResults) {
    const criticalIssues = validationResults.analyticalQuality?.criticalIssues?.length || 0;
    const complianceValid = validationResults.compliance?.isValid !== false;

    if (criticalIssues > 0) return 'DRAFT';
    if (overallScore >= 0.95 && complianceValid) return 'CERTIFIED';
    if (overallScore >= 0.85 && complianceValid) return 'PREMIUM';
    if (overallScore >= 0.75) return 'INTERNALLY_REVIEWED';
    if (overallScore >= 0.60) return 'REVIEWED';
    return 'DRAFT';
  }

  getPublicationRecommendation(score, certification) {
    const recommendations = {
      CERTIFIED: 'Ready for immediate publication. Meets all quality standards.',
      PREMIUM: 'Ready for publication. Consider minor improvements before enterprise distribution.',
      INTERNALLY_REVIEWED: 'Ready for publication. Recommend internal review before customer delivery.',
      REVIEWED: 'Publication acceptable. Recommend improvements before enterprise distribution.',
      DRAFT: 'Not ready for publication. Address critical issues before proceeding.',
    };

    return recommendations[certification] || 'Review required before publication';
  }

  identifyQualityGaps(analyticalScore, evidenceScore, confidenceScore, completenessScore, technicalScore, editorialScore) {
    const gaps = [];

    if (analyticalScore < 0.8) {
      gaps.push({
        dimension: 'Analytical Quality',
        score: analyticalScore,
        recommendation: 'Add supporting evidence to findings or strengthen reasoning',
      });
    }

    if (evidenceScore < 0.8) {
      gaps.push({
        dimension: 'Evidence Quality',
        score: evidenceScore,
        recommendation: 'Improve evidence reliability/strength or add additional sources',
      });
    }

    if (confidenceScore < 0.8) {
      gaps.push({
        dimension: 'Confidence Integrity',
        score: confidenceScore,
        recommendation: 'Ensure confidence levels align with evidence quantity and quality',
      });
    }

    if (completenessScore < 0.8) {
      gaps.push({
        dimension: 'Completeness',
        score: completenessScore,
        recommendation: 'Expand report with additional sections, findings, or assessments',
      });
    }

    if (technicalScore < 0.8) {
      gaps.push({
        dimension: 'Technical Coverage',
        score: technicalScore,
        recommendation: 'Add IOCs, techniques, infrastructure analysis, or detection opportunities',
      });
    }

    if (editorialScore < 0.8) {
      gaps.push({
        dimension: 'Editorial Quality',
        score: editorialScore,
        recommendation: 'Expand content, improve formatting, or add evidence citations',
      });
    }

    return gaps;
  }
}

module.exports = { QualityScorer };
