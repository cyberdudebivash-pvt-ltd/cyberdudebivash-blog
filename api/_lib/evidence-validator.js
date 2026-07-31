'use strict';

const redis = require('./redis');

class EvidenceValidator {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async validateFinding(finding) {
    const issues = [];

    if (!finding.statement || finding.statement.trim().length === 0) {
      issues.push({
        severity: 'critical',
        code: 'EMPTY_STATEMENT',
        message: 'Finding statement is required and cannot be empty',
      });
    }

    if (!finding.evidence || finding.evidence.length === 0) {
      issues.push({
        severity: 'critical',
        code: 'NO_EVIDENCE',
        message: 'Finding must have at least one evidence item',
      });
    } else {
      const evidenceIssues = await this.validateEvidenceArray(finding.evidence);
      issues.push(...evidenceIssues);
    }

    if (!finding.reasoning || finding.reasoning.trim().length === 0) {
      issues.push({
        severity: 'high',
        code: 'NO_REASONING',
        message: 'Finding must include reasoning that connects evidence to conclusion',
      });
    }

    if (!finding.assumptions || finding.assumptions.length === 0) {
      issues.push({
        severity: 'medium',
        code: 'NO_ASSUMPTIONS',
        message: 'Finding should document key assumptions',
      });
    }

    if (!finding.limitations || finding.limitations.length === 0) {
      issues.push({
        severity: 'medium',
        code: 'NO_LIMITATIONS',
        message: 'Finding should acknowledge analytical limitations',
      });
    }

    if (!finding.alternativeHypotheses || finding.alternativeHypotheses.length === 0) {
      issues.push({
        severity: 'low',
        code: 'NO_ALTERNATIVES',
        message: 'Finding should consider alternative hypotheses',
      });
    }

    const confidenceIssues = this.validateConfidence(finding.confidence, finding.evidence);
    issues.push(...confidenceIssues);

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      criticalIssues: issues.filter(i => i.severity === 'critical'),
      warnings: issues.filter(i => i.severity !== 'critical'),
      allIssues: issues,
    };
  }

  async validateEvidenceArray(evidence) {
    const issues = [];

    for (const evid of evidence) {
      if (!evid.evidenceId) {
        issues.push({
          severity: 'critical',
          code: 'MISSING_EVIDENCE_ID',
          message: 'Each evidence item must have an evidenceId',
        });
      }

      if (!evid.reliability || !['high', 'medium', 'low'].includes(evid.reliability)) {
        issues.push({
          severity: 'high',
          code: 'INVALID_RELIABILITY',
          message: `Evidence reliability must be one of: high, medium, low (got: ${evid.reliability})`,
        });
      }

      if (!evid.strength || !['strong', 'moderate', 'weak'].includes(evid.strength)) {
        issues.push({
          severity: 'high',
          code: 'INVALID_STRENGTH',
          message: `Evidence strength must be one of: strong, moderate, weak (got: ${evid.strength})`,
        });
      }

      if (!evid.context || evid.context.trim().length === 0) {
        issues.push({
          severity: 'medium',
          code: 'MISSING_CONTEXT',
          message: 'Each evidence item should have context explaining its relevance',
        });
      }
    }

    return issues;
  }

  validateConfidence(confidence, evidence) {
    const issues = [];

    if (!confidence || !['confirmed', 'likely', 'possible', 'unlikely', 'unsubstantiated'].includes(confidence)) {
      issues.push({
        severity: 'critical',
        code: 'INVALID_CONFIDENCE',
        message: 'Confidence must be one of: confirmed, likely, possible, unlikely, unsubstantiated',
      });
    }

    if (evidence && evidence.length > 0) {
      const avgReliability = this.calculateAverageReliability(evidence);
      const avgStrength = this.calculateAverageStrength(evidence);

      if (confidence === 'confirmed' && (avgReliability < 0.8 || avgStrength < 0.8)) {
        issues.push({
          severity: 'high',
          code: 'CONFIDENCE_MISMATCH',
          message: 'Confirmed confidence requires predominantly high-reliability, strong evidence. Current evidence quality does not support this confidence level.',
        });
      }

      if (confidence === 'likely' && (avgReliability < 0.5 || avgStrength < 0.5)) {
        issues.push({
          severity: 'medium',
          code: 'CONFIDENCE_MISMATCH',
          message: 'Likely confidence requires reasonable evidence quality. Consider downgrading confidence level.',
        });
      }
    }

    return issues;
  }

  calculateAverageReliability(evidence) {
    const reliabilityScores = { high: 1.0, medium: 0.6, low: 0.3 };
    const total = evidence.reduce((sum, e) => sum + (reliabilityScores[e.reliability] || 0), 0);
    return evidence.length > 0 ? total / evidence.length : 0;
  }

  calculateAverageStrength(evidence) {
    const strengthScores = { strong: 1.0, moderate: 0.6, weak: 0.3 };
    const total = evidence.reduce((sum, e) => sum + (strengthScores[e.strength] || 0), 0);
    return evidence.length > 0 ? total / evidence.length : 0;
  }

  async validateSituationAssessment(assessment) {
    const issues = [];

    if (!assessment.overview || assessment.overview.trim().length === 0) {
      issues.push({ severity: 'critical', code: 'NO_OVERVIEW', message: 'Situation assessment must include an overview' });
    }

    if (!assessment.scope || assessment.scope.trim().length === 0) {
      issues.push({ severity: 'critical', code: 'NO_SCOPE', message: 'Situation assessment must define scope' });
    }

    if (!assessment.affectedSectors || assessment.affectedSectors.length === 0) {
      issues.push({ severity: 'high', code: 'NO_SECTORS', message: 'Situation assessment should identify affected sectors' });
    }

    if (!assessment.geographicContext || assessment.geographicContext.length === 0) {
      issues.push({ severity: 'medium', code: 'NO_GEOGRAPHY', message: 'Situation assessment should include geographic context' });
    }

    if (!assessment.estimatedImpact || assessment.estimatedImpact.trim().length === 0) {
      issues.push({ severity: 'high', code: 'NO_IMPACT', message: 'Situation assessment must estimate impact' });
    }

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
    };
  }

  async validateThreatActorAssessment(assessment) {
    const issues = [];

    if (!assessment.attribution || assessment.attribution.trim().length === 0) {
      issues.push({ severity: 'critical', code: 'NO_ATTRIBUTION', message: 'Threat actor assessment must include attribution' });
    }

    if (!assessment.attributionConfidence || !['confirmed', 'likely', 'possible', 'unlikely', 'unsubstantiated'].includes(assessment.attributionConfidence)) {
      issues.push({ severity: 'critical', code: 'INVALID_CONFIDENCE', message: 'Attribution confidence is required and must be valid' });
    }

    if (!assessment.supportingEvidence || assessment.supportingEvidence.length === 0) {
      issues.push({ severity: 'high', code: 'NO_SUPPORTING_EVIDENCE', message: 'Attribution should include supporting evidence' });
    }

    if (!assessment.attributionGaps || assessment.attributionGaps.length === 0) {
      issues.push({ severity: 'medium', code: 'NO_GAPS', message: 'Attribution assessment should acknowledge gaps in evidence' });
    }

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
    };
  }

  async validateTechnicalAssessment(assessment) {
    const issues = [];

    if (!assessment.iocs || assessment.iocs.length === 0) {
      issues.push({ severity: 'medium', code: 'NO_IOCS', message: 'Technical assessment should include indicators of compromise' });
    }

    if (!assessment.techniques || assessment.techniques.length === 0) {
      issues.push({ severity: 'medium', code: 'NO_TECHNIQUES', message: 'Technical assessment should map MITRE ATT&CK techniques' });
    } else {
      for (const technique of assessment.techniques) {
        if (!technique.techniqueId || !technique.techniqueId.match(/^T\d{4}(\.\d{3})?$/)) {
          issues.push({
            severity: 'high',
            code: 'INVALID_MITRE_ID',
            message: `Invalid MITRE technique ID: ${technique.techniqueId}. Must be T#### or T####.###`,
          });
        }
      }
    }

    if (!assessment.infrastructure || assessment.infrastructure.length === 0) {
      issues.push({ severity: 'medium', code: 'NO_INFRASTRUCTURE', message: 'Technical assessment should map infrastructure' });
    }

    if (!assessment.detectionOpportunities || assessment.detectionOpportunities.length === 0) {
      issues.push({ severity: 'low', code: 'NO_DETECTION_OPPS', message: 'Technical assessment should suggest detection opportunities' });
    }

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
    };
  }

  async validateExecutiveAssessment(assessment) {
    const issues = [];

    if (!assessment.businessImpact || assessment.businessImpact.trim().length === 0) {
      issues.push({ severity: 'high', code: 'NO_BUSINESS_IMPACT', message: 'Executive assessment must include business impact analysis' });
    }

    if (!assessment.operationalImpact || assessment.operationalImpact.trim().length === 0) {
      issues.push({ severity: 'high', code: 'NO_OPERATIONAL_IMPACT', message: 'Executive assessment must include operational impact analysis' });
    }

    if (!assessment.recommendedActions || assessment.recommendedActions.length === 0) {
      issues.push({ severity: 'critical', code: 'NO_RECOMMENDATIONS', message: 'Executive assessment must include recommended actions' });
    }

    if (!assessment.priorityLevel || !['critical', 'high', 'medium', 'low'].includes(assessment.priorityLevel)) {
      issues.push({ severity: 'critical', code: 'INVALID_PRIORITY', message: 'Priority level must be one of: critical, high, medium, low' });
    }

    return {
      isValid: issues.filter(i => i.severity === 'critical').length === 0,
      issues,
    };
  }
}

module.exports = { EvidenceValidator };
