/**
 * Policy Engine
 * Configurable publication policies with thresholds
 */

import { v4 as uuidv4 } from 'uuid';
import type { PublicationPolicy, PolicyEvaluationResult, PolicyViolation, GateSeverity } from './types';
import { GateSeverity as GateSeverityEnum } from './types';

// ============================================================================
// POLICY ENGINE
// ============================================================================

export class PolicyEngine {
  private policies: Map<string, PublicationPolicy> = new Map();
  private evaluations: Map<string, PolicyEvaluationResult[]> = new Map();

  /**
   * Create a publication policy
   */
  createPolicy(
    name: string,
    description: string,
    minimumConfidenceRequired: number = 70,
    minimumQualityScoreRequired: number = 75,
    minimumReviewsRequired: number = 1,
    requirePeerReview: boolean = true,
    requireSecurityReview: boolean = true,
    mandatoryFields: string[] = [],
    minimumIOCsRequired: number = 1,
    requireIOCValidation: boolean = true,
    requireDetectionRules: boolean = false,
    minimumDetectionCoverage: number = 0,
    requireMITREMapping: boolean = true,
    minimumTechniquesRequired: number = 1,
    minimumReferencesRequired: number = 1,
    maximumAgeInDays: number = 365,
    requireEvidenceAttribution: boolean = true,
    minimumEvidencePerClaim: number = 1
  ): PublicationPolicy {
    const policyId = uuidv4();

    const policy: PublicationPolicy = {
      policyId,
      name,
      description,
      minimumConfidenceRequired,
      minimumQualityScoreRequired,
      minimumReviewsRequired,
      requirePeerReview,
      requireSecurityReview,
      mandatoryFields,
      minimumIOCsRequired,
      requireIOCValidation,
      requireDetectionRules,
      minimumDetectionCoverage,
      requireMITREMapping,
      minimumTechniquesRequired,
      minimumReferencesRequired,
      maximumAgeInDays,
      requireEvidenceAttribution,
      minimumEvidencePerClaim,
      active: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      updatedBy: 'system',
    };

    this.policies.set(policyId, policy);
    return policy;
  }

  /**
   * Get policy
   */
  getPolicy(policyId: string): PublicationPolicy | undefined {
    return this.policies.get(policyId);
  }

  /**
   * Get active policies
   */
  getActivePolicies(): PublicationPolicy[] {
    return Array.from(this.policies.values()).filter(p => p.active);
  }

  /**
   * Update policy
   */
  updatePolicy(policyId: string, updates: Partial<PublicationPolicy>, updatedBy: string): PublicationPolicy {
    const policy = this.policies.get(policyId);
    if (!policy) {
      throw new Error(`Policy not found: ${policyId}`);
    }

    Object.assign(policy, updates);
    policy.updatedAt = new Date();
    policy.updatedBy = updatedBy;

    return policy;
  }

  /**
   * Disable policy
   */
  disablePolicy(policyId: string, updatedBy: string): PublicationPolicy {
    return this.updatePolicy(policyId, { active: false }, updatedBy);
  }

  /**
   * Enable policy
   */
  enablePolicy(policyId: string, updatedBy: string): PublicationPolicy {
    return this.updatePolicy(policyId, { active: true }, updatedBy);
  }

  /**
   * Evaluate object against policy
   */
  evaluatePolicy(
    policyId: string,
    objectId: string,
    object: any
  ): PolicyEvaluationResult {
    const policy = this.policies.get(policyId);
    if (!policy) {
      throw new Error(`Policy not found: ${policyId}`);
    }

    if (!policy.active) {
      throw new Error(`Policy is not active: ${policyId}`);
    }

    const violations: PolicyViolation[] = [];

    // Check confidence threshold
    if (object.confidence !== undefined && object.confidence < policy.minimumConfidenceRequired) {
      violations.push({
        rule: 'minimumConfidenceRequired',
        severity: GateSeverityEnum.ERROR,
        message: `Confidence (${object.confidence}) is below minimum (${policy.minimumConfidenceRequired})`,
        currentValue: object.confidence,
        requiredValue: policy.minimumConfidenceRequired,
      });
    }

    // Check quality score threshold
    if (object.qualityScore !== undefined && object.qualityScore < policy.minimumQualityScoreRequired) {
      violations.push({
        rule: 'minimumQualityScoreRequired',
        severity: GateSeverityEnum.ERROR,
        message: `Quality score (${object.qualityScore}) is below minimum (${policy.minimumQualityScoreRequired})`,
        currentValue: object.qualityScore,
        requiredValue: policy.minimumQualityScoreRequired,
      });
    }

    // Check mandatory fields
    for (const field of policy.mandatoryFields) {
      if (!object[field]) {
        violations.push({
          rule: 'mandatoryFields',
          severity: GateSeverityEnum.ERROR,
          message: `Mandatory field missing: ${field}`,
          currentValue: object[field],
          requiredValue: `${field} must be present`,
        });
      }
    }

    // Check minimum IOCs
    const iocCount = object.iocs?.length || 0;
    if (iocCount < policy.minimumIOCsRequired) {
      violations.push({
        rule: 'minimumIOCsRequired',
        severity: GateSeverityEnum.ERROR,
        message: `IOC count (${iocCount}) is below minimum (${policy.minimumIOCsRequired})`,
        currentValue: iocCount,
        requiredValue: policy.minimumIOCsRequired,
      });
    }

    // Check IOC validation
    if (policy.requireIOCValidation && object.iocs) {
      const invalidIOCs = object.iocs.filter((ioc: any) => !ioc.validated);
      if (invalidIOCs.length > 0) {
        violations.push({
          rule: 'requireIOCValidation',
          severity: GateSeverityEnum.WARNING,
          message: `${invalidIOCs.length} IOC(s) require validation`,
          currentValue: invalidIOCs.length,
          requiredValue: 0,
        });
      }
    }

    // Check detection rules
    if (policy.requireDetectionRules) {
      const detectionCount = object.detections?.length || 0;
      if (detectionCount === 0) {
        violations.push({
          rule: 'requireDetectionRules',
          severity: GateSeverityEnum.WARNING,
          message: 'No detection rules provided',
          currentValue: detectionCount,
          requiredValue: '> 0',
        });
      }
    }

    // Check detection coverage
    if (object.detectionCoverage !== undefined && object.detectionCoverage < policy.minimumDetectionCoverage) {
      violations.push({
        rule: 'minimumDetectionCoverage',
        severity: GateSeverityEnum.WARNING,
        message: `Detection coverage (${object.detectionCoverage}%) is below minimum (${policy.minimumDetectionCoverage}%)`,
        currentValue: object.detectionCoverage,
        requiredValue: policy.minimumDetectionCoverage,
      });
    }

    // Check MITRE mapping
    if (policy.requireMITREMapping) {
      const techniqueCount = object.techniques?.length || 0;
      if (techniqueCount < policy.minimumTechniquesRequired) {
        violations.push({
          rule: 'minimumTechniquesRequired',
          severity: GateSeverityEnum.ERROR,
          message: `MITRE techniques (${techniqueCount}) below minimum (${policy.minimumTechniquesRequired})`,
          currentValue: techniqueCount,
          requiredValue: policy.minimumTechniquesRequired,
        });
      }
    }

    // Check references
    const referenceCount = object.references?.length || 0;
    if (referenceCount < policy.minimumReferencesRequired) {
      violations.push({
        rule: 'minimumReferencesRequired',
        severity: GateSeverityEnum.ERROR,
        message: `References (${referenceCount}) below minimum (${policy.minimumReferencesRequired})`,
        currentValue: referenceCount,
        requiredValue: policy.minimumReferencesRequired,
      });
    }

    // Check evidence attribution
    if (policy.requireEvidenceAttribution && object.sections) {
      const unattributedSections = object.sections.filter(
        (s: any) => !s.evidence || s.evidence.length < policy.minimumEvidencePerClaim
      );
      if (unattributedSections.length > 0) {
        violations.push({
          rule: 'requireEvidenceAttribution',
          severity: GateSeverityEnum.WARNING,
          message: `${unattributedSections.length} section(s) lack sufficient evidence`,
          currentValue: unattributedSections.length,
          requiredValue: 0,
        });
      }
    }

    // Check age
    if (object.createdAt) {
      const ageInDays = (Date.now() - new Date(object.createdAt).getTime()) / (1000 * 60 * 60 * 24);
      if (ageInDays > policy.maximumAgeInDays) {
        violations.push({
          rule: 'maximumAgeInDays',
          severity: GateSeverityEnum.WARNING,
          message: `Content age (${Math.round(ageInDays)} days) exceeds maximum (${policy.maximumAgeInDays} days)`,
          currentValue: Math.round(ageInDays),
          requiredValue: policy.maximumAgeInDays,
        });
      }
    }

    const result: PolicyEvaluationResult = {
      policyId,
      objectId,
      passed: violations.length === 0,
      violations,
      canPublish: violations.filter(v => v.severity === GateSeverityEnum.ERROR).length === 0,
      timestamp: new Date(),
    };

    // Store evaluation
    if (!this.evaluations.has(objectId)) {
      this.evaluations.set(objectId, []);
    }
    this.evaluations.get(objectId)!.push(result);

    return result;
  }

  /**
   * Get policy evaluation history for object
   */
  getEvaluationHistory(objectId: string): PolicyEvaluationResult[] {
    return this.evaluations.get(objectId) || [];
  }

  /**
   * Get latest evaluation for object
   */
  getLatestEvaluation(objectId: string): PolicyEvaluationResult | undefined {
    const history = this.getEvaluationHistory(objectId);
    return history.length > 0 ? history[history.length - 1] : undefined;
  }

  /**
   * Check if object passes all active policies
   */
  passesAllPolicies(objectId: string, object: any): boolean {
    const activePolicies = this.getActivePolicies();
    for (const policy of activePolicies) {
      const result = this.evaluatePolicy(policy.policyId, objectId, object);
      if (!result.canPublish) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get policy statistics
   */
  getPolicyStats(): {
    totalPolicies: number;
    activePolicies: number;
    inactivePolicies: number;
    totalEvaluations: number;
    passRate: number;
  } {
    const activePolicies = this.getActivePolicies();
    const inactivePolicies = this.policies.size - activePolicies.length;

    let totalEvaluations = 0;
    let passedEvaluations = 0;

    for (const evaluations of this.evaluations.values()) {
      totalEvaluations += evaluations.length;
      passedEvaluations += evaluations.filter(e => e.passed).length;
    }

    const passRate = totalEvaluations > 0 ? (passedEvaluations / totalEvaluations) * 100 : 0;

    return {
      totalPolicies: this.policies.size,
      activePolicies: activePolicies.length,
      inactivePolicies,
      totalEvaluations,
      passRate: Math.round(passRate),
    };
  }

  /**
   * Export all policies
   */
  exportPolicies(): PublicationPolicy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Generate policy report
   */
  generatePolicyReport(policyId: string): string {
    const policy = this.policies.get(policyId);
    if (!policy) return '';

    let report = `# Publication Policy Report: ${policy.name}\n\n`;
    report += `**Description:** ${policy.description}\n`;
    report += `**Status:** ${policy.active ? 'Active' : 'Inactive'}\n\n`;

    report += '## Thresholds\n\n';
    report += `- Minimum Confidence: ${policy.minimumConfidenceRequired}%\n`;
    report += `- Minimum Quality Score: ${policy.minimumQualityScoreRequired}%\n`;
    report += `- Minimum Reviews Required: ${policy.minimumReviewsRequired}\n`;
    report += `- Minimum IOCs Required: ${policy.minimumIOCsRequired}\n`;
    report += `- Minimum MITRE Techniques: ${policy.minimumTechniquesRequired}\n`;
    report += `- Minimum References: ${policy.minimumReferencesRequired}\n`;
    report += `- Minimum Evidence Per Claim: ${policy.minimumEvidencePerClaim}\n`;
    report += `- Maximum Content Age: ${policy.maximumAgeInDays} days\n\n`;

    report += '## Requirements\n\n';
    report += `- Peer Review Required: ${policy.requirePeerReview ? 'Yes' : 'No'}\n`;
    report += `- Security Review Required: ${policy.requireSecurityReview ? 'Yes' : 'No'}\n`;
    report += `- IOC Validation Required: ${policy.requireIOCValidation ? 'Yes' : 'No'}\n`;
    report += `- Detection Rules Required: ${policy.requireDetectionRules ? 'Yes' : 'No'}\n`;
    report += `- MITRE Mapping Required: ${policy.requireMITREMapping ? 'Yes' : 'No'}\n`;
    report += `- Evidence Attribution Required: ${policy.requireEvidenceAttribution ? 'Yes' : 'No'}\n\n`;

    if (policy.mandatoryFields.length > 0) {
      report += '## Mandatory Fields\n\n';
      for (const field of policy.mandatoryFields) {
        report += `- ${field}\n`;
      }
      report += '\n';
    }

    return report;
  }
}

export const policyEngine = new PolicyEngine();
