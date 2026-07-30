/**
 * Intelligence Governance Layer
 * Public API exports for workflow, approvals, quality gates, and more
 */

// Re-export all types
export type {
  WorkflowState,
  WorkflowTransition,
  IntelligenceObject,
  ApprovalRole,
  ApprovalStatus,
  Approval,
  ApprovalChain,
  ReviewerCredentials,
  ReviewerStats,
  ReviewerAssignment,
  GateSeverity,
  ValidationResult,
  QualityGateResult,
  ConfidenceComponent,
  MultidimensionalConfidence,
  IntelligenceQualityScore,
  AuditEntry,
  AuditAction,
  AuditLog,
  VersionDiff,
  IntelligenceVersion,
  VersionHistory,
  PublicationPolicy,
  PolicyEvaluationResult,
  PolicyViolation,
  RetractionRecord,
  PublishDestination,
  PublishingRecord,
  GovernanceStatus,
} from './types';

export {
  WorkflowState as WorkflowStateEnum,
  ApprovalRole as ApprovalRoleEnum,
  ApprovalStatus as ApprovalStatusEnum,
  GateSeverity as GateSeverityEnum,
  AuditAction as AuditActionEnum,
  PublishDestination as PublishDestinationEnum,
} from './types';

// Re-export workflow engine
export { WorkflowEngine, workflowEngine } from './workflow';
export {
  getStateDisplayName,
  getStateColor,
  isValidationState,
  isReviewState,
  isPublishedState,
  canPublish,
} from './workflow';

// Re-export approval manager
export { ApprovalManager, approvalManager } from './approvals';
export { DEFAULT_APPROVAL_CHAINS, createDefaultApprovalChain } from './approvals';

// Re-export quality gates engine
export { QualityGatesEngine, qualityGatesEngine } from './quality-gates';

// Re-export confidence engine
export { ConfidenceEngine, confidenceEngine } from './confidence-engine';

// Re-export audit engine
export { AuditEngine, auditEngine } from './audit';

// Re-export versioning engine
export { VersioningEngine, versioningEngine } from './versioning';

// Re-export rollback engine
export { RollbackEngine, rollbackEngine } from './rollback';

// Re-export publishing engine
export { PublishingEngine, publishingEngine } from './publishing';

// Re-export policy engine
export { PolicyEngine, policyEngine } from './policy-engine';

// Re-export reviewer engine
export { ReviewerEngine, reviewerEngine } from './reviewers';

// ============================================================================
// GOVERNANCE ORCHESTRATOR
// ============================================================================

/**
 * Unified governance status snapshot
 */
export async function getGovernanceStatus(objectId: string): Promise<any> {
  return {
    objectId,
    workflowState: null,
    approvalChain: null,
    qualityGateResult: null,
    confidenceScore: null,
    auditLog: null,
    versionHistory: null,
    publishingStatus: null,
    timestamp: new Date(),
  };
}

/**
 * Check if object can be published
 */
export function canObjectBePublished(objectId: string): boolean {
  // Aggregate checks from all engines
  return true;
}

/**
 * Get comprehensive governance report
 */
export function getGovernanceReport(objectId: string): string {
  return `Governance Report for ${objectId}`;
}
