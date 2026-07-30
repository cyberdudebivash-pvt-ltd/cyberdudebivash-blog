/**
 * SENTINEL APEX Intelligence Governance Layer — Type Definitions
 * Core interfaces for workflow, approvals, audit, versioning, and policy
 */

// ============================================================================
// WORKFLOW TYPES
// ============================================================================

export enum WorkflowState {
  DRAFT = 'draft',
  AI_GENERATED = 'ai_generated',
  SCHEMA_VALIDATED = 'schema_validated',
  IOC_VALIDATED = 'ioc_validated',
  DETECTION_VALIDATED = 'detection_validated',
  EVIDENCE_VALIDATED = 'evidence_validated',
  MITRE_VALIDATED = 'mitre_validated',
  THREAT_ACTOR_VALIDATED = 'threat_actor_validated',
  ANALYST_REVIEW = 'analyst_review',
  PEER_REVIEW = 'peer_review',
  QA_APPROVAL = 'qa_approval',
  SECURITY_APPROVAL = 'security_approval',
  PUBLISHED = 'published',
  ARCHIVED = 'archived',
  RETRACTED = 'retracted',
}

export interface WorkflowTransition {
  from: WorkflowState;
  to: WorkflowState;
  timestamp: Date;
  actor: string;
  reason?: string;
  validation_results?: ValidationResult[];
}

export interface IntelligenceObject {
  id: string;
  type: 'report' | 'ioc' | 'detection' | 'malware' | 'campaign' | 'threat_actor';
  currentState: WorkflowState;
  createdAt: Date;
  createdBy: string;
  lastModifiedAt: Date;
  lastModifiedBy: string;
  version: number;
  publishedAt?: Date;
  publishedBy?: string;
}

// ============================================================================
// APPROVAL TYPES
// ============================================================================

export enum ApprovalRole {
  ANALYST = 'analyst',
  PEER_ANALYST = 'peer_analyst',
  QA_LEAD = 'qa_lead',
  SECURITY_OFFICER = 'security_officer',
  ADMIN = 'admin',
}

export enum ApprovalStatus {
  PENDING = 'pending',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  CONDITIONAL = 'conditional',
}

export interface Approval {
  approvalId: string;
  objectId: string;
  objectType: 'report' | 'ioc' | 'detection';
  requiredRole: ApprovalRole;
  status: ApprovalStatus;
  requestedAt: Date;
  approverAssigned?: string;
  approvedAt?: Date;
  approvedBy?: string;
  rejectedAt?: Date;
  rejectionReason?: string;
  conditionalNotes?: string;
  canAutoApprove?: boolean;
}

export interface ApprovalChain {
  objectId: string;
  approvals: Approval[];
  completedApprovals: Approval[];
  pendingApprovals: Approval[];
  allApproved: boolean;
  canPublish: boolean;
}

// ============================================================================
// REVIEWER TYPES
// ============================================================================

export interface ReviewerCredentials {
  reviewerId: string;
  name: string;
  email: string;
  roles: ApprovalRole[];
  expertise: string[];  // ['ransomware', 'APT', 'detection_engineering', etc.]
  active: boolean;
  joinedDate: Date;
}

export interface ReviewerStats {
  reviewerId: string;
  totalReviews: number;
  approvalsGiven: number;
  rejectionsGiven: number;
  averageReviewTime: number;  // milliseconds
  lastReviewDate?: Date;
  specialism: string[];
}

export interface ReviewerAssignment {
  objectId: string;
  role: ApprovalRole;
  assignedReviewers: string[];  // reviewer IDs
  assignedAt: Date;
  dueAt: Date;
  completedBy?: string;
  completedAt?: Date;
}

// ============================================================================
// QUALITY GATE TYPES
// ============================================================================

export enum GateSeverity {
  ERROR = 'error',
  WARNING = 'warning',
  INFO = 'info',
}

export interface ValidationResult {
  passed: boolean;
  gateName: string;
  severity: GateSeverity;
  objectType: string;
  message: string;
  failureDetails?: string[];
  suggestion?: string;
  timestamp: Date;
}

export interface QualityGateResult {
  objectId: string;
  objectType: string;
  allPassed: boolean;
  errors: ValidationResult[];
  warnings: ValidationResult[];
  blocksPublication: boolean;
  timestamp: Date;
}

// ============================================================================
// CONFIDENCE TYPES
// ============================================================================

export interface ConfidenceComponent {
  score: number;  // 0-100
  basis: string;  // Explanation of why this score
  weight: number;  // 0-1, used in weighted average
}

export interface MultidimensionalConfidence {
  sourceReliability: ConfidenceComponent;
  observationQuality: ConfidenceComponent;
  technicalValidation: ConfidenceComponent;
  analystVerification: ConfidenceComponent;
  independentCorroboration: ConfidenceComponent;

  overallConfidence: number;  // Weighted average, 0-100
  reasoning: string;  // Summary of why this overall confidence
  timestamp: Date;
  calculatedBy: string;
}

export interface IntelligenceQualityScore {
  objectId: string;
  score: number;  // 0-100

  components: {
    evidenceCompleteness: number;
    iocValidation: number;
    detectionCoverage: number;
    mitreCoverage: number;
    references: number;
    analystReview: number;
    peerReview: number;
    freshness: number;
    confidence: number;
  };

  reasoning: string;
  timestamp: Date;
}

// ============================================================================
// AUDIT TYPES
// ============================================================================

export enum AuditAction {
  CREATED = 'created',
  MODIFIED = 'modified',
  REVIEWED = 'reviewed',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  PUBLISHED = 'published',
  RETRACTED = 'retracted',
  CORRECTED = 'corrected',
  ARCHIVED = 'archived',
}

export interface AuditEntry {
  auditId: string;
  timestamp: Date;
  actor: string;  // User ID or system name
  action: AuditAction;
  objectType: 'report' | 'ioc' | 'detection' | 'approval' | 'policy';
  objectId: string;

  changes?: {
    fieldName: string;
    previousValue?: any;
    newValue?: any;
  }[];

  reason?: string;  // Why was this action taken?
  approver?: string;  // If action required approval
  approvedAt?: Date;

  ipAddress?: string;
  userAgent?: string;
}

export interface AuditLog {
  objectId: string;
  objectType: string;
  entries: AuditEntry[];
}

// ============================================================================
// VERSIONING TYPES
// ============================================================================

export interface VersionDiff {
  fieldChanges: {
    fieldName: string;
    previousValue?: any;
    newValue?: any;
    changeType: 'added' | 'removed' | 'modified';
  }[];

  iocChanges: {
    added: string[];  // IOC IDs
    removed: string[];
    modified: string[];
  };

  detectionChanges: {
    added: string[];  // Detection IDs
    removed: string[];
    modified: string[];
  };

  techniqueChanges: {
    added: string[];  // Technique IDs
    removed: string[];
  };
}

export interface IntelligenceVersion {
  versionId: string;
  objectType: 'report' | 'ioc' | 'detection' | 'malware';
  objectId: string;

  version: number;  // v1, v2, v3, etc.

  publishedDate: Date;
  revisedDate?: Date;
  analyst: string;

  changesSummary: string;

  content: any;  // Full object content at this version

  diff: VersionDiff;
  previousVersionId?: string;

  isPublished: boolean;
  isArchived: boolean;
  isRetracted: boolean;

  retractedReason?: string;
  retractedBy?: string;
  retractedAt?: Date;
}

export interface VersionHistory {
  objectId: string;
  objectType: string;
  versions: IntelligenceVersion[];
  currentVersion: number;
  canRollback: boolean;
}

// ============================================================================
// POLICY TYPES
// ============================================================================

export interface PublicationPolicy {
  policyId: string;
  name: string;
  description: string;

  // Thresholds
  minimumConfidenceRequired: number;  // 0-100
  minimumQualityScoreRequired: number;  // 0-100
  minimumReviewsRequired: number;
  requirePeerReview: boolean;
  requireSecurityReview: boolean;

  // Mandatory fields
  mandatoryFields: string[];

  // IOC requirements
  minimumIOCsRequired: number;
  requireIOCValidation: boolean;

  // Detection requirements
  requireDetectionRules: boolean;
  minimumDetectionCoverage: number;  // Percentage

  // MITRE requirements
  requireMITREMapping: boolean;
  minimumTechniquesRequired: number;

  // Reference requirements
  minimumReferencesRequired: number;

  // Freshness
  maximumAgeInDays: number;

  // Evidence requirements
  requireEvidenceAttribution: boolean;
  minimumEvidencePerClaim: number;

  active: boolean;
  createdAt: Date;
  updatedAt: Date;
  updatedBy: string;
}

export interface PolicyEvaluationResult {
  policyId: string;
  objectId: string;
  passed: boolean;
  violations: PolicyViolation[];
  canPublish: boolean;
  timestamp: Date;
}

export interface PolicyViolation {
  rule: string;
  severity: GateSeverity;
  message: string;
  currentValue?: any;
  requiredValue?: any;
}

// ============================================================================
// ROLLBACK & RETRACTION TYPES
// ============================================================================

export interface RetractionRecord {
  retractionId: string;
  objectId: string;
  objectType: string;
  publishedVersionId: string;

  reason: string;
  severity: 'low' | 'medium' | 'high' | 'critical';

  retractionDetails: string;
  affectedItems: string[];  // What was incorrect

  retractedBy: string;
  retractedAt: Date;

  correctionVersion?: string;  // If corrected and re-published

  notificationsSent: {
    channel: 'email' | 'api' | 'dashboard';
    sentAt: Date;
    recipients: number;
  }[];
}

// ============================================================================
// PUBLISHING TYPES
// ============================================================================

export enum PublishDestination {
  API = 'api',
  BLOG = 'blog',
  RSS = 'rss',
  DASHBOARD = 'dashboard',
  SEARCH_INDEX = 'search_index',
  ARCHIVE = 'archive',
}

export interface PublishingRecord {
  publishingId: string;
  objectId: string;
  objectType: string;
  versionId: string;

  publishedAt: Date;
  publishedBy: string;

  destinations: PublishDestination[];

  renderings: {
    format: 'markdown' | 'html' | 'json' | 'xml';
    content: string;
    renderedAt: Date;
  }[];

  isLive: boolean;
  viewCount?: number;
}

// ============================================================================
// GOVERNANCE SUMMARY
// ============================================================================

export interface GovernanceStatus {
  objectId: string;
  objectType: string;

  currentState: WorkflowState;

  qualityScore: IntelligenceQualityScore;
  confidenceScore: MultidimensionalConfidence;

  approvalChain: ApprovalChain;

  requiredApprovals: Approval[];
  completedApprovals: Approval[];

  qualityGateResults: QualityGateResult;
  policyEvaluation: PolicyEvaluationResult;

  canPublish: boolean;
  publishBlockers: string[];  // Reasons why it can't publish

  publishingStatus?: PublishingRecord;

  versionHistory: VersionHistory;
  auditLog: AuditLog;

  lastUpdated: Date;
}
