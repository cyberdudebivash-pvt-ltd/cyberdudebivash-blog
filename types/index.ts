/**
 * SENTINEL APEX Type Definitions
 * Central export point for all TypeScript types used across the platform
 */

// Re-export all malware intelligence types
export type {
  ConfidenceLevel,
  Evidence,
  Reference,
  IOC,
  MitreTechnique,
  ThreatActor,
  Campaign,
  MalwareVariant,
  MalwareFamily,
  DetectionRule,
  ReportMetadata,
  MalwareIntelligenceSummary,
  KnowledgeGraphNode,
  KnowledgeGraphEdge,
  KnowledgeGraph,
  KnowledgeGraphEntityType,
} from '../lib/intelligence/schema';

export {
  IOCType,
  Platform,
  MalwareType,
} from '../lib/intelligence/schema';

// Re-export validators for external use
export {
  ConfidenceLevelSchema,
  IOCTypeSchema,
  PlatformSchema,
  MalwareTypeSchema,
  EvidenceSchema,
  ReferenceSchema,
  IOCSchema,
  MitreTechniqueSchema,
  ThreatActorSchema,
  CampaignSchema,
  MalwareVariantSchema,
  MalwareFamilySchema,
  ReportMetadataSchema,
  DetectionRuleSchema,
  MalwareIntelligenceSummarySchema,
  KnowledgeGraphNodeSchema,
  KnowledgeGraphEdgeSchema,
  KnowledgeGraphSchema,
  validateMalwareFamily,
  validateMalwareFamilySafe,
  validateIOC,
  validateReportMetadata,
  validateKnowledgeGraph,
} from '../lib/intelligence/validators';

export type {
  ValidatedMalwareFamily,
  ValidatedIOC,
  ValidatedEvidence,
  ValidatedMitreTechnique,
  ValidatedThreatActor,
  ValidatedCampaign,
  ValidatedReportMetadata,
  ValidatedDetectionRule,
  ValidatedKnowledgeGraph,
} from '../lib/intelligence/validators';

// Re-export reporting engine types and functions
export {
  ReportEngine,
  generateReport,
} from '../lib/reporting/report-engine';

export type {
  ReportOutput,
  ReportValidationError,
} from '../lib/reporting/report-engine';

export {
  ReportBuilder,
} from '../lib/reporting/report-builder';

export type {
  MalwareReport,
  ReportSection,
} from '../lib/reporting/report-builder';

export {
  MarkdownRenderer,
  HTMLRenderer,
  JSONRenderer,
  getRenderer,
} from '../lib/reporting/renderers';

export type {
  Renderer,
} from '../lib/reporting/renderers';

export {
  generateMetadata,
  generateFrontmatter,
  formatFrontmatterYAML,
  generateSEOMetadata,
  generateStructuredData,
} from '../lib/reporting';

export type {
  MalwareReportMetadata,
  Frontmatter,
  SEOMetadata,
} from '../lib/reporting';

// Re-export Intelligence Governance Layer types and functions
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
} from '../lib/governance';

export {
  WorkflowEngine,
  workflowEngine,
  getStateDisplayName,
  getStateColor,
  isValidationState,
  isReviewState,
  isPublishedState,
  canPublish,
  ApprovalManager,
  approvalManager,
  DEFAULT_APPROVAL_CHAINS,
  createDefaultApprovalChain,
  QualityGatesEngine,
  qualityGatesEngine,
  ConfidenceEngine,
  confidenceEngine,
  AuditEngine,
  auditEngine,
  VersioningEngine,
  versioningEngine,
  RollbackEngine,
  rollbackEngine,
  PublishingEngine,
  publishingEngine,
  PolicyEngine,
  policyEngine,
  ReviewerEngine,
  reviewerEngine,
} from '../lib/governance';

// Re-export IOC Intelligence Engine types and functions
export {
  createIOCEngine,
  normalizeIOC,
  validateIOC as validateIOCValue,
  aggregateConfidence,
  scoreEvidence,
  calculateCorrelationConfidence,
  calculateCompositeScore,
  deduplicate,
  createCorrelationEngine,
} from '../lib/ioc';

export type {
  NormalizedIOC,
  IOCNormalizationResult,
  IOCValidationResult,
  IOCWithMetadata,
  IOCRelationship,
  IOCCorrelationResult,
  IOCSearchQuery,
  IOCDeduplicationConfig,
  ConfidenceComponents,
} from '../lib/ioc';

// Re-export detection engineering types and functions
export type {
  SigmaRule,
  YaraRule,
  SuricataRule,
  SEMRule,
  DetectionRuleCollection,
  GenerateDetectionRequest,
  GenerateDetectionResponse,
  DetectionRuleExport,
  DetectionSearchQuery,
  RuleValidationResult,
  DeduplicationResult,
  OptimizationMetrics,
} from '../lib/detection/schema';

export {
  DetectionFormat,
  RuleSeverity,
  DetectionBehavior,
  generateSigmaFromIOC,
  generateYaraFromIOC,
  generateSuricataFromIOC,
  generateSEMRuleFromIOC,
  validateDetectionRule,
  validateSigmaRule,
  validateYaraRule,
  validateSuricataRule,
  validateSEMRule,
  deduplicateRules,
  optimizeSigmaLogsources,
  optimizeYaraStrings,
  consolidateSuricataRules,
  renderDetectionRuleExport,
  exportDetectionRuleBundle,
  buildDetectionCollection,
  mapBehaviorToTechniques,
  linkRulesToMalware,
  linkRulesToTechniques,
  linkRulesToCampaigns,
  linkRulesToActors,
  calculateRuleCoverage,
  prioritizeRules,
  calculateRuleEffectiveness,
} from '../lib/detection/index';

export type {
  TechniqueMapping,
  CoverageAnalysis,
  RulePriority,
  RuleEffectiveness,
  IOCCoverage,
  FPAnalysis,
  RulePerformanceProfile,
} from '../lib/detection/index';
