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
