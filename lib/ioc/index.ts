/**
 * SENTINEL APEX IOC Intelligence Engine - Public API
 * Central export point for all IOC processing functionality
 */

export { IOCIntelligenceEngine, createIOCEngine } from './engine';

export { normalizeIOC, normalizationRules } from './normalizers';

export { validateIOC, validationRules } from './validators';

export { DeduplicationEngine, deduplicate } from './deduplication';

export {
  aggregateConfidence,
  scoreEvidence,
  calculateCorrelationConfidence,
  calculateCompositeScore,
  formatConfidenceExplanation,
} from './confidence';

export { RelationshipGraph, createEntityRelationship, deduplicateRelationships } from './relationships';

export { CorrelationEngine, createCorrelationEngine } from './correlator';

export type {
  NormalizedIOC,
  IOCNormalizationResult,
  IOCValidationResult,
  IOCWithMetadata,
  IOCRelationship,
  IOCCorrelationResult,
  IOCSearchQuery,
  IOCDeduplicationConfig,
  NormalizationRule,
  ValidationRule,
} from './types';

export type { ConfidenceComponents } from './confidence';
export type { DeduplicationResult } from './deduplication';
