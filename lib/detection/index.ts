/**
 * SENTINEL APEX Detection Engineering - Public API
 * Central export point for all detection rule generation and management
 */

// Schemas
export type {
  SigmaLogsource,
  SigmaDetectionField,
  SigmaDetection,
  SigmaRule,
  YaraString,
  YaraMetadata,
  YaraRule,
  SuricataFlow,
  SuricataContent,
  SuricataRule,
  SEMRuleField,
  SEMRule,
  RuleMetadata,
  DetectionRule,
  DetectionRuleCollection,
  GenerateDetectionRequest,
  GenerateDetectionResponse,
  DetectionRuleExport,
  DetectionSearchQuery,
  DeduplicationResult,
  OptimizationMetrics,
  RuleValidationError,
  RuleValidationResult,
} from './schema';

export {
  DetectionFormat,
  RuleSeverity,
  DetectionBehavior,
} from './schema';

// Validators
export {
  validateSigmaRule,
  validateYaraRule,
  validateSuricataRule,
  validateSEMRule,
  validateDetectionRule,
} from './validators';

// Generators
export {
  generateSigmaFromIOC,
  generateSigmaRuleSet,
} from './generators/sigma';

export {
  generateYaraFromIOC,
  generateYaraRuleSet,
} from './generators/yara';

export {
  generateSuricataFromIOC,
  generateSuricataRuleSet,
  formatSuricataRule,
} from './generators/suricata';

export {
  generateSEMRuleFromIOC,
  generateSEMRuleSet,
} from './generators/siem';

export type {
  SigmaGeneratorOptions,
  IOCForGeneration as SigmaIOCForGeneration,
  YaraGeneratorOptions,
  IOCForYaraGeneration,
  SuricataGeneratorOptions,
  IOCForSuricataGeneration,
  SEMGeneratorOptions,
  IOCForSEMGeneration,
} from './generators/sigma';

// Correlator
export {
  mapBehaviorToTechniques,
  linkRulesToMalware,
  linkRulesToTechniques,
  linkRulesToCampaigns,
  linkRulesToActors,
  calculateRuleCoverage,
  buildDetectionCollection,
  prioritizeRules,
  calculateRuleEffectiveness,
} from './correlator';

export type {
  TechniqueMapping,
  CoverageAnalysis,
  RulePriority,
  RuleEffectiveness,
} from './correlator';

// Optimizer
export {
  deduplicateRules,
  optimizeSigmaLogsources,
  optimizeYaraStrings,
  consolidateSuricataRules,
  calculateIOCCoverage,
  analyzeFalsePositives,
  optimizeRuleSet,
  profileRulePerformance,
} from './optimizer';

export type {
  IOCCoverage,
  FPAnalysis,
  RulePerformanceProfile,
} from './optimizer';

// Renderer
export {
  renderSigmaYAML,
  renderSigmaCollection,
  renderYaraRule,
  renderYaraCollection,
  renderSuricataCollection,
  renderSplunkQueries,
  renderELKQueries,
  renderSentinelKQL,
  renderDetectionRuleMarkdown,
  renderDetectionRuleExport,
  exportDetectionRuleBundle,
  renderDetectionRuleHTML,
} from './renderer';
