# Module Ownership & Responsibility Map

**Status:** RC1 Certification  
**Last Updated:** 2026-07-30  

---

## Module Ownership Structure

Each module has a single owner responsible for:
- Correctness and test coverage
- Backward compatibility
- Performance characteristics
- Documentation and examples
- Breaking change decisions

---

## Phase 1A — Malware Intelligence Model

### lib/intelligence/schema.ts
**Owner:** Core Intelligence Team  
**Responsibility:** Define malware intelligence data model  
**Stability:** **Immutable** (foundation)

**Public Exports:**
```typescript
// Enums
export enum ConfidenceLevel { }
export enum IOCType { }
export enum Platform { }
export enum MalwareType { }

// Core types
export type Evidence { }
export type Reference { }
export type IOC { }
export type MitreTechnique { }
export type ThreatActor { }
export type Campaign { }
export type MalwareVariant { }
export type MalwareFamily { }
export type DetectionRule { }
export type ReportMetadata { }
export type MalwareIntelligenceSummary { }

// Knowledge graph
export type KnowledgeGraphNode { }
export type KnowledgeGraphEdge { }
export type KnowledgeGraph { }
```

**Consumers:**
- lib/reporting/* (all)
- lib/detection/* (all)
- lib/ioc/* (validators)
- types/index.ts (re-export)

**Change Policy:**
- Adding new fields to existing types: **Backward compatible**
- Removing fields: **Breaking change** (major version)
- Adding enum values: **Backward compatible**
- Reordering enum values: **Breaking change**

### lib/intelligence/validators.ts
**Owner:** Core Intelligence Team  
**Responsibility:** Zod schema validation, transformation

**Public Exports:**
```typescript
export const ConfidenceLevelSchema = z.enum([...])
export const IOCSchema = z.object({ ... })
export const MitreTechniqueSchema = z.object({ ... })
// ... more schemas

export function validateMalwareFamily(data: any): ValidatedMalwareFamily
export function validateIOC(data: any): ValidatedIOC
```

**Consumers:**
- lib/reporting/report-engine.ts
- lib/ioc/validators.ts
- Custom validation code

**Test Coverage:** 40+ test cases per type

---

## Phase 1B — Report Engine

### lib/reporting/report-engine.ts
**Owner:** Report Generation Team  
**Responsibility:** Orchestrate report generation pipeline

**Public Class:**
```typescript
export class ReportEngine {
  async generateReport(metadata, malwareFamily, options?)
  async validateReport(report): Promise<ValidationResult>
}

export const generateReport = (metadata, family) => Promise<MalwareReport>
```

**Consumers:**
- lib/api/intelligence-reports.ts
- Custom report generation

**Dependencies:**
- `../intelligence/validators` (Phase 1A)
- `./report-builder`
- `./metadata`
- `./renderers`
- `./seo`

**Change Policy:**
- Constructor signature: **Stable**
- Method return types: **Stable**
- Adding methods: **Backward compatible**

**Test Coverage:**
- End-to-end report generation: 15+ tests
- Validation: 10+ tests
- Error handling: 8+ tests

### lib/reporting/report-builder.ts
**Owner:** Report Generation Team  
**Responsibility:** Chainable API for report construction

**Public Class:**
```typescript
export class ReportBuilder {
  buildExecutiveSummary()
  buildThreatOverview()
  buildMitreMappings()
  buildIOCIntelligence()
  buildDetectionEngineering()
  buildThreatActorAttribution()
  buildCampaignAnalysis()
  buildRecommendations()
  toReport(): MalwareReport
}
```

**Consumers:**
- lib/reporting/report-engine.ts
- Custom report builders

**Dependencies:**
- `./confidence` (report-specific)
- `./references`

**Change Policy:**
- Method order: **Can change** (fluent API)
- Method names: **Stable**
- Adding methods: **Backward compatible**

### lib/reporting/renderers.ts
**Owner:** Report Generation Team  
**Responsibility:** Multi-format output rendering

**Public Classes:**
```typescript
export interface Renderer { render(report: MalwareReport): string }
export class MarkdownRenderer implements Renderer { }
export class HTMLRenderer implements Renderer { }
export class JSONRenderer implements Renderer { }
export function getRenderer(format): Renderer
```

**Consumers:**
- lib/reporting/report-engine.ts
- Custom rendering

**Output Formats:**
- **Markdown** → Blog publishing
- **HTML** → Dashboard display
- **JSON** → API responses
- **STIX** (planned Phase 2D)
- **TAXII** (planned Phase 2D)

**Change Policy:**
- Adding new Renderer implementations: **Backward compatible**
- Changing output format: **Document in changelog**
- Output schema: **Freeze in v1 APIs**

### lib/reporting/metadata.ts
**Owner:** Report Generation Team  
**Responsibility:** Extract/generate report metadata

**Public Functions:**
```typescript
export function generateMetadata(report): MalwareReportMetadata
export function generateFrontmatter(report, metadata): string
export function formatFrontmatterYAML(frontmatter): string
```

**Consumers:**
- lib/reporting/report-engine.ts

### lib/reporting/seo.ts
**Owner:** Report Generation Team  
**Responsibility:** SEO metadata and structured data generation

**Public Functions:**
```typescript
export function generateSEOMetadata(report): SEOMetadata
export function generateStructuredData(report, metadata): StructuredData
```

**Consumers:**
- lib/reporting/report-engine.ts
- Blog publishing pipeline

### lib/reporting/references.ts
**Owner:** Report Generation Team  
**Responsibility:** Citation and bibliography management

**Public Functions:**
```typescript
export function extractReferences(report)
export function formatBibliography(references, style)
```

**Consumers:**
- lib/reporting/report-builder.ts

### lib/reporting/confidence.ts
**Owner:** Report Generation Team  
**Responsibility:** Report-level confidence aggregation

**Public Functions:**
```typescript
export function calculateReportConfidence(evidence)
export function aggregateIOCConfidence(iocs)
```

**Consumers:**
- lib/reporting/renderers.ts
- lib/reporting/report-builder.ts

### lib/reporting/index.ts
**Owner:** Report Generation Team  
**Responsibility:** Public API surface

**Public Exports:**
```typescript
export { ReportEngine, generateReport } from './report-engine'
export { ReportBuilder } from './report-builder'
export { MarkdownRenderer, HTMLRenderer, JSONRenderer } from './renderers'
export { generateMetadata, generateFrontmatter, generateSEOMetadata } from '.'
export type { MalwareReport, ReportSection } from './report-builder'
```

---

## Phase 1C — IOC Intelligence Engine

### lib/ioc/engine.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** Orchestrate IOC processing

**Public Class:**
```typescript
export class IOCIntelligenceEngine {
  addIOC(ioc): IOC
  getIOC(id): IOC
  search(query): IOC[]
  deduplicate(strategy): IOC[]
  correlate(): IOCCorrelationResult
  relationships(iocId): IOCRelationship[]
  stats(): Record<string, any>
  export(format): string
}

export const createIOCEngine = () => IOCIntelligenceEngine
```

**Consumers:**
- lib/reporting/report-engine.ts
- lib/detection/* (all)
- Custom IOC processing

**Dependencies:**
- `./normalizers`
- `./validators`
- `./deduplication`
- `./correlator`
- `./confidence`
- `./relationships`

**Change Policy:**
- Core methods (addIOC, getIOC, search): **Stable**
- Return types: **Stable**
- Adding methods: **Backward compatible**

**Test Coverage:**
- All 18 IOC types: 50+ tests
- Normalization: 36 tests (2 per type)
- Validation: 36 tests
- Deduplication: 15+ tests
- Correlation: 20+ tests
- Performance: 5+ benchmarks

### lib/ioc/normalizers.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** Normalize 18 IOC types to canonical form

**Public Functions:**
```typescript
export function normalizeIOC(type: IOCType, value: string): string
export const normalizationRules: Record<IOCType, Function>
```

**Rules (per IOC type):**
- **SHA256/SHA1/MD5**: Uppercase
- **Domain**: Lowercase, strip http(s)://
- **Email**: Lowercase
- **URL**: Normalize scheme, lowercase host, decode path
- **IPv4**: Validate octets
- **IPv6**: Compress zero groups
- **Registry**: Uppercase
- **File Path**: Normalize separators
- **Process Name**: Lowercase
- **API Call**: Normalize format
- **JA3/JA4**: Uppercase
- **Certificate**: Normalize format
- **ASN**: Extract number
- **Port**: Validate range
- **CIDR**: Normalize notation
- **MAC Address**: Uppercase, standard format
- **User Agent**: Canonical string
- **Mutex**: Normalize format

**Test Coverage:** 2 tests per type (36 total)

### lib/ioc/validators.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** Validate IOC syntax and format

**Public Functions:**
```typescript
export function validateIOC(type: IOCType, value: string): boolean
export const validationRules: Record<IOCType, RegExp | Function>
```

**Validation Rules:**
- **Hashes**: Length and character constraints
- **Domains**: DNS naming rules
- **URLs**: RFC 3986 compliance
- **IPs**: Octet ranges, IPv6 compression
- **Email**: RFC 5322 subset
- **Registry**: Windows registry path format
- **JA3/JA4**: Checksum validation

**Test Coverage:** 36+ tests (comprehensive)

### lib/ioc/confidence.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** IOC-level confidence scoring

**Public Functions:**
```typescript
export function aggregateConfidence(
  sourceReliability: number,
  observationQuality: number,
  analystVerification: number,
  independentCorroboration: number
): number

export function scoreEvidence(evidence): number
```

### lib/ioc/correlator.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** Link IOCs to malware, campaigns, actors

**Public Functions:**
```typescript
export function createCorrelationEngine()
export class CorrelationEngine {
  correlate(ioc1, ioc2): CorrelationResult
  findRelated(ioc, type): IOC[]
}
```

### lib/ioc/deduplication.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** Identify and merge duplicate IOCs

**Public Functions:**
```typescript
export class DeduplicationEngine {
  identify(iocs): DuplicateGroup[]
  merge(group, strategy): IOC
}
```

**Strategies:**
- `first_seen`: Keep earliest observation
- `highest_confidence`: Keep highest confidence
- `most_evidence`: Keep most supported

### lib/ioc/relationships.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** Model IOC relationships

**Public Functions:**
```typescript
export class RelationshipGraph {
  addEdge(ioc1, ioc2, relationship)
  getRelationships(ioc): IOCRelationship[]
  findPath(ioc1, ioc2): IOCRelationship[]
}
```

### lib/ioc/types.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** TypeScript interfaces

**Exports:**
```typescript
export interface IOCWithMetadata { }
export interface IOCRelationship { }
export interface IOCCorrelationResult { }
export interface IOCSearchQuery { }
```

### lib/ioc/index.ts
**Owner:** IOC Intelligence Team  
**Responsibility:** Public API surface

---

## Phase 1D — Detection Engineering

### lib/detection/schema.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Detection rule type definitions

**Public Types:**
```typescript
export interface DetectionRule { }
export interface SigmaRule { }
export interface YaraRule { }
export interface SuricataRule { }
export interface SEMRule { }
export enum DetectionFormat { }
export enum RuleSeverity { }
```

### lib/detection/generators/sigma.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Sigma YAML rule generation

**Public Functions:**
```typescript
export function generateSigmaFromIOC(ioc: IOC): SigmaRule
export function generateSigmaFromTechnique(technique: MitreTechnique): SigmaRule[]
```

### lib/detection/generators/yara.ts
**Owner:** Detection Engineering Team  
**Responsibility:** YARA rule generation

**Public Functions:**
```typescript
export function generateYaraFromIOC(ioc: IOC): YaraRule
export function generateYaraFromBehavior(behavior: string): YaraRule
```

### lib/detection/generators/suricata.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Suricata network rule generation

**Public Functions:**
```typescript
export function generateSuricataFromIOC(ioc: IOC): SuricataRule
export function generateSuricataFromTechnique(technique: MitreTechnique): SuricataRule[]
```

### lib/detection/generators/siem.ts
**Owner:** Detection Engineering Team  
**Responsibility:** SIEM platform rule generation

**Supported Platforms:**
- Splunk SPL
- Elastic (ELK) KQL
- Azure Sentinel KQL
- ArcSight AEL

**Public Functions:**
```typescript
export function generateSplunkFromIOC(ioc: IOC): string
export function generateSentinelFromIOC(ioc: IOC): string
export function generateElasticFromIOC(ioc: IOC): string
export function generateArcSightFromIOC(ioc: IOC): string
```

### lib/detection/validators.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Rule format validation

**Public Functions:**
```typescript
export function validateDetectionRule(rule: DetectionRule): ValidationResult
export function validateSigmaRule(yaml: string): ValidationResult
export function validateYaraRule(text: string): ValidationResult
export function validateSuricataRule(text: string): ValidationResult
```

### lib/detection/optimizer.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Rule optimization and deduplication

**Public Functions:**
```typescript
export function deduplicateRules(rules: DetectionRule[]): DetectionRule[]
export function optimizeSigmaLogsources(rules: SigmaRule[]): SigmaRule[]
export function optimizeYaraStrings(rule: YaraRule): YaraRule
export function consolidateSuricataRules(rules: SuricataRule[]): SuricataRule[]
```

### lib/detection/correlator.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Link rules to techniques, malware, campaigns

**Public Functions:**
```typescript
export function linkRulesToMalware(rules: DetectionRule[], malware: MalwareFamily)
export function linkRulesToTechniques(rules: DetectionRule[], techniques: MitreTechnique[])
export function calculateRuleCoverage(rules: DetectionRule[]): CoverageAnalysis
```

### lib/detection/renderer.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Multi-format rule export

**Public Functions:**
```typescript
export function renderDetectionRuleExport(
  rules: DetectionRule[],
  format: DetectionFormat
): string

export function exportDetectionRuleBundle(
  rules: DetectionRule[],
  formats: DetectionFormat[]
): Record<DetectionFormat, string>
```

### lib/detection/index.ts
**Owner:** Detection Engineering Team  
**Responsibility:** Public API surface

---

## Phase 2A — Intelligence Governance Layer

### lib/governance/types.ts
**Owner:** Governance Team  
**Responsibility:** Governance type definitions

**Public Types:**
```typescript
// Enums
export enum WorkflowState { }
export enum ApprovalRole { }
export enum ApprovalStatus { }
export enum GateSeverity { }
export enum AuditAction { }
export enum PublishDestination { }

// Interfaces
export interface WorkflowTransition { }
export interface Approval { }
export interface ApprovalChain { }
export interface ValidationResult { }
export interface MultidimensionalConfidence { }
export interface IntelligenceVersion { }
export interface PublishingRecord { }
// ... 30+ more types
```

**Stability:** **Immutable** (type foundation)

### lib/governance/workflow.ts
**Owner:** Governance Team  
**Responsibility:** 15-state workflow state machine

**Public Class:**
```typescript
export class WorkflowEngine {
  canTransition(from, to): boolean
  transitionState(objectId, from, to, actor, reason): WorkflowTransition
  getCurrentState(objectId): WorkflowState
  getTransitionHistory(objectId): WorkflowTransition[]
  resetToDraft(objectId, actor, reason): WorkflowTransition
  getWorkflowStats(objectIds): WorkflowStatistics
}

export const workflowEngine = new WorkflowEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/approvals.ts
**Owner:** Governance Team  
**Responsibility:** 4-role approval hierarchy

**Public Class:**
```typescript
export class ApprovalManager {
  createApprovalChain(objectId, type, roles): ApprovalChain
  approve(approvalId, approver, notes): Approval
  reject(approvalId, rejector, reason): Approval
  approveConditional(approvalId, approver, notes): Approval
  getPendingApprovals(role?): Approval[]
  getApprovalStats(): ApprovalStatistics
}

export const approvalManager = new ApprovalManager()
export const DEFAULT_APPROVAL_CHAINS: Record<string, ApprovalRole[]>
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/quality-gates.ts
**Owner:** Governance Team  
**Responsibility:** Extensible quality gate validators

**Public Class:**
```typescript
export class QualityGatesEngine {
  registerGate(gate: QualityGate): void
  validateObject(type, object): QualityGateResult
  getAllGates(): QualityGate[]
  getGatesForType(type): QualityGate[]
}

export const qualityGatesEngine = new QualityGatesEngine()
```

**Built-in Gates:**
- `report_missing_metadata` (ERROR)
- `report_missing_iocs` (ERROR)
- `report_missing_mitre` (ERROR)
- `report_missing_evidence` (ERROR)
- `report_missing_references` (ERROR)
- `ioc_missing_metadata` (ERROR)
- `detection_missing_evidence` (ERROR)
- `object_missing_id` (ERROR)
- `object_missing_timestamp` (ERROR)

**Stability:** **Stable** (RC1 ready)

### lib/governance/confidence-engine.ts
**Owner:** Governance Team  
**Responsibility:** Multidimensional confidence scoring

**Public Class:**
```typescript
export class ConfidenceEngine {
  calculateConfidence(
    objectId, sourceReliability, observationQuality,
    technicalValidation, analystVerification,
    independentCorroboration, reasoning
  ): MultidimensionalConfidence

  updateComponent(objectId, component, newValue, reasoning): MultidimensionalConfidence
  getCurrentConfidence(objectId): MultidimensionalConfidence
  getConfidenceTrend(objectId): 'increasing' | 'decreasing' | 'stable'
  meetsThreshold(objectId, threshold): boolean
}

export const confidenceEngine = new ConfidenceEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/audit.ts
**Owner:** Governance Team  
**Responsibility:** Immutable audit trail

**Public Class:**
```typescript
export class AuditEngine {
  recordEntry(actor, action, objectType, objectId, changes, reason, approver): AuditEntry
  getAuditLog(objectId): AuditLog
  getEntries(objectId): AuditEntry[]
  getFieldChangeHistory(objectId, fieldName): AuditEntry[]
  verifyIntegrity(objectId): IntegrityResult
  generateAuditReport(objectId): string
}

export const auditEngine = new AuditEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/versioning.ts
**Owner:** Governance Team  
**Responsibility:** Version control with diffs

**Public Class:**
```typescript
export class VersioningEngine {
  createVersion(objectType, objectId, version, content, analyst, summary, diff): IntelligenceVersion
  getVersion(versionId): IntelligenceVersion
  getVersionHistory(objectId): VersionHistory
  publishVersion(versionId, publishedBy): IntelligenceVersion
  getVersionChangelog(objectId): Changelog[]
  canRollback(objectId, targetVersion): boolean
  rollback(objectId, targetVersion, reason, rolledBackBy): RollbackResult
}

export const versioningEngine = new VersioningEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/rollback.ts
**Owner:** Governance Team  
**Responsibility:** Retraction and correction handling

**Public Class:**
```typescript
export class RollbackEngine {
  retract(objectId, type, versionId, reason, severity, details, items, retractedBy): RetractionRecord
  getRetraction(retractionId): RetractionRecord
  markCorrected(retractionId, correctionVersionId): RetractionRecord
  getCorrectionHistory(objectId): RetractionRecord[]
  generateRetractionReport(objectId): string
}

export const rollbackEngine = new RollbackEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/publishing.ts
**Owner:** Governance Team  
**Responsibility:** Multi-destination publication

**Public Class:**
```typescript
export class PublishingEngine {
  publish(objectId, type, versionId, publishedBy, destinations, renderings): PublishingRecord
  getPublishingRecord(publishingId): PublishingRecord
  updateViewCount(publishingId, count): PublishingRecord
  unpublishFromDestination(publishingId, destination): PublishingRecord
  getMostPopular(limit): PopularObjects[]
  getPublicationStats(): PublicationStatistics
}

export const publishingEngine = new PublishingEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/policy-engine.ts
**Owner:** Governance Team  
**Responsibility:** Configurable publication policies

**Public Class:**
```typescript
export class PolicyEngine {
  createPolicy(
    name, description, minConfidence, minQuality,
    minReviews, requirePeer, requireSecurity, ...
  ): PublicationPolicy

  evaluatePolicy(policyId, objectId, object): PolicyEvaluationResult
  passesAllPolicies(objectId, object): boolean
  disablePolicy(policyId, updatedBy): PublicationPolicy
  getPolicyStats(): PolicyStatistics
}

export const policyEngine = new PolicyEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/reviewers.ts
**Owner:** Governance Team  
**Responsibility:** Reviewer management and assignment

**Public Class:**
```typescript
export class ReviewerEngine {
  registerReviewer(name, email, roles, expertise): ReviewerCredentials
  getReviewersByRole(role): ReviewerCredentials[]
  getReviewersByExpertise(expertise): ReviewerCredentials[]
  recordReview(reviewerId, approved, timeMs): ReviewerStats
  findBestReviewerForRole(role, expertise?): ReviewerCredentials
  getTopApprovers(limit): TopApprover[]
}

export const reviewerEngine = new ReviewerEngine()
```

**Stability:** **Stable** (RC1 ready)

### lib/governance/index.ts
**Owner:** Governance Team  
**Responsibility:** Public API surface

---

## API Layer

### lib/api/intelligence-reports.ts
**Owner:** API Team  
**Responsibility:** HTTP endpoints for reports

**Public Endpoints:**
```
POST   /api/v1/reports/generate
GET    /api/v1/reports/{id}
GET    /api/v1/reports/{id}/versions
GET    /api/v1/reports/{id}/audit-log
POST   /api/v1/reports/{id}/publish
POST   /api/v1/reports/{id}/retract
```

**Dependencies:**
- `../reporting/report-engine`

**Stability:** **Frozen** (v1 contract)

### lib/api/detection-rules.ts
**Owner:** API Team  
**Responsibility:** HTTP endpoints for detection rules

**Public Endpoints:**
```
POST   /api/v1/detections/generate
GET    /api/v1/detections/search
POST   /api/v1/detections/export
GET    /api/v1/detections/{id}/coverage
GET    /api/v1/detections/stats
```

**Dependencies:**
- `../detection/index`

**Stability:** **Frozen** (v1 contract)

---

## Responsibility Summary

| Team | Modules | Stability | Critical Path |
|------|---------|-----------|---|
| Core Intelligence | intelligence/* | Immutable | Foundation |
| IOC Intelligence | ioc/* | Stable | Critical |
| Report Generation | reporting/* | Stable | Critical |
| Detection Engineering | detection/* | Stable | Critical |
| Governance | governance/* | Stable | Critical |
| API Gateway | api/* | Frozen | Release Gate |

---

## Decision Rights

| Decision Type | Owner | Approval Required |
|---|---|---|
| Add new IOC type | IOC Intelligence Team | Governance Team |
| Modify validation logic | (Module Owner) | Architecture Review |
| Add new workflow state | Governance Team | API Team |
| Change API response schema | API Team | Product Lead |
| Add new detection format | Detection Engineering Team | Governance Team |
| Breaking change to public API | (Module Owner) | Architecture Review, Release Manager |

---

## Handoff Criteria for New Owners

When transferring ownership of a module:

1. **Current owner** provides 2-week overlap period
2. **New owner** completes all unit tests
3. **Architecture review** verifies no regressions
4. **Documentation** is updated with new owner
5. **Commit history** reviewed for context

