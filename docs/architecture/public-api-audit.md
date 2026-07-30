# Public API Surface Audit

**Status:** RC1 Certification  
**Date:** 2026-07-30  
**Scope:** All exported symbols across Sentinel APEX  

---

## API Stability Classification

```
IMMUTABLE   → Foundation layer, never breaking changes
STABLE      → Core functionality, rare breaking changes
FROZEN      → v1 contract, all breaking changes = v2+
EXPERIMENTAL → Not for production use
DEPRECATED  → Phase-out in progress, use alternative
```

---

## Phase 1A — Intelligence Schema (IMMUTABLE)

**Module:** `lib/intelligence/schema.ts`  
**Consumers:** All phases, all consumers  
**Stability:** **IMMUTABLE**

### Enums (IMMUTABLE)

```typescript
export enum ConfidenceLevel {
  UNVERIFIED = 'unverified',
  PROBABLE = 'probable',
  VERIFIED = 'verified',
}

export enum IOCType {
  SHA256 = 'sha256',
  SHA1 = 'sha1',
  MD5 = 'md5',
  DOMAIN = 'domain',
  EMAIL = 'email',
  URL = 'url',
  IPV4 = 'ipv4',
  IPV6 = 'ipv6',
  REGISTRY = 'registry',
  FILE_PATH = 'file_path',
  PROCESS_NAME = 'process_name',
  API_CALL = 'api_call',
  JA3 = 'ja3',
  JA4 = 'ja4',
  CERTIFICATE = 'certificate',
  ASN = 'asn',
  PORT = 'port',
  CIDR = 'cidr',
  // Note: Adding new IOC type = minor version bump
}

export enum Platform {
  WINDOWS = 'windows',
  LINUX = 'linux',
  MACOS = 'macos',
  ANDROID = 'android',
  IOS = 'ios',
}

export enum MalwareType {
  TROJAN = 'trojan',
  RANSOMWARE = 'ransomware',
  WORM = 'worm',
  SPYWARE = 'spyware',
  ROOTKIT = 'rootkit',
  BACKDOOR = 'backdoor',
  DROPPER = 'dropper',
  LOADER = 'loader',
  STEALER = 'stealer',
  INFOSTEALER = 'infostealer',
  BOTNET = 'botnet',
  KEYLOGGER = 'keylogger',
  WEBSHELL = 'webshell',
  EXPLOIT = 'exploit',
  PACKER = 'packer',
  CRYPTOR = 'cryptor',
  REMOTE_ACCESS_TROJAN = 'remote_access_trojan',
}
```

**Change Policy:**
- Adding new enum values: **Minor version bump**
- Removing enum values: **Major version bump**
- Reordering enum values: **Major version bump** (breaks string comparisons)
- Renaming enum values: **Major version bump**

### Core Interfaces (IMMUTABLE)

```typescript
export interface Evidence {
  evidenceId: string;
  claim: string;
  source: {
    type: 'sample' | 'sandbox' | 'reverse_engineering' | 'cti_source' | 'analyst_observation';
    reference: string;
    collectedDate: Date;
    collectedBy: string;
  };
  confidence: 'verified' | 'probable' | 'suspected';
  reasoning: string;
}

export interface Reference {
  title: string;
  url: string;
  publishedDate?: Date;
  source?: string;
}

export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  confidence: ConfidenceLevel;
  firstSeen: Date;
  lastSeen: Date;
  validated: boolean;
  evidence?: Evidence[];
}

export interface MitreTechnique {
  id: string;  // T1234
  name: string;
  tactics: string[];
  description: string;
  mitigation?: string;
}

export interface DetectionRule {
  id: string;
  type: 'sigma' | 'yara' | 'suricata' | 'spl' | 'kql';
  content: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detects?: string[];  // IOC values detected
  techniques?: string[];  // MITRE technique IDs
}

export interface MalwareFamily {
  id: string;
  name: string;
  type: MalwareType[];
  description: string;
  aliases?: string[];
  firstSeen: Date;
  lastSeen: Date;
  iocs: IOC[];
  detectionRules?: DetectionRule[];
  techniques?: MitreTechnique[];
  threats?: ThreatActor[];
  campaigns?: Campaign[];
  samples?: string[];  // SHA256 hashes
}

export interface MalwareVariant {
  id: string;
  familyId: string;
  version: string;
  samples: string[];
  iocs: IOC[];
  techniques: MitreTechnique[];
  detectionRules: DetectionRule[];
  firstSeen: Date;
  changes: string;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  motivation: 'financial' | 'espionage' | 'hacktivism' | 'state-sponsored';
  firstSeen: Date;
  lastSeen: Date;
  campaigns: Campaign[];
  malware: MalwareFamily[];
  victims?: { sector?: string; country?: string }[];
}

export interface Campaign {
  id: string;
  name: string;
  description: string;
  operators: ThreatActor[];
  malware: MalwareFamily[];
  iocs: IOC[];
  startDate: Date;
  endDate?: Date;
  targets?: { sector?: string; country?: string }[];
}
```

**Change Policy:**
- Adding new fields: **Backward compatible** (consumers can ignore)
- Removing fields: **Major version bump**
- Changing field types: **Major version bump**
- Making optional fields required: **Major version bump**

### Knowledge Graph (IMMUTABLE)

```typescript
export type KnowledgeGraphEntityType = 
  | 'malware_family' 
  | 'malware_variant' 
  | 'threat_actor' 
  | 'campaign' 
  | 'ioc' 
  | 'detection_rule' 
  | 'mitre_technique';

export interface KnowledgeGraphNode {
  id: string;
  type: KnowledgeGraphEntityType;
  label: string;
  properties: Record<string, any>;
}

export interface KnowledgeGraphEdge {
  source: string;  // node ID
  target: string;  // node ID
  relationship: string;  // 'uses', 'implements', 'targets', etc.
  properties?: Record<string, any>;
}

export interface KnowledgeGraph {
  nodes: KnowledgeGraphNode[];
  edges: KnowledgeGraphEdge[];
}
```

---

## Phase 1B — Report Engine (STABLE)

**Module:** `lib/reporting/report-engine.ts`  
**Consumers:** lib/api/intelligence-reports, custom report generation  
**Stability:** **STABLE** (v1)

### ReportEngine Class (STABLE)

```typescript
export class ReportEngine {
  async generateReport(
    metadata: ReportMetadata,
    malwareFamily: MalwareFamily,
    options?: GenerateReportOptions
  ): Promise<MalwareReport>
  
  async validateReport(report: MalwareReport): Promise<ValidationResult>
}

export interface GenerateReportOptions {
  includeSEO?: boolean;
  includeStructuredData?: boolean;
  format?: 'markdown' | 'html' | 'json';
}

export const generateReport = (metadata, family, options?) => Promise<MalwareReport>
```

**Change Policy:**
- Adding optional parameters: **Backward compatible**
- Changing return type: **Major version bump**
- Making required parameter optional: **Backward compatible**
- Making optional parameter required: **Major version bump**

### ReportBuilder Class (STABLE)

```typescript
export class ReportBuilder {
  buildExecutiveSummary(summary: string): ReportBuilder
  buildThreatOverview(threat: string): ReportBuilder
  buildMitreMappings(techniques: MitreTechnique[]): ReportBuilder
  buildIOCIntelligence(iocs: IOC[]): ReportBuilder
  buildDetectionEngineering(rules: DetectionRule[]): ReportBuilder
  buildThreatActorAttribution(actor: ThreatActor): ReportBuilder
  buildCampaignAnalysis(campaign: Campaign): ReportBuilder
  buildRecommendations(recommendations: string[]): ReportBuilder
  toReport(): MalwareReport
}
```

**Fluent API contract:** Method chaining always supported

### Renderers (STABLE)

```typescript
export interface Renderer {
  render(report: MalwareReport): string
}

export class MarkdownRenderer implements Renderer {
  render(report: MalwareReport): string
}

export class HTMLRenderer implements Renderer {
  render(report: MalwareReport): string
}

export class JSONRenderer implements Renderer {
  render(report: MalwareReport): string
}

export function getRenderer(format: 'markdown' | 'html' | 'json'): Renderer
```

**Supported Formats:**
- **markdown** → Blog content
- **html** → Dashboard display
- **json** → API responses
- **stix** (planned Phase 2D)
- **taxii** (planned Phase 2D)

---

## Phase 1C — IOC Engine (STABLE)

**Module:** `lib/ioc/engine.ts`  
**Consumers:** Reporting, Detection, external integrations  
**Stability:** **STABLE** (v1)

### IOCIntelligenceEngine Class (STABLE)

```typescript
export class IOCIntelligenceEngine {
  addIOC(ioc: IOC): IOC
  getIOC(id: string): IOC | undefined
  search(query: IOCSearchQuery): IOC[]
  deduplicate(strategy: 'first_seen' | 'highest_confidence' | 'most_evidence'): IOC[]
  correlate(): IOCCorrelationResult
  relationships(iocId: string): IOCRelationship[]
  stats(): {
    totalIOCs: number
    byType: Record<IOCType, number>
    averageConfidence: number
    lastUpdated: Date
  }
  export(format: 'json' | 'csv' | 'stix'): string
}

export const createIOCEngine = (): IOCIntelligenceEngine
```

**Change Policy:**
- Adding methods: **Backward compatible**
- Changing method signatures: **Major version bump**
- Changing return types: **Major version bump**
- Adding enum values to strategy parameter: **Minor version bump**

### Normalization Functions (STABLE)

```typescript
export function normalizeIOC(type: IOCType, value: string): string

export const normalizationRules: Record<IOCType, (value: string) => string>
```

**Normalization is deterministic:** Same input always produces same output

### Validation Functions (STABLE)

```typescript
export function validateIOC(type: IOCType, value: string): boolean

export const validationRules: Record<IOCType, RegExp | ((value: string) => boolean)>
```

**Validation is idempotent:** Normalized IOC always passes validation

---

## Phase 1D — Detection Engineering (STABLE)

**Module:** `lib/detection/index.ts`  
**Consumers:** lib/api/detection-rules, external SIEM platforms  
**Stability:** **STABLE** (v1)

### Generator Functions (STABLE)

```typescript
export function generateSigmaFromIOC(ioc: IOC): SigmaRule
export function generateYaraFromIOC(ioc: IOC): YaraRule
export function generateSuricataFromIOC(ioc: IOC): SuricataRule
export function generateSEMRuleFromIOC(ioc: IOC, platform: 'splunk' | 'sentinel' | 'elastic' | 'arcsight'): string

// Bulk generation
export function buildDetectionCollection(
  iocs: IOC[],
  techniques: MitreTechnique[],
  formats: DetectionFormat[]
): DetectionRuleCollection
```

**Change Policy:**
- Adding new generator: **Backward compatible**
- Changing output format of existing generator: **Coordinate with consumers**
- Changing rule field names: **Major version bump**

### Validator Functions (STABLE)

```typescript
export function validateDetectionRule(rule: DetectionRule): RuleValidationResult
export function validateSigmaRule(yaml: string): RuleValidationResult
export function validateYaraRule(text: string): RuleValidationResult
export function validateSuricataRule(text: string): RuleValidationResult
```

### Optimizer Functions (STABLE)

```typescript
export function deduplicateRules(rules: DetectionRule[]): DeduplicationResult
export function optimizeSigmaLogsources(rules: SigmaRule[]): OptimizationMetrics
export function optimizeYaraStrings(rule: YaraRule): OptimizationMetrics
export function consolidateSuricataRules(rules: SuricataRule[]): OptimizationMetrics
```

---

## Phase 2A — Governance (STABLE)

**Module:** `lib/governance/index.ts`  
**Consumers:** Publication pipeline, approval workflows  
**Stability:** **STABLE** (v1)

### Workflow Engine (STABLE)

```typescript
export class WorkflowEngine {
  canTransition(currentState: WorkflowState, nextState: WorkflowState): boolean
  getAllowedTransitions(currentState: WorkflowState): WorkflowState[]
  async transitionState(
    objectId: string,
    currentState: WorkflowState,
    nextState: WorkflowState,
    actor: string,
    reason?: string
  ): Promise<WorkflowTransition>
  getTransitionHistory(objectId: string): WorkflowTransition[]
  getCurrentState(objectId: string): WorkflowState | null
  isStale(objectId: string, maxAgeMs: number): boolean
  async resetToDraft(objectId: string, actor: string, reason: string): Promise<WorkflowTransition>
}

export const workflowEngine = new WorkflowEngine()
```

**State Machine is Immutable:** Transitions defined at engine creation time

### Approval Manager (STABLE)

```typescript
export class ApprovalManager {
  createApprovalChain(
    objectId: string,
    objectType: 'report' | 'ioc' | 'detection',
    requiredRoles: ApprovalRole[]
  ): ApprovalChain
  
  async approve(approvalId: string, approver: string, notes?: string): Promise<Approval>
  async reject(approvalId: string, rejector: string, reason: string): Promise<Approval>
  async approveConditional(approvalId: string, approver: string, notes: string): Promise<Approval>
  
  getApprovalChain(objectId: string): ApprovalChain | undefined
  getPendingApprovals(role?: ApprovalRole): Approval[]
  getApprovalHistory(objectId: string): Approval[]
  getApprovalStats(): ApprovalStatistics
}

export const approvalManager = new ApprovalManager()
export const DEFAULT_APPROVAL_CHAINS: Record<'report' | 'ioc' | 'detection', ApprovalRole[]>
export function createDefaultApprovalChain(objectId, type): ApprovalChain
```

### Quality Gates Engine (STABLE)

```typescript
export class QualityGatesEngine {
  registerGate(gate: QualityGate): void
  async validateObject(objectType: string, object: any): Promise<QualityGateResult>
  getAllGates(): QualityGate[]
  getGatesForType(objectType: string): QualityGate[]
}

export const qualityGatesEngine = new QualityGatesEngine()
```

### Other Governance Engines (STABLE)

All governance engines follow the same pattern:

```typescript
export class ConfidenceEngine { }
export const confidenceEngine = new ConfidenceEngine()

export class AuditEngine { }
export const auditEngine = new AuditEngine()

export class VersioningEngine { }
export const versioningEngine = new VersioningEngine()

export class RollbackEngine { }
export const rollbackEngine = new RollbackEngine()

export class PublishingEngine { }
export const publishingEngine = new PublishingEngine()

export class PolicyEngine { }
export const policyEngine = new PolicyEngine()

export class ReviewerEngine { }
export const reviewerEngine = new ReviewerEngine()
```

---

## HTTP API Surface (FROZEN)

**Module:** `lib/api/*`  
**Consumers:** External integrations, dashboard, blog  
**Stability:** **FROZEN** (v1 contract)

### Intelligence Reports API

```
POST /api/v1/reports/generate
  Request:  { metadata: ReportMetadata, malwareFamily: MalwareFamily }
  Response: { report: MalwareReport, rendered: { markdown, html, json } }
  Status:   201 Created | 400 Bad Request | 422 Unprocessable Entity

GET /api/v1/reports/{id}
  Response: { report: MalwareReport, versions: IntelligenceVersion[] }
  Status:   200 OK | 404 Not Found

GET /api/v1/reports/{id}/versions
  Response: { versions: IntelligenceVersion[], currentVersion: number }
  Status:   200 OK | 404 Not Found

GET /api/v1/reports/{id}/audit-log
  Response: { entries: AuditEntry[], timestamp: Date }
  Status:   200 OK | 404 Not Found

POST /api/v1/reports/{id}/publish
  Request:  { destinations: PublishDestination[] }
  Response: { publishingRecord: PublishingRecord }
  Status:   200 OK | 409 Conflict | 422 Unprocessable Entity

POST /api/v1/reports/{id}/retract
  Request:  { reason: string, severity: 'low'|'medium'|'high'|'critical' }
  Response: { retractionRecord: RetractionRecord }
  Status:   200 OK | 409 Conflict | 422 Unprocessable Entity
```

### Detection Rules API

```
POST /api/v1/detections/generate
  Request:  { iocs: IOC[], techniques: MitreTechnique[], formats: DetectionFormat[] }
  Response: { rules: Record<DetectionFormat, string> }
  Status:   201 Created | 400 Bad Request

GET /api/v1/detections/search
  Query:    ?q=&format=&severity=&technique=
  Response: { rules: DetectionRule[], total: number, page: number }
  Status:   200 OK | 400 Bad Request

POST /api/v1/detections/export
  Request:  { ruleIds: string[], format: DetectionFormat }
  Response: { bundle: string }
  Status:   200 OK | 400 Bad Request

GET /api/v1/detections/{id}/coverage
  Response: { coverage: CoverageAnalysis, affectedIOCs: IOC[] }
  Status:   200 OK | 404 Not Found

GET /api/v1/detections/stats
  Response: { stats: DetectionStatistics }
  Status:   200 OK
```

**All HTTP responses include:**
```typescript
{
  data: T,                    // Actual response data
  timestamp: Date,            // ISO 8601 timestamp
  requestId: string,          // For tracing
  version: 'v1',              // API version
  error?: {                   // Only on error
    code: string,
    message: string,
    details?: Record<string, any>
  }
}
```

---

## Breaking Change Process

| Scenario | Action | Timeline | Notification |
|----------|--------|----------|---|
| Fix incorrect behavior | Deploy immediately | N/A | Release notes |
| Add new field | Backward compatible | Immediate | Release notes |
| Add new optional parameter | Backward compatible | Immediate | Release notes |
| Deprecate symbol | Add deprecation warning | v1.x | Release notes, 12-month notice |
| Remove deprecated symbol | Breaking change | v2.0+ | Documented in migration guide |
| Change enum order | Breaking change | v2.0+ | Documented migration |

---

## Summary

| Phase | Stability | Status | Exit Gate |
|-------|-----------|--------|---|
| 1A — Intelligence | IMMUTABLE | Foundation ✓ | All consumers validated |
| 1B — Reporting | STABLE | Core ✓ | All tests passing |
| 1C — IOC | STABLE | Core ✓ | All tests passing |
| 1D — Detection | STABLE | Core ✓ | All tests passing |
| 2A — Governance | STABLE | Core ✓ | All tests passing |
| HTTP API | FROZEN | v1 ✓ | Ready for external integration |

**All public APIs documented and ready for RC1 release.**

