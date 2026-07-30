# ADR 0001: Isolate Phase 2A (Governance) from Phase 1A-1D (Content Generation)

**Date:** 2026-07-30  
**Status:** Accepted  
**Deciders:** Governance Team, Architecture Review  

---

## Context

Sentinel APEX consists of two architectural concerns:

1. **Content Generation Pipeline** (Phase 1A-1D): Intelligence creation
   - Malware schema definition (1A)
   - Report generation (1B)
   - IOC processing (1C)
   - Detection rule generation (1D)

2. **Governance Control Plane** (Phase 2A): Publication authorization
   - Workflow state machine
   - Approval hierarchy
   - Quality gate validators
   - Audit trail
   - Versioning and rollback
   - Policy enforcement

Early designs proposed governance as a "quality filter" downstream of generation. However, this creates a fundamental architectural mismatch:

- Governance is **not** a filter; it is a **control plane**
- Intelligence flows **through** governance, not **past** it
- All publication decisions originate in governance, not in generation

---

## Decision

**Isolate Phase 2A from Phase 1A-1D with zero cross-dependencies.**

Governance modules (`lib/governance/*`) will:
- ✓ Import only `./types` (internal)
- ✓ Define no dependencies on Phase 1A-1D
- ✓ Be consumable by external systems independently
- ✓ Operate as a standalone orchestration layer

Phase 1A-1D modules will:
- ✓ Remain unaware of governance
- ✓ Export clean, introspectable data structures
- ✓ Not reference governance decision logic
- ✓ Be testable without governance running

**Data Flow:**
```
Phase 1A-1D (Generate)
        ↓
Phase 2A (Govern)  ← Single entry point for all publication
        ↓
Phase 2B-2E (Publish)
```

---

## Rationale

### 1. Governance is Authorization, Not Validation

- **Validation** (Phase 1D): "Does this detection rule have valid syntax?"
- **Governance** (Phase 2A): "Is this report allowed to publish?"

Governance cannot be a post-generation filter because:
- Quality gates must run **before** approvals (not after)
- Approvals must sequence (analyst → peer → QA → security)
- Policies must be evaluated **once**, not conditionally

### 2. Enterprise Audit Requirements

Isolation enables immutable audit trails:
- Every governance decision is recorded
- No bypass paths exist
- Rollback procedures are predictable
- Regulatory compliance is verifiable

If governance were downstream, audit would be fragmented across multiple systems.

### 3. Operational Clarity

Isolation enables clear operational roles:
- **Generation team** owns content quality
- **Governance team** owns publication authorization
- **Operations team** owns deployment
- No role confusion; clear handoffs

### 4. Testing & Reliability

Isolation enables independent testing:
- Unit tests for governance don't require content generation
- Content generation can be tested without governance
- Failure in one system doesn't cascade to the other
- Performance isolation: governance throughput independent of generation

### 5. Future Evolution

Isolation enables parallel development:
- Phase 2B-2E can be designed without governance blocking
- Governance can be enhanced without regenerating intelligence
- New content types (vulnerability, threat intel, etc.) can bypass generation but use governance
- Search, knowledge graph, and distribution can operate independently

---

## Implementation

### Module Boundaries

**Phase 2A Core:**
```
lib/governance/
├── types.ts            (definitions only)
├── workflow.ts         (state machine)
├── approvals.ts        (approval hierarchy)
├── quality-gates.ts    (gate validators)
├── confidence-engine.ts (multidimensional scoring)
├── audit.ts            (immutable trail)
├── versioning.ts       (version control)
├── rollback.ts         (retraction handling)
├── publishing.ts       (multi-destination dispatch)
├── policy-engine.ts    (policy evaluation)
├── reviewers.ts        (reviewer management)
└── index.ts            (public API)
```

All modules import only `./types`, never other phases.

### Import Validation (CI Check)

```bash
# Fail if any governance module imports from Phase 1:
grep -r "import.*from.*\.\./\.\./\(intelligence\|ioc\|reporting\|detection\)" lib/governance/

# Fail if Phase 1 imports from governance:
grep -r "import.*from.*governance" lib/intelligence lib/ioc lib/reporting lib/detection
```

### Data Contracts

Phase 1A-1D export generic, introspectable structures:
```typescript
// Phase 1A exports
interface MalwareFamily {
  id: string
  name: string
  iocs: IOC[]
  techniques: MitreTechnique[]
  // No governance state
}

interface IOC {
  id: string
  type: IOCType
  value: string
  confidence: ConfidenceLevel
  // No governance state
}

// Phase 2A receives and wraps
interface IntelligenceObject {
  id: string
  type: 'report' | 'ioc' | 'detection'
  currentState: WorkflowState
  createdAt: Date
  // Governance state added here
}
```

---

## Consequences

### Positive

✓ **Governance is an universal control plane** — all systems eventually flow through it  
✓ **Audit is trustworthy** — no bypass paths  
✓ **Scaling is independent** — governance throughput independent of generation  
✓ **Testing is simpler** — each system has clear entry/exit contracts  
✓ **Operations is clear** — distinct team responsibilities  

### Negative

⚠ **Duplication between layers:** Some validation appears in both Phase 1D and Phase 2A (quality gates)
- *Mitigation:* This is intentional; Phase 1D validates intrinsic correctness (e.g., "is this valid Sigma YAML?"), while Phase 2A validates publication readiness (e.g., "does this report have required metadata?")

⚠ **Latency:** Intelligence flows through both generation and governance
- *Mitigation:* Both systems are designed for async processing; orchestrator handles sequencing

⚠ **Coordination complexity:** Two independent systems must coordinate on data format
- *Mitigation:* Clear contract in types/index.ts; versioning policy prevents drift

---

## Implementation Checklist

- [x] Phase 2A designed with zero Phase 1A-1D imports
- [x] All Phase 2A modules depend only on ./types.ts
- [x] types/index.ts re-exports all governance types
- [x] lib/governance/index.ts exports clean public API
- [x] CI validation rules added to prevent circular imports
- [ ] Integration tests verify Phase 1→2A data flow
- [ ] End-to-end tests: generate report → flow through governance → publish
- [ ] Performance benchmarks: governance latency independent of generation

---

## Related ADRs

- ADR 0002: Multidimensional Confidence Scoring (Phase 2A confidence-engine)
- ADR 0003: Immutable Audit Trail Design (Phase 2A audit engine)
- ADR 0004: State Machine Transitions (Phase 2A workflow engine)

---

## Approval

- **Architecture Review:** ✓ Approved
- **Governance Team:** ✓ Approved
- **API Team:** ✓ Approved (no HTTP API impact)

