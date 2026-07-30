# Workstream 2 — Enterprise Test Certification Plan

**Status:** Planning Phase  
**Date:** 2026-07-30  
**Scope:** Comprehensive testing across all phases and critical paths

---

## Overview

Workstream 2 establishes enterprise-grade test coverage for Sentinel APEX RC1. After architecture certification (Workstream 1), test certification validates that all components work together reliably at production scale.

### Goals
- **100% integration test pass rate** across all phases
- **Baseline performance metrics** established for SLA contracts
- **Failure scenarios documented** with recovery procedures
- **Zero data corruption** under concurrent load

---

## Test Infrastructure Setup

### Phase 1: Test Framework Configuration

**Objective:** Establish unified test infrastructure across all phases

#### 1.1 Jest Configuration
- Create `jest.config.js` with TypeScript support
- Configure test paths for unit and integration tests
- Set coverage thresholds (80% minimum)
- Define timeout values for integration tests (30s+)

**Files to create:**
- `jest.config.js`
- `jest.setup.ts`
- `.jestignore`

#### 1.2 Test Utilities
- Create shared test fixtures and factories
- Implement mock data generators for each phase
- Build test database initialization helpers
- Create performance instrumentation utilities

**Files to create:**
- `tests/fixtures/index.ts`
- `tests/factories/malware-factory.ts`
- `tests/factories/ioc-factory.ts`
- `tests/factories/detection-factory.ts`
- `tests/helpers/performance.ts`
- `tests/helpers/database.ts`

#### 1.3 CI Pipeline Configuration
- Add GitHub Actions workflow for test execution
- Configure parallel test runs (8 workers)
- Set up coverage reporting
- Configure test result publishing

**Files to create/update:**
- `.github/workflows/test.yml`
- Coverage config in package.json

---

## Test Categories & Coverage Plan

### Category A: End-to-End Tests (E2E)

**Objective:** Full report lifecycle from intelligence creation through publication

#### A.1 Full Report Generation Pipeline
```
Phase 1A (Intelligence) 
  → Phase 1B (Report Generation)
  → Phase 1C (IOC Processing)
  → Phase 1D (Detection Engineering)
  → Phase 2A (Governance)
  → Published
```

**Test Coverage:**
1. **Input:** Malware family JSON from threat feed
2. **Process:**
   - Validate malware schema (Phase 1A)
   - Extract IOCs and normalize (Phase 1C)
   - Generate markdown report (Phase 1B)
   - Generate detection rules in 4 formats (Phase 1D)
   - Submit through governance workflow (Phase 2A)
3. **Output:** Published report across all formats

**File:** `tests/e2e/full-report-lifecycle.test.ts`

Expected test cases:
- ✓ Simple malware family → complete report
- ✓ Complex malware with 100+ IOCs
- ✓ Edge case: Malware with no detection rules
- ✓ Edge case: Malware with conflicting IOCs
- ✓ Concurrent: 10 parallel reports

---

### Category B: Governance Workflow Tests

**Objective:** All 15 workflow states, transitions, and approval chains

#### B.1 Workflow State Machine
```
Draft 
  → Submitted → In Review → QA Check → Approved → Published
  ↑                                          ↓
  └─────── Rejected / Retracted ────────────┘
```

**Test Coverage:**
1. **State Transitions** (15 states × 20+ transitions)
   - Valid transitions allowed
   - Invalid transitions blocked
   - Transition history maintained

2. **Approval Chains** (4-role hierarchy)
   - Analyst → Peer Analyst → QA Lead → Security Officer
   - Role-based access control
   - Skip conditions (conditional approvals)

3. **Quality Gates** (9 built-in gates)
   - Missing metadata detection
   - Missing evidence detection
   - MITRE technique validation
   - Confidence threshold validation

**Files to create:**
- `tests/governance/workflow-state-machine.test.ts`
- `tests/governance/approval-hierarchy.test.ts`
- `tests/governance/quality-gates.test.ts`

---

### Category C: Large IOC Corpus Tests

**Objective:** Validate performance and correctness at scale

#### C.1 5K+ IOC Processing
```
Input: 5,000 diverse IOCs
  → Normalization
  → Deduplication
  → Correlation
  → Confidence scoring
  → Rule generation
Output: 4,850 deduplicated, correlated, scored IOCs
```

**Test Coverage:**
1. **Volume Handling**
   - 5,000 IOCs across 18 types
   - Memory usage tracking
   - Processing time baseline

2. **Accuracy**
   - Normalization correctness for each IOC type
   - Deduplication accuracy (no false positives/negatives)
   - Correlation link completeness

3. **Performance Metrics**
   - Throughput: IOCs/second
   - Latency: p50, p95, p99
   - Memory: Peak usage

**File:** `tests/performance/ioc-corpus.test.ts`

---

### Category D: Concurrent Execution Tests

**Objective:** 50 parallel report generations, no data corruption

#### D.1 Stress Testing
```
Spawn: 50 concurrent report generation tasks
Observe: 
  - All complete successfully
  - Zero data corruption
  - No resource exhaustion
  - No deadlocks
```

**Test Coverage:**
1. **Concurrency Scenarios**
   - 50 parallel simple reports
   - 25 parallel complex + 25 simple
   - Mixed with approval workflows

2. **Resource Monitoring**
   - Memory leak detection
   - File descriptor leaks
   - Database connection pool exhaustion

3. **Data Integrity**
   - Each report generates independently
   - No cross-contamination
   - Audit trail consistency

**File:** `tests/performance/concurrent-generation.test.ts`

---

### Category E: Regression Suite

**Objective:** Critical paths validated after any change

#### E.1 Critical Path Tests
```
Path 1: Simple Malware → Report → Published (< 5s)
Path 2: Complex Malware → All Formats → Published (< 30s)
Path 3: IOC Correlation → Detection Rules → 4 Formats (< 20s)
Path 4: Governance Workflow → State Changes → Audit Trail (< 2s)
```

**Test Coverage:**
1. **Phase Boundaries** (8 boundaries)
   - 1A → 1B, 1B → 1C, 1C → 1D, 1D → 2A
   - Data contract validation
   - No data loss in transitions

2. **API Contract** (6 endpoints)
   - Request validation
   - Response schema compliance
   - Error handling

3. **Audit Trail** (append-only validation)
   - Every governance change recorded
   - No mutations of historical entries
   - Integrity verification

**File:** `tests/regression/critical-paths.test.ts`

---

### Category F: Performance Benchmarks

**Objective:** Establish baseline SLA metrics

#### F.1 Baseline Measurements

| Metric | Target | Measurement Method |
|--------|--------|---|
| Report generation (simple) | < 5s | Single malware family |
| Report generation (complex, 500 IOCs) | < 30s | Stress test |
| IOC normalization (per IOC) | < 1ms | 5K corpus ÷ time |
| Detection rule generation (per IOC) | < 2ms | 4 formats per IOC |
| Governance transition | < 100ms | State machine |
| Approval chain (4-role) | < 500ms | Full chain execution |
| Confidence scoring | < 50ms | Per object |
| Audit log write | < 10ms | Per entry |

**File:** `tests/benchmarks/baseline-slas.test.ts`

Performance instrumentation:
- CPU time per phase
- Memory allocation per phase
- Wall clock time per endpoint
- Database query performance

---

### Category G: Failure Injection Tests

**Objective:** Graceful degradation under adverse conditions

#### G.1 Failure Scenarios

1. **Network Failures**
   - Database connection timeout
   - External API timeout
   - Partial network partition

2. **Data Errors**
   - Invalid IOC format (caught and skipped)
   - Corrupted confidence data (recovery)
   - Missing evidence references

3. **Resource Exhaustion**
   - Memory pressure (< 100MB free)
   - Disk space low (< 1GB free)
   - Database connection pool exhausted

4. **Concurrency Issues**
   - Race conditions in correlation
   - Deadlock in approval chains
   - File lock contention

**File:** `tests/resilience/failure-injection.test.ts`

Expected outcomes:
- Graceful error handling
- Audit trail records failure
- Retry logic works correctly
- No data corruption

---

### Category H: Rollback Validation

**Objective:** Retract and restore procedures work correctly

#### H.1 Retraction Scenarios

```
Published Report
  → Retraction Request
  → Record Retraction
  → Verify Removal
  → Restore Previous Version
  → Verify Restoration
```

**Test Coverage:**
1. **Retraction** (mark as invalid)
   - Remove from publication targets
   - Record retraction reason/severity
   - Audit trail entry

2. **Correction** (publish fix)
   - New version published
   - Links old version to new
   - Update all references

3. **Partial Rollback** (revert specific section)
   - Rollback detection rules only
   - Rollback IOCs only
   - Keep report metadata

**File:** `tests/governance/rollback-validation.test.ts`

---

## Test Implementation Schedule

### Week 1: Infrastructure (Days 1-5)
- [ ] Day 1-2: Jest configuration, test utilities
- [ ] Day 3-4: Mock data generators, fixtures
- [ ] Day 5: CI pipeline setup

### Week 2: E2E & Governance (Days 6-10)
- [ ] Day 6-7: End-to-end pipeline tests
- [ ] Day 8-9: Governance workflow tests (15 states, 4-role approvals)
- [ ] Day 10: Quality gates tests

### Week 3: Scale & Performance (Days 11-15)
- [ ] Day 11-12: 5K+ IOC corpus tests
- [ ] Day 13: 50 concurrent generation tests
- [ ] Day 14-15: Performance baseline measurement

### Week 4: Resilience & Completion (Days 16-20)
- [ ] Day 16-17: Failure injection tests
- [ ] Day 18: Rollback validation
- [ ] Day 19: Regression suite
- [ ] Day 20: Coverage analysis, documentation

---

## Success Criteria

### Exit Gate 1: Infrastructure Ready
- [x] Jest configured
- [x] Test utilities implemented
- [x] CI pipeline functional
- [x] All 4 unit test files passing (400+ tests)

### Exit Gate 2: Integration Testing Complete
- [ ] E2E tests: 100% pass (20+ tests)
- [ ] Governance tests: 100% pass (50+ tests)
- [ ] Quality gates: All 9 gates tested

### Exit Gate 3: Scale Validation
- [ ] 5K IOC corpus: 100% accuracy
- [ ] 50 concurrent reports: 100% success rate
- [ ] Zero data corruption
- [ ] Memory stable under load

### Exit Gate 4: Performance Certified
- [ ] All latency SLAs met
- [ ] Throughput baselines documented
- [ ] Performance regression tests in CI

### Exit Gate 5: Resilience Proven
- [ ] All 12+ failure scenarios handled gracefully
- [ ] Audit trail integrity verified
- [ ] Rollback procedures validated

### Exit Gate 6: Coverage Complete
- [ ] 80%+ line coverage
- [ ] 100% critical path coverage
- [ ] All phase boundaries tested
- [ ] All API endpoints tested

---

## Deliverables

### Test Files
```
tests/
├── fixtures/
│   ├── index.ts
│   ├── malware-families.ts
│   ├── iocs.ts
│   └── detection-rules.ts
├── factories/
│   ├── malware-factory.ts
│   ├── ioc-factory.ts
│   └── detection-factory.ts
├── helpers/
│   ├── performance.ts
│   └── database.ts
├── e2e/
│   └── full-report-lifecycle.test.ts (20+ tests)
├── governance/
│   ├── workflow-state-machine.test.ts (50+ tests)
│   ├── approval-hierarchy.test.ts (30+ tests)
│   ├── quality-gates.test.ts (25+ tests)
│   └── rollback-validation.test.ts (15+ tests)
├── performance/
│   ├── ioc-corpus.test.ts (10+ tests)
│   ├── concurrent-generation.test.ts (10+ tests)
│   └── baseline-slas.test.ts (20+ tests)
└── resilience/
    └── failure-injection.test.ts (20+ tests)
```

### Configuration Files
```
jest.config.js                  (Jest configuration)
jest.setup.ts                   (Test initialization)
.jestignore                     (Excluded paths)
.github/workflows/test.yml      (CI pipeline)
```

### Documentation
```
docs/testing/
├── test-plan.md               (This document, finalized)
├── test-results.md            (Exit gate sign-off)
├── performance-baseline.md    (SLA metrics)
└── failure-scenarios.md       (Recovery procedures)
```

---

## Metrics & Tracking

### Coverage Metrics
- Line coverage: Target 80%+ (report per phase)
- Branch coverage: Target 70%+
- Critical path coverage: 100%

### Performance Metrics
- Report generation latency (p50, p95, p99)
- IOC processing throughput
- Concurrent execution stability
- Memory consumption baseline

### Quality Metrics
- Test pass rate: Target 100%
- Flaky test detection: 0 allowed
- Test execution time: < 5 minutes for full suite

---

## Risk Mitigation

| Risk | Mitigation |
|------|---|
| Flaky tests (timing-dependent) | Use deterministic clock in tests, increase timeout allowance |
| Test data consistency | Implement database fixtures, isolation per test |
| Performance variance | Run benchmarks 5× each, report range, use p50 as baseline |
| External API calls | Mock external APIs, inject failures |
| Resource exhaustion | Use containerized test environment, monitor during runs |

---

## Next Steps

Once Workstream 1 is merged to main and architecture.yml CI checks pass:

1. **Approve this plan** with team leads
2. **Assign test ownership** to engineering teams
3. **Create GitHub issues** for each test category (8 issues)
4. **Set up test environment** (database fixtures, mock servers)
5. **Begin Week 1 infrastructure work**

---

## References

- [Workstream 1 Architecture Certification](./architecture/README.md)
- [Module Ownership Map](./architecture/module-ownership.md) — Test owner assignments
- [Public API Audit](./architecture/public-api-audit.md) — API contract validation
- [ADR 0001: Phase 2A Isolation](./adr/0001-phase-2a-isolation.md) — Governance isolation patterns
- [ADR 0002: Multidimensional Confidence](./adr/0002-multidimensional-confidence.md) — Scoring validation rules

---

**Status: Ready for Executive Review & Approval**

*This plan establishes enterprise test certification as the foundation for RC1 production readiness.*
