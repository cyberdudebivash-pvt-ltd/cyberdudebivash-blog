# ADR 0002: Multidimensional Confidence Scoring

**Date:** 2026-07-30  
**Status:** Accepted  
**Deciders:** Governance Team, Intelligence Team, Security Review  

---

## Context

Previous CTI platforms often reduce confidence to a single score: 0-100, where the reasoning is opaque.

```typescript
// ❌ Insufficient
{
  confidence: 85,  // Why? Unknown.
}
```

This creates:
- **Audit blindness:** Can't trace why confidence is high or low
- **Policy inflexibility:** Can't say "require 95% technical validation" or "accept 70% if source is reliable"
- **False precision:** Single number implies certainty that doesn't exist
- **Enterprise distrust:** Customers demand explainability, not a black box

---

## Decision

**Replace single-score confidence with multidimensional component architecture.**

Every intelligence object carries five independent confidence components:

```typescript
interface MultidimensionalConfidence {
  sourceReliability: ConfidenceComponent;           // Is the source trustworthy?
  observationQuality: ConfidenceComponent;          // Is the observation clear?
  technicalValidation: ConfidenceComponent;         // Has it been validated?
  analystVerification: ConfidenceComponent;         // Has an analyst reviewed it?
  independentCorroboration: ConfidenceComponent;    // Do multiple sources confirm?
  
  overallConfidence: number;  // Weighted average (0-100)
  reasoning: string;          // Human explanation
  timestamp: Date;
  calculatedBy: string;
}

interface ConfidenceComponent {
  score: number;      // 0-100
  basis: string;      // Why this score?
  weight: number;     // 0-1, used in weighted average
}
```

Every claim stores the full reasoning:
```typescript
// Example: IOC found in sandbox analysis
{
  sourceReliability: {
    score: 95,
    basis: "Direct observation from Cuckoo sandbox infrastructure",
    weight: 0.25
  },
  observationQuality: {
    score: 90,
    basis: "Full behavioral analysis with network monitoring",
    weight: 0.25
  },
  technicalValidation: {
    score: 95,
    basis: "Hash verified against VirusTotal (45/70 vendors)",
    weight: 0.2
  },
  analystVerification: {
    score: 85,
    basis: "Reviewed by John Smith, ransomware specialist",
    weight: 0.15
  },
  independentCorroboration: {
    score: 80,
    basis: "Confirmed by 3 other CTI sources",
    weight: 0.15
  },
  
  overallConfidence: 88,  // Weighted average
  reasoning: "High confidence based on direct sandbox observation, technical validation, and independent corroboration. Analyst verification pending additional analysis."
}
```

---

## Rationale

### 1. Enterprise Explainability

Customers demand answers to:
- "Why is this IOC confidence 85%?"
- "Should we block this?" (depends on their risk tolerance and observation quality)
- "Can we use this for detection?" (depends on technical validation)

Multidimensional scoring enables clear answers.

### 2. Policy Flexibility

Governance policies can now express nuance:
```typescript
// Before: "Require 80% confidence"
// After: "Require:
//   - sourceReliability >= 75, OR
//   - (observationQuality >= 85 AND technicalValidation >= 80), OR
//   - (independentCorroboration >= 90)"
```

Different organization requirements can be satisfied without regenerating intelligence.

### 3. Audit Trail

Every component and its basis is recorded:
- Why was sourceReliability scored at 95?
- Who set the weight for analystVerification?
- When was this calculated?
- By what system?

Immutable audit trail enables forensic confidence review.

### 4. Analyst Workflow

Analysts can update individual components without recalculating everything:
- "I verified this sample" → update `analystVerification`
- "VirusTotal confirms it" → update `technicalValidation`
- "A partner shared this" → update `independentCorroboration`

Each update is tracked independently.

### 5. Temporal Confidence

Confidence degrades over time:
```typescript
// Day 1: High confidence from recent sandbox
// Day 30: Same IOC, but newer variants exist
// Recommendation: Reduce observationQuality weight if observations are old
```

Timestamp enables temporal reasoning.

---

## Implementation

### Confidence Engine

```typescript
export class ConfidenceEngine {
  calculateConfidence(
    objectId: string,
    sourceReliability: ConfidenceComponent,
    observationQuality: ConfidenceComponent,
    technicalValidation: ConfidenceComponent,
    analystVerification: ConfidenceComponent,
    independentCorroboration: ConfidenceComponent,
    reasoning: string
  ): MultidimensionalConfidence
  
  updateComponent(
    objectId: string,
    componentName: keyof Omit<MultidimensionalConfidence, ...>,
    newComponent: ConfidenceComponent,
    reasoning: string
  ): MultidimensionalConfidence
  
  getCurrentConfidence(objectId: string): MultidimensionalConfidence
  getConfidenceTrend(objectId: string): 'increasing' | 'decreasing' | 'stable'
  getWeakestComponent(objectId: string): ComponentAnalysis
  meetsThreshold(objectId: string, threshold: number): boolean
}
```

### Backward Compatibility

For external consumers expecting a single score:
```typescript
// Automatically available
const singleScore = multidimensionalConfidence.overallConfidence;

// With reasoning
const reasoning = multidimensionalConfidence.reasoning;

// With transparency
const breakdown = {
  sourceReliability: 95,
  observationQuality: 90,
  technicalValidation: 95,
  analystVerification: 85,
  independentCorroboration: 80,
};
```

---

## Policy Integration

Phase 2A (Governance) can now express sophisticated policies:

```typescript
// Enterprise Policy: "High confidence reports only"
interface PublicationPolicy {
  // Option 1: Require all components above threshold
  minimumConfidenceRequired: 80;  // overall score
  
  // Option 2: (Planned) Require specific component thresholds
  // minimumComponentThresholds: {
  //   sourceReliability: 85,
  //   technicalValidation: 90,
  // }
  
  // Option 3: (Planned) Allow policy expressions
  // policyExpression: "sourceReliability > 80 AND (technicalValidation > 90 OR independentCorroboration > 85)"
}
```

---

## Example Scenarios

### Scenario 1: Zero-Day Exploit
```
- Source Reliability: 95 (direct researcher disclosure)
- Observation Quality: 40 (single observation)
- Technical Validation: 30 (no sandbox analysis yet)
- Analyst Verification: 60 (preliminary review)
- Independent Corroboration: 0 (not yet confirmed)
→ Overall: ~45% (high uncertainty, urgent publication)

Policy: "Allow publication if sourceReliability > 90"
Result: ✓ Publishes as "URGENT: Preliminary Analysis"
```

### Scenario 2: Common Malware
```
- Source Reliability: 85 (third-party CTI)
- Observation Quality: 90 (multiple samples analyzed)
- Technical Validation: 95 (signatures verified)
- Analyst Verification: 90 (senior analyst review)
- Independent Corroboration: 95 (confirmed by 5+ sources)
→ Overall: ~91% (high confidence, mature analysis)

Policy: "Require overall > 85"
Result: ✓ Publishes as "Confirmed: Widespread Malware"
```

### Scenario 3: Suspicious But Unconfirmed
```
- Source Reliability: 70 (secondary source)
- Observation Quality: 75 (limited context)
- Technical Validation: 60 (incomplete analysis)
- Analyst Verification: 65 (not fully reviewed)
- Independent Corroboration: 0 (not yet confirmed)
→ Overall: ~66% (low-medium confidence, needs more work)

Policy: "Require overall > 75"
Result: ✗ Blocked; requires independent corroboration
```

---

## Consequences

### Positive

✓ **Enterprise trust:** Transparency in confidence scoring  
✓ **Policy flexibility:** Express sophisticated publication rules  
✓ **Audit clarity:** Every component and its basis is recorded  
✓ **Analyst workflow:** Update individual components without recalculation  
✓ **Temporal reasoning:** Enable time-based confidence decay  

### Negative

⚠ **Complexity:** Five components instead of one score
- *Mitigation:* `overallConfidence` provides single number for backward compat

⚠ **Analyst burden:** Requires explicit reasoning for each component
- *Mitigation:* UI guides analysts through standard scoring rubrics

⚠ **Storage footprint:** Full component history vs. single score
- *Mitigation:* Compress historical components; keep last 10 versions

---

## Scoring Rubric (Analyst Guidance)

### Source Reliability
- **95+:** Direct observation (sandbox, network)
- **85-94:** Trusted partner (verified researcher, commercial SIEM)
- **75-84:** Reputable publication (CVE database, vendor advisory)
- **65-74:** Secondary source (news, security blog)
- **0-64:** Unverified claim (social media, rumor)

### Observation Quality
- **95+:** Multiple independent observations (different sandboxes, different analysts)
- **85-94:** Clear, detailed observation (full behavioral log, network trace)
- **75-84:** Good observation (missing some context)
- **65-74:** Limited observation (single platform, abbreviated)
- **0-64:** Minimal observation (hash only, no analysis)

### Technical Validation
- **95+:** Verified by automated tools + manual review (VirusTotal + analysis)
- **85-94:** Verified by automated tools (VirusTotal, sandbox engines)
- **75-84:** Partial validation (signatures match, one detection engine)
- **65-74:** Minimal validation (hash format correct)
- **0-64:** Unvalidated (format unverified)

### Analyst Verification
- **95+:** Senior analyst (10+ years experience, published researcher)
- **85-94:** Experienced analyst (5+ years, multiple domains)
- **75-84:** Competent analyst (2+ years, specialized domain)
- **65-74:** Junior analyst (< 2 years, narrow domain)
- **0-64:** Not yet reviewed (no analyst touch)

### Independent Corroboration
- **95+:** Confirmed by 5+ independent sources
- **85-94:** Confirmed by 3-4 sources
- **75-84:** Confirmed by 2 sources
- **65-74:** Confirmed by 1 source
- **0-64:** Not yet confirmed (isolated observation)

---

## Implementation Checklist

- [x] ConfidenceComponent interface defined
- [x] MultidimensionalConfidence interface defined
- [x] ConfidenceEngine implemented (lib/governance/confidence-engine.ts)
- [x] 50+ tests for confidence calculations
- [ ] Analyst rubric documented in UI
- [ ] API exports overallConfidence in v1 responses (backward compat)
- [ ] Documentation with scoring examples
- [ ] Audit trail records component changes
- [ ] Policy engine integrates with components (Phase 2 follow-up)

---

## Related ADRs

- ADR 0001: Phase 2A Isolation (governance independence)
- ADR 0003: Immutable Audit Trail (component change tracking)

---

## Approval

- **Governance Team:** ✓ Approved
- **Intelligence Team:** ✓ Approved
- **Security Review:** ✓ Approved (transparency increases confidence in publication decisions)

