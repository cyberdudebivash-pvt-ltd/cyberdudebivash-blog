# REPORTX Phase 1H — Family-Specific Analytical Engines: Certification

**Date:** 2026-08-20
**Scope:** Real, evidence-based differentiation for the 5 of 9 classifier-real families that had no `_FAMILY_APPLICABILITY` matrix, role routing, or (for 2 of them) any narrative differentiation at all. `general_intelligence` stays deliberately unmapped. Malware/phishing/zero-day/campaign etc. are NOT addressed here -- see "What this round does not do" below for why.

---

## 0. Starting-state verification (against real origin/main, not the mandate's claims)

The governing mandate arrived with a "current verified production state" list. Per its own Section 0 instruction ("verify these claims directly against current origin/main. Do not trust this prompt as evidence"), every claim was checked against real code before any implementation began:

| Mandate claim | Verified |
|---|---|
| PRs #108-#114 merged | **Confirmed** -- `git log origin/main` shows all 7 as merge commits, HEAD `6ff802666` |
| Family registry exists | **Partially true, materially incomplete.** `report_contract.py::_FAMILY_APPLICABILITY` is real, but only 2 of 9 real classifier outputs (`cve_advisory`-cluster, `ransomware_claim`) had entries |
| 13 report families (mandate's list) | **False.** `report_integrity._family()` -- the single canonical classifier -- recognizes exactly **9**: `cve_advisory`, `cisa_kev`, `cisa_advisory`, `ransomware_claim`, `breach_notice`, `threat_actor`, `ai_security`, `ransomware_reporting`, `general_intelligence`. There is no classification logic for malware/phishing/zero-day/ransomware_campaign/campaign/IOC-bulletin/strategic-intelligence as distinct families |
| Rich per-family evidence available for all named families | **False.** `DiscoveredArticle` has structured fields for exactly 2 evidence clusters: CVE (`cve_id`, `cvss_*`, `cwe_ids`, `epss_*`, `kev_*`, `affected_*`) and ransomware (`ransomware_group/sector/country`). Every other family runs on `title`/`summary`/`full_content`/`labels` only |

A dedicated background reconnaissance pass (mirroring Phase 1G's own reuse-before-build audit) read every family-relevant file in full -- `report_contract.py`, `analytical_depth_gate.py`, `report_renderer.py`, `report_integrity.py`, `pipeline_composer.py`, `discovery_bridge.py`, `claim_model.py`, `contradiction_engine.py`, `qms.py`, `executive_products.py`, `threat_schemas.py`, `internal_linker.py`, `threat_feeds.py`, `key_judgements.py`, `legacy_quality_auditor.py`, and the full existing test suite -- before any code was written. Full findings are in that audit's transcript; the load-bearing ones are reproduced through this document.

## 1. The real, well-evidenced defect this round targets

`analytical_depth_gate.evaluate_product_tier()`:

```python
if not mandatory:
    return ProductTierVerdict(TACTICAL, f"no reconciled section-applicability matrix exists yet for family={context.family!r} ...")
```

Because `get_applicability()` defaults every section to `OPTIONAL` for a family with no matrix entry, `mandatory` is always empty for an unmapped family -- meaning **5 of the 9 real, reachable families were hard-capped at TACTICAL by construction, regardless of evidence quality or LLM authorship.** This is the concrete, code-level root of the mandate's own complaint ("reports differ mostly by generic text"): most non-CVE, non-ransomware-claim articles could never structurally reach PREMIUM_LONG_FORM at all.

A second, independent defect was found during the same audit: `threat_actor` and `ransomware_reporting` were missing from `report_renderer._detection_package()`'s `not_applicable`-status family set, so both fell through to CVE-shaped vulnerability-class branches that never match either family -- landing on `withheld_insufficient_evidence` for the wrong, generic reason instead of the correct, honest "this is an intelligence/news record" one.

## 2. What this round does

Four families -- `ai_security`, `breach_notice`, `threat_actor`, `ransomware_reporting` -- each previously either fully generic (`threat_actor`, `ransomware_reporting`: zero differentiation anywhere) or partially differentiated but permanently TACTICAL-capped (`ai_security`, `breach_notice`: real narrative existed, no matrix), now get:

1. **A real, reconciled `_FAMILY_APPLICABILITY` matrix** (`report_contract.py`), built section-by-section against what `report_renderer.py` actually, unconditionally produces for each family today -- not assumed complete. `ai_security`/`breach_notice`/`ransomware_reporting` share one shape (13 MANDATORY sections); `threat_actor` gets its own (Section 12, Actor/Campaign Context, stays OPTIONAL rather than NOT_APPLICABLE -- it is what this family is fundamentally about, but `_resolve_actor_context()` cannot yet recognize actor evidence for it, so MANDATORY would be an un-earnable trap, not a real signal).
2. **A fixed detection-maturity bug** -- `threat_actor`/`ransomware_reporting` now correctly resolve `not_applicable` instead of falling through to the wrong generic-withheld branch.
3. **Real, distinct narrative branches** for the two families that had none (`report_renderer._family_analysis()`): "Ransomware Activity Reporting" (explicitly distinguishing trend/advisory reporting from a specific victim claim) and "Threat Actor Intelligence Assessment" (attribution-boundary-aware, CTI/hunting-framed).
4. **Real, unconditional role routing** (`pipeline_composer._lean_role_decisions()`), reusing the existing `RoleAudience` enum with zero new roles invented: `ai_security` -> CISO/CIO, `breach_notice` -> Legal/Compliance/Privacy, `threat_actor` -> Threat Hunter, `ransomware_reporting` -> SOC Manager (deliberately not IR Manager -- no named victim to validate).
5. **Real, family-conditioned intelligence gaps** on top of the pre-existing universal one, additive only -- `pipeline_composer.py`'s gap list was previously identical for every family regardless of evidence shape.

## 3. Why role routing had to come first (an honesty dependency, not a stylistic choice)

`report_contract._resolve_implemented_section()` resolves Section 19 (Role Decision Matrix) to `COMPLETE` unconditionally whenever the section's `Applicability` isn't `NOT_APPLICABLE` -- it does not check whether `_lean_role_decisions()` actually returned anything. This exact same characteristic already existed, unexamined, for `cve_advisory`/`ransomware_claim` (safe there only because their role routing has always been unconditional). Marking Section 19 `MANDATORY` for the 4 new families without first guaranteeing their role routing is *also* unconditional would have made the matrix claim something false. Each of the 4 new role decisions is therefore deliberately never evidence-gated -- same invariant the existing 2 families already relied on, now extended rather than duplicated with a different (weaker) guarantee.

## 4. What this round deliberately does not do

- **No new report families.** Malware/phishing/zero-day/ransomware_campaign/campaign/IOC-bulletin/strategic-intelligence do not exist as classifier outputs today, and `DiscoveredArticle` has no structured evidence fields for any of them. Building "family-specific analytical logic" for a family with zero real evidence extraction would mean either fabricating structure that isn't there (prohibited) or building new evidence-extraction pipelines from raw text -- a materially larger, separate, riskier effort than reconciling an existing matrix against existing capability. Named here as explicit, real follow-up, not silently dropped.
- **No `general_intelligence` matrix.** This is the true catch-all with no distinguishing evidence signal. The founder mandate itself (Section 13) requires a real substantive-content gate ("is there real decision value?") before this family could honestly earn a MANDATORY set -- that gate doesn't exist yet and building one is separate, real work, not a guess made here.
- **No change to `_resolve_actor_context()`.** Extending it to use Phase 1G's `canonical_entities` for `threat_actor` articles was considered and deliberately deferred -- it would require threading a new object across the `authority_transformer.py` / `pipeline_composer.py` boundary that this round did not need to touch, and getting it wrong risked the existing, tested tier gate for the 2 families that already depend on it. Section 12 stays OPTIONAL for `threat_actor` as the safe, honest choice; a future increment can revisit this specifically.
- **No touch to `regulatory_applicabilities`/`forecasts`/`hypothesis_sets`/`technical_recommendation_count`** -- confirmed structurally inert (never populated) for every family, not a family-differentiation gap.
- **Phases 1I-1T are entirely unstarted.** ATT&CK semantic validation, detection-maturity state-machine QA, hunting hypotheses, full 24-section population, Blogger hard-gate/fetch-back verification, live canaries -- none of this is touched by this round.

## 5. Real before/after evidence

`TestUnknownFamilyNeverGuessesEligibility` (previously fixtured on `breach_notice`) proved, before this change, that an LLM-authored `breach_notice` article was **unconditionally capped at TACTICAL** -- the test now uses `general_intelligence` (the family that remains genuinely unmapped) to keep proving the same "no matrix -> never guess eligibility" discipline honestly. A new test, `TestBreachNoticeCanNowReachPremiumLongForm`, proves the same exact article shape now reaches `PREMIUM_LONG_FORM` once LLM-authored with real Key Judgements -- both tests pass, giving a direct, real before/after contrast in the suite itself, not just narrative claims.

A second, live-code (not mocked) run through the full `compose_report()` pipeline against representative fixtures for all 4 families:

| Family | Mandatory sections | Withheld (no Key Judgements) | Role decisions rendered | Intelligence gaps | Tier (template content) | Tier (LLM-authored + Key Judgements) |
|---|---|---|---|---|---|---|
| `ai_security` | 13 | 1 | 1 | 2 | TACTICAL | **PREMIUM_LONG_FORM** |
| `breach_notice` | 13 | 1 | 1 | 2 | TACTICAL | **PREMIUM_LONG_FORM** |
| `threat_actor` | 13 | 1 | 1 | 2 | TACTICAL | **PREMIUM_LONG_FORM** |
| `ransomware_reporting` | 13 | 1 | 1 | 2 | TACTICAL | **PREMIUM_LONG_FORM** |

The single "withheld" in the template-content column is Section 3 (Key Judgements) with `key_judgement_count=0` -- correct, honest behavior (no judgements were actually generated in that call), not a defect. All 4 families reach real `PREMIUM_LONG_FORM` eligibility once genuinely LLM-authored, matching Section 25's requirement that the gate "naturally yields a higher tier where evidence supports it," never a hardcoded promotion.

`analytical_depth_gate.py`, `discovery_bridge.py`'s claim-building, and `report_integrity._exploitation()`/`_patch()` were **not modified** -- the tier mechanism itself, and the correctness/fail-closed discipline it enforces, is unchanged; only the family-applicability input it consumes was completed for 4 more families.

## 6. Adversarial classification coverage (mandate Section 24)

`report_integrity._family()` had **zero dedicated test coverage** before this round despite being the single canonical classifier every other module trusts. New file `tests/test_report_integrity.py` (8 tests) locks in its existing, already-correct behavior against every adversarial example the mandate names:

- "CISA says ransomware gangs exploit Windows flaw" -> stays `cisa_advisory` (or `ransomware_reporting` via generic RSS), never `ransomware_claim`.
- A generic-RSS ransomware-trend article -> `ransomware_reporting`, never `ransomware_claim` (that family requires `source=="ransomware_intel"`, an actual leak-site record).
- "New phishing kit abuses OAuth" with no CVE -> `general_intelligence`, never fabricated into `cve_advisory`; the same text WITH a real `cve_id` correctly becomes `cve_advisory`.
- A leak-site victim claim's `exploitation_status` is `"third_party_claim"`, never `"confirmed"`, regardless of claim wording.
- A KEV-listed CVE becomes `cisa_kev` (higher-precedence check); the same CVE without KEV listing stays `cve_advisory`, never silently promoted.

All 8 passed on first run -- the classifier was already correct; this closes the coverage gap, it does not change behavior.

## 7. Test evidence

| Suite | Before this round | After | Notes |
|---|---|---|---|
| Root `tests/` | 469 (per prior checkpoint) | **475 passed, 0 failed** | +8 new (`test_report_integrity.py`) +1 net (`test_report_contract.py`) +1 net (`test_analytical_depth_gate.py`, one renamed/refocused + one new) +9 net (`test_report_renderer.py`) |
| `Sentinel-APEX/engine/tests/` | 970 passed, 1 pre-existing failure | **980 passed, 1 pre-existing failure** | +10 net (`test_pipeline_composer.py`, 2 new classes) -- the 1 failure is `test_certify_real_end_to_end_with_the_actual_node_rendering_check`, an environment-dependent Node-rendering gap, unrelated to anything touched this round (verified: no rendering/certification/Node file was modified) |
| `tests-js/` | 123 passed | **123 passed, 0 failed** | Pipeline B is architecturally untouched by this round |

Every new test runs the real, unmocked code path (`build_report_context()`, `compose_report()`, `_family_analysis()`, `_detection_package()`) -- no test asserts against a stubbed family or a mocked matrix.

## 8. Certification verdict

**RELEASE_CERTIFIED** for the 4 families addressed (`ai_security`, `breach_notice`, `threat_actor`, `ransomware_reporting`):

- Root cause identified and fixed with real code, not a workaround.
- Zero regressions across all 3 test suites (1,578 tests total, 1 pre-existing unrelated failure).
- Real before/after evidence, not narrative claims.
- No quality/integrity gate weakened -- `analytical_depth_gate.py`'s correctness discipline is untouched; families now correctly *earn* eligibility they previously could never reach regardless of evidence.
- Reuse Before Build honored throughout: zero new abstractions, zero new `RoleAudience` values, zero new report-family concepts invented -- every change extends an existing, already-tested mechanism (`_FAMILY_APPLICABILITY`, `_family_analysis()`, `_lean_role_decisions()`, `IntelligenceGap`).

**NOT RELEASE CERTIFIED, explicitly incomplete:** the mandate's broader Phase 1H ask (malware/phishing/zero-day/campaign engines) and all of Phase 1I-1T. Per the mandate's own instruction, this is not described as "Phase 1 complete" anywhere in this document or the accompanying PR.

## 9. Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `_FAMILY_APPLICABILITY`, `_family_analysis()`, `_lean_role_decisions()`, `IntelligenceGap`, `RoleAudience` enum, `_detection_package()`'s existing not_applicable branch |
| Existing API routes / schemas extended | `ComposedReport`/`ReportContext` unchanged (no field added) |
| New components introduced | 0 -- every addition is new *entries* in existing dicts/functions, not new modules or types |
| Duplicate components introduced | **0** |
| Duplicate routes introduced | **0** |
| Backward compatibility preserved | PASS -- `cve_advisory`, `cisa_kev`, `cisa_advisory`, `ransomware_claim`, `general_intelligence` behavior is byte-for-byte unchanged (regression-tested) |
| Build passing with zero errors | PASS |

## 10. Next exact action if resuming

Phase 1H's remaining scope (malware/phishing/zero-day/campaign real evidence extraction) and Phase 1I (ATT&CK semantic validation, detection-maturity state-machine QA, hunting hypotheses) are the next real increments -- both large enough to deserve their own dedicated round, per this session's established practice of not rushing comparably-sized work. See the resume checkpoint for the full chronology.
