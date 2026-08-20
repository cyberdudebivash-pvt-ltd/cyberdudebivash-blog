# REPORTX Phase 1I — ATT&CK Semantic Validation, Detection Maturity & Threat-Hunting Certification

**Date:** 2026-08-20
**Scope:** Real, evidence-based hardening of the technical intelligence inside premium reports — reconciling the detection-maturity vocabulary, elevating an existing ATT&CK-justification check from score-only to a hard gate, and wiring real hunt-hypothesis content for one family. Not a rebuild of any existing system.

---

## 0. Starting-state verification

PR #115 (Phase 1H) confirmed merged into `origin/main` (`git log origin/main` shows it as a real merge commit) before any work began. Per this round's own governing instruction ("verify these claims directly against current origin/main"), the mandate's assumptions about existing ATT&CK/detection/hunting architecture were checked against real code, not trusted:

| Mandate assumption | Verified reality |
|---|---|
| A canonical detection-maturity vocabulary needs reconciling | **True, but not from scratch.** `detection_validation.DetectionValidationState` already existed: `DRAFT`/`SYNTAX_VALIDATED`/`LAB_VALIDATED`/`TELEMETRY_VALIDATED`/`PRODUCTION_CANDIDATE`/`PRODUCTION_VALIDATED`/`WITHHELD_INSUFFICIENT_EVIDENCE`, with a real, tested, already-wired promotion-language gate (`check_state_promotion()`). It just had no `NOT_APPLICABLE`/`TELEMETRY_SPECIFICATION` states, so `pipeline_composer.py`'s old mapping collapsed 3 of 4 real `DetectionPackage.status` strings into one. |
| "Syntax ≠ semantics" needs a new gate | **Already a real, live, hard-gating control.** `commercial_readiness.py`'s `detection_evidence_discipline` control (in `CORRECTNESS_CONTROLS`, meaning a FAIL here already drops a report to `PUBLIC_REFERENCE_DRAFT` and blocks publication) already calls `check_state_promotion()` unconditionally. |
| ATT&CK mappings need a structured object with `status`/`evidence_refs`/`confidence` | **A sophisticated version already exists, just not wired into the live render path.** `attack_mapper.map_techniques()` — negation-aware, evidence-anchored, already used by `intelligence_validation.py`'s `_score_mitre_attack_justification()` scorer — was real and tested, but that check was scored (0-100), never gated. |
| Hunting needs a hypothesis model | **`executive_products.HuntHypothesis` already existed**, ~70% aligned with the mandate's 12-field ask, real and tested by `_score_threat_hunting_guidance()` — but never called from `pipeline_composer.py`. Section 14 (Threat Hunting) was permanently `WITHHELD_INSUFFICIENT_EVIDENCE` for every article, every family. |
| Named historical regressions ("CodeWhale symlink/path traversal", "VMware/IIOP KEV") | **Not found anywhere in this repository.** Checked via repo-wide grep for both terms before writing any regression test. "CodeWhale" is coincidentally the name of a real CVE-2026-75912 record used in this codebase's own tests, for an unrelated defect (non-discriminating related-report labels), with a CWE-88 (argument injection) classification — not path traversal/symlink. Treated as the mandate's own illustrative framing of a defect *class*, not a real prior incident; regression tests below are honestly framed as targeting that class, not as reproducing an unverified specific incident. |

## 1. What was reused, not rebuilt

- `DetectionValidationState` + `check_state_promotion()`/`check_all_rules()`/`check_withheld_rules_have_rationale()` — extended (2 new enum members, corresponding logic branches), never replaced.
- `attack_mapper.map_techniques()`/`is_valid_technique_id()`/`extract_technique_ids()` — the exact same negation-aware primitives `intelligence_validation.py`'s scorer already used, reused verbatim for the new hard gate. Zero new ATT&CK-matching logic written.
- `executive_products.HuntHypothesis`/`render_hunt_package()` — extended with the 4 fields the mandate's Section 12 names beyond what already existed, never replaced.
- `report_renderer.DetectionPackage.telemetry` — reused verbatim as `HuntHypothesis.required_telemetry` for the one family wired this round, rather than re-deriving a second copy of the same vulnerability-class-conditioned telemetry guidance.
- `commercial_readiness.py`'s existing `detection_evidence_discipline` control row — the new ATT&CK-citation check was folded into this existing row, not added as a 24th row, because this module's own docstring names "the exact 23-row matrix Section 33/46 requires" as a fixed external contract (see §2).

## 2. Why the new ATT&CK gate is a sub-check, not a new control

`commercial_readiness.py` orchestrates a **named, external, fixed-size 23-control matrix** (its own module docstring: "Orchestrates every gate this package implements into the exact 23-row matrix Section 33/46 requires"). Adding a 24th row was the first implementation attempt; it broke 13 tests that hardcode "23" as a contract invariant, not an incidental count. Reverted and folded the new check into the existing `detection_evidence_discipline` row instead — same control_id, an additional failure-mode check inside the same PASS/FAIL row. Zero rows added or removed; the 23-row contract is intact.

## 3. Two real defects found — and one design lesson learned — empirically, not assumed

Wiring the new ATT&CK-citation-justification check surfaced real findings on the *first* run against real data, not synthetic fixtures:

1. **A design lesson, caught before merge:** the first version of the gate also hard-failed on `attack_mapper.is_valid_technique_id()` (curated-registry membership), mirroring the existing scorer exactly. Run against two real, gold-standard, already-published canary exports (`dragonforce-vermont-xcenter`, `medusalocker-bija-industrie`), both failed — not because their content was wrong, but because the curated `KNOWN_TECHNIQUES` subset was incomplete relative to real report content. **Hard-failing on curated-registry completeness would have downgraded and blocked two legitimately good, already-published reports.** The gate was narrowed to hard-fail only on the negation-aware textual-evidence check (empirically verified safe — see §5) and leave registry-membership as informational only, not a failure condition.
2. **`attack_mapper.KNOWN_TECHNIQUES` was missing T1219 (Remote Access Software)** — a real, standalone MITRE technique cited by the dragonforce canary with genuine, non-negated textual support (verified directly against the export JSON). Added.
3. **A parent/sub-technique granularity mismatch**: the medusalocker canary's real, CISA/FBI/Treasury/FinCEN-advisory-sourced detection rule cited the bare parent `T1053` (Scheduled Task/Job), but the rendered text's only supporting language is "a scheduled task," which `attack_mapper.py`'s existing lexicon maps to the more specific sub-technique `T1053.005` — two distinct dict keys. Retargeted the canary's rule to `T1053.005` (verified via the rule's own sourced description as the more accurate citation) rather than changing the matching logic.

Both real canary exports now pass 23/23 controls again, verified via a **single-line, surgical diff** to the export JSON (not a wholesale regeneration — an attempted full regeneration was reverted after it silently pulled in unrelated, unverified confidence-value drift from a separately-stale part of the export; see the git history on this branch for that revert).

## 4. What this round builds

1. **Detection-maturity reconciliation** (`detection_validation.py`, `pipeline_composer.py`): `NOT_APPLICABLE` and `TELEMETRY_SPECIFICATION` added to `DetectionValidationState`, both correctly excluded from the promotion-rank ladder (same off-ladder treatment as `WITHHELD_INSUFFICIENT_EVIDENCE` — a rule in any of the three can never be described with validated-state language). `pipeline_composer._STATUS_TO_VALIDATION_STATE` now maps all 4 real `DetectionPackage.status` strings correctly instead of collapsing 3 into 1.
2. **ATT&CK-citation justification as a hard gate** (`commercial_readiness.py`): a cited technique_id on an *active* (non-off-ladder) detection rule must have real, negation-aware textual evidence somewhere in the rendered report, or the report fails `detection_evidence_discipline` and is capped at `PUBLIC_REFERENCE_DRAFT`. A technique_id tagged on a withheld/not-applicable rule (a topic tag, not an assertion) is correctly exempted.
3. **Real hunt hypotheses for `cve_advisory`** (`pipeline_composer.py`, `executive_products.py`, `report_contract.py`, `analytical_depth_gate.py`): a genuine, evidence-grounded exposure-plus-exploitation hunt hypothesis, reusing the same vulnerability-class-conditioned telemetry guidance `_detection_package()` already computes. Reaches the rendered HTML, the `intelligence_validation.py` scorecard, and `report_contract.py`'s Section 14 state resolution (now `COMPLETE` instead of permanently `WITHHELD_INSUFFICIENT_EVIDENCE` for this family). Scoped to one family this round — see §7.

## 5. Real-data validation

Empirical verification (not reasoning alone) that the new gate's safe half is actually safe, using the real dragonforce export:

```
T1219 found at index 6700 in the real rendered_text
context: "...command and control** (T1071, T1090, T1105, T1219, T1571)..."
map_techniques() result: T1219 present, evidence "technique ID T1219 cited explicitly in source"
negated? False
```

And that the medusalocker gap was genuinely a granularity mismatch, not a missing citation:

```
grep for bare "T1053" (not followed by ".") in the real rendered_text: zero matches
"scheduled task" phrase found at index 5860, real supporting context present
map_techniques() result: T1053.005 present; T1053 absent
```

A full before/after run of the hunt-hypothesis wiring against a representative `cve_advisory` fixture:

| Signal | Before | After |
|---|---|---|
| `ComposedReport.hunt_hypotheses` | n/a (field did not exist) | 1 real hypothesis |
| Rendered HTML contains "Threat Hunting" | No | Yes |
| `intelligence_validation` scorecard, Threat Hunting Guidance dimension | `BLOCKED` — "No hunt hypotheses supplied" | `PASS`, score 100 |
| `report_contract` Section 14 state (`hunt_hypothesis_count=0` vs. real count) | `WITHHELD_INSUFFICIENT_EVIDENCE` | `COMPLETE` |

## 6. Adversarial results

New tests (all passed on first run after implementation, i.e. found no further defects, only confirmed correct behavior):

- **Hallucinated technique ID** (zero textual evidence anywhere): `detection_evidence_discipline` → FAIL.
- **Explicitly negated/rejected citation** ("T1486 ... was considered and rejected"): → FAIL, proving the check is negation-aware, not merely presence-based.
- **Genuinely evidenced citation** (contrast case, same technique_id with real support): → PASS, proving the check discriminates real evidence from absence rather than failing everything.
- **Technique_id tag on a withheld rule**: never held to the evidence bar (a topic tag, not an assertion) — → PASS, confirmed not a regression on the pre-existing `test_withheld_detection_rule_with_rationale_and_gap_passes` test.
- **`NOT_APPLICABLE`/`TELEMETRY_SPECIFICATION` rules claiming a validated state in prose**: both → flagged, same discipline as `WITHHELD_INSUFFICIENT_EVIDENCE` already had.
- **Hunt-hypothesis genericness**: asserted `required_telemetry` never contains "monitor suspicious activity"/"review logs"/"check for unusual behavior" (the mandate's own named generic-advice phrases) and that every mandate-named field is genuinely non-empty, not populated to satisfy a completeness check alone.
- **Hunt-hypothesis never asserts compromise occurred**: statement text is conditional ("if X, then look for Y"), never "was exploited"/"has been compromised".
- **Family scoping**: `ransomware_claim` and `general_intelligence` correctly get zero hunt hypotheses (no evidence basis for this family's shape yet — "no evidence = withhold," not a generic hunt bolted on regardless).

## 7. What this round deliberately does not do

- **No structured ATT&CK object with a formal `status` field (OBSERVED/ASSESSED/CONDITIONAL/NOT_SUPPORTED) reaching the rendered report.** `report_renderer._detection_package()`'s mappings remain prose sentences, already worded "conditional on X" and already governed by `_attack_section()`'s own section-level disclaimer ("Mappings are conditional analytical aids, not claims that the technique occurred"). Formalizing this into a structured field is real, separate work — deliberately not attempted alongside the ATT&CK-citation gate in the same round, given how much real, non-obvious ripple that one gate alone caused through two gold-standard fixtures (§3). Named as explicit follow-up, not silently dropped.
- **No `cisa_kev` hunt hypothesis** (mandate Section 15's "retrospective exploitation hunt"). Scoped to `cve_advisory` only this round to prove the wiring pattern once, cleanly, rather than risk a rushed second family. Real, separate follow-up.
- **No malware/phishing/ransomware-campaign hunting policy** — those families don't exist as real classifier outputs yet (per Phase 1H's own certification), so hunting policy for them is not yet reachable work.
- **No change to `attack_mapper.py`'s negation heuristic (`_is_negated()`/`_clause_span()`)** — both real defects found this round were data/citation-precision issues, not negation-detection bugs; verified empirically that the specific citations involved were already correctly detected as non-negated (§5). A previously-documented "minified HTML clause-boundary" false-negative concern in `test_intelligence_validation_against_real_canaries.py`'s old docstring is not claimed fixed or unfixed in general — only that it did not affect either of the two citations this round touched.

## 8. Test evidence

| Suite | Before this round | After |
|---|---|---|
| Root `tests/` | 475 passed | **478 passed, 0 failed** |
| `Sentinel-APEX/engine/tests/` | 980 passed, 1 pre-existing failure | **998 passed, 1 pre-existing failure** (same `test_certify_real_end_to_end_with_the_actual_node_rendering_check`, environment-dependent Node-rendering gap, confirmed untouched) |
| `tests-js/` | 123 passed | **123 passed, 0 failed** (Pipeline B architecturally untouched) |

No existing test's assertions were weakened. Two existing artifacts were corrected for accuracy as a **direct, intended** consequence of a real fix, not a workaround: `reportx-canary/medusalocker_bija_industrie_canary.py`'s rule technique_id (T1053 → T1053.005, more precise) and its corresponding export JSON (one-line surgical fix); `test_intelligence_validation_against_real_canaries.py`'s `_KNOWN_MITRE_JUSTIFICATION_FAILURES` set (both formerly-known failures are now genuinely resolved, documented with the real fix method, not asserted away).

## 9. Semantic review (manual, not just programmatic)

- The new gate's rendered evidence ("T1219 cited explicitly in source", verified against real context around a real MITRE ATT&CK mapping table) is technically defensible to a reader: the technique is named alongside its correct tactic grouping, in a section explicitly labeled as documented actor capability, not an assertion this specific incident exhibited it.
- The hunt hypothesis's statement genuinely corresponds to the exploit mechanism it's paired with: it reuses the SAME vulnerability-class-conditioned telemetry `_detection_package()` computes for the Detection Engineering section immediately above it in the rendered report, so the two sections cannot silently drift apart on what telemetry the evidence actually supports.
- The hunt hypothesis is testable: it names required telemetry, a concrete validation procedure (3 numbered steps), explicit success criteria, and explicit escalation criteria requiring independent corroboration before IR involvement — not "monitor for suspicious activity."

## 10. Certification verdict

**RELEASE_CERTIFIED** for the three real changes this round makes (detection-maturity reconciliation, ATT&CK-citation hard gate, `cve_advisory` hunt-hypothesis wiring):

- Zero regressions across all 3 suites (1,599 tests total, 1 pre-existing unrelated failure).
- Two real, previously-invisible defects found and fixed with minimal, verified, surgical changes — not assumed, not guessed.
- One real design risk (curated-registry-completeness as a hard-fail condition) identified empirically before merge and narrowed to the safe half of the check, rather than shipped and discovered in production.
- No quality/integrity gate weakened. The new gate is strictly additive protection; the softened design decision (§3.1) was a deliberate, documented choice to avoid a false-positive-driven production regression, not a shortcut.
- Reuse Before Build honored throughout: zero new report-family concepts, zero new ATT&CK-matching logic, zero new detection-maturity vocabularies invented from scratch — every change extends an existing, already-tested mechanism.

**NOT RELEASE CERTIFIED, explicitly incomplete:** a formal structured ATT&CK status object, `cisa_kev`/other-family hunting, and all of Phase 1J onward. Per the mandate's own instruction, this is not described as "Phase 1 complete" anywhere in this document or the accompanying PR.

## 11. Rollback

Every change in this round is additive (new enum members, a new check folded into an existing control row, a new field with safe defaults, a new function gated to one family). Reverting the PR restores prior behavior exactly: `DetectionValidationState` loses its 2 new members (harmless — nothing outside this PR references them), `detection_evidence_discipline` loses its ATT&CK-citation sub-check, and `cve_advisory` articles lose their hunt-hypothesis section (reverting to the pre-existing, permanently-`WITHHELD` Section 14 state). No data migration, no schema change, no irreversible step.
