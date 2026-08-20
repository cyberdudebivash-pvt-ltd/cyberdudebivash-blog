# REPORTX Phase 1K — 24-Section Semantic Population: Certification

**Written:** 2026-08-20, same session as the Phase 1J recovery round.

---

## 1. Starting-state verification

- PR #119 (Phase 1J) confirmed merged into `main` via the GitHub API (`merged: true`, head sha
  matches the exact commit pushed last round). No open PRs. Branch restarted from `origin/main`
  per the already-merged-PR protocol (`git checkout -B claude/production-session-recovery-036t5a
  origin/main`).
- `role_decision_count` reconfirmed present in the 3 files Phase 1J touched (grep counts 6/3/1)
  and the Phase 1J certification doc reconfirmed present on `main` — Phase 1J's claims verified
  against code, not trusted.
- Baseline reproduced fresh on the new `main`, before any Phase 1K edit: root 497 passed, engine
  1045 passed + 1 pre-existing unrelated failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`,
  reconfirmed present, Node-rendering environment issue), JS 123 passed — exactly matching Phase
  1J's own certified numbers.

## 2. 24-section contract audit

Full audit: `docs/audits/REPORTX-PHASE1K-SECTION-AUDIT.md`, written before any implementation this
phase. Read `report_contract.py`, `report_renderer.py`, `authority_transformer.py`, and
`pipeline_composer.py` in full; traced every structured object's actual reach into
`transform()`'s published output across all 3 real content paths (`reportx_composer` /
LLM-authored / legacy `template`), not assumed from section-state claims alone.

**Findings:** of 24 sections, 3 real defects found (not counting Section 19, already fixed in
Phase 1J):

| # | Section | Defect | Severity |
|---|---|---|---|
| 6 | Evidence & Source Assessment | Claimed unconditional COMPLETE, but the real two-axis reliability/corroboration content it was claiming only ever reached the published page on 1 of 3 content paths | Real, customer-facing |
| 21 | Intelligence Gaps | Claimed PARTIAL_EVIDENCE on the strength of a real, family-conditioned gap list that had **never once** reached a published page, on **any** of the 3 content paths — including the composer's own | Real, customer-facing, broader reach than #6 |
| 22 | Forecast / Outlook | `forecast.py`'s `Forecast`/`WithheldForecast` (real, tested, certified) were never imported by the live pipeline at all — permanently WITHHELD for every article regardless of family | Certified-but-dormant module (the 4th recurrence of this exact defect class: hunt_hypotheses, attack_mapping, role_decisions, now forecast) |

Sections 4, 10, 16, 17, 20 remain honestly `WITHHELD`/`NOT_APPLICABLE` — no real evidence-extraction
capability exists in this pipeline for any of them, and building one is new capability work, not a
wiring fix. Not attempted this round; named explicitly in the audit doc, not silently skipped.
Sections 7/9's article-invariant-but-family-real content for the non-CVE trio, and the legacy
`template` fallback's own content-integrity characteristics, are documented findings, also not
touched this round (full reasoning in the audit doc §3/§6).

## 3. Implementation

### 3.1 Section 6 (`automation/authority_transformer.py`, `Sentinel-APEX/.../pipeline_composer.py`)

`reliability_html` (already computed, real, per-article) exposed as a new field on
`ComposedReport`/`_ComposerOutcome` and passed through as a pre-built HTML string — no new render
function needed (unlike hunt/attack/role, exactly one place ever constructs this content, so no
duplication risk from passing the string directly). Duplicate-guarded the same way as the other
three fixed sections: `if content_source != "reportx_composer" and composer_outcome.reliability_html`.

### 3.2 Section 21 (`pipeline_composer.py`, `authority_transformer.py`)

New `_render_intelligence_gaps_html()` in both modules (structured-object version in the composer,
dict-shape version in `authority_transformer.py`, mirroring the established pattern for every prior
structured section). The `intelligence_gaps` computation was moved to *before* the `html`
assembly line (it previously ran after) so `gaps_html` could be included in `html` on the composer's
own path — this also means `find_all_contradictions()` and `DepthAssessment` now correctly see the
complete page, gaps included, which they did not before (a strict improvement, not a behavior
change to guard against).

### 3.3 Section 22 (`forecast.py` wired for the first time)

`pipeline_composer._cve_forecast()` (new): scoped to `cve_advisory`/`cisa_kev`/`cisa_advisory`
only, mirroring `_cve_hunt_hypotheses()`'s own "prove the wiring pattern on the family with the
strongest real evidence first" precedent (RX-P1I). The only real, structural forecasting signal
this pipeline has for a CVE is the CISA KEV catalog listing (`discovery_bridge.py` only ever
constructs the `c-kev-listed` claim when `article.kev_listed is True`):

- **KEV-listed** → a real `Forecast`: judgment grounded in the confirmed federal exploitation
  signal, `time_horizon` stays qualitative ("until remediated," never an invented calendar
  deadline — mandate §10), `supporting_observation_claim_ids=("c-kev-listed",)`,
  `confidence="MEDIUM"` (reused from the existing `Confidence` enum, not a new vocabulary),
  explicit `confidence_rationale` and `what_would_change_assessment`.
- **Not KEV-listed** → an explicit, reasoned `WithheldForecast` ("no observed activity baseline to
  forecast from"), never a guessed judgment — this is the honest, correct outcome for the large
  majority of routine CVEs this pipeline sees, matching `forecast.py`'s own module-level philosophy
  ("either fully structured, or withheld").

`_render_forecast_html()` (both modules) renders **only** a real, `is_adequately_supported()`
forecast — a `WithheldForecast`'s reason is exposed structurally (in the output dict) but not as
customer-visible prose, matching every other `WITHHELD` section's own silent-omission convention
already established throughout this pipeline.

**Applicability reconciliation (`report_contract.py`):** `cve_advisory`'s matrix had
`SECTION_22_FORECAST_OUTLOOK: NOT_APPLICABLE` — a blanket judgment made when Section 22 had zero
implementation anywhere to weigh against. Found by running my own premium-candidate benchmark
(§6) and seeing a real, adequately-supported forecast resolve `NOT_APPLICABLE` regardless of its
count. Reconciled to `OPTIONAL` (never `MANDATORY` — a routine, non-KEV CVE correctly has no
forecast to offer), with the reasoning documented directly in the matrix. `cisa_kev`/
`cisa_advisory` inherit this via the existing alias, unchanged.

**A second, independent wiring gap found and fixed via the same benchmark:**
`commercial_readiness.py` already has a real, tested `forecast_methodology` control (part of the
separate, older 23-control `ReportBundle` scorecard — a different ladder from `report_contract.py`'s
24-section model, see `analytical_depth_gate.py`'s own docstring on why these stay independent) that
reads `bundle.forecasts` — never populated by `pipeline_composer.py`'s `ReportBundle(...)`
construction. Fixed with one line (`forecasts=forecasts`). Confirmed via the same real KEV article:
`forecast_methodology` went from `BLOCKED` ("No forecasts attempted in this bundle") to `PASS`. The
remaining failed controls on that same benchmark (`alternative_hypotheses`, `current_statistics`,
`premium_depth`, `regulatory_specificity`, `technical_recommendations`) belong to that separate,
older scorecard and are out of Phase 1K's scope (24-section semantic population); not touched.

## 4. Applicability matrix

Unchanged from Phase 1H/1I/1J except the one Section 22/`cve_advisory` reconciliation in §3.3
above. Full current matrix and per-family classification: `docs/audits/REPORTX-PHASE1K-SECTION-AUDIT.md`
§1.

## 5. Anti-duplication / source-to-analysis ratio

No new duplication-detection capability was built this round — none of the 3 fixes this round
introduce content that could plausibly duplicate another section (reliability grading, intelligence
gaps, and forecasts are each structurally distinct from every other section's content, and each is
rendered exactly once per report via the same duplication guard already proven correct for
hunt/attack/role). A dedicated cross-section semantic-overlap detector (mandate §16/§17) is real,
separate work appropriately scoped to Phase 1M (semantic/factual QA), not this round.

## 6. Real-data results

`reportx-canary/phase1k_section_completeness_representative_fixtures.py` (new): exercises the
real, unmocked `AuthorityTransformer(Config()).transform()` call for all 7 named families plus
`general_intelligence`, asserting — not just printing — that every section a count claims
`COMPLETE`/non-empty for genuinely appears in the rendered HTML:

| Case | Family | KJ | Role | ATT&CK | Hunt | Gaps | Fcst | S6 | S19 | S21 | S22 | Tier |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE (not KEV) | cve_advisory | 0 | 2 | 1 | 1 | 1 | 0 | COMPLETE | COMPLETE | PARTIAL_EVIDENCE | WITHHELD | TACTICAL |
| KEV (confirmed exploited) | cisa_kev | 0 | 2 | 1 | 0 | 1 | 1 | COMPLETE | COMPLETE | PARTIAL_EVIDENCE | **COMPLETE** | TACTICAL |
| Ransomware claim | ransomware_claim | 0 | 1 | 0 | 0 | 1 | 0 | COMPLETE | COMPLETE | PARTIAL_EVIDENCE | WITHHELD | TACTICAL |
| Ransomware reporting | ransomware_reporting | 0 | 1 | 2 | 0 | 2 | 0 | COMPLETE | COMPLETE | PARTIAL_EVIDENCE | WITHHELD | TACTICAL |
| Threat actor | threat_actor | 0 | 1 | 0 | 0 | 2 | 0 | COMPLETE | COMPLETE | PARTIAL_EVIDENCE | WITHHELD | TACTICAL |
| AI security | ai_security | 0 | 1 | 0 | 0 | 2 | 0 | COMPLETE | COMPLETE | PARTIAL_EVIDENCE | WITHHELD | TACTICAL |
| Breach notice | breach_notice | 0 | 1 | 0 | 0 | 2 | 0 | COMPLETE | COMPLETE | PARTIAL_EVIDENCE | WITHHELD | TACTICAL |
| General intelligence | general_intelligence | 0 | 0 | 0 | 0 | 1 | 0 | COMPLETE | WITHHELD | PARTIAL_EVIDENCE | WITHHELD | TACTICAL |

Every row is `TACTICAL`, not `PREMIUM_LONG_FORM` — expected: these fixtures run without a live LLM
provider configured in this environment, and Key Judgements (LLM-authored only) gates premium
regardless of any Phase 1K signal. This is the correct, honest result the mandate itself names as
the actual bar: "The expected result is NOT that all reports become premium. The expected result is
that section states become truthful."

All 3 prior real-data scripts (Phase 1I's ATT&CK fixtures, Phase 1J's role-decision fixtures, and
this round's) were re-run together at the end of this round — all pass, confirming zero regressions
across the full ReportX evolution to date, not just this round's own additions.

## 7. Premium candidate benchmark

A hand-built, evidence-rich KEV-listed CVE (`compose_report()` called directly, bypassing
`validate_publication()`'s stricter gate to inspect `DowngradeResult` directly): `achieved_tier =
TACTICAL_READY`. This is exactly what surfaced the `ReportBundle.forecasts` wiring gap (§3.3) — a
genuine, real defect a premium-candidate run caught that no unit test alone would have (none of
the existing unit tests exercise `commercial_readiness.py`'s 23-control scorecard against a
Phase-1K-shaped forecast). Not force-promoted to premium; the gate was not touched to make this
pass, only the real wiring defect it exposed was fixed.

## 8. Adversarial section-gaming results

`Sentinel-APEX/engine/tests/reportx/test_pipeline_composer.py::TestRXP1KForecastWiring` and
`tests/test_authority_transformer.py::TestAdversarialForecastGaming` (4 tests): a forecast with no
`confidence_rationale`, a forecast with no `supporting_observation_claim_ids`, an explicitly
`withheld` entry with other fields populated to look real, and an empty list — all confirmed to
render nothing and never reach customer-visible content. A forecast judgment was also confirmed to
never contain an invented numeric deadline pattern (`\d+\s*(hour|day|week)s?`).

## 9. Cross-section consistency

`phase1k_section_completeness_representative_fixtures.py` includes a live spot-check: a
`ransomware_claim` report's family-specific "Claim Assessment" section (not the whole page — see
below) must never assert a confirmed breach/compromise. **This check initially produced a false
positive** against the universal Executive Summary "Decision:" boilerplate line ("...before
treating this record as an incident, confirmed compromise, or customer-specific finding" — cautionary
guidance, the opposite of an assertion) when scanning the whole page; fixed by scoping the check to
the `data-section="claim-assessment"` block specifically. Documented here rather than silently
corrected, since a naive whole-page substring match is exactly the kind of check Phase 1M will need
to do far more carefully with real claim-to-render traceability, not simplistic pattern matching.

## 10. Test evidence

| Suite | Before this round | After this round | Delta |
|---|---|---|---|
| Root (`tests/`) | 497 passed | 515 passed | +18, 0 regressions |
| Engine (`Sentinel-APEX/engine/tests/`) | 1045 passed + 1 known unrelated failure | 1056 passed + the same 1 known unrelated failure | +11, 0 regressions |
| JS (`tests-js/`) | 123 passed | 123 passed | unchanged |

The one engine failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`) was
reconfirmed present and identical both before any Phase 1K code was written and after — a
Node-rendering environment issue, unrelated to anything this round touched.

## 11. Certification verdict

**`RELEASE_CERTIFIED`**

- All 3 confirmed missing-render/dormant-module defects found in the §2 audit are fixed, each with
  the same duplication-guard discipline already proven correct in Phase 1I/1J, verified against
  real (not mocked) `compose_report()`/`transform()` calls across all 3 content paths.
- One applicability-matrix reconciliation (Section 22/`cve_advisory`) made with documented
  reasoning, not a silent change — and one second, independent wiring gap (the separate
  `commercial_readiness.py` scorecard) found and fixed as a direct result of premium-candidate
  benchmarking, not left undiscovered.
- Zero regressions across root/engine/JS suites (exact counts above); all 3 real-data scripts
  (Phase 1I/1J/1K) re-verified together.
- A false positive in my own adversarial cross-section-consistency check was found, understood, and
  corrected before being reported as a passing result — not silently patched over.
- What remains deliberately unbuilt (Sections 4/10/16/17/20, the trio's per-article Technical
  Analysis depth, the legacy template's content-integrity characteristic) is named explicitly in
  the audit doc, not silently omitted.

This is **not** a claim that Phase 1 is complete, nor that every section is now semantically
populated — the mandate's own bar ("section states become truthful," not "every report reaches
premium") is the one this phase was measured against. Phase 1M (semantic/factual QA), 1N (premium
certification ladder), 1P (Blogger hard gate), and 1Q (post-publication fetch-back) remain, each
requiring its own audit-first round.
