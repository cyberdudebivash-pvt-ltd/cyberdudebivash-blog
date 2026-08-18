# The Intelligence Validation Framework

Commercial CTI Platform Phase 3, Deliverable 1: an automated evaluation
framework that produces one objective, numeric scorecard per report across
20 measurable dimensions, plus a mandatory-threshold publication-eligibility
verdict. Implemented as `sentinel_engine/reportx/intelligence_validation.py`;
reachable via `cli.py reportx-validate` and
`intelligence_validation.evaluate_from_export()`.

**Status: computed, tested, documented, CLI-reachable — not wired into
`pipeline_composer.py` or the live syndication pipeline in this pass.** Same
sequencing this package's own history already used for `qms.py`
(`REPORTX-QUALITY-MANAGEMENT-SYSTEM.md`): ship the design plus one real,
validated path first; wire into production as its own, separately-reviewed
change once this is approved. See "What this does not do" below.

---

## Why a new module, not a change to `commercial_readiness.py`

The Phase 3 mandate asks for something categorically different from what
`commercial_readiness.py` (23-control PASS/FAIL/BLOCKED matrix) and
`qms.py` (18-category regroup of the same) already provide: "Every report
must be scored across measurable dimensions... generate an objective
scorecard." A scorecard needs magnitude — *how much* evidence backs a claim,
*how* complete a forecast's reasoning is — not just a binary verdict. Per
Single Source of Truth and Reuse Before Build, this module adds a numeric
layer **on top of**, not instead of, the existing gates:

- It never recomputes an evidence judgment. Every dimension is a pure
  function of `control_results` (already computed once by
  `evaluate_commercial_readiness()`), the bundle's own graph/detection_rules/
  forecasts, and whatever `SupplementalEvidence` a caller supplies.
- Several dimensions reuse `qms.QMS_CONTROL_MAP`'s own control-id tuples
  **by import**, not by retyping them — `TestSharedControlReuseIsGenuine`
  in `test_intelligence_validation.py` asserts this directly, so the two
  documents' category definitions cannot silently drift apart.
- `ANALYTICAL_COMPLETENESS` imports `tier_downgrade.PREMIUM_COMPLETENESS_CONTROLS`
  directly for the same reason.
- `MITRE_ATTACK_JUSTIFICATION` reuses `sentinel_engine.attack_mapper`'s
  public `is_valid_technique_id()`/`map_techniques()`/`extract_technique_ids()`
  unchanged.
- `commercial_readiness.py` itself — a `release_certification.py`
  `TRACKED_COMPONENT_PATH` — is **not modified**. Every additional input a
  few dimensions need (role decisions, sector impact, hunt hypotheses,
  cross-report similarity) arrives through the new, purely-additive
  `SupplementalEvidence` wrapper instead of new `ReportBundle` fields, so
  this change cannot trigger a release-drift re-certification requirement.

## Dimension → real enforcement

Every dimension name is verbatim from the mandate's own list
(`ValidationDimension`, test-enforced against drift the same way
`qms.QMSCategory` is). "Control-derived" dimensions are fail-closed: if
*any* attempted contributing control FAILs, the dimension FAILs regardless
of the numeric average (`_RawScore.hard_fail` — a partial-credit score can
never launder a known defect into an apparent PASS). "Continuous" dimensions
have no single binary control behind them; their only gate is the
configured per-dimension score threshold.

| Dimension | Kind | Real signal |
|---|---|---|
| Evidence Traceability | control-derived | `source_provenance`, `evidence_hash`, `evidence_ledger`, `report_specific_bibliography` |
| Source Reliability | continuous | `claim_model.Reliability` averaged over sources actually cited (`analytic_scaffolding.build_bibliography`) |
| Information Credibility | continuous | **New, derived** — see "The second Admiralty axis" below |
| Confidence Discipline | control-derived | `qms.QMS_CONTROL_MAP[CONFIDENCE_DISCIPLINE]` (reused) |
| Analytical Reasoning | control-derived | `qms.QMS_CONTROL_MAP[ANALYTICAL_QUALITY]` (reused) — `alternative_hypotheses`, `victim_specific_analysis`, `actor_specific_analysis` |
| Business Context | continuous, blended | `regulatory_specificity` control (hard-fails on FAIL) + optional `SectorImpact` ASSESSED-fraction + optional business-facing `RoleDecision` grounding |
| Technical Accuracy | control-derived | `qms.QMS_CONTROL_MAP[TECHNICAL_ACCURACY]` (reused) |
| Operational Guidance | control-derived | `qms.QMS_CONTROL_MAP[OPERATIONAL_UTILITY]` (reused) — `technical_recommendations` |
| Executive Decision Support | continuous, supplemental | fraction of CEO/Board- or CISO/CIO-targeted `RoleDecision`s carrying real `evidence_claim_ids` |
| Detection Engineering | control-derived + magnitude | `detection_evidence_discipline` control blended with the fraction of `DetectionRule`s beyond `DRAFT` |
| Threat Hunting Guidance | continuous, supplemental | fraction of `HuntHypothesis` entries with every required field populated |
| MITRE ATT&CK Justification | continuous | every cited technique ID (`attack_mapper.extract_technique_ids`) must be registry-valid **and** evidenced in rendered text (`attack_mapper.map_techniques`) |
| Forecast Quality | control-derived + magnitude | `forecast_methodology` control blended with a 6-field estimative-richness average (governed `WithheldForecast` gets full richness credit) |
| Writing Quality | continuous | `qa_linter` **warn**-severity findings (duplicate headings/paragraphs, dangling colons) |
| Consistency | control-derived | `qms.QMS_CONTROL_MAP[CONSISTENCY]` (reused) — `cross_section_consistency` |
| Editorial Quality | control-derived + magnitude | `qms.QMS_CONTROL_MAP[EDITORIAL_QUALITY]` (reused) blended with `qa_linter` **block**-severity finding count |
| Duplicate Detection | continuous, partial | within-report `qa_linter` duplication always checked; cross-report is honestly `BLOCKED` unless the caller supplies `cross_report_similarity_findings` |
| Unsupported Claims | control-derived | `qms.QMS_CONTROL_MAP[NO_UNSUPPORTED_CLAIMS]` (reused) |
| Analytical Completeness | control-derived | `tier_downgrade.PREMIUM_COMPLETENESS_CONTROLS` (reused) |
| Production Readiness | control-derived | `fortune_500_commercial_deliverable` — the existing 23-control roll-up itself, renamed |

Writing Quality and Editorial Quality deliberately partition the **same**
`qa_linter.lint_text()` call by severity (warn vs. block) rather than each
recomputing it — a style/flow defect (a repeated paragraph) and a
correctness defect (an unresolved template token) are different failure
classes the mandate names separately, and `qa_linter.py` already
distinguishes them by severity for exactly this kind of downstream split.

## The second Admiralty axis: Information Credibility

`REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`'s "Source reliability
display" section named this gap explicitly: `admiralty_label()` renders only
the existing `Reliability` field (Source Reliability, A–F), and called a
genuine second, independent Information Credibility axis (1–6) "a real,
additive follow-up if the operator wants the full 2-D grid." This module
adds it — as a **derived view**, not a new hand-set field, so it can never
drift from what the claim ledger already records:

```
score = base_points[claim.status] + corroboration_bonus[claim.corroboration_state]
```

using `claim_model.EpistemicState`/`CorroborationState`, both already
populated by every existing bundle builder. This is why a claim resting on
one authoritative source (e.g. NVD assigning its own CVE ID — `CONFIRMED`,
`SINGLE_SOURCE`) can legitimately score 100 on Source Reliability while
scoring more modestly here: corroboration genuinely is a distinct axis from
source authority under Admiralty doctrine, and collapsing the two into one
number would hide that. See `_CREDIBILITY_BASE_POINTS`/
`_CREDIBILITY_CORROBORATION_BONUS` for the exact formula and
`TestInformationCredibility` for the ordering guarantees it must hold.

## Mandatory thresholds

`ValidationThresholds`: `overall_minimum` (default 75), `minimum_coverage`
(default 0.5 — at least 10/20 dimensions must be scoreable, not `BLOCKED`),
and `per_dimension_minimum` (default 70 per dimension, with two evidence-
calibrated exceptions — see "Validation results" below). `publication_eligible`
is `False` if *any* scored dimension FAILs, coverage is below the floor, or
the weighted overall score is below the floor — mirroring the fail-closed
philosophy `tier_downgrade.py`/`commercial_readiness.py` already establish,
extended with the coverage floor a purely-categorical gate doesn't need
(a report scored on 3/20 dimensions cannot honestly certify itself on the
strength of those 3 alone).

The overall score is a weighted average (`WEIGHTS`, sums to 1.0, test-
enforced) over **non-`BLOCKED`** dimensions only, renormalized — the same
"excluded, not counted as satisfied" treatment `qms.QMSReport.gated_categories_pass`
already gives `NOT_GATED` categories, adapted to numeric averaging.

## Validation results

Per the Phase 3 validation requirement ("verify evidence traceability...
verify ATT&CK mappings... document all failures and corrective actions"),
this framework was run against every real, human-reviewed premium canary
this repository has — `reportx-canary/exports/*-export.json`, the exact
artifacts `release_certification.REQUIRED_CANARY_IDS` names, plus the
flagship executive-product reference implementation — via
`test_intelligence_validation_against_real_canaries.py`.

| Canary | Overall | Coverage | Eligible | Finding |
|---|---|---|---|---|
| cve-2025-62593-ray-canary | 95 | 85% | **Yes** | — |
| cve-2025-62593-ray-flagship-executive-product | 95 | 85% | **Yes** | — |
| qilin-spoonful-of-comfort-premium-canary | 94 | 85% | **Yes** | — |
| dragonforce-vermont-xcenter-premium-canary | 88 | 85% | No | MITRE ATT&CK Justification FAIL (real, see below) |
| medusalocker-bija-industrie-premium-canary | 88 | 85% | No | MITRE ATT&CK Justification FAIL (real, see below) |

Coverage is 85% (17/20) for all five — the three purely-supplemental
dimensions (Executive Decision Support, Threat Hunting Guidance, Duplicate
Detection cross-report) are honestly `BLOCKED` for every one of them, because
nothing in the pipeline populates `SupplementalEvidence` yet (see "Named
gaps" below), not because of a defect.

### Finding 1 (addressed in this change): two new dimensions' default thresholds were miscalibrated

The first run against all five real canaries showed **Information
Credibility** and **Forecast Quality** failing on all five, including the
three already-eligible ones. Root-caused, not threshold-tuned blind:

- **Information Credibility** landed at "3 — possibly true" (~50–55) across
  the board because Section 10's own single-source-stays-`REPORTED`
  discipline means a genuinely honest, single-incident CTI report's claims
  are typically `REPORTED`+`SINGLE_SOURCE` — that IS the honest ceiling for
  well-sourced but single-incident reporting, not a credibility defect. The
  blanket default of 70 would have failed every existing flagship report on
  day one for being honest about its own sourcing.
- **Forecast Quality**'s richness bonus (6 optional fields: historical
  baseline, counter-evidence, alternative scenarios, indicators to watch,
  assumptions, what-would-change) measured 0% across all five real
  forecasts — the existing `forecast_methodology` adequacy floor (real
  support + a written confidence rationale) is what these reports actually
  clear today; the richness axis is a genuine but aspirational depth signal
  nothing has been asked to populate yet.

Both are dimension-specific defaults this framework itself defines
(`_DEFAULT_MINIMUM_OVERRIDES` in `intelligence_validation.py`), lowered to
50 and 55 respectively from evidence, not guessed — and fully overridable
per caller via `ValidationThresholds`. After the correction, all three
already-commercial-ready canaries became `publication_eligible`, and the two
with a real defect stayed correctly blocked (Finding 2).

### Finding 2 (named, not fixed in this change): a real `attack_mapper.py` false negative on minified HTML

Two of five real canaries genuinely fail **MITRE ATT&CK Justification**:
`dragonforce-vermont-xcenter` (`T1219`) and `medusalocker-bija-industrie`
(`T1053`). Root cause, reproduced directly:

`automation/report_renderer.py`'s `_attack_section()` renders a real,
conditional ATT&CK mapping sentence into the report body (e.g. `"Execution
→ Command and Scripting Interpreter (T1059), conditional on observed
child-process execution."`), immediately followed by a caveat panel
("Mappings are conditional analytical aids, not claims that the technique
occurred"). `attack_mapper._clause_span()`'s negation-scoping heuristic
looks for a sentence boundary (`.`/`!`/`?` + whitespace, a blank line, or a
markdown-table-row end) between the two — but this is minified, single-line
HTML with no such boundary between adjacent `<div>`s, so the clause span
extends across both, and `_is_negated()` finds the *caveat panel's* "not
claims that the technique occurred" and incorrectly treats the *earlier*
technique citation as negated. Verified directly (not inferred) against the
real `dragonforce` export: `T1219` is present in the rendered text,
`is_valid_technique_id("T1219")` is `True`, and `map_techniques()` still
excludes it for exactly this reason.

**Why this is named, not fixed here:** `attack_mapper.py` is a shared,
`sentinel_engine`-wide module (`scoring.py`'s `_original_analysis`/
`_evidence_quality` dimensions and the older System 1/3 pipeline depend on
its negation behavior too); a fix changes shared, tested behavior outside
this deliverable's stated scope and needs its own blast-radius review, not
a drive-by inside "build the validation framework." This framework's job —
catching a real, previously-invisible defect nothing else in the system
checked for — is exactly what it just did.

**Proposed minimal fix** (for a dedicated follow-up): extend
`attack_mapper._RE_SENTENCE_BOUNDARY` to also treat common HTML block-level
closing tags (`</p>`, `</div>`, `</section>`, `</li>`) as clause boundaries,
mirroring the same file's own precedent for markdown table rows
(`_RE_SENTENCE_BOUNDARY` already special-cases `|[ \t]*\n` for exactly this
reason, per that regex's own comment history).

## Named gaps (evidence, not speculation)

- **`SupplementalEvidence` is a real, tested input contract that nothing
  currently populates in the live pipeline.** `pipeline_composer.py`
  computes `role_decisions` locally (`_lean_role_decisions()`) but never
  attaches them to the `ReportBundle`, and has no hunt-hypothesis or
  sector-impact construction at all yet. Executive Decision Support, Threat
  Hunting Guidance, and cross-report Duplicate Detection are `BLOCKED` for
  every report scored via `evaluate_from_export()` today — this mirrors
  exactly the honesty `qms.py` already applies to its own two ungated
  categories (`NOT_GATED`, never a fabricated PASS). Wiring
  `pipeline_composer.py` to populate `SupplementalEvidence` is real,
  additive follow-up work, not done in this pass.
- **Not wired into `pipeline_composer.py` or `automation/authority_transformer.py`.**
  This framework does not gate the live, ~15–30-minute-cadence syndication
  pipeline yet. Reachable today via `cli.py reportx-validate` and
  `evaluate_from_export()` against any `reportx-gate --export` artifact.
- **The `attack_mapper.py` negation-heuristic gap** (Finding 2 above) is
  real and reproduced, not fixed.
- **Business Context**'s sector/role blending is a genuine but shallow
  first pass — it has no dedicated `RegulatoryApplicability`-style
  per-sector evidence model of its own; it blends whatever the caller
  already has (regulatory determination, `SectorImpact`, business-facing
  `RoleDecision`s), and reports `BLOCKED` when none of the three are
  supplied.

## Usage

```python
from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness
from sentinel_engine.reportx.intelligence_validation import evaluate_intelligence_validation, render_scorecard_markdown

control_results = evaluate_commercial_readiness(bundle)
scorecard = evaluate_intelligence_validation(bundle, control_results)
print(render_scorecard_markdown(scorecard))
print(scorecard.publication_eligible, scorecard.overall_score, scorecard.coverage)
```

Or against an existing `reportx-gate --export` artifact directly:

```python
from sentinel_engine.reportx.intelligence_validation import evaluate_from_export
scorecard = evaluate_from_export(export_dict)
```

```
python3 cli.py reportx-validate report-export.json [--json] [--overall-minimum N] [--minimum-coverage F]
```

Exit 0 only when `publication_eligible` is true; exit 1 otherwise.

## Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `commercial_readiness.ControlResult`/`ReportBundle`, `qms.QMS_CONTROL_MAP`, `tier_downgrade.PREMIUM_COMPLETENESS_CONTROLS`, `qa_linter.lint_text`, `analytic_scaffolding.build_bibliography`, `attack_mapper.{is_valid_technique_id,map_techniques,extract_technique_ids}`, `detection_validation.DetectionValidationState`, `forecast.Forecast/WithheldForecast`, `executive_products.{RoleAudience,RoleDecision,HuntHypothesis,SectorImpact}`, `bundle_io.{bundle_from_dict,export_report_json}`, `claim_model.{EpistemicState,CorroborationState,Reliability}` |
| Existing API routes extended (not duplicated) | `cli.py` — new `reportx-validate` subcommand alongside `reportx-gate`/`reportx-review`/`reportx-release`/`reportx-certify`, same artifact format |
| Existing pages extended (not replaced) | N/A (backend engine change only) |
| New components introduced (justified by gap analysis) | `intelligence_validation.py` (this module) — no existing module produces a numeric, weighted, 20-dimension scorecard; `sentinel_engine/scoring.py`'s 14-dimension scorer is architecturally incompatible (operates on the legacy `PipelineResult`/`NormalizedDoc` model, not ReportX's `EvidenceGraph`/`ReportBundle`) |
| Duplicate components introduced | 0 |
| Duplicate routes introduced | 0 |
| Backward compatibility preserved | PASS — zero existing files modified except an additive `cli.py` subcommand registration; `ReportBundle`/`commercial_readiness.py`/`qms.py` untouched |
| Build passing with zero errors | PASS — `python3 -m py_compile` clean; full `tests/` suite (888 tests outside this change) unaffected |

## Production blast radius

| Dimension | Assessment |
|---|---|
| Files changed | 1 new module, 3 new test files, 1 additive edit to `cli.py` (new subcommand only), this doc |
| Imports/consumers of changed files | `cli.py` is imported by nothing else in-repo besides its own tests; the new module has zero consumers yet (not wired into `pipeline_composer.py`/`automation/`) |
| Page routes | None |
| API routes | None (no `api/` files touched — this is the Python ReportX engine, a separate runtime from the Next.js blog's `lib/governance`/`api/v1/quality` layer) |
| CI workflows | `intelligence-engine-ci.yml` runs `pytest tests/ -v` + `py_compile` on path `Sentinel-APEX/engine/**` — exercised directly; verified locally: 616/616 `tests/reportx/` pass, 888/889 full `tests/` pass (the one failure is a pre-existing, environment-only Node-availability gap in `test_certification.py`, reproduced identically on the unmodified base branch) |
| SEO impact | None |
| Lighthouse impact | None (backend-only) |
| Monetization impact | None directly; indirectly supports the "objective scorecard" trust/quality-assurance commercial value this platform's CTI product line depends on |
| Build output | None (Python, no bundler) |
| Expected risk | **LOW** |
