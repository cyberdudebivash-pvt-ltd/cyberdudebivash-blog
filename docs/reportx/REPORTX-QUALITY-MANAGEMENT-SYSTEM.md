# Quality Management System — ROLE Mandate Category Mapping

The Intelligence Factory ROLE mandate requires a "Quality Management
System" with named, measurable gates: "Reports cannot be published unless
all mandatory gates pass." This document maps its exact 18 named
categories onto the real, already-existing, already-tested gates that
enforce them, and names the gaps honestly where no automated gate exists
yet. It is the category-first companion to `REPORTX-QUALITY-GATES.md`
(module-first: what each gate checks and how); this document does not
re-explain gate mechanics already covered there.

The orchestrator implementing this mapping is
`sentinel_engine/reportx/qms.py`. It computes nothing new — it re-groups
the already-computed output of `commercial_readiness.evaluate_commercial_readiness()`
under the mandate's category names. Single Source of Truth: if a control's
PASS/FAIL logic ever needs to change, it changes in `commercial_readiness.py`
(or the module it delegates to) once, and every category that references
it inherits the fix.

## The mandate, verbatim

> Quality gates must evaluate: Evidence, Analytical Quality, Tradecraft,
> Technical Accuracy, Editorial Quality, Consistency, Traceability,
> Confidence Discipline, Detection Quality, Operational Utility, Executive
> Readability, Role-based Guidance, Forecast Quality, No unsupported
> claims, No hallucinations, No duplicated content, No boilerplate
> repetition, No fabricated evidence.

18 categories. `qms.py`'s `QMSCategory` enum reproduces these 18 names
verbatim (`test_qms.py::TestCategoryFidelityToTheMandate` checks the enum
against this exact list, so a future edit here or there cannot drift
silently).

## Category → real enforcement

| Category | Contributing `commercial_readiness.py` controls | Notes |
|---|---|---|
| Evidence | `source_provenance`, `evidence_hash`, `evidence_ledger`, `source_specific_facts` | Backed by `evidence_integrity.py` (content hash / reasoned excerpt-fingerprint fallback) and `claim_support_matrix.py`. |
| Analytical Quality | `alternative_hypotheses`, `victim_specific_analysis`, `actor_specific_analysis` | `analytic_scaffolding.py`'s `HypothesisSet`/`NotApplicableHypothesisSet` is the real Analysis-of-Competing-Hypotheses-pattern implementation. See gap below: other named Structured Analytical Techniques are not separately modeled. |
| Tradecraft | `cross_source_corroboration`, `human_analyst_certification_governance` | Underlying discipline is `claim_model.py`'s 9-state `EpistemicState` vocabulary, `ObservedVsContext`, and the `HIGH_IMPACT_CLAIM_TYPES` cap (a high-impact claim type is never `CONFIRMED` off one source). |
| Technical Accuracy | `threat_type_schema_correctness`, `temporal_integrity`, `detection_evidence_discipline` | `report_renderer.py`'s `_validated_sigma()` performs real YAML syntax validation before any Sigma body is rendered. |
| Editorial Quality | `grammar_synthesis_qa` | `qa_linter.py`'s full check suite: dangling fragments, unresolved template placeholders, duplicate headings/paragraphs, dangling colons, code-fence balance, markdown table cell counts. |
| Consistency | `cross_section_consistency` | `contradiction_engine.py`'s dimension-tag and text-pattern contradiction checks. |
| Traceability | `report_specific_bibliography`, `evidence_ledger`, `source_provenance` | `analytic_scaffolding.py`'s `build_bibliography()`/`find_orphan_citations()`; every rendered report carries its own `_provenance()` section. |
| Confidence Discipline | `cross_source_corroboration`, `human_analyst_certification_governance` | `Reliability` enum + `executive_products.admiralty_label()` for source-reliability-labeled confidence; `human_review.resolve_certification_state()` for report-level certification confidence. |
| Detection Quality | `detection_evidence_discipline` | `detection_validation.py`'s `DetectionValidationState` + the state-promotion-language regex gate (`check_state_promotion`/`check_all_rules`) + rationale requirement for withheld rules. |
| Operational Utility | `technical_recommendations` | Recommendations must carry an `evidence_basis`; `executive_products.render_hunt_package()` for hunt-oriented operational content. |
| Executive Readability | **none** | See gap list. |
| Role-based Guidance | **none** | See gap list. |
| Forecast Quality | `forecast_methodology` | `forecast.py`'s `Forecast`/`WithheldForecast`; a withheld forecast requires a constructor-enforced `reason` and a recorded `intelligence_gaps` entry. |
| No unsupported claims | `source_specific_facts`, `victim_specific_analysis`, `evidence_ledger`, `current_statistics`, `regulatory_specificity`, `technical_recommendations` | `claim_support_matrix.STATUSES_REQUIRING_EVIDENCE` is the shared frozenset this and the Evidence category both key off, so the two policies cannot drift apart. |
| No hallucinations | `source_specific_facts`, `evidence_ledger`, `cross_section_consistency` (partial) | Stronger, unconditional gate is outside this matrix — see "The floor" below. |
| No duplicated content | `grammar_synthesis_qa` (partial — within-report only) | Cross-report duplication is a separate check — see "The floor" below. |
| No boilerplate repetition | `grammar_synthesis_qa` (partial — within-report only) | Same cross-report caveat, plus the architectural fix described below. |
| No fabricated evidence | `evidence_hash`, `source_provenance` | `evidence_integrity.py` — a source is never assigned a hash it wasn't computed from. |

`qms.py` reports a category `PASS` only if every contributing control that
is actually present is `PASS` (a `BLOCKED` control — genuinely absent
optional input, e.g. no forecast was ever attempted for a record type that
doesn't need one — does not sink the category, mirroring the same
tolerant-of-`BLOCKED` semantics `tier_downgrade.py`'s `CORRECTNESS_CONTROLS`
already established). Any real `FAIL` fails the category outright.

## The floor: what actually blocks publication today

**Scope caveat, stated plainly:** the 23-control matrix this whole
document maps categories onto is unconditionally exercised in the ReportX
premium/canary product pipeline (`reportx-canary/`, the `reportx-certify`
CLI path). In the live blog-syndication pipeline
(`automation/main.py` → `authority_transformer.transform()`), it is
exercised only when the new `reportx_composer` rung is reached — an LLM-
authored report, or one that falls all the way through to the legacy
template, is never passed through `evaluate_commercial_readiness()` at
all. For those two paths, `validate_publication()` below is the entire
automated quality floor; most of this document's category mapping does
not apply to them yet. Extending the composer's gate to run for the
LLM-authored path too is not built in this pass.

Two categories above (`No hallucinations`, `No duplicated content` /
`No boilerplate repetition`) are marked partial because their strongest
real enforcement runs **outside** the 23-control matrix `qms.py` reads:

- **`automation/report_integrity.py`'s `validate_publication()`** runs
  unconditionally on every report, regardless of `content_source`
  (LLM / `reportx_composer` / legacy template alike), and hard-blocks
  publication by raising `PublicationIntegrityError` — not a tier
  downgrade, an outright refusal to publish. It checks: required
  provenance fields present, minimum body length, no placeholder text, no
  unsupported commercial-scale claims, exploitation-assertion consistency
  with KEV status, no ransomware/AI schema contamination, no fabricated
  human-analyst attribution. This is the real, unconditional "No
  hallucinations" floor. By the time a report reaches `qms.py`, this gate
  has already passed — `qms.py` cannot re-check it because it is never
  given the rendered HTML, only the already-computed `ControlResult`s.
- **`automated_certification.derive_cross_report_similarity_escalation()`**
  (built in the P0 release-certification work) calls
  `product_depth.find_template_repetition()` across a report and a corpus
  of prior reports' sections. This is the real cross-report "No duplicated
  content" / "No boilerplate repetition" check. It is not wired into the
  per-report `pipeline_composer.compose_report()` path today — it operates
  at the release/export layer, where a corpus is actually available. A
  single-report orchestrator like `qms.py` structurally cannot run it.

The empirical root cause of prior boilerplate — 97.6% of historically
generated reports rendered via the deterministic legacy template, per
`REPORTX-LEGACY-PIPELINE-AUDIT.md` — is addressed architecturally as of
this work, not just detected after the fact: `pipeline_composer.py` now
supplies evidence-graph-backed, per-article content ahead of that
template in `authority_transformer.transform()`, whenever its own
fail-closed tier ladder (`tier_downgrade.determine_achieved_tier()`)
clears. The legacy template remains reachable as the final,
deprecated-not-deleted fallback, not the default path.

## Named gaps (evidence, not speculation)

- **Executive Readability** and **Role-based Guidance** have no
  `commercial_readiness.py` control at all. Real, tested support exists —
  `report_renderer.py`'s Executive Summary section;
  `executive_products.py`'s `RoleAudience` enum, `RoleDecision`, and
  `render_role_decisions()`, used by `pipeline_composer._lean_role_decisions()`
  — but nothing computes a PASS/FAIL verdict from it. Coverage today is
  enforced only by test assertions
  (`test_pipeline_composer.py::TestNoRepeatedBoilerplate::test_role_decisions_reflect_this_articles_own_evidence_not_a_fixed_sentence`),
  not by a production gate. `qms.py` reports both as `NOT_GATED` rather
  than fabricating a PASS.
- **Structured Analytical Techniques beyond the ACH pattern.** The mandate
  names Analysis of Competing Hypotheses, Key Assumptions Check,
  Indicators and Warnings, Alternative Futures, Hypothesis Testing,
  Opportunity Analysis, and Risk Assessment. Only the ACH pattern has a
  real implementation (`analytic_scaffolding.HypothesisSet`, gated by the
  `alternative_hypotheses` control). The other named techniques have no
  dedicated class or gate today.
- **Role coverage: the mandate's 17 named roles map onto 11 `RoleAudience`
  members**, some deliberately merged (`CEO_BOARD` covers Board and CEO;
  `CISO_CIO` covers CISO and CIO; `LEGAL_COMPLIANCE_PRIVACY` covers Legal,
  Privacy, and Compliance) plus one, `MSSP`, the mandate does not name.
  Three named roles have no corresponding member at all: **SOC Analyst**,
  **Detection Engineer**, **Identity Team**. `SOC_MANAGER` and
  `THREAT_HUNTER` exist; a SOC Analyst or Detection Engineer reading a
  report today gets no role-specific decision distinct from the SOC
  Manager's.
- **Detection format coverage is Sigma and Sentinel KQL**, both from the
  same evidence-conditioned generator
  (`report_renderer._detection_package()` / `_validated_sigma()` /
  `_validated_kql()`) and gated by the identical vulnerability-class
  decision — a package that withholds Sigma withholds KQL too, never one
  without the other. `_validated_kql()` applies the same rigor level as
  `_validated_sigma()` for its own language: balanced quoting/parens
  (correctly ignoring parens that are part of a string literal's content,
  e.g. the real SQLi indicator `"SLEEP("`), a bare-identifier table line
  followed only by pipe stages, and a non-empty `where` filter using a
  recognized operator — not a full KQL grammar parser, exactly as
  `_validated_sigma()` is not a full Sigma-spec validator either.
  `pipeline_composer._detection_rules()` (plural) emits one
  `DetectionRule` per format actually present. The mandate's DETECTION
  ENGINEERING section names ten formats total: Sigma, YARA, Suricata,
  Splunk SPL, Sentinel KQL, Elastic, QRadar, Chronicle, Defender XDR,
  CrowdStrike. Eight remain unimplemented.

## Using `qms.py`

```python
from sentinel_engine.reportx.pipeline_composer import compose_report
from sentinel_engine.reportx.qms import evaluate_quality_management_system, render_qms_summary

composed = compose_report(article, config)
qms_report = evaluate_quality_management_system(composed.control_results)
print(render_qms_summary(qms_report))
print(qms_report.gated_categories_pass)       # bool — every GATED category clear (NOT_GATED excluded, not assumed passing)
print(qms_report.not_gated_categories)        # the categories with no automated control yet
```

`QMSReport.to_dict()` is JSON-serializable for logging or a future
`reportx-qms` CLI surface (not built in this pass — no CLI command
currently calls this module; `cli.py`'s existing `reportx-release` /
`reportx-certify` commands are unchanged).
