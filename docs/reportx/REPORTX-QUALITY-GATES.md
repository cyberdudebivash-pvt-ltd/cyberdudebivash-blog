# ReportX Quality Gates

Reference for every executable gate implemented in
`Sentinel-APEX/engine/sentinel_engine/reportx/`. Each gate is real,
tested code — this document explains what each one checks and why; run
`python3 -m pytest tests/reportx/ -v` from `Sentinel-APEX/engine/` for the
executable proof.

---

## Contradiction engine (`contradiction_engine.py`) — Section 11

Two layers:

1. **Dimension consistency** (`find_dimension_contradictions`) — claims
   tagged with the same canonical dimension (`kev_state`,
   `detection_state`, `actor_identity`, etc.) must not report directly
   opposed `EpistemicState` values (currently: `CONFIRMED` vs.
   `NOT_APPLICABLE`). `DISPUTED` is deliberately never self-flagged — it is
   the *correct* representation of a genuine source conflict, not an
   engine defect.
2. **Text-pattern contradictions** (`find_text_contradictions`) — three
   regex rules encoding the task's own motivating examples verbatim:
   "no validated actor-specific TTPs" co-occurring with "attribution based
   on TTPs"; `DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE`
   co-occurring with "push detection rules... immediately"; "experimental"
   detection co-occurring with "production-validated" detection.

Gate: `unresolved_contradictions == 0`.

## Claim-support matrix (`claim_support_matrix.py`) — Section 9

`build_claim_support_matrix()` produces one row per claim (claim, section,
type, evidence, source, corroboration, confidence, status).
`evaluate_claim_support_gate()` requires every claim in an *assertive*
epistemic state (`CONFIRMED`/`REPORTED`/`CORROBORATED`/`ASSESSED`/
`DISPUTED`) to carry `evidence_refs` or `source_refs`. Claims honestly
declaring a gap (`NOT_ASSESSED`/`NOT_APPLICABLE`/`UNKNOWN`/`HYPOTHESIS`)
are exempt — absence of evidence *is* the correct representation there,
not a defect. Four named high-risk buckets are tracked separately:
quantitative claims, actor-attribution claims, victim-impact claims,
observed-TTP claims.

## Detection validation governance (`detection_validation.py`) — Section 12

Seven-state canonical enum: `DRAFT` → `SYNTAX_VALIDATED` → `LAB_VALIDATED`
→ `TELEMETRY_VALIDATED` → `PRODUCTION_CANDIDATE` → `PRODUCTION_VALIDATED`,
plus the terminal `WITHHELD_INSUFFICIENT_EVIDENCE`. `check_state_promotion()`
scans rendered text describing a rule for language claiming a state ranked
above what's actually stored (ordinal comparison, not string matching), and
a `WITHHELD` rule is never allowed *any* positive-deployment language —
including the task's own "push detection rules... immediately" phrasing.

## Statistics registry (`metrics_registry.py`) — Section 13

`ExternalMetric` (metric_id, name, value, unit, scope, source, source_url,
publication_year, retrieved_at, `valid_until`, `review_after`,
sample_scope, notes) plus `MetricsRegistry`. `valid_until` (hard expiry)
and `review_after` (soft staleness marker) are tracked separately — a
metric with no stated expiry is never auto-flagged expired, since that
would require guessing a shelf life the source never stated.
`evaluate_statistics_gate()` requires every *rendered* quantitative claim
to resolve to a registered, cited, non-expired `metric_id`.

## Regulatory applicability engine (`regulatory.py`) — Section 14

`RegulatoryApplicability` (jurisdiction, victim/operations/data-subject
geography, sector, entity classification, `incident_facts_claim_ids`,
regulation, `ApplicabilityState`, basis, confidence). `ApplicabilityState`
is `CONFIRMED`/`LIKELY`/`POTENTIAL`/`NOT_ASSESSED`/`NOT_APPLICABLE`. Any
positive determination requires both a written basis (enforced by the
dataclass's own `__post_init__` — cannot construct one without it) *and*
linked incident-fact claim ids (enforced by `evaluate_regulatory_gate()` —
a basis sentence with nothing behind it is still flagged unsupported).

## Grammar/synthesis QA (`qa_linter.py`) — Section 23

Deterministic checks: dangling sentence fragments from an unsubstituted
template variable (the task's own example, "confirming active exploitation
in the .", is a permanent regression test), unresolved template tokens
(`{{var}}`/`${var}`/`{var}`/`%(var)s`), placeholder leaks (`TBD`/`TODO`/
`FIXME`), a field-value-context-scoped `None`-leak detector (narrowed after
a real false positive on legitimate English "None of..." usage — see
`qilin_spoonful_of_comfort.py`'s fixture history), duplicate headings,
duplicate paragraphs, dangling colons, unbalanced code fences, and ragged
markdown table rows. `to_gate_result()` bridges into the parent package's
existing `GateFinding`/`GateResult` shape.

## Forecast methodology (`forecast.py`) — Section 16

A `Forecast` is "adequately supported" only if it has *both* real
supporting-observation claim ids *and* a written confidence rationale — a
bare confidence label ("HIGH CONFIDENCE" because a template says so) fails.
`WithheldForecast` is a first-class, always-passing alternative: Section
16's "withholding an unsupported forecast is a PASS" is not a suggestion,
it's how the gate is implemented.

## Alternative hypotheses, intelligence gaps, bibliography (`analytic_scaffolding.py`) — Sections 17, 18, 22

`HypothesisSet.is_well_formed()` requires ≥2 real alternatives, each
carrying evidence on at least one side — a "set" of one restated conclusion
doesn't count as alternative reasoning. `derive_ransomware_gaps()`
mechanically produces Section 18's known-unknowns checklist from a
`VictimObservation`, so gaps reflect actual data absence rather than being
hand-typed per report. `build_bibliography()`/`find_orphan_citations()`
implement Section 22's citation graph both directions: only sources
actually cited by a claim appear in the bibliography, and any source
present in the graph but never cited is flagged as an orphan.

## Human review governance (`human_review.py`) — Sections 26, 44

`ReviewRecord` binds a decision to an exact artifact SHA-256.
`is_review_valid_for_artifact()` recomputes the hash of the *current* text
and compares — any edit invalidates the prior approval automatically.
`resolve_certification_state()` has no manual-override parameter anywhere
in its signature; `PREMIUM_CERTIFIED` is reachable only through a real,
artifact-bound `APPROVE` review.

## Product depth / anti-padding (`product_depth.py`) — Sections 24, 27, 28

Reuses `quality.py`'s existing shingle/Jaccard near-duplicate detector
(the same mechanism `gate_corpus` already uses for cross-report Sigma/IOC
duplication) rather than re-implementing similarity scoring, applied to
named incident-specific sections (Actor Analysis, Campaign Analysis,
Victimology, Forecast, Technical Analysis, Business Impact) across
*different* reports. `DepthAssessment.passes_premium_depth()` fails
immediately on any cross-report template repetition, regardless of word
count or claim count — page count alone is never sufficient (Section 28).

## Commercial readiness validator (`commercial_readiness.py`) — Sections 31-33, 46

`evaluate_commercial_readiness()` orchestrates every gate above into the
exact 23-row matrix Section 33/46 requires. Every row's status is computed
from the other modules' real output; a `BLOCKED` row (required input
simply absent from the bundle) counts against the final roll-up exactly
like a `FAIL` — Section 46's literal "23/23 PASS" mandate, not
"23-minus-BLOCKED." `bundle_io.py` + `cli.py`'s `reportx-gate` subcommand
provide a JSON-in, Markdown/JSON-out CLI entry point.
