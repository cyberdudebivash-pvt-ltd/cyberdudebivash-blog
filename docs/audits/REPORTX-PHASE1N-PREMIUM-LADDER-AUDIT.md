# REPORTX Phase 1N — Premium Certification Ladder: Architecture Audit

**Written:** 2026-08-20, same session as the Phase 1J/1K/1M recovery rounds. Read
`commercial_readiness.py`, `release_certification.py`, `automated_certification.py`,
`intelligence_validation.py`, `tier_downgrade.py`, and `automation/analytical_depth_gate.py` in
full before writing any code this phase.

## 0. Starting-state verification

- Confirmed via the GitHub API that PR #120 (Phase 1K + Phase 1M combined, squash-merged) is
  `merged: true` on `main`, head SHA matching this branch's own tip exactly, with zero file-level
  diff against `main` on every ReportX-relevant path (only unrelated, ongoing SENTINEL APEX
  auto-syndication/content-bot commits differ). "Intelligence Engine CI" (the real GitHub Actions
  workflow covering `Sentinel-APEX/engine/**`) ran against that exact merge commit and reported
  `conclusion: success`. Branch restarted to the merged tip (`ed80387d8`, no force-push needed,
  since the remote already held it) before beginning this phase's work.
- Baseline reproduced fresh: root 541 passed, engine 1056 passed + 1 pre-existing unrelated
  failure (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`, a Node-rendering
  environment issue, reconfirmed), matching Phase 1M's own certified numbers exactly.

## 1. The mandate's question, precisely

Phase 1N's charge: *"confirm no single high aggregate score can override a hard failure across
evidence integrity/claim traceability/contradictions/Key Judgements/ATT&CK/detection/hunting/
roles/semantic QA/provenance/artifact integrity, with adversarial 'try to game PREMIUM_LONG_FORM'
tests."*

Answering this precisely requires first mapping **which certification/tier system is actually
live** — this codebase has three, not one, and conflating them would make the audit meaningless.

## 2. The three "premium" systems, mapped

| System | Vocabulary | Live in `authority_transformer.transform()`? | Mechanism |
|---|---|---|---|
| `analytical_depth_gate.evaluate_product_tier()` | FLASH / TACTICAL / PREMIUM_LONG_FORM | **Yes** — this is the tier every published report actually carries (`ProductTierVerdict.tier`, gated in `report_integrity.validate_publication()` via the `product_tier == "FLASH"` hard block) | Sequential boolean gates over `report_contract.evaluate_section_states()` — no numeric score anywhere |
| `tier_downgrade.determine_achieved_tier()` | PUBLIC_REFERENCE_DRAFT / FLASH_READY / TACTICAL_READY / PREMIUM_READY_PENDING_HUMAN / PREMIUM_CERTIFIED | **Yes** — `pipeline_composer.compose_report()` computes this as `downgrade`, exposed as `context.achieved_tier` and hard-gated in `validate_publication()` via the `achieved_tier == "PUBLIC_REFERENCE_DRAFT"` block | A strict, ordered ladder over the real 23 `commercial_readiness.py` `ControlResult`s — any correctness-control `FAIL` bottoms out the tier unconditionally, checked *before* any "how much else passed" logic runs |
| `intelligence_validation.evaluate_intelligence_validation()` | 20-dimension weighted scorecard, `overall_score`/`publication_eligible` | **Computed and logged, but never gates anything** — `pipeline_composer.compose_report()` does call it (confirmed by reading the source, not by trusting the module's own docstring), and `authority_transformer.py` stores its output as `quality_score`/`quality_score_eligible`, but grep across the entire `automation/` package confirms **zero** `if`-statements ever branch on `quality_score_eligible` — it reaches `main.py`'s persisted state record and nothing else | A real weighted average (`WEIGHTS` sums to 1.0, test-enforced) — the one system in this audit that *could* in principle launder a hard failure into a high number, examined closely in §3 |

`release_certification.py`/`automated_certification.py` are a fourth, separate layer again — a
one-time, human-triggered *release* certification (not a per-article decision), driven by hand-run
canary exports, with its own strict boolean-AND `certify_release()`. Not part of the live per-article
publication path at all; not this audit's concern.

**This resolves an ambiguity the mandate's own wording could invite:** "PREMIUM_LONG_FORM" is
`analytical_depth_gate.py`'s vocabulary specifically, not `intelligence_validation.py`'s
`publication_eligible` or `tier_downgrade.py`'s `PREMIUM_CERTIFIED`. The audit below examines all
three real, live-relevant mechanisms (the two hard gates plus the one weighted scorer), not only
the one whose tier name matches literally.

## 3. Is the weighted scorer (`intelligence_validation.py`) gameable in principle?

Read `evaluate_intelligence_validation()`'s assembly loop closely (not merely its docstring):

```python
for dimension in ValidationDimension:
    r = raw[dimension]
    if r.score is None: status = "BLOCKED"
    elif r.hard_fail or r.score < thresholds.minimum_for(dimension): status = "FAIL"
    else: status = "PASS"
    ...
    if status == "FAIL": blocking_reasons.append(...)
...
if overall < thresholds.overall_minimum: blocking_reasons.append(...)
publication_eligible = not blocking_reasons
```

Every dimension scorer that wraps an underlying `commercial_readiness.py` correctness control sets
`hard_fail = bool(failing)` (see `_binary()`) — a real control `FAIL` **always** forces that
dimension's `status` to `"FAIL"`, independent of its numeric score, and that `FAIL` **always**
lands in `blocking_reasons`, which **always** makes `publication_eligible = False` — regardless of
how high `overall` (the weighted average across the other 19 dimensions) happens to be. A
partial-credit average cannot launder a hard-failing dimension into an apparent PASS, by
construction, at the per-dimension level; and the per-dimension result is what actually reaches
`publication_eligible`, not `overall` in isolation. This module already carries its own
adversarial proof of exactly this property
(`test_intelligence_validation.py::TestBinaryDimensionFailurePropagation::test_a_fail_never_reads_as_pass_even_with_partial_credit`,
`TestScorecardAssembly::test_publication_ineligible_when_any_scored_dimension_fails`) — reconfirmed
passing this round, not duplicated.

**Conclusion:** even the one system with a real numeric aggregate is correctly designed against the
exact failure mode the mandate worries about. And since this system doesn't gate live publication
at all (§2), the question is moot for what actually ships regardless.

## 4. Are the two live hard gates actually hard, adversarially?

`tier_downgrade.determine_achieved_tier()` checks `CORRECTNESS_CONTROLS` **first**, unconditionally:
a single correctness-control `FAIL` returns `PUBLIC_REFERENCE_DRAFT` immediately, before any
"how many controls passed overall" logic is even reached. `analytical_depth_gate.evaluate_product_tier()`
is a sequential chain of hard gates (mandatory-section withholding → LLM authorship → independent
corroboration) with no numeric score anywhere in its implementation at all — there is nothing to
average.

Both already carry extensive, real, passing adversarial "try to game it" coverage, reconfirmed this
round rather than re-derived:

- `test_tier_downgrade.py::TestCorrectnessFailuresAlwaysBottomOut` — every individual correctness
  control tested to bottom out the tier alone; `test_a_correctness_failure_outranks_an_otherwise_perfect_report`
  is the literal "22/23 PASS, one FAIL" adversarial case.
- `test_tier_downgrade.py::TestNeverManufacturesAHigherTierThanRequested` — every correctness AND
  completeness control, individually, proven never to let the achieved tier outrank the requested one.
- `test_analytical_depth_gate.py::TestCurrentRealityCannotReachPremium` — proves today's real
  content genuinely cannot reach PREMIUM_LONG_FORM by accident; `TestRoleDecisionCountGatesSectionNineteen`
  proves a real caller measuring zero role decisions caps at TACTICAL.

New this round (§6): a **cross-system** adversarial test that neither existing suite covered —
proving `determine_achieved_tier()`'s result is not merely *designed* independently of the scorecard,
but *empirically* unmoved even when the scorecard is forced to report a maximal, fully-eligible
result on a report that genuinely earns a downgrade.

## 5. The one real defect found

`pipeline_composer.compose_report()` (line ~864) calls:

```python
scorecard = evaluate_intelligence_validation(
    bundle, control_results, supplemental=SupplementalEvidence(hunt_hypotheses=tuple(hunt_hypotheses)),
)
```

`role_decisions` — computed earlier in the same function (line ~674, real and gate-passed since
RX-P1J), and already passed into `ComposedReport(...)` a few lines below this call — was never
added to `SupplementalEvidence`. `_score_executive_decision_support()` and `_score_business_context()`
both read `supplemental.role_decisions`, filtered to CEO/Board-, CISO/CIO-, or business-facing roles.
With `role_decisions` always `()` here, **every** report's Executive Decision Support dimension
reported `BLOCKED` ("No CEO/Board- or CISO/CIO-targeted role decisions supplied") even for families
— `ai_security`, `ransomware_claim`, and others — that genuinely carry a real, gate-passed decision
for exactly those roles.

This is the same "computed but never fully wired through" defect class found four times already
this session (hunt_hypotheses, attack_mapping, role_decisions-rendering, reliability/gaps/forecast-
rendering) — this time affecting the scorecard's own input, not rendered HTML. Confirmed **not**
already covered by any existing test: `test_intelligence_validation.py`'s own
`TestSupplementalEvidenceDrivenDimensions` tests always construct a fresh `SupplementalEvidence`
directly at the unit level; none of them inspect `pipeline_composer.py`'s own internally-computed
`ComposedReport.scorecard`, so the live wiring gap was invisible to the existing suite.

**Severity, precisely:** this scorecard does not gate live publication today (§2) — the fix
corrects the accuracy of an observability signal, not a publication-safety hole. It matters because
`ComposedReport.scorecard`'s own docstring names "elevating it to a gate" as a real, pending,
separate calibration decision that "must be made from live evidence, not assumed" — that future
decision would have been made from artificially low Executive Decision Support / Business Context
coverage numbers had this gap gone uncorrected.

## 6. What this round implements

1. **Fix:** `SupplementalEvidence(hunt_hypotheses=tuple(hunt_hypotheses), role_decisions=tuple(role_decisions))`
   — one-line, additive, zero-blast-radius (the only consumer of this call's return value is
   `ComposedReport.scorecard`, itself observability-only).
2. **Regression test** (`TestRXP1NRoleDecisionsReachTheScorecard`, 2 tests): proves, via the real
   unmocked `compose_report()` path on the `ai_security` family (which genuinely earns a CISO_CIO
   decision), that Executive Decision Support is no longer falsely `BLOCKED`; verified the test
   actually catches the defect by reverting the fix locally and re-running it (failed with the
   exact real rationale string), then restoring the fix and re-confirming green — not merely
   asserted to be a real regression test.
3. **Cross-system adversarial test** (`TestRXP1NAchievedTierNeverConsultsTheScorecard`, 2 tests):
   patches `evaluate_intelligence_validation()` to return a maximal, fully-eligible scorecard
   (`overall_score=100, publication_eligible=True`) on an article independently known to earn a
   real downgrade, and proves `achieved_tier` is completely unmoved; a second test proves both
   ladders are fed the exact same real `control_results` object, not independently-drifting copies.

## 7. What this round does not attempt, named explicitly

- **Elevating `intelligence_validation.py`'s scorecard to a live gate.** Explicitly named in
  `pipeline_composer.py`'s own prior, dated decision (`COMMERCIAL-QUALITY-2026-08-18`) as "a
  separate, deliberate calibration decision... that must be made from live evidence" — not
  something to flip unilaterally inside an audit round. Worth a dedicated future round, once this
  round's role_decisions fix has had a chance to produce real coverage data to calibrate against.
- **`sector_impacts` for `SupplementalEvidence`.** Confirmed via grep: `pipeline_composer.py` never
  computes sector-impact data anywhere today — its absence from the scorecard call is an honest
  gap (nothing to wire), not a wiring defect, matching `cross_report_similarity_findings`'s own
  documented `None`-means-"never checked" convention.
- **`_score_mitre_attack_justification()`'s softer 70%-threshold-with-partial-credit design.**
  Real observation (§3's analysis surfaced it): a report could cite several ATT&CK techniques with
  up to 30% unjustified and still PASS this *specific, non-live* dimension. Not a live defect —
  `commercial_readiness.py`'s own `detection_evidence_discipline` correctness control (which IS in
  `CORRECTNESS_CONTROLS` and DOES hard-fail on any unjustified technique_id) is the actual live
  gate for this concern, and it has no partial-credit tolerance. Named for completeness, not fixed,
  since fixing a non-live dimension's threshold is not in scope for a round about the live gates.
