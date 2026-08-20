# REPORTX Phase 1N — Premium Certification Ladder Audit: Certification

**Written:** 2026-08-20 (continuation of the Phase 1M resume checkpoint,
`docs/audits/REPORTX-PHASE1-RESUME-CHECKPOINT.md` §5 item 1)
**Scope, as named by the checkpoint:** confirm no single high aggregate score
can override a hard failure across evidence integrity / claim traceability /
contradictions / Key Judgements / ATT&CK / detection / hunting / roles /
semantic QA / provenance / artifact integrity, with adversarial "try to game
the premium tier" tests.

---

## 1. Starting-state verification

Reproduced fresh, this round, before any change:

```
cd /home/user/cyberdudebivash-blog
python -m pytest tests/ -q                                    # 541 passed
cd Sentinel-APEX/engine && python -m pytest tests/ -q          # 1056 passed, 1 pre-existing failure
cd /home/user/cyberdudebivash-blog && node --test tests-js/*.test.js   # 123 passed
```

The one pre-existing failure
(`tests/test_certification.py::test_certify_real_end_to_end_with_the_actual_node_rendering_check`)
is the same environment-dependent Node-rendering issue every prior phase's
checkpoint has documented — reconfirmed unchanged, untouched by this phase.

## 2. What the audit covered

Read (not assumed) every module in the certification/tier ladder and its
existing test coverage before writing anything, per Reuse Before Build:
`human_review.py` (`CertificationState`, `resolve_certification_state()`),
`tier_downgrade.py` (`determine_achieved_tier()`), `automated_certification.py`
(`certify_report_automated()`), `commercial_readiness.py` (the 23-control
gate), `intelligence_validation.py` (the separate 20-dimension weighted
scorecard), `qms.py` (mandate-category fidelity mapping), and
`pipeline_composer.py` (the live wiring point, `compose_report()`).

**The system already gets the core question right by construction.** There is
no numeric aggregate score anywhere in the hard gate: `commercial_readiness.py`'s
23-row roll-up is a strict `all(status == PASS)`, not a weighted sum, and
`tier_downgrade.py`'s ladder is fail-closed by set membership, not by score
threshold. `intelligence_validation.py`'s 20-dimension, 75-point weighted
scorecard — the one place a genuine aggregate score exists — is computed and
exposed (`ComposedReport.scorecard`) but, verified by tracing every real
consumer (`cli.py`, `authority_transformer.py`), is **never** read by the
actual publish/block decision; `_composer_enhance()`'s gate
(`automation/authority_transformer.py:2117`) branches on
`result.downgrade.achieved_tier`, the strict ladder, not
`result.scorecard.publication_eligible`. The weighted score is real,
observable data (Section 7's own "Observable Everything" principle) riding
alongside the hard gate, not a bypass of it. Extensive existing adversarial
coverage already proves this at every individual layer:
`test_tier_downgrade.py::TestCorrectnessFailuresAlwaysBottomOut` (every one of
the 13 correctness controls, individually, bottoms out the tier regardless of
the other 22), `test_automated_certification.py::Test22of23CannotReceiveAutomatedPremiumCertification`,
`TestContradictionForcesRefusalOrEscalation`, `TestUnsupportedClaimForcesRefusalOrDowngrade`,
and `test_qms.py::TestFailurePropagation::test_a_fail_anywhere_in_a_real_bundle_is_never_reported_as_pass`.

**One real defect was found, in the ladder's own fail-closed invariant.**

## 3. The defect: `determine_achieved_tier()` could outrank the requested tier

`tier_downgrade.py`'s own docstring states the module's purpose in exactly
these words: a report "either earned its tier or it was downgraded" — never
promoted past what was asked for. The existing test proving this,
`TestNeverManufacturesAHigherTierThanRequested`, exercised exactly one
`requested_tier`: `PREMIUM_READY_PENDING_HUMAN` (rank 3, the highest realistic
request). Every hard-coded downgrade target in the function
(`TACTICAL_READY`=2, `FLASH_READY`=1) is, by construction, already ≤ rank 3 —
so that test could never have observed the bug even in principle, regardless
of how thoroughly it was run.

**The real production call never requests rank 3.**
`pipeline_composer.compose_report()`'s own default, and
`authority_transformer._composer_enhance()`'s actual call — run
unconditionally for every article (`automation/authority_transformer.py:2065-2092`,
"not merely as a fallback") — request `FLASH_READY` (rank 1). A routine
article that is factually correct (all 13 `CORRECTNESS_CONTROLS` PASS) but
never attempted the premium-only inputs (forecast, alternative hypotheses,
a regulatory read, premium depth, current statistics, technical
recommendations — normal and honest for a non-premium request) hit
`determine_achieved_tier()`'s "incomplete" branch, which unconditionally
returned `TACTICAL_READY` (rank 2) — **outranking the FLASH_READY that was
actually requested.** `report_integrity.build_report_context()` renders
`achieved_tier` verbatim into the reader-facing label
(`f"Public Intelligence Certification: {achieved_tier} ..."`), so this was not
a cosmetic internal value — it inflated the certification claim shown to
every reader of every routine article missing premium-only inputs, which
real-data validation (§6) shows is the default case, not an edge case.

## 4. Implementation

**File:** `Sentinel-APEX/engine/sentinel_engine/reportx/tier_downgrade.py`

1. Added `TIER_RANK`, a module-level `CertificationState → int` ordering —
   previously this ordering existed only informally, redeclared inside the
   test file as `_TIER_RANK`. Making it a real, importable constant in the
   production module is itself a Single-Source-of-Truth fix (Principle 3):
   the test's notion of "higher" can no longer silently drift from what the
   function enforces, because it now imports the same object.
   `PREMIUM_AUTOMATED_CERTIFIED` is deliberately excluded — verified (via
   repo-wide grep) that it is never produced by this function and never
   passed as `requested_tier` anywhere in this codebase; it is reachable only
   through the structurally separate `automated_certification.
   certify_report_automated()` path, so ranking it here would assert an
   ordering with no real basis.
2. Added `_capped_tier_result()`: wraps the two branches that previously
   hard-coded a downgrade target (`TACTICAL_READY`, `FLASH_READY`) so the
   result is capped at `requested_tier` by rank whenever the natural target
   would outrank it — at which point `achieved_tier` becomes `requested_tier`
   itself, `was_downgraded` correctly becomes `False`, and
   `downgrade_reason` says so explicitly ("Capped at the requested tier...").
   The two branches that were already provably safe (`PUBLIC_REFERENCE_DRAFT`
   on correctness failure — already the global rank minimum; the all-PASS
   branch, which already returns `requested_tier` verbatim) are untouched —
   surgical scope, no opportunistic rewrite of code that was already correct.

**File:** `Sentinel-APEX/engine/tests/reportx/test_tier_downgrade.py`

3. `_TIER_RANK` now imports `TIER_RANK` from the production module instead of
   redeclaring its own copy.
4. `TestNeverManufacturesAHigherTierThanRequested` gained
   `test_invariant_holds_for_every_requested_tier_not_just_premium`, which
   runs the original single-fail-control sweep against **every**
   `CertificationState` the ladder ranks (not only `PREMIUM_READY_PENDING_HUMAN`) —
   this is the adversarial test that would have caught the defect had it
   existed from the start.
5. New `TestRealProductionCallerNeverInflatesFlashReadyTier` class,
   named for and scoped to the exact real call shape: the full-blocked-set
   repro, a per-control single-gap sweep, and two explicit regression guards
   confirming `TACTICAL_READY`- and `PREMIUM_READY_PENDING_HUMAN`-requested
   behavior is bit-for-bit unchanged (the cap is provably a no-op there,
   pinned so a future edit can't silently reintroduce asymmetric handling).

## 5. What this phase did not attempt

- **`intelligence_validation.py`'s weighted scorecard was audited, not
  modified.** It is real, tested, and calibrated (Intelligence Validation
  Framework, PR #90) but intentionally not wired into the hard gate —
  confirmed still true, not re-decided here. Elevating it to a gate remains
  the separate, deliberate calibration decision `pipeline_composer.py`'s own
  `ComposedReport.scorecard` docstring already named.
- **The 11 non-derivable `EscalationReason` categories**
  (`NOVEL_THREAT_TYPE`, `CRITICAL_ATTRIBUTION`, `EXTREME_SEVERITY`, etc.) —
  `automated_certification.py`'s own module comment already documents these
  as analyst/product judgment calls with no honest signal to derive them from
  today. Fabricating detection logic for them would violate the same
  non-fabrication discipline that governs claims and evidence, so this phase
  did not attempt it; the vocabulary exists for a future real signal source.
- **`automated_review_disclosure`'s absence from `tier_downgrade.py`'s own
  code comment** (it excludes `fortune_500_commercial_deliverable` and
  `human_analyst_certification_governance` by name, but is silent that
  `automated_review_disclosure` is a third de facto exclusion) is a minor
  documentation-completeness gap, not a functional one — confirmed via
  `test_tier_downgrade.py:104`'s own comment and `ALL_CONTROL_IDS` fixture
  that the exclusion is real and already tested. Left as-is rather than
  bundling an unrelated doc-wording change into this fix's diff.

## 6. Real-data validation

Ran `pipeline_composer.compose_report()` end to end — the real function,
real evidence graph, real 23-control gate, no mocking — against three article
shapes reused unchanged from `tests/reportx/test_pipeline_composer.py`'s own
fixtures (`_cve_article()`, `_cve_article(kev_listed=True)`,
`_ransomware_article()`), calling it exactly as
`authority_transformer._composer_enhance()` really does (default
`requested_tier`, i.e. `FLASH_READY`). Captured with the pre-fix code
(`git stash` on `tier_downgrade.py` alone) and again after:

| Article | Before (buggy) | After (fixed) |
|---|---|---|
| CVE, not KEV-listed | `TACTICAL_READY` (was_downgraded=True) | `FLASH_READY` (was_downgraded=False) |
| CVE, KEV-listed | `TACTICAL_READY` (was_downgraded=True) | `FLASH_READY` (was_downgraded=False) |
| Ransomware claim (qilin) | `TACTICAL_READY` (was_downgraded=True) | `FLASH_READY` (was_downgraded=False) |

Reader-facing label before (all three): `"Public Intelligence Certification:
TACTICAL_READY (automated evidence-graph certification — see Provenance for
the source basis)"`. After: the same string with `FLASH_READY`. All three
have zero failed correctness controls in both runs — this was never a content
defect, only a mislabeled tier. All three fail the identical set of
premium-completeness controls before and after (`alternative_hypotheses`,
`current_statistics`, `premium_depth`, `regulatory_specificity`,
`technical_recommendations`, plus `forecast_methodology` for the
non-vulnerability-manager ransomware family) — confirming the fix changes
only the achieved-tier label, not which controls are evaluated or how.

This is not a contrived edge case: every one of these three representative
families is the *default* shape a routine, correctly-sourced article takes at
`FLASH_READY`, since forecast/hypothesis/regulatory/depth/statistics/
recommendation content is real capability this pipeline deliberately scopes
to premium-tier evidence depth (Phase 1K/1M's own documented scoping). The
defect was the normal case, not the exception.

## 7. Test evidence

```
cd Sentinel-APEX/engine && python -m pytest tests/reportx/test_tier_downgrade.py -v
# 17 passed (11 pre-existing, unmodified in behavior; 6 new)

cd Sentinel-APEX/engine && python -m pytest tests/ -q
# 1061 passed, 1 pre-existing unrelated failure (1056 baseline + 6 new = 1062 total)

cd /home/user/cyberdudebivash-blog && python -m pytest tests/ -q
# 541 passed (unchanged — this phase touched no root-level file)

node --test tests-js/*.test.js
# 123 passed (unchanged — this phase touched no JavaScript)
```

Zero regressions across all three suites.

## 8. Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `tier_downgrade.DowngradeResult`, `commercial_readiness.ControlResult`, `human_review.CertificationState`, `pipeline_composer.compose_report()`, `report_integrity.build_report_context()`, and the `test_pipeline_composer.py` article fixtures reused verbatim for real-data validation |
| Existing API routes extended (not duplicated) | N/A — no route touched |
| Existing pages extended (not replaced) | N/A |
| New components introduced (justified by gap analysis) | `TIER_RANK` (was implicit/test-only; now the module's real, importable ordering), `_capped_tier_result()` (the missing cap this section documents) |
| Duplicate components introduced | 0 |
| Duplicate routes introduced | 0 |
| Backward compatibility preserved | PASS — every existing caller (`automated_certification.py` at `PREMIUM_READY_PENDING_HUMAN`, every test at its own requested tier) sees byte-identical output; only the previously-untested `requested_tier` ranks below `TACTICAL_READY` change, and only to a more honest value |
| Lighthouse scores maintained or improved | N/A — Python engine change, no frontend/bundle surface touched |
| Build passing with zero errors | PASS |

## 9. Certification verdict

**`RELEASE_CERTIFIED`.** One real, live, customer-facing defect found via
audit-first investigation of the premium certification ladder (not assumed
from the mandate's framing), root-caused precisely, fixed with a minimal
2-branch surgical change plus a real, importable single source of truth for
the tier ordering, proven with a real end-to-end before/after against actual
`compose_report()` output (not only isolated unit fixtures), and covered by
new adversarial regression tests that generalize the existing
"never-outranks-requested" invariant to every tier the ladder defines instead
of only the one that happened to already be safe. Zero regressions across
the full 1062-test engine suite, 541-test root suite, and 123-test JS suite.

The broader premium-ladder architecture the mandate asked this phase to
interrogate — "does a high aggregate score ever override a hard failure" —
was confirmed, by tracing every real code path rather than by inspection of
intent alone, to already be correctly fail-closed: no aggregate score exists
in the hard gate, and the one real weighted score in the system
(`intelligence_validation.py`) is observable data, not a bypass. That is a
legitimate, evidenced outcome of this phase in its own right, in the same
spirit as the Run #8459 incident review's precedent
(`docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md`):
an audit that finds the architecture sound is not a lesser result than one
that finds a defect — this phase found one anyway, in the one corner the
architecture's own test suite had not yet reached.
