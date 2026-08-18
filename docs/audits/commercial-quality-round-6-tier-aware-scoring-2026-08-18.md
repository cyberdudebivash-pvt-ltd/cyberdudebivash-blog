# Commercial Quality — Round 6: Making the Scorecard Tier-Aware

**Scope:** the tier-calibration gap Round 5 found and deliberately did not rush — `intelligence_validation.py` scoring every report against premium-dossier-only completeness regardless of what tier it was actually produced for.

## The gap

Round 5 wired the 20-dimension scorecard into the live pipeline and found, from a live dry-run, that `publication_eligible` was `False` for every real article despite strong overall scores. Two of the three blocking dimensions were a genuine calibration mismatch, not a defect: `Analytical Completeness` (bound to `tier_downgrade.PREMIUM_COMPLETENESS_CONTROLS` — forecast methodology, alternative hypotheses, intelligence gaps, regulatory specificity, 30-40 page depth, current statistics, technical recommendations) and `Production Readiness` (bound to the 22-control `fortune_500_commercial_deliverable` roll-up) were scored as universally required, `FAIL`-if-missing, with no awareness that this pipeline's real, live output is deliberately lean `FLASH_READY`-tier content that was never designed to carry premium-dossier completeness.

`tier_downgrade.determine_achieved_tier()` already draws exactly this distinction for the identical control set — its own comment is explicit: "BLOCKED or FAILED here means correct, but missing a component premium tier requires — caps the tier at TACTICAL rather than treating it as a correctness defect." `intelligence_validation.py` had no equivalent.

## Why this was safe to fix now, not a guess

`commercial_readiness.py` computes `premium_depth`, `fortune_500_commercial_deliverable`, and the rest of `PREMIUM_COMPLETENESS_CONTROLS` as a raw content fact ("is this actually 30-40 pages?") with no tier awareness of its own — confirmed by reading its source directly (control #22, `premium_depth`, is gated purely on `bundle.depth_assessment`, never on `bundle.is_premium_tier`). The tier-awareness already lives one layer up, in `tier_downgrade.py` and `human_review.resolve_certification_state()`.

Critically, `ReportBundle` already carries `is_premium_tier: bool = False`, and `pipeline_composer.compose_report()` already sets it correctly from `requested_tier` (`True` only for `PREMIUM_READY_PENDING_HUMAN` / `PREMIUM_CERTIFIED` / `PREMIUM_AUTOMATED_CERTIFIED`). `evaluate_intelligence_validation(bundle, control_results)` already receives `bundle` as its first argument. No new parameter, no new plumbing, no signature change anywhere in the call chain was needed — the exact signal required was already flowing through, unused by this one module.

## The fix

Added `_binary_unless_lean_tier()` next to the existing `_binary()` helper: identical contract, except it returns an honest `BLOCKED` (score `None`, not a claimed defect) when `bundle.is_premium_tier` is `False`, before ever consulting the underlying control results. `ANALYTICAL_COMPLETENESS` and `PRODUCTION_READINESS` now use it instead of bare `_binary()`. Every other dimension is untouched — this never softens a genuine premium-dossier defect: a bundle that *is* targeting a premium tier still gets the real, unchanged PASS/FAIL signal.

## Verification — real numbers, before and after

Ran the exact same live `compose_report()` call (a realistic CVE/KEV article, `FLASH_READY`-tier, the pipeline's real default) before and after:

| | Before | After |
|---|---|---|
| `Analytical Completeness` | FAIL — "failing: 30-40 page premium depth" | BLOCKED — not applicable at this tier |
| `Production Readiness` | FAIL — "failing: Fortune-500 commercial deliverable" | BLOCKED — not applicable at this tier |
| `overall_score` | 91 | 96 |
| `coverage` | 70% (14/20) | 60% (12/20) — still above the 50% minimum |
| `publication_eligible` | **False** | **True** |

This is the first real, live, good `FLASH_READY`-tier article to actually clear `publication_eligible` since the scorecard was wired in.

Checked against every canary this repository has before changing anything: all 5 real premium canary exports (`reportx-canary/exports/*.json`) already have `is_premium_tier=True` and already score `PASS`/100 on both dimensions today — the fix is a pure no-op for genuine premium dossiers, confirmed by running `evaluate_from_export()` against all 5 directly. `tests/reportx/test_intelligence_validation_against_real_canaries.py`'s existing assertions (including the two canaries with a real, separate, already-documented MITRE ATT&CK finding) are unaffected.

## Verification — test suite

- 83/83 targeted tests pass (`test_intelligence_validation.py` + `test_intelligence_validation_against_real_canaries.py`).
- 919/920 pass across `Sentinel-APEX/engine`; the 1 failure is the same pre-existing, environment-only Node-rendering-certification failure documented in every round since #91 (`test_certify_real_end_to_end_with_the_actual_node_rendering_check`) — unrelated to this change (confirmed: zero overlap in touched files).
- 330/330 pass at the repository root.
- One existing test (`test_flash_tier_report_correctly_fails_analytical_completeness_and_production_readiness`) had enshrined the bug as expected behavior — its own name and comment claimed a FLASH-tier bundle "has not attempted the premium-only controls at all," which is factually wrong (they are attempted and genuinely fail; the tier match is what's wrong). Renamed and reasserted against the now-correct behavior, not deleted.
- 4 new regression tests added: a direct unit-level check that non-premium bundles are `BLOCKED` (not `FAIL`) even when the underlying controls genuinely fail, and two tests proving premium-tier bundles keep the real, unchanged PASS/FAIL signal in both directions.

## What this does *not* do

`publication_eligible` is still not wired into the live publish path as a hard gate — that remains a separate, deliberate decision. This round only removes the specific tier-calibration mismatch that made the gate meaningless for the pipeline's real, lean-tier output; it does not, by itself, decide whether flipping the gate on is the right call. That decision should follow from watching real `quality_score`/`quality_score_eligible` observability data (already wired in Round 5) across a run or two of actual live publishing, not from this fix alone.

## What remains, named plainly

- **Deciding whether/how `publication_eligible` becomes a real hard gate**, now that it is no longer structurally miscalibrated against the pipeline's real output.
- **An active corroboration engine** (fetching a genuine second, independent source, not just grading whatever is already in the graph).
- **Historical/campaign correlation** beyond the false-positive fix in Round 4.
