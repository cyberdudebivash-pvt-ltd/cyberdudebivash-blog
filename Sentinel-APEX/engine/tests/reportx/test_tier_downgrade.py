"""Tests for sentinel_engine.reportx.tier_downgrade -- Section 17 test #15
("tier downgrade is fail-closed") plus general module coverage.

"Fail-closed" here means two specific, separately-tested guarantees:
1. The achieved tier is NEVER higher than what the actual control results
   support (no manufactured PASS, no borrowed evidence).
2. A correctness-control failure ALWAYS bottoms out at the lowest tier
   (PUBLIC_REFERENCE_DRAFT), regardless of how many other controls passed
   -- more passing controls elsewhere can never buy back a content defect.
"""

from __future__ import annotations

import itertools

from sentinel_engine.reportx.commercial_readiness import ControlResult
from sentinel_engine.reportx.human_review import CertificationState
from sentinel_engine.reportx.tier_downgrade import (
    CORRECTNESS_CONTROLS,
    PREMIUM_COMPLETENESS_CONTROLS,
    TIER_RANK,
    determine_achieved_tier,
)

ALL_CONTROL_IDS = [
    "source_provenance", "evidence_hash", "automated_review_disclosure", "source_specific_facts",
    "cross_source_corroboration", "threat_type_schema_correctness", "cross_section_consistency",
    "actor_specific_analysis", "victim_specific_analysis", "current_statistics", "regulatory_specificity",
    "technical_recommendations", "detection_evidence_discipline", "temporal_integrity", "grammar_synthesis_qa",
    "forecast_methodology", "evidence_ledger", "alternative_hypotheses", "intelligence_gaps",
    "report_specific_bibliography", "human_analyst_certification_governance", "premium_depth",
    "fortune_500_commercial_deliverable",
]


def _results(overrides: dict[str, str]) -> list[ControlResult]:
    return [
        ControlResult(cid, cid, overrides.get(cid, "PASS"), "x",
                      ["induced"] if overrides.get(cid, "PASS") != "PASS" else [])
        for cid in ALL_CONTROL_IDS
    ]


# The tier ladder's total ordering -- imported from the production module
# itself (single source of truth) rather than redeclared here, so this
# test's notion of "higher" can never silently drift from what
# determine_achieved_tier() actually enforces.
_TIER_RANK = TIER_RANK


class TestAllPassKeepsRequestedTier:
    def test_23_of_23_never_downgrades(self):
        result = determine_achieved_tier(_results({}), requested_tier=CertificationState.PREMIUM_READY_PENDING_HUMAN)
        assert result.achieved_tier == CertificationState.PREMIUM_READY_PENDING_HUMAN
        assert not result.was_downgraded
        assert not result.failed_controls


class TestCorrectnessFailuresAlwaysBottomOut:
    def test_every_individual_correctness_control_bottoms_out(self):
        for control_id in CORRECTNESS_CONTROLS:
            result = determine_achieved_tier(_results({control_id: "FAIL"}))
            assert result.achieved_tier == CertificationState.PUBLIC_REFERENCE_DRAFT, (
                f"{control_id} FAIL should bottom out the tier, got {result.achieved_tier}"
            )
            assert control_id in result.failed_controls

    def test_a_correctness_failure_outranks_an_otherwise_perfect_report(self):
        # 22/23 PASS, only cross_section_consistency FAILs -- still bottom tier.
        result = determine_achieved_tier(_results({"cross_section_consistency": "FAIL"}))
        assert result.achieved_tier == CertificationState.PUBLIC_REFERENCE_DRAFT

    def test_correctness_failure_combined_with_completeness_gaps_is_still_bottom_tier(self):
        overrides = {"cross_section_consistency": "FAIL", "forecast_methodology": "BLOCKED",
                     "premium_depth": "FAIL"}
        result = determine_achieved_tier(_results(overrides))
        assert result.achieved_tier == CertificationState.PUBLIC_REFERENCE_DRAFT


class TestPremiumCompletenessGapsCapAtTactical:
    def test_missing_forecast_caps_at_tactical(self):
        result = determine_achieved_tier(_results({"forecast_methodology": "BLOCKED"}))
        assert result.achieved_tier == CertificationState.TACTICAL_READY
        assert "forecast_methodology" in result.failed_controls

    def test_missing_premium_depth_caps_at_tactical(self):
        result = determine_achieved_tier(_results({"premium_depth": "FAIL"}))
        assert result.achieved_tier == CertificationState.TACTICAL_READY

    def test_completeness_gap_never_reaches_correctness_bottom_tier(self):
        # Zero correctness failures + one completeness gap -- must land at
        # TACTICAL, never at PUBLIC_REFERENCE_DRAFT (that tier is reserved
        # for actual content defects, not merely-incomplete reports).
        result = determine_achieved_tier(_results({"intelligence_gaps": "BLOCKED"}))
        assert result.achieved_tier == CertificationState.TACTICAL_READY
        assert result.achieved_tier != CertificationState.PUBLIC_REFERENCE_DRAFT


class TestMinorGapsLandAtFlash:
    def test_a_non_correctness_non_completeness_fail_lands_at_flash(self):
        # automated_review_disclosure and human_analyst_certification_governance
        # are neither correctness nor premium-completeness controls.
        result = determine_achieved_tier(_results({"human_analyst_certification_governance": "FAIL"}))
        assert result.achieved_tier == CertificationState.FLASH_READY


class TestNeverManufacturesAHigherTierThanRequested:
    def test_achieved_tier_is_never_ranked_above_requested_tier(self):
        requested = CertificationState.PREMIUM_READY_PENDING_HUMAN
        single_fail_ids = list(CORRECTNESS_CONTROLS) + list(PREMIUM_COMPLETENESS_CONTROLS) + ["human_analyst_certification_governance"]
        for control_id in single_fail_ids:
            for status in ("FAIL", "BLOCKED"):
                result = determine_achieved_tier(_results({control_id: status}), requested_tier=requested)
                assert _TIER_RANK[result.achieved_tier] <= _TIER_RANK[requested]

    def test_requesting_a_lower_tier_is_honored_when_earned(self):
        result = determine_achieved_tier(_results({}), requested_tier=CertificationState.TACTICAL_READY)
        assert result.achieved_tier == CertificationState.TACTICAL_READY

    def test_invariant_holds_for_every_requested_tier_not_just_premium(self):
        # The original version of this invariant (above) only ever exercised
        # requested_tier=PREMIUM_READY_PENDING_HUMAN -- the highest realistic
        # request, where every downgrade branch's hard-coded target
        # (TACTICAL_READY, FLASH_READY) is already <= the request by
        # construction, so capping could never have been observed to matter.
        # It matters a great deal at requested_tier=FLASH_READY: that is
        # compose_report()'s own default and authority_transformer.
        # _composer_enhance()'s actual unconditional call for every real
        # article -- exercised here for every requested tier the ladder
        # defines, not only the one call shape that happened to already be
        # safe.
        single_fail_ids = list(CORRECTNESS_CONTROLS) + list(PREMIUM_COMPLETENESS_CONTROLS) + ["human_analyst_certification_governance"]
        for requested in CertificationState:
            if requested not in _TIER_RANK:
                continue  # PREMIUM_AUTOMATED_CERTIFIED: never a real requested_tier, unranked by design.
            for control_id in single_fail_ids:
                for status in ("FAIL", "BLOCKED"):
                    result = determine_achieved_tier(_results({control_id: status}), requested_tier=requested)
                    assert _TIER_RANK[result.achieved_tier] <= _TIER_RANK[requested], (
                        f"requested={requested.value} control={control_id}={status} "
                        f"achieved={result.achieved_tier.value} outranks the request"
                    )


class TestRealProductionCallerNeverInflatesFlashReadyTier:
    """The live gap this whole capping mechanism exists to close:
    ``pipeline_composer.compose_report()``'s own default -- and
    ``authority_transformer._composer_enhance()``'s actual, unconditional,
    every-article call -- requests ``FLASH_READY``, not
    ``PREMIUM_READY_PENDING_HUMAN``. A routine article that is correct but
    (normally, honestly) never attempted a forecast, hypothesis set,
    regulatory read, premium depth, current statistics, or technical
    recommendations -- i.e. every real FLASH_READY-tier article today --
    must be labelled FLASH_READY, not silently relabelled TACTICAL_READY, a
    tier nobody asked this report to reach and whose own completeness bar
    was never evaluated in service of. ``report_integrity.
    build_report_context()`` renders ``achieved_tier`` verbatim into the
    reader-facing "Public Intelligence Certification" label, so this is a
    real commercial-integrity defect, not a cosmetic one, when it regresses."""

    def test_flash_ready_request_with_all_premium_completeness_blocked_stays_flash_ready(self):
        # The exact, realistic shape of a routine article's control mix:
        # every correctness control clean, every premium-only control
        # honestly BLOCKED (never attempted at this tier).
        overrides = {cid: "BLOCKED" for cid in PREMIUM_COMPLETENESS_CONTROLS}
        result = determine_achieved_tier(_results(overrides), requested_tier=CertificationState.FLASH_READY)
        assert result.achieved_tier == CertificationState.FLASH_READY
        assert not result.was_downgraded
        assert "Capped at the requested tier" in result.downgrade_reason

    def test_flash_ready_request_with_single_premium_completeness_gap_stays_flash_ready(self):
        for control_id in PREMIUM_COMPLETENESS_CONTROLS:
            result = determine_achieved_tier(
                _results({control_id: "BLOCKED"}), requested_tier=CertificationState.FLASH_READY,
            )
            assert result.achieved_tier == CertificationState.FLASH_READY, (
                f"{control_id} BLOCKED alone should not lift a FLASH_READY request to "
                f"{result.achieved_tier.value}"
            )

    def test_tactical_ready_request_with_incomplete_premium_completeness_is_unaffected(self):
        # Regression guard: TACTICAL_READY is exactly what the natural
        # (uncapped) branch already returns for this scenario, so a
        # TACTICAL_READY *request* must see identical behaviour before and
        # after the capping fix -- the cap is a no-op here by construction
        # (natural_tier == requested_tier), not a coincidence.
        result = determine_achieved_tier(
            _results({"forecast_methodology": "BLOCKED"}), requested_tier=CertificationState.TACTICAL_READY,
        )
        assert result.achieved_tier == CertificationState.TACTICAL_READY
        assert "Capped at the requested tier" not in result.downgrade_reason

    def test_premium_tier_request_with_incomplete_premium_completeness_is_unaffected(self):
        # Regression guard: the original, still-passing
        # TestPremiumCompletenessGapsCapAtTactical class already covers this
        # at the default requested_tier; this pins the same outcome
        # explicitly at PREMIUM_READY_PENDING_HUMAN, the other tier real
        # code actually requests (automated_certification.py).
        result = determine_achieved_tier(
            _results({"forecast_methodology": "BLOCKED"}),
            requested_tier=CertificationState.PREMIUM_READY_PENDING_HUMAN,
        )
        assert result.achieved_tier == CertificationState.TACTICAL_READY


class TestDowngradeResultReporting:
    def test_to_dict_round_trips_the_fields(self):
        result = determine_achieved_tier(_results({"cross_section_consistency": "FAIL"}))
        d = result.to_dict()
        assert d["achieved_tier"] == "PUBLIC_REFERENCE_DRAFT"
        assert d["requested_tier"] == "PREMIUM_READY_PENDING_HUMAN"
        assert "cross_section_consistency" in d["failed_controls"]
        assert d["downgrade_reason"]

    def test_was_downgraded_is_false_only_when_tier_is_unchanged(self):
        clean = determine_achieved_tier(_results({}))
        downgraded = determine_achieved_tier(_results({"premium_depth": "FAIL"}))
        assert not clean.was_downgraded
        assert downgraded.was_downgraded
