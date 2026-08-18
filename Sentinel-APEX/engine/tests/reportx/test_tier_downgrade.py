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


# The tier ladder's total ordering, highest to lowest -- used to assert
# "never higher than requested" without hard-coding numeric ranks elsewhere.
_TIER_RANK = {
    CertificationState.PREMIUM_CERTIFIED: 4,
    CertificationState.PREMIUM_READY_PENDING_HUMAN: 3,
    CertificationState.TACTICAL_READY: 2,
    CertificationState.FLASH_READY: 1,
    CertificationState.PUBLIC_REFERENCE_DRAFT: 0,
}


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
