"""Tests for sentinel_engine.reportx.executive_products (Intelligence
Factory architecture, flagship-report renderers)."""

from __future__ import annotations

from sentinel_engine.reportx.claim_model import CorroborationState, Reliability
from sentinel_engine.reportx.executive_products import (
    HuntHypothesis,
    RoleAudience,
    RoleDecision,
    SectorApplicability,
    SectorImpact,
    admiralty_label,
    information_credibility,
    overall_analytical_confidence,
    render_hunt_package,
    render_role_decisions,
    render_sector_impact_matrix,
    role_display_label,
    source_reliability_grade,
    two_axis_reliability,
    worst_corroboration_state,
)


class TestAdmiraltyLabel:
    def test_covers_every_reliability_value(self):
        for r in Reliability:
            label = admiralty_label(r)
            assert label

    def test_high_maps_to_reliable_tier(self):
        assert "Reliable" in admiralty_label(Reliability.HIGH)

    def test_unknown_maps_to_f(self):
        assert admiralty_label(Reliability.UNKNOWN).startswith("F")


class TestTwoAxisReliability:
    """COMMERCIAL-QUALITY-2026-08-18: independently verified live (and
    separately flagged in the same terms by an external review) that the
    platform rendered one blended label ("nvd: A/B — Reliable") instead of
    the real, independent 2-axis Admiralty matrix -- Source Reliability
    (the publisher) graded completely separately from Information
    Credibility (this specific claim's corroboration standing)."""

    def test_every_reliability_value_has_a_grade(self):
        for r in Reliability:
            assert source_reliability_grade(r)

    def test_reliability_grades_are_never_a_slash_combo(self):
        # The exact defect: "A/B" is not a real, single Admiralty grade.
        for r in Reliability:
            grade = source_reliability_grade(r)
            assert "/" not in grade
            assert len(grade) == 1

    def test_every_corroboration_state_has_a_credibility_number_and_label(self):
        for state in CorroborationState:
            number, label = information_credibility(state)
            assert 1 <= number <= 6
            assert label

    def test_multi_source_independent_is_the_best_credibility(self):
        number, _ = information_credibility(CorroborationState.MULTI_SOURCE_INDEPENDENT)
        assert number == 1

    def test_uncorroborated_is_the_worst_credibility(self):
        number, _ = information_credibility(CorroborationState.UNCORROBORATED)
        assert number == 6

    def test_dependent_sources_are_not_graded_as_independent_confirmation(self):
        # Syndicated copies of the same original report must not be
        # rewarded the same as genuine independent confirmation.
        dependent_number, _ = information_credibility(CorroborationState.MULTI_SOURCE_DEPENDENT)
        independent_number, _ = information_credibility(CorroborationState.MULTI_SOURCE_INDEPENDENT)
        assert dependent_number > independent_number

    def test_high_confidence_requires_both_axes_strong(self):
        assert overall_analytical_confidence(Reliability.HIGH, 1) == "HIGH"
        # Strong publisher alone, with only a single uncorroborated source,
        # is not enough for HIGH -- both axes must be strong together.
        assert overall_analytical_confidence(Reliability.HIGH, 3) != "HIGH"

    def test_low_reliability_or_bad_credibility_forces_low_confidence(self):
        assert overall_analytical_confidence(Reliability.UNKNOWN, 1) == "LOW"
        assert overall_analytical_confidence(Reliability.HIGH, 6) == "LOW"

    def test_two_axis_reliability_renders_three_separate_labeled_lines(self):
        out = two_axis_reliability(Reliability.HIGH, CorroborationState.SINGLE_SOURCE)
        assert "Source Reliability:" in out
        assert "Information Credibility:" in out
        assert "Overall Analytical Confidence:" in out
        assert "A/B" not in out

    def test_worst_corroboration_state_picks_the_least_corroborated(self):
        assert worst_corroboration_state([
            CorroborationState.MULTI_SOURCE_INDEPENDENT, CorroborationState.SINGLE_SOURCE,
        ]) == CorroborationState.SINGLE_SOURCE

    def test_worst_corroboration_state_defaults_to_uncorroborated_when_empty(self):
        assert worst_corroboration_state([]) == CorroborationState.UNCORROBORATED


class TestRoleDecisions:
    def test_empty_list_renders_nothing(self):
        assert render_role_decisions([]) == ""

    def test_renders_role_decision_and_grounds_it_in_evidence(self):
        d = RoleDecision(
            role=RoleAudience.CISO_CIO, decision="Authorize emergency patching.",
            rationale="Confirmed KEV listing with a 3-day federal deadline.",
            evidence_claim_ids=("c-kev-listed",), timeline="Immediate",
        )
        out = render_role_decisions([d])
        # COMMERCIAL-QUALITY-2026-08-18: str.title() on the raw enum value
        # used to render this as "Ciso Cio" -- an acronym-aware label is now
        # the only correct output.
        assert "CISO / CIO" in out
        assert "Ciso Cio" not in out
        assert "c-kev-listed" in out
        assert "Authorize emergency patching." in out

    def test_only_supplied_roles_are_rendered_not_padded_to_all(self):
        d = RoleDecision(role=RoleAudience.LEGAL_COMPLIANCE_PRIVACY, decision="x", rationale="y", evidence_claim_ids=())
        out = render_role_decisions([d])
        assert "Legal / Compliance / Privacy" in out
        assert "CEO / Board" not in out

    def test_default_construction_leaves_every_rx_p1j_field_falsy(self):
        # RX-P1J additive fields must never silently default to a truthy
        # placeholder -- "" / () means "not established," and every one of
        # the 7 real production call sites in pipeline_composer.
        # _lean_role_decisions() constructs without most of these, so this
        # is also the real backward-compatibility proof for that module.
        d = RoleDecision(role=RoleAudience.SOC_MANAGER, decision="x", rationale="y", evidence_claim_ids=("c-1",))
        assert d.action == "" and d.priority == "" and d.claim_refs == ()
        assert d.time_horizon == "" and d.deadline_or_trigger == ""
        assert d.escalation_condition == "" and d.conditions_that_change_decision == ""
        assert d.limitations == ""

    def test_to_dict_includes_every_rx_p1j_field(self):
        d = RoleDecision(
            role=RoleAudience.IR_MANAGER, decision="Validate internally.", rationale="Single-source claim.",
            evidence_claim_ids=("c-victim-claim",), action="Open a validation ticket.", priority="P2",
            claim_refs=("claim-1",), time_horizon="Near-term", deadline_or_trigger="",
            escalation_condition="Independent corroboration is found.",
            conditions_that_change_decision="A second independent source reports the same claim.",
            limitations="Based on a single third-party source only.",
        )
        out = d.to_dict()
        assert out["action"] == "Open a validation ticket."
        assert out["priority"] == "P2"
        assert out["claim_refs"] == ["claim-1"]
        assert out["time_horizon"] == "Near-term"
        assert out["escalation_condition"] == "Independent corroboration is found."
        assert out["conditions_that_change_decision"] == "A second independent source reports the same claim."
        assert out["limitations"] == "Based on a single third-party source only."

    def test_rendered_output_shows_escalation_and_limitations_when_present(self):
        d = RoleDecision(
            role=RoleAudience.IR_MANAGER, decision="Validate internally.", rationale="Single-source claim.",
            evidence_claim_ids=("c-victim-claim",),
            escalation_condition="Independent corroboration is found.",
            limitations="Based on a single third-party source only.",
        )
        out = render_role_decisions([d])
        assert "**Escalate when:** Independent corroboration is found." in out
        assert "**Limitations:** Based on a single third-party source only." in out

    def test_rendered_output_omits_empty_optional_fields(self):
        # A decision with no genuine basis for the new fields must not
        # render empty "Priority:"/"Escalate when:" lines -- honest
        # omission, not a blank placeholder.
        d = RoleDecision(role=RoleAudience.SOC_MANAGER, decision="x", rationale="y", evidence_claim_ids=("c-1",))
        out = render_role_decisions([d])
        assert "Priority:" not in out
        assert "Escalate when:" not in out
        assert "Limitations:" not in out
        assert "Deadline/Trigger:" not in out


class TestRoleDisplayLabel:
    """COMMERCIAL-QUALITY-2026-08-18: independently verified live (and
    separately flagged in the same terms by an external review) that
    str.title() on an underscore-joined RoleAudience value mangles every
    acronym-bearing role -- "Ir Manager", "Soc Manager", "Ciso Cio",
    "Ot Team", "Mssp". role_display_label() is the single source of truth
    fix; every RoleAudience member must have a correct entry."""

    def test_every_role_has_a_display_label(self):
        for role in RoleAudience:
            label = role_display_label(role)
            assert label

    def test_acronym_roles_are_not_mangled(self):
        expected = {
            RoleAudience.CEO_BOARD: "CEO / Board",
            RoleAudience.CISO_CIO: "CISO / CIO",
            RoleAudience.SOC_MANAGER: "SOC Manager",
            RoleAudience.IR_MANAGER: "IR Manager",
            RoleAudience.OT_TEAM: "OT Team",
            RoleAudience.MSSP: "MSSP",
        }
        for role, label in expected.items():
            assert role_display_label(role) == label


class TestHuntPackage:
    def test_empty_list_renders_nothing(self):
        assert render_hunt_package([]) == ""

    def test_renders_all_required_hunt_fields(self):
        h = HuntHypothesis(
            hypothesis_id="h1", statement="Adversaries reused the RondoDox User-Agent string.",
            required_telemetry=("Reverse-proxy access logs",),
            pivot_opportunities=("Pivot from source IP to ASN",),
            expected_observations=("A literal 'Mozilla' substring in the payload User-Agent",),
            negative_indicators=("No POST requests to /api/jobs/ observed at all",),
            false_positive_considerations=("Legitimate internal job-submission clients",),
            validation_steps=("Confirm the request originated externally",),
            success_criteria="At least one matching request is confirmed non-internal.",
            evidence_claim_ids=("c-rondodox-flaw",),
        )
        out = render_hunt_package([h])
        for expected in (
            "Reverse-proxy access logs", "Pivot from source IP to ASN",
            "A literal 'Mozilla' substring", "No POST requests", "Legitimate internal job-submission",
            "Confirm the request originated externally", "At least one matching request",
            "c-rondodox-flaw",
        ):
            assert expected in out

    def test_no_evidence_ids_states_forward_looking_explicitly(self):
        h = HuntHypothesis(
            hypothesis_id="h2", statement="s", required_telemetry=(), pivot_opportunities=(),
            expected_observations=(), negative_indicators=(), false_positive_considerations=(),
            validation_steps=(), success_criteria="c",
        )
        out = render_hunt_package([h])
        assert "forward-looking hunt" in out


class TestSectorImpactMatrix:
    def test_empty_list_renders_nothing(self):
        assert render_sector_impact_matrix([]) == ""

    def test_not_assessed_sector_is_explicit_not_silently_dropped(self):
        rows = [
            SectorImpact("Healthcare", SectorApplicability.NOT_ASSESSED,
                          "No source reviewed establishes healthcare-sector deployment.", ""),
        ]
        out = render_sector_impact_matrix(rows)
        assert "Healthcare" in out
        assert "NOT_ASSESSED" in out

    def test_assessed_sector_carries_its_own_note_not_shared_boilerplate(self):
        rows = [
            SectorImpact("Technology", SectorApplicability.ASSESSED,
                          "Confirmed production use at Uber (named, quoted adopter).",
                          "No sector-specific regulatory determination made.", ("c-uber-user",)),
            SectorImpact("Manufacturing", SectorApplicability.NOT_ASSESSED,
                          "No source reviewed establishes manufacturing-sector deployment.", ""),
        ]
        out = render_sector_impact_matrix(rows)
        assert "Confirmed production use at Uber" in out
        assert "No source reviewed establishes manufacturing" in out
        # the two sectors must not share the same exposure text
        assert out.count("Confirmed production use at Uber") == 1
