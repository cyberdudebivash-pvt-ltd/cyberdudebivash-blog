"""Tests for sentinel_engine.reportx.executive_products (Intelligence
Factory architecture, flagship-report renderers)."""

from __future__ import annotations

from sentinel_engine.reportx.claim_model import Reliability
from sentinel_engine.reportx.executive_products import (
    HuntHypothesis,
    RoleAudience,
    RoleDecision,
    SectorApplicability,
    SectorImpact,
    admiralty_label,
    render_hunt_package,
    render_role_decisions,
    render_sector_impact_matrix,
    role_display_label,
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
