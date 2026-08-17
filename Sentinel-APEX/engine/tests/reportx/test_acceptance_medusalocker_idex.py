"""ReportX Section 34 acceptance test: MedusaLocker / Idex Group.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
medusalocker_idex_group.py (repo root). Built from real research
retrieved this session (see that module's own docstring for sources).

Distinct shape: the load-bearing finding is a name-collision risk between
the small leak-site victim "Idex Group" (idex-group.com) and the
unrelated, much larger "IDEX Corporation" (idexcorp.com, S&P 500,
~9,000 employees) that a naive business-description search would surface.
This fixture proves the schema does not borrow the wrong entity's profile
just because a search engine returns it prominently.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "medusalocker_idex_group.py"


def _load_fixture_module():
    spec = importlib.util.spec_from_file_location("medusalocker_idex_group", FIXTURE_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["medusalocker_idex_group"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fixture_module():
    assert FIXTURE_MODULE_PATH.is_file(), f"expected {FIXTURE_MODULE_PATH}"
    return _load_fixture_module()


class TestThreeLayerSeparation:
    def test_victim_observation_carries_no_actor_general_context(self, fixture_module):
        claim = fixture_module.build_ransomware_victim_claim()
        import dataclasses
        vo_fields = {f.name for f in dataclasses.fields(type(claim.victim_observation))}
        assert "sectors" not in vo_fields
        assert "geographies" not in vo_fields

    def test_generic_readiness_always_carries_its_label(self, fixture_module):
        claim = fixture_module.build_ransomware_victim_claim()
        assert claim.generic_readiness.to_dict()["label"] == "GENERIC_DEFENSIVE_READINESS"


class TestSchemaIsolation:
    def test_no_linked_vulnerability_means_vuln_markers_stay_not_applicable(self, fixture_module):
        claim = fixture_module.build_ransomware_victim_claim()
        assert not claim.has_linked_vulnerability()
        assert claim.cisa_kev_state.value == "NOT_APPLICABLE"
        assert claim.cvss_state.value == "NOT_APPLICABLE"
        assert claim.patch_state.value == "NOT_APPLICABLE"
        assert claim.exploit_cve_status.value == "NOT_APPLICABLE"


class TestNameCollisionIsNotFabricatedAcross:
    """The load-bearing case: 'Idex Group' (the actual victim) must never
    borrow 'IDEX Corporation's (an unrelated S&P 500 company) public
    profile, employee count, or business-segment description, no matter
    how prominently a name search surfaces the wrong entity."""

    def test_disambiguation_claim_is_assessed_not_confirmed_from_a_source(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-not-idex-corporation"]
        assert claim.status.value == "ASSESSED"
        assert claim.source_refs == []  # an analytic judgment, not sourced to a single authority

    def test_no_victim_or_actor_claim_borrows_idex_corporations_profile_details(self, fixture_module):
        # The disambiguation claim itself (c-not-idex-corporation) legitimately
        # NAMES what it's excluding -- checked here on every OTHER claim, i.e.
        # that the wrong entity's profile never leaks into the actual victim
        # description or actor-context claims.
        graph = fixture_module.build_graph()
        forbidden = ["s&p 500", "northbrook", "9,000 employees", "idexcorp.com"]
        for cid, c in graph.claims.items():
            if cid == "c-not-idex-corporation":
                continue
            lowered = c.text.lower()
            for token in forbidden:
                assert token not in lowered, f"{cid} leaked IDEX Corporation detail: {token!r}"

    def test_rendered_report_explicitly_disclaims_the_conflation(self, fixture_module):
        bundle = fixture_module.build_bundle()
        assert "not idex corporation" in bundle.rendered_text.lower()

    def test_sector_field_is_honest_about_missing_independent_description(self, fixture_module):
        victim_observation = fixture_module.build_ransomware_victim_claim().victim_observation
        assert "no independent business description" in victim_observation.sector.lower()


class TestSingleSourceCorroborationPolicy:
    def test_leak_site_claim_itself_is_single_source_and_stays_reported(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-idex"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred-idex"]
        assert claim.status.value == "UNKNOWN"
        assert claim.evidence_refs == []
        assert claim.source_refs == []


class TestQAAndRendering:
    def test_rendered_text_has_no_critical_qa_defects(self, fixture_module):
        from sentinel_engine.reportx.qa_linter import critical_defect_count, lint_text
        bundle = fixture_module.build_bundle()
        findings = lint_text(bundle.rendered_text)
        assert critical_defect_count(findings) == 0

    def test_contradiction_engine_finds_nothing(self, fixture_module):
        from sentinel_engine.reportx.contradiction_engine import find_all_contradictions
        graph = fixture_module.build_graph()
        bundle = fixture_module.build_bundle()
        assert find_all_contradictions(graph, {}, full_text=bundle.rendered_text) == []

    def test_rendered_text_never_asserts_compromise_as_fact(self, fixture_module):
        bundle = fixture_module.build_bundle()
        assert "unknown on current evidence" in bundle.rendered_text.lower()
        assert "does not assert it did" in bundle.rendered_text.lower()


class TestIntelligenceGapsDerivation:
    def test_derive_ransomware_gaps_surfaces_the_real_absences(self, fixture_module):
        from sentinel_engine.reportx.analytic_scaffolding import derive_ransomware_gaps
        claim = fixture_module.build_ransomware_victim_claim()
        gaps = derive_ransomware_gaps(claim.victim_observation)
        descriptions = " ".join(g.description for g in gaps).lower()
        assert "acknowledgement" in descriptions
