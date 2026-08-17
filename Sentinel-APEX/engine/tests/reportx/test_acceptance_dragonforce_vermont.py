"""ReportX Section 34 acceptance test: DragonForce / Vermont XCenter.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
dragonforce_vermont_xcenter.py (repo root). Built from real research
retrieved this session (see that module's own docstring for sources).

Distinct shape from the earlier fixtures: the victim's own site is used
as a genuine VICTIM_STATEMENT-tier corroborating source for the business
description (the leak-site tracker left its own 'sector' field
unpopulated), and this is the first fixture with passive-DNS
infrastructure fingerprinting (MX/TXT records) as a distinct TTP_OBSERVED
claim, kept separate from the leak-site claim and from the unusually
large infostealer-exposure signal.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "dragonforce_vermont_xcenter.py"


def _load_fixture_module():
    spec = importlib.util.spec_from_file_location("dragonforce_vermont_xcenter", FIXTURE_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["dragonforce_vermont_xcenter"] = module
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

    def test_actor_context_claims_are_separately_sourced_from_victim_claims(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = fixture_module.build_ransomware_victim_claim()
        for cid in claim.actor_context.raas_model_claim_ids:
            c = graph.claims[cid]
            assert c.source_refs == ["s-groupib-dragonforce"]
            assert "s-ransomwarelive-vxc" not in c.source_refs

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


class TestVictimSelfDescriptionIsAGenuineCorroboratingSource:
    def test_business_description_is_confirmed_from_the_companys_own_site(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-victim-business-description"]
        assert claim.status.value == "CONFIRMED"
        assert claim.source_refs == ["s-vermont-own-site"]

    def test_source_type_is_victim_statement(self, fixture_module):
        graph = fixture_module.build_graph()
        source = graph.sources["s-vermont-own-site"]
        assert source.source_type.value == "VICTIM_STATEMENT"


class TestDistinctTechnicalSignalsStayDistinct:
    """Infostealer exposure telemetry and passive-DNS infrastructure
    fingerprinting are two DIFFERENT observations from the same tracker
    page -- must not be merged into one over-broad claim, and neither is
    evidence of the incident's initial-access vector."""

    def test_infostealer_exposure_and_infra_fingerprint_are_separate_claims(self, fixture_module):
        graph = fixture_module.build_graph()
        assert "c-infostealer-exposure-vxc" in graph.claims
        assert "c-infra-fingerprint-vxc" in graph.claims
        assert graph.claims["c-infostealer-exposure-vxc"].text != graph.claims["c-infra-fingerprint-vxc"].text

    def test_neither_signal_is_asserted_as_the_initial_access_vector(self, fixture_module):
        bundle = fixture_module.build_bundle()
        assert "initial-access vector by any source" in bundle.rendered_text.lower() or \
            "not attributed to the incident's initial-access vector" in bundle.rendered_text.lower()


class TestSingleSourceCorroborationPolicy:
    def test_leak_site_claim_itself_is_single_source_and_stays_reported(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-vxc"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred-vxc"]
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
