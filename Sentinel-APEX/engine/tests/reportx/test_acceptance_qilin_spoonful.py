"""ReportX Section 34 acceptance test: Qilin / Spoonful of Comfort.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
qilin_spoonful_of_comfort.py (repo root). Built from real research
retrieved this session (see that module's own docstring for sources).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "qilin_spoonful_of_comfort.py"


def _load_fixture_module():
    spec = importlib.util.spec_from_file_location("qilin_spoonful_of_comfort", FIXTURE_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["qilin_spoonful_of_comfort"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fixture_module():
    assert FIXTURE_MODULE_PATH.is_file(), f"expected {FIXTURE_MODULE_PATH}"
    return _load_fixture_module()


class TestThreeLayerSeparation:
    def test_victim_observation_carries_no_actor_general_context(self, fixture_module):
        claim = fixture_module.build_ransomware_victim_claim()
        # The victim-observation layer's own fields are all incident-scoped
        # (claim_date, sample_proof_status, etc.) -- it has no field that
        # could hold "since 2023, victims span energy/manufacturing..."
        # style actor-historical prose; that lives only in actor_context.
        import dataclasses
        vo_fields = {f.name for f in dataclasses.fields(type(claim.victim_observation))}
        assert "sectors" not in vo_fields  # that's an ActorHistoricalContext field
        assert "geographies" not in vo_fields

    def test_actor_context_claims_are_separately_sourced_from_victim_claims(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = fixture_module.build_ransomware_victim_claim()
        # Every actor-context claim_id must resolve to a real Claim with
        # its OWN source_refs -- Section 19's "historical Qilin behavior
        # is not evidence for this incident" enforced structurally: these
        # claims cite s-wikipedia-qilin, never s-hendryadrian (the
        # victim-specific claim's own source).
        for cid in claim.actor_context.raas_model_claim_ids + claim.actor_context.historical_tooling_claim_ids:
            c = graph.claims[cid]
            assert "s-wikipedia-qilin" in c.source_refs
            assert "s-hendryadrian" not in c.source_refs

    def test_generic_readiness_always_carries_its_label(self, fixture_module):
        claim = fixture_module.build_ransomware_victim_claim()
        d = claim.generic_readiness.to_dict()
        assert d["label"] == "GENERIC_DEFENSIVE_READINESS"


class TestSchemaIsolation:
    def test_no_linked_vulnerability_means_vuln_markers_stay_not_applicable(self, fixture_module):
        claim = fixture_module.build_ransomware_victim_claim()
        assert not claim.has_linked_vulnerability()
        assert claim.cisa_kev_state.value == "NOT_APPLICABLE"
        assert claim.cvss_state.value == "NOT_APPLICABLE"
        assert claim.patch_state.value == "NOT_APPLICABLE"
        assert claim.exploit_cve_status.value == "NOT_APPLICABLE"


class TestSingleSourceCorroborationPolicy:
    def test_leak_site_claim_itself_is_single_source_and_stays_reported(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"  # not CONFIRMED
        assert not claim.requires_downgrade_without_corroboration()  # already correctly at REPORTED

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        # Section 10's core distinction: a leak-site claim establishes that
        # a CLAIM was made, not that compromise/encryption/theft occurred.
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred"]
        assert claim.status.value == "UNKNOWN"
        assert claim.evidence_refs == []
        assert claim.source_refs == []


class TestActorContextIsRealAndSourced:
    def test_raas_affiliate_split_is_a_real_sourced_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-raas-model"]
        assert "80-85%" in claim.text
        assert claim.source_refs == ["s-wikipedia-qilin"]
        assert claim.observed_vs_context.value == "CONTEXT"


class TestQAAndRendering:
    def test_rendered_text_has_no_critical_qa_defects(self, fixture_module):
        from sentinel_engine.reportx.qa_linter import critical_defect_count, lint_text
        bundle = fixture_module.build_bundle()
        findings = lint_text(bundle.rendered_text)
        assert critical_defect_count(findings) == 0

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
        assert "ioc" in descriptions.lower() or "IOC" in " ".join(g.description for g in gaps)
