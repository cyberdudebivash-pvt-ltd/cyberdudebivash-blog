"""ReportX Section 34 acceptance test: Panzer / SAGASTA s.r.o.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
panzer_sagasta_sro.py (repo root). Built from real research retrieved
this session (see that module's own docstring for sources). Distinct
shape from the Qilin fixture: a brand-new, thinly-documented threat actor,
and two independent sources that describe the SAME leak-site post with
different specificity rather than a directly opposed fact -- exercises
that the contradiction engine does not over-flag differing detail as a
conflict.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "panzer_sagasta_sro.py"


def _load_fixture_module():
    spec = importlib.util.spec_from_file_location("panzer_sagasta_sro", FIXTURE_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["panzer_sagasta_sro"] = module
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
        for cid in (
            claim.actor_context.historical_ttp_claim_ids
            + claim.actor_context.affiliate_behavior_claim_ids
        ):
            c = graph.claims[cid]
            assert c.source_refs, f"{cid} must carry its own source_refs"
            assert "s-ransomwarelive" not in c.source_refs
            assert "s-galaxywarden" not in c.source_refs

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


class TestTwoSourcesDifferingDetailIsNotAContradiction:
    """The core novel case this fixture exercises: ransomware.live says
    '46GB', GalaxyWarden says 'internal documents and at least one
    password field' -- different specificity about the SAME leak-site
    post, not a directly opposed EpistemicState. The engine must not
    manufacture a contradiction out of differing detail."""

    def test_both_claims_stay_reported_not_disputed(self, fixture_module):
        graph = fixture_module.build_graph()
        a = graph.claims["c-leak-site-claim"]
        b = graph.claims["c-leak-site-claim-contents"]
        assert a.status.value == "REPORTED"
        assert b.status.value == "REPORTED"

    def test_contradiction_engine_does_not_flag_the_pair(self, fixture_module):
        from sentinel_engine.reportx.contradiction_engine import find_all_contradictions
        graph = fixture_module.build_graph()
        bundle = fixture_module.build_bundle()
        contradictions = find_all_contradictions(graph, {}, full_text=bundle.rendered_text)
        assert contradictions == []

    def test_each_leak_claim_is_single_source_from_its_own_publisher(self, fixture_module):
        graph = fixture_module.build_graph()
        assert graph.claims["c-leak-site-claim"].source_refs == ["s-ransomwarelive"]
        assert graph.claims["c-leak-site-claim-contents"].source_refs == ["s-galaxywarden"]


class TestSingleSourceCorroborationPolicy:
    def test_leak_site_claim_itself_is_single_source_and_stays_reported(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred"]
        assert claim.status.value == "UNKNOWN"
        assert claim.evidence_refs == []
        assert claim.source_refs == []


class TestBlockedSourceHandledHonestly:
    """The DarkWebInformer X post could not be fetched directly this
    session (HTTP 402). Section 37's 'fail closed on an unfetchable
    source' principle applied at the source level: it is registered with
    low reliability and an explicit blocked-accessibility marker, and used
    only for the one narrow claim the search-engine snippet actually
    supports -- never upgraded to back a specific (revenue split,
    platform list) no independently-fetched source states."""

    def test_darkwebinformer_source_is_marked_blocked_and_low_reliability(self, fixture_module):
        graph = fixture_module.build_graph()
        source = graph.sources["s-darkwebinformer"]
        assert source.accessibility == "BLOCKED_DIRECT_FETCH_402"
        assert source.reliability.value == "LOW"

    def test_no_claim_asserts_an_affiliate_revenue_split(self, fixture_module):
        # Unlike the Qilin fixture (Group-IB's independently-fetched 80-85%
        # figure), no source reachable this session establishes a Panzer
        # revenue split -- the actor-context model must not invent one.
        graph = fixture_module.build_graph()
        claim = fixture_module.build_ransomware_victim_claim()
        assert claim.actor_context.raas_model_claim_ids == []
        for c in graph.claims.values():
            assert "%" not in c.text or "revenue" not in c.text.lower()


class TestActorContextIsRealAndSourced:
    def test_actor_recruitment_claim_is_a_real_sourced_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-actor-recruitment"]
        assert claim.source_refs == ["s-securityarsenal"]
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
