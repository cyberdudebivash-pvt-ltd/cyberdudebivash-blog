"""ReportX Section 34 acceptance test: Qilin / Mulino Padano.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
qilin_mulino_padano.py (repo root). Built from real research retrieved
this session (see that module's own docstring for sources) -- the same
actor (Qilin) as the Spoonful of Comfort fixture, deliberately reusing the
same already-verified Wikipedia-sourced actor-context facts, so this pair
of fixtures also exercises the anti-padding / template-repetition control
(Sections 24, 28) against two REAL reports about the same actor, not
synthetic text.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "qilin_mulino_padano.py"
QILIN_SOC_MODULE_PATH = FIXTURES_DIR / "qilin_spoonful_of_comfort.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fixture_module():
    assert FIXTURE_MODULE_PATH.is_file(), f"expected {FIXTURE_MODULE_PATH}"
    return _load("qilin_mulino_padano", FIXTURE_MODULE_PATH)


@pytest.fixture(scope="module")
def qilin_soc_module():
    assert QILIN_SOC_MODULE_PATH.is_file(), f"expected {QILIN_SOC_MODULE_PATH}"
    return _load("qilin_spoonful_of_comfort", QILIN_SOC_MODULE_PATH)


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
        for cid in claim.actor_context.raas_model_claim_ids + claim.actor_context.historical_tooling_claim_ids:
            c = graph.claims[cid]
            assert "s-wikipedia-qilin-mp" in c.source_refs
            assert "s-ransomwarelive-mp" not in c.source_refs

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
        claim = graph.claims["c-leak-site-claim-mp"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred-mp"]
        assert claim.status.value == "UNKNOWN"
        assert claim.evidence_refs == []
        assert claim.source_refs == []


class TestActorContextIsRealAndSourced:
    def test_raas_affiliate_split_is_a_real_sourced_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-raas-model-mp"]
        assert "80-85%" in claim.text
        assert claim.source_refs == ["s-wikipedia-qilin-mp"]
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


class TestCrossReportAntiPadding:
    """Sections 24/28 against two REAL reports about the same actor. The
    victim-specific content differs (Italy/food-production vs. US/
    hospitality); the actor-historical prose was deliberately reused
    (legitimately -- same true facts about the same actor, verified once).
    This class proves the anti-padding control does exactly what it's
    supposed to: it does NOT flag the two reports' honestly-labeled
    'Actor Historical Context' sections (that heading isn't one of the six
    names Section 24 holds to this check), but DOES flag the same reused
    prose if a renderer mislabels it under the incident-specific 'Actor
    Analysis' heading instead -- catching the exact failure mode the
    control exists to prevent, using real fixture text rather than
    synthetic duplicates."""

    def _actor_context_text(self, module) -> str:
        # Pull the literal "Actor Historical Context" section out of each
        # fixture's own rendered_text rather than hand-copying prose --
        # keeps this test honest to what the fixtures actually render.
        bundle = module.build_bundle()
        text = bundle.rendered_text
        start = text.index("## Actor Historical Context")
        end = text.index("## Generic Defensive Readiness")
        return text[start:end]

    def test_actor_historical_context_heading_is_not_held_to_the_incident_specific_check(
        self, fixture_module, qilin_soc_module
    ):
        from sentinel_engine.reportx.product_depth import ReportSection, find_template_repetition
        sections = [
            ReportSection(report_id="qilin-mulino-padano", section_name="Actor Historical Context",
                          text=self._actor_context_text(fixture_module)),
            ReportSection(report_id="qilin-spoonful-of-comfort", section_name="Actor Historical Context",
                          text=self._actor_context_text(qilin_soc_module)),
        ]
        findings = find_template_repetition(sections)
        assert findings == []

    def test_same_prose_mislabeled_as_actor_analysis_is_correctly_flagged(
        self, fixture_module, qilin_soc_module
    ):
        from sentinel_engine.reportx.product_depth import ReportSection, find_template_repetition
        sections = [
            ReportSection(report_id="qilin-mulino-padano", section_name="Actor Analysis",
                          text=self._actor_context_text(fixture_module)),
            ReportSection(report_id="qilin-spoonful-of-comfort", section_name="Actor Analysis",
                          text=self._actor_context_text(qilin_soc_module)),
        ]
        findings = find_template_repetition(sections)
        assert len(findings) == 1
        assert findings[0].similarity >= 0.80
