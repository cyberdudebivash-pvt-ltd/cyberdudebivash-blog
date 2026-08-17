"""ReportX Section 34 acceptance test: MedusaLocker / Bija Industrie.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
medusalocker_bija_industrie.py (repo root). Built from real research
retrieved this session (see that module's own docstring for sources).

This is the 10th and final golden fixture in the named acceptance-case
set. Distinct shape: the victim's own site independently confirms a
sensitive defense-industrial-base detail (serves civil AND military
aviation programs) -- retained for context, but a dedicated test proves
no claim escalates that context into an assertion that military-related
data was actually exfiltrated (the leak-site claim states only an email
count). This fixture also closes out a three-way same-actor set (with
Twal Family IT Lab and All Parts Dry Cleaning) for a three-fixture
anti-padding check.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "medusalocker_bija_industrie.py"
TWAL_MODULE_PATH = FIXTURES_DIR / "medusalocker_twal_family_it_lab.py"
ALL_PARTS_MODULE_PATH = FIXTURES_DIR / "medusalocker_all_parts_dry_cleaning.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fixture_module():
    assert FIXTURE_MODULE_PATH.is_file(), f"expected {FIXTURE_MODULE_PATH}"
    return _load("medusalocker_bija_industrie", FIXTURE_MODULE_PATH)


@pytest.fixture(scope="module")
def twal_module():
    return _load("medusalocker_twal_family_it_lab", TWAL_MODULE_PATH)


@pytest.fixture(scope="module")
def all_parts_module():
    return _load("medusalocker_all_parts_dry_cleaning", ALL_PARTS_MODULE_PATH)


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


class TestSensitiveContextIsNotEscalatedIntoAnUnsupportedClaim:
    """The victim's own site states it serves military aviation programs.
    That fact is retained (it is real, self-stated, and analytically
    relevant), but nothing in this fixture may escalate it into an
    assertion that military-related data was exfiltrated -- the leak-site
    claim itself only states an email count."""

    def test_business_description_is_confirmed_from_the_companys_own_site(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-victim-business-description-bija"]
        assert claim.status.value == "CONFIRMED"
        assert claim.source_refs == ["s-bija-own-site"]

    def test_no_claim_asserts_military_data_was_exfiltrated(self, fixture_module):
        graph = fixture_module.build_graph()
        for c in graph.claims.values():
            lowered = c.text.lower()
            if "military" in lowered:
                assert "exfiltrat" not in lowered and "stolen" not in lowered and "extracted" not in lowered

    def test_leak_site_claim_states_only_an_email_count(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-bija"]
        assert "693 emails" in claim.text
        assert "military" not in claim.text.lower()

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred-bija"]
        assert claim.status.value == "UNKNOWN"
        assert claim.evidence_refs == []
        assert claim.source_refs == []


class TestSingleSourceCorroborationPolicy:
    def test_leak_site_claim_itself_is_single_source_and_stays_reported(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-bija"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()


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


class TestThreeFixtureCrossReportAntiPadding:
    """Closes out the three-fixture MedusaLocker set (Twal Family IT Lab,
    All Parts Dry Cleaning, Bija Industrie) with a pairwise check across
    all three: the honestly-labeled 'Actor Historical Context' heading is
    never flagged, but every pair mislabeled as the incident-specific
    'Actor Analysis' heading is."""

    def _actor_context_text(self, module) -> str:
        bundle = module.build_bundle()
        text = bundle.rendered_text
        start = text.index("## Actor Historical Context")
        end = text.index("## Generic Defensive Readiness")
        return text[start:end]

    def test_three_way_actor_historical_context_is_never_flagged(
        self, fixture_module, twal_module, all_parts_module
    ):
        from sentinel_engine.reportx.product_depth import ReportSection, find_template_repetition
        modules = {
            "medusalocker-bija-industrie": fixture_module,
            "medusalocker-twal-family-it-lab": twal_module,
            "medusalocker-all-parts-dry-cleaning": all_parts_module,
        }
        sections = [
            ReportSection(report_id=report_id, section_name="Actor Historical Context",
                          text=self._actor_context_text(module))
            for report_id, module in modules.items()
        ]
        findings = find_template_repetition(sections)
        assert findings == []

    def test_three_way_actor_analysis_mislabeling_is_flagged_for_every_pair(
        self, fixture_module, twal_module, all_parts_module
    ):
        from sentinel_engine.reportx.product_depth import ReportSection, find_template_repetition
        modules = {
            "medusalocker-bija-industrie": fixture_module,
            "medusalocker-twal-family-it-lab": twal_module,
            "medusalocker-all-parts-dry-cleaning": all_parts_module,
        }
        sections = [
            ReportSection(report_id=report_id, section_name="Actor Analysis",
                          text=self._actor_context_text(module))
            for report_id, module in modules.items()
        ]
        findings = find_template_repetition(sections)
        # 3 reports, all pairwise-identical prose -> C(3,2) = 3 findings
        assert len(findings) == 3
        assert all(f.similarity >= 0.80 for f in findings)
