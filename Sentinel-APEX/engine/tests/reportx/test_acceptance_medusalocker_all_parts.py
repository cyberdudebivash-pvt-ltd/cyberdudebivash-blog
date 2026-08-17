"""ReportX Section 34 acceptance test: MedusaLocker / All Parts Dry Cleaning.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
medusalocker_all_parts_dry_cleaning.py (repo root). Built from real
research retrieved this session (see that module's own docstring for
sources) -- the same actor (MedusaLocker) as the Twal Family IT Lab
fixture, reusing the same already-verified CISA-advisory-derived actor
context. Like the Qilin pair, this also exercises the anti-padding
control against two REAL same-actor reports.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "medusalocker_all_parts_dry_cleaning.py"
TWAL_MODULE_PATH = FIXTURES_DIR / "medusalocker_twal_family_it_lab.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fixture_module():
    assert FIXTURE_MODULE_PATH.is_file(), f"expected {FIXTURE_MODULE_PATH}"
    return _load("medusalocker_all_parts_dry_cleaning", FIXTURE_MODULE_PATH)


@pytest.fixture(scope="module")
def twal_module():
    assert TWAL_MODULE_PATH.is_file(), f"expected {TWAL_MODULE_PATH}"
    return _load("medusalocker_twal_family_it_lab", TWAL_MODULE_PATH)


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
            assert c.source_refs == ["s-cybersecuritydive-medusalocker-apdc"]
            assert "s-ransomwarelive-apdc" not in c.source_refs

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


class TestSingleSourceCorroborationPolicy:
    def test_leak_site_claim_itself_is_single_source_and_stays_reported(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-apdc"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred-apdc"]
        assert claim.status.value == "UNKNOWN"
        assert claim.evidence_refs == []
        assert claim.source_refs == []


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
    """Same pattern proven for the Qilin pair: an honestly-labeled
    'Actor Historical Context' heading is not held to Section 24's
    incident-specific-section check, but the same prose mislabeled as
    'Actor Analysis' is correctly flagged as cross-report repetition."""

    def _actor_context_text(self, module) -> str:
        bundle = module.build_bundle()
        text = bundle.rendered_text
        start = text.index("## Actor Historical Context")
        end = text.index("## Generic Defensive Readiness")
        return text[start:end]

    def test_actor_historical_context_heading_is_not_held_to_the_incident_specific_check(
        self, fixture_module, twal_module
    ):
        from sentinel_engine.reportx.product_depth import ReportSection, find_template_repetition
        sections = [
            ReportSection(report_id="medusalocker-all-parts-dry-cleaning", section_name="Actor Historical Context",
                          text=self._actor_context_text(fixture_module)),
            ReportSection(report_id="medusalocker-twal-family-it-lab", section_name="Actor Historical Context",
                          text=self._actor_context_text(twal_module)),
        ]
        findings = find_template_repetition(sections)
        assert findings == []

    def test_same_prose_mislabeled_as_actor_analysis_is_correctly_flagged(
        self, fixture_module, twal_module
    ):
        from sentinel_engine.reportx.product_depth import ReportSection, find_template_repetition
        sections = [
            ReportSection(report_id="medusalocker-all-parts-dry-cleaning", section_name="Actor Analysis",
                          text=self._actor_context_text(fixture_module)),
            ReportSection(report_id="medusalocker-twal-family-it-lab", section_name="Actor Analysis",
                          text=self._actor_context_text(twal_module)),
        ]
        findings = find_template_repetition(sections)
        assert len(findings) == 1
        assert findings[0].similarity >= 0.80
