"""ReportX Section 34 acceptance test: MedusaLocker / Twal Family IT Lab.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
medusalocker_twal_family_it_lab.py (repo root). Built from real research
retrieved this session (see that module's own docstring for sources and
for the deliberate privacy-scoping decision -- this victim is a personal
home lab, and the fixture excludes the individual's name/address while
retaining everything the schema actually needs).

Distinct shape from the earlier three ransomware fixtures: this is the
first case with two sources syndicating the SAME underlying leak-site
post (correctly MULTI_SOURCE_DEPENDENT, not MULTI_SOURCE_INDEPENDENT),
and the first with a tracker's own documented self-correction of an
earlier misattribution.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "medusalocker_twal_family_it_lab.py"


def _load_fixture_module():
    spec = importlib.util.spec_from_file_location("medusalocker_twal_family_it_lab", FIXTURE_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["medusalocker_twal_family_it_lab"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fixture_module():
    assert FIXTURE_MODULE_PATH.is_file(), f"expected {FIXTURE_MODULE_PATH}"
    return _load_fixture_module()


class TestPrivacyScoping:
    """The fixture's own docstring commits to excluding the individual's
    name/employer/street address. Enforce that commitment mechanically so
    a future edit can't silently reintroduce it."""

    def test_no_street_address_or_personal_name_anywhere_in_the_fixture_source(self):
        text = FIXTURE_MODULE_PATH.read_text(encoding="utf-8")
        assert "Wolfe Point" not in text
        assert "K1V" not in text
        assert "Daniel" not in text
        assert "Technology North" not in text

    def test_rendered_report_never_names_the_individual_or_address(self, fixture_module):
        bundle = fixture_module.build_bundle()
        assert "Daniel" not in bundle.rendered_text
        assert "Wolfe Point" not in bundle.rendered_text


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
            assert c.source_refs == ["s-cybersecuritydive-medusalocker"]
            assert "s-hendryadrian-twal" not in c.source_refs
            assert "s-ransomwarelive-twal" not in c.source_refs

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


class TestMultiSourceDependentCorroboration:
    """The first fixture in this set where two trackers syndicate the SAME
    underlying leak-site post rather than independently observing it --
    must resolve to MULTI_SOURCE_DEPENDENT, not MULTI_SOURCE_INDEPENDENT,
    and must not be treated as stronger evidence than a single-source
    claim just because two URLs cite it."""

    def test_leak_site_claim_is_multi_source_dependent(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-twal"]
        assert claim.corroboration_state.value == "MULTI_SOURCE_DEPENDENT"
        assert len(claim.source_refs) == 2

    def test_both_sources_share_one_independence_group(self, fixture_module):
        graph = fixture_module.build_graph()
        groups = {graph.sources[sid].independence_group for sid in graph.claims["c-leak-site-claim-twal"].source_refs}
        assert groups == {"medusalocker-twal-leak-site-post"}

    def test_dependent_corroboration_still_does_not_upgrade_status_to_confirmed(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-twal"]
        assert claim.status.value == "REPORTED"

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred-twal"]
        assert claim.status.value == "UNKNOWN"
        assert claim.evidence_refs == []
        assert claim.source_refs == []


class TestMisattributionCorrectionIsRepresentedHonestly:
    def test_correction_claim_is_confirmed_about_the_tracker_not_the_incident(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-misattribution-correction"]
        assert claim.status.value == "CONFIRMED"
        assert "forces.gc.ca" in claim.text.lower()

    def test_rendered_text_surfaces_the_correction_as_a_caution(self, fixture_module):
        bundle = fixture_module.build_bundle()
        assert "misidentified" in bundle.rendered_text.lower()


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
