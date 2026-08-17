"""ReportX Section 34 acceptance test: Aurora / Lloyd Coils Europe.

Golden fixture: tests/fixtures/reportx-commercial-readiness/
aurora_lloyd_coils_europe.py (repo root). Built from real research
retrieved this session (see that module's own docstring for sources).

Distinct shape from all six earlier ransomware fixtures: the first case
with a genuinely MULTI_SOURCE_INDEPENDENT claim (two non-syndicating,
independently-fetched sources agreeing on the corporate HQ), the first
case where a field is deliberately left NOT_ASSESSED because the source
itself redacted the data (HudsonRock metrics shown as em-dashes) rather
than because no source was found, and the first case exercising a
three-way actor-name collision ("Aurora" the 2026 leak-site group vs. the
Go-based malware/infostealer vs. the unrelated 2018 "OneKeyLocker/Zorro"
family) with the ambiguity represented as UNKNOWN rather than resolved by
assumption.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
FIXTURE_MODULE_PATH = FIXTURES_DIR / "aurora_lloyd_coils_europe.py"


def _load_fixture_module():
    spec = importlib.util.spec_from_file_location("aurora_lloyd_coils_europe", FIXTURE_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["aurora_lloyd_coils_europe"] = module
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


class TestMultiSourceIndependentCorroboration:
    """The first genuinely MULTI_SOURCE_INDEPENDENT claim in this fixture
    set: two different, non-syndicating publishers (a manufacturer
    directory and the company's own site) independently state the same
    HQ address."""

    def test_hq_context_claim_is_multi_source_independent(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-hq-context-lce"]
        assert claim.corroboration_state.value == "MULTI_SOURCE_INDEPENDENT"
        assert claim.status.value == "CONFIRMED"

    def test_the_two_sources_have_different_independence_groups(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-hq-context-lce"]
        groups = {graph.sources[sid].independence_group for sid in claim.source_refs}
        assert len(groups) == 2

    def test_hq_context_does_not_overwrite_the_primary_trackers_country_field(self, fixture_module):
        # Section 19-adjacent discipline: a disambiguating fact is recorded
        # ADDITIONALLY, not by silently mutating the primary source's own
        # stated field.
        victim_observation = fixture_module.build_ransomware_victim_claim().victim_observation
        assert victim_observation.country == "United Kingdom"


class TestRedactedFieldIsNotFabricated:
    """The source itself redacted the HudsonRock metrics (em-dashes, no
    numbers) -- this must produce an empty/NOT_ASSESSED result, never
    invented placeholder numbers."""

    def test_no_infostealer_ttp_claim_was_invented(self, fixture_module):
        victim_observation = fixture_module.build_ransomware_victim_claim().victim_observation
        assert victim_observation.observed_incident_ttp_claim_ids == []

    def test_no_claim_in_the_graph_states_a_specific_infostealer_count(self, fixture_module):
        graph = fixture_module.build_graph()
        for c in graph.claims.values():
            assert "compromised employees" not in c.text.lower()
            assert "compromised users" not in c.text.lower()


class TestActorNamingAmbiguityIsRepresentedHonestly:
    def test_naming_ambiguity_claim_is_unknown_not_resolved(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-aurora-naming-ambiguity"]
        assert claim.status.value == "UNKNOWN"
        assert claim.source_refs == []

    def test_no_2018_era_tooling_is_attributed_to_the_actor_context(self, fixture_module):
        claim = fixture_module.build_ransomware_victim_claim()
        assert claim.actor_context.historical_tooling_claim_ids == []

    def test_operational_profile_claim_is_scoped_to_the_2026_group_page_only(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-aurora-operational-profile"]
        assert claim.source_refs == ["s-ransomwarelive-aurora-group"]
        assert "2018" not in claim.text
        assert "OneKeyLocker" not in claim.text


class TestSingleSourceCorroborationPolicy:
    def test_leak_site_claim_itself_is_single_source_and_stays_reported(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-leak-site-claim-lce"]
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()

    def test_compromise_occurrence_is_honestly_unknown_not_assumed_from_the_claim(self, fixture_module):
        graph = fixture_module.build_graph()
        claim = graph.claims["c-compromise-occurred-lce"]
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
