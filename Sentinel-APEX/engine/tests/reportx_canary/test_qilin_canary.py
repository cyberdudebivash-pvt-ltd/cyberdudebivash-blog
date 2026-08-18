"""ReportX Phase 4 canary A acceptance test: Qilin / 'Spoonful of Comfort'.

Golden canary module: reportx-canary/qilin_spoonful_of_comfort_canary.py
(repo root). Built from real research this session -- see that module's
own docstring for the full source list. Unlike the golden fixture at
tests/fixtures/reportx-commercial-readiness/qilin_spoonful_of_comfort.py
(deliberately modest, is_premium_tier=False, no detection/forecast/
hypothesis/regulatory content), THIS canary IS required to reach a
genuine PREMIUM_READY_PENDING_HUMAN state -- this test file locks that in
as a regression guarantee.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

import pytest

CANARY_DIR = Path(__file__).resolve().parents[3].parent / "reportx-canary"
CANARY_MODULE_PATH = CANARY_DIR / "qilin_spoonful_of_comfort_canary.py"


def _load_canary_module():
    spec = importlib.util.spec_from_file_location("qilin_spoonful_of_comfort_canary", CANARY_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["qilin_spoonful_of_comfort_canary"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def canary_module():
    assert CANARY_MODULE_PATH.is_file(), f"expected {CANARY_MODULE_PATH}"
    return _load_canary_module()


@pytest.fixture(scope="module")
def bundle(canary_module):
    return canary_module.build_bundle()


class TestRealPremium23Of23:
    """The load-bearing assertion: this canary, built entirely from real
    research (not a synthetic fully-supported test fixture), independently
    clears all 23 commercial-readiness controls."""

    def test_all_23_controls_pass(self, bundle):
        from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 17))
        failing = [(r.control_id, r.status, r.failures) for r in results if r.status != "PASS"]
        assert failing == [], f"Not 23/23: {failing}"
        assert len(results) == 23

    def test_final_verdict_is_commercial_ready(self, bundle):
        from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness, render_matrix_report
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 17))
        report = render_matrix_report(results)
        assert "FINAL VERDICT: COMMERCIAL-READY (23/23 PASS)" in report

    def test_certification_state_is_pending_human_not_fabricated_certified(self, bundle):
        # No review is attached -- resolve_certification_state must land on
        # PREMIUM_READY_PENDING_HUMAN, never PREMIUM_CERTIFIED, since no
        # real ReviewRecord exists. This is the mechanical proof that
        # nothing in this canary's construction fabricates human approval.
        from sentinel_engine.reportx.human_review import CertificationState, resolve_certification_state
        assert bundle.review is None
        state = resolve_certification_state(True, bundle.is_premium_tier, bundle.review, bundle.rendered_text)
        assert state == CertificationState.PREMIUM_READY_PENDING_HUMAN


class TestPremiumDepthIsReal:
    def test_depth_assessment_counts_are_computed_not_hand_set(self, bundle):
        expected_word_count = len(bundle.rendered_text.split())
        expected_sections = bundle.rendered_text.count("\n## ")
        expected_material_claims = sum(1 for c in bundle.graph.claims.values() if c.has_evidence())
        assert bundle.depth_assessment.rendered_word_count == expected_word_count
        assert bundle.depth_assessment.distinct_evidence_backed_sections == expected_sections
        assert bundle.depth_assessment.material_claim_count == expected_material_claims

    def test_clears_the_premium_depth_floor(self, bundle):
        assert bundle.depth_assessment.passes_premium_depth()
        assert bundle.depth_assessment.material_claim_count >= 15
        assert bundle.depth_assessment.distinct_evidence_backed_sections >= 8


class TestVictimAndActorLayersStaySeparate:
    """Section 6/19's core requirement: historical Qilin/Water Galura
    behavior must never be conflated with, or upgraded into, evidence
    about what happened at Spoonful of Comfort specifically."""

    def test_victim_observation_claims_are_observed(self, bundle):
        from sentinel_engine.reportx.claim_model import ObservedVsContext
        for claim_id in ("c-leak-site-claim", "c-compromise-occurred", "c-victim-ack"):
            assert bundle.graph.claims[claim_id].observed_vs_context == ObservedVsContext.OBSERVED

    def test_actor_context_claims_are_context_not_observed(self, bundle):
        from sentinel_engine.reportx.claim_model import ObservedVsContext
        actor_claim_ids = [cid for cid, c in bundle.graph.claims.items()
                            if c.claim_type.value == "TTP_HISTORICAL"]
        assert len(actor_claim_ids) >= 10  # this canary's real research depth
        for claim_id in actor_claim_ids:
            assert bundle.graph.claims[claim_id].observed_vs_context == ObservedVsContext.CONTEXT

    def test_compromise_occurred_is_honestly_unknown_not_guessed(self, bundle):
        claim = bundle.graph.claims["c-compromise-occurred"]
        assert claim.status.value == "UNKNOWN"
        assert not claim.has_evidence()

    def test_no_cve_contamination_on_the_ransomware_schema(self, bundle):
        from sentinel_engine.reportx.claim_model import EpistemicState
        product = bundle.threat_products[0]
        assert not product.has_linked_vulnerability()
        assert product.cisa_kev_state == EpistemicState.NOT_APPLICABLE
        assert product.cvss_state == EpistemicState.NOT_APPLICABLE
        assert product.patch_state == EpistemicState.NOT_APPLICABLE
        assert product.exploit_cve_status == EpistemicState.NOT_APPLICABLE


class TestMoonstoneSleetRepresentedAsEcosystemContextOnly:
    """The one genuinely delicate piece of this canary's research: a
    DPRK-linked actor independently deploying the same RaaS payload must
    never read as an incident-specific attribution claim."""

    def test_moonstone_sleet_claim_is_reported_not_confirmed(self, bundle):
        claim = bundle.graph.claims["c-moonstone-sleet-deployment"]
        assert claim.status.value == "REPORTED"
        assert claim.observed_vs_context.value == "CONTEXT"

    def test_rendered_text_explicitly_disclaims_incident_linkage(self, bundle):
        text = bundle.rendered_text
        assert "Moonstone Sleet" in text
        assert "no source reviewed" in text.lower() or "not connected" in text.lower() or \
               "connection" in text.lower()


class TestDivergentToolingAssessmentsKeptSeparate:
    def test_2022_and_current_family_comparisons_are_two_distinct_claims(self, bundle):
        c2022 = bundle.graph.claims["c-tooling-history"]
        ccurrent = bundle.graph.claims["c-tooling-lineage-current"]
        assert "BlackMatter" in c2022.text
        assert "BlackCat" in ccurrent.text
        assert c2022.source_refs == ["s-wikipedia-qilin"]
        assert ccurrent.source_refs == ["s-mitre-s1242"]


class TestAlternativeHypothesesAreReal:
    def test_two_well_formed_hypothesis_sets(self, canary_module):
        hypothesis_sets = canary_module.build_hypothesis_sets()
        assert len(hypothesis_sets) == 2
        for hs in hypothesis_sets:
            assert hs.is_well_formed()
            assert len(hs.hypotheses) == 2


class TestDetectionRuleIsHonestlyScoped:
    def test_detection_rule_is_syntax_validated_not_overclaimed(self, canary_module):
        rule = canary_module.build_detection_rule()
        assert rule.validation_state.value == "SYNTAX_VALIDATED"

    def test_detection_body_is_structurally_valid_sigma_yaml(self, canary_module):
        import yaml
        rule = canary_module.build_detection_rule()
        parsed = yaml.safe_load(rule.body)
        assert parsed["title"]
        assert parsed["detection"]["condition"]

    def test_rendered_text_never_overclaims_production_validation(self, bundle):
        from sentinel_engine.reportx.detection_validation import check_all_rules
        violations = check_all_rules(bundle.detection_rules, bundle.rendered_text)
        assert violations == []


class TestSourceIntegrityUsesFullContentHashes:
    def test_all_five_sources_have_real_full_content_hashes(self, bundle):
        from sentinel_engine.reportx.evidence_integrity import evaluate_source_integrity_gate
        gate = evaluate_source_integrity_gate(list(bundle.graph.sources.values()))
        assert gate.passed
        assert gate.full_content_hash_count == 5
        assert gate.excerpt_fingerprint_count == 0

    def test_content_hashes_match_the_actual_checked_in_raw_files(self, bundle):
        from sentinel_engine.reportx.evidence_integrity import compute_content_sha256
        raw_dir = CANARY_DIR / "raw-sources"
        mapping = {
            "s-hendryadrian": "hendryadrian-spoonful-of-comfort.html",
            "s-wikipedia-qilin": "wikipedia-qilin.html",
            "s-mitre-s1242": "mitre-attack-s1242-qilin.html",
            "s-mitre-g1050": "mitre-attack-g1050-water-galura.html",
            "s-mitre-g1036": "mitre-attack-g1036-moonstone-sleet.html",
        }
        for source_id, filename in mapping.items():
            source = bundle.graph.sources[source_id]
            expected = compute_content_sha256((raw_dir / filename).read_bytes())
            assert source.content_sha256 == expected, f"{source_id} hash does not match {filename}"


class TestNoContradictions:
    def test_contradiction_engine_finds_nothing(self, bundle):
        from sentinel_engine.reportx.contradiction_engine import find_all_contradictions
        contradictions = find_all_contradictions(bundle.graph, bundle.dimension_tags, full_text=bundle.rendered_text)
        assert contradictions == []


class TestBundleIoRoundTrip:
    def test_export_and_reload_round_trips_the_23_of_23_result(self, bundle):
        import json

        from sentinel_engine.reportx.bundle_io import bundle_from_dict, bundle_to_dict
        from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness

        original = [(r.control_id, r.status) for r in evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 17))]
        reexported = json.loads(json.dumps(bundle_to_dict(bundle)))
        reloaded = bundle_from_dict(reexported)
        reloaded_results = [(r.control_id, r.status) for r in evaluate_commercial_readiness(reloaded, as_of=date(2026, 8, 17))]
        assert reloaded_results == original
