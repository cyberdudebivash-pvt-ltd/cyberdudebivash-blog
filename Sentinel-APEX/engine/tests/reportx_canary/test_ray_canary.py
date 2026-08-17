"""ReportX Phase 4 canary D acceptance test: CVE-2025-62593 (Ray).

Golden canary module: reportx-canary/cve_2025_62593_ray_canary.py (repo
root). Built from real research this session -- see that module's own
docstring for the full source list. Unlike the golden fixtures under
tests/reportx/test_acceptance_*.py (which deliberately test specific
mechanisms and are not required to reach 23/23), this canary IS required
to reach a genuine PREMIUM_READY_PENDING_HUMAN state -- this test file
locks that in as a regression guarantee.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

import pytest

CANARY_DIR = Path(__file__).resolve().parents[3].parent / "reportx-canary"
CANARY_MODULE_PATH = CANARY_DIR / "cve_2025_62593_ray_canary.py"


def _load_canary_module():
    spec = importlib.util.spec_from_file_location("cve_2025_62593_ray_canary", CANARY_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["cve_2025_62593_ray_canary"] = module
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
    def test_depth_assessment_counts_are_computed_not_hand_set(self, canary_module, bundle):
        # Recomputes from the actual rendered text / graph and checks the
        # bundle's own depth_assessment matches -- catches drift if the
        # canary module is edited without recomputing.
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


class TestCorroborationPolicyAppliedHonestly:
    """The three high-impact claims that originally FAILED cross-source
    corroboration during construction (CISA SSVC, the RondoDox
    implementation-flaw finding, and the Uber business-impact quote) were
    fixed by downgrading to REPORTED, not by weakening the gate -- this
    class locks that in."""

    @pytest.mark.parametrize("claim_id", ["c-ssvc-active", "c-rondodox-implementation-flaw", "c-uber-user"])
    def test_single_sourced_high_impact_claims_stay_at_reported(self, bundle, claim_id):
        claim = bundle.graph.claims[claim_id]
        assert claim.is_high_impact()
        assert claim.corroboration_state.value == "SINGLE_SOURCE"
        assert claim.status.value == "REPORTED"
        assert not claim.requires_downgrade_without_corroboration()


class TestDivergentAuthoritativeScoresKeptSeparate:
    def test_ghsa_and_nvd_cvss_scores_are_two_distinct_claims(self, bundle):
        v4 = bundle.graph.claims["c-cvss-v4-ghsa"]
        v31 = bundle.graph.claims["c-cvss-v31-nvd"]
        assert "9.4" in v4.text
        assert "8.8" in v31.text
        assert v4.source_refs == ["s-ghsa"]
        assert v31.source_refs == ["s-nvd"]


class TestExploitationTensionIsNotResolvedByAssumption:
    def test_tension_claim_is_assessed_not_confirmed_either_direction(self, bundle):
        claim = bundle.graph.claims["c-exploitation-tension"]
        assert claim.status.value == "ASSESSED"
        assert set(claim.source_refs) == {"s-nvd", "s-bitsight"}

    def test_hypothesis_set_offers_two_real_alternatives(self, canary_module):
        hypothesis_sets = canary_module.build_hypothesis_sets()
        assert len(hypothesis_sets) == 1
        assert hypothesis_sets[0].is_well_formed()
        assert len(hypothesis_sets[0].hypotheses) == 2


class TestKevAndEpssAreBothRepresented:
    def test_kev_listing_is_confirmed_and_dated(self, bundle):
        claim = bundle.graph.claims["c-kev-listed"]
        assert claim.status.value == "CONFIRMED"
        assert "2026-08-17" in claim.text
        assert "2026-08-20" in claim.text

    def test_epss_score_is_a_real_cited_statistic(self, bundle):
        claim = bundle.graph.claims["c-epss-score"]
        assert claim.claim_type.value == "STATISTIC"
        assert "0.369%" in claim.text
        assert claim.source_refs == ["s-first-epss"]
        assert "m-epss" in bundle.cited_metric_ids


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


class TestSourceIntegrityUsesBothTiers:
    def test_six_sources_have_real_full_content_hashes(self, bundle):
        from sentinel_engine.reportx.evidence_integrity import evaluate_source_integrity_gate
        gate = evaluate_source_integrity_gate(list(bundle.graph.sources.values()))
        assert gate.passed
        assert gate.full_content_hash_count == 6

    def test_ghsa_source_uses_the_reasoned_excerpt_fallback(self, bundle):
        source = bundle.graph.sources["s-ghsa"]
        assert source.content_sha256 is None
        assert source.excerpt_fingerprint_sha256
        assert "403" in source.fingerprint_fallback_reason

    def test_content_hashes_match_the_actual_checked_in_raw_files(self, bundle):
        from sentinel_engine.reportx.evidence_integrity import compute_content_sha256
        raw_dir = CANARY_DIR / "raw-sources"
        mapping = {
            "s-nvd": "nvd-cve-2025-62593.json",
            "s-cisa-kev": "cisa-kev-cve-2025-62593-extraction.json",
            "s-first-epss": "first-epss-cve-2025-62593.json",
            "s-bitsight": "bitsight-rondodox.html",
            "s-pytorch-foundation": "pytorch-foundation-ray.html",
            "s-mitre-t1190": "mitre-attack-t1190.html",
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
