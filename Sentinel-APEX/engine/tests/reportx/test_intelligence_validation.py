"""Tests for sentinel_engine.reportx.intelligence_validation -- the Phase 3
Intelligence Validation Framework: a 20-dimension numeric scorecard layered
on top of the already-tested commercial_readiness.py / qms.py / qa_linter.py
/ product_depth.py / attack_mapper.py machinery, never a second evidence
judgment.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from automation.config import Config
from automation.content_discovery import DiscoveredArticle

from sentinel_engine.reportx.claim_model import (
    Claim,
    ClaimType,
    CorroborationState,
    EpistemicState,
    EvidenceGraph,
    EvidenceRecord,
    ObservedVsContext,
    Reliability,
    SourceRecord,
    SourceRole,
    SourceType,
)
from sentinel_engine.reportx.commercial_readiness import ControlResult, ReportBundle, evaluate_commercial_readiness
from sentinel_engine.reportx.detection_validation import DetectionRule, DetectionValidationState
from sentinel_engine.reportx.executive_products import HuntHypothesis, RoleAudience, RoleDecision, SectorApplicability, SectorImpact
from sentinel_engine.reportx.forecast import Forecast, WithheldForecast
from sentinel_engine.reportx.intelligence_validation import (
    WEIGHTS,
    DimensionScore,
    IntelligenceScorecard,
    SupplementalEvidence,
    ValidationDimension,
    ValidationThresholds,
    evaluate_from_export,
    evaluate_intelligence_validation,
    render_scorecard_markdown,
)
from sentinel_engine.reportx.pipeline_composer import compose_report
from sentinel_engine.reportx.product_depth import DepthAssessment, TemplateRepetitionFinding
from sentinel_engine.reportx.qms import QMS_CONTROL_MAP, QMSCategory
from sentinel_engine.reportx.regulatory import ApplicabilityState, RegulatoryApplicability
from sentinel_engine.reportx.tier_downgrade import PREMIUM_COMPLETENESS_CONTROLS

CONFIG = Config()

# Verbatim from the Phase 3 mandate's own dimension list, independent of the
# module's own enum, so a rename in the enum can't silently pass this test
# (mirrors test_qms.py::TestCategoryFidelityToTheMandate).
_MANDATE_DIMENSION_NAMES = (
    "Evidence Traceability", "Source Reliability", "Information Credibility", "Confidence Discipline",
    "Analytical Reasoning", "Business Context", "Technical Accuracy", "Operational Guidance",
    "Executive Decision Support", "Detection Engineering", "Threat Hunting Guidance",
    "MITRE ATT&CK Justification", "Forecast Quality", "Writing Quality", "Consistency",
    "Editorial Quality", "Duplicate Detection", "Unsupported Claims", "Analytical Completeness",
    "Production Readiness",
)


def _cve_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-77777",
        title="CVE-2026-77777 test vulnerability",
        summary="A test vulnerability allows remote code execution via crafted OS command injection in a "
                "web-facing administrative endpoint.",
        published_at="2026-08-17T11:16:44Z", content_hash="fadedcab", labels=["Vulnerabilities"], source="nvd",
        cve_id="CVE-2026-77777", cvss_score=9.1, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-78"], kev_listed=False,
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _controls(*pairs: tuple[str, str]) -> list[ControlResult]:
    """One synthetic ControlResult per (control_id, status) pair -- mirrors
    test_qms.py::TestFailurePropagation's own synthetic-fixture style."""
    return [
        ControlResult(cid, cid, status, "synthetic fixture",
                      failures=([f"{cid} synthetically failed"] if status == "FAIL" else []))
        for cid, status in pairs
    ]


def _empty_bundle(**overrides) -> ReportBundle:
    defaults = dict(report_id="rb-synthetic", graph=EvidenceGraph())
    defaults.update(overrides)
    return ReportBundle(**defaults)


class TestDimensionFidelityToPhase3Mandate:
    def test_every_mandate_dimension_name_is_represented_exactly_once(self):
        enum_values = [d.value for d in ValidationDimension]
        assert sorted(enum_values) == sorted(_MANDATE_DIMENSION_NAMES)
        assert len(enum_values) == len(set(enum_values)) == 20


class TestWeights:
    def test_weights_sum_to_one_and_cover_every_dimension(self):
        assert set(WEIGHTS) == set(ValidationDimension)
        assert round(sum(WEIGHTS.values()), 6) == 1.0

    def test_every_weight_is_positive(self):
        assert all(w > 0 for w in WEIGHTS.values())


class TestSharedControlReuseIsGenuine:
    """Several dimensions must reuse qms.QMS_CONTROL_MAP's own tuples
    directly rather than re-typing a duplicate list that could silently
    drift from the QMS category it mirrors (Single Source of Truth)."""

    def test_technical_accuracy_reuses_qms_control_map(self):
        bundle = _empty_bundle()
        results = _controls(("threat_type_schema_correctness", "PASS"))
        card = evaluate_intelligence_validation(bundle, results)
        d = card.dimension(ValidationDimension.TECHNICAL_ACCURACY)
        assert set(d.contributing_control_ids) == set(QMS_CONTROL_MAP[QMSCategory.TECHNICAL_ACCURACY])

    def test_unsupported_claims_reuses_qms_control_map(self):
        bundle = _empty_bundle()
        card = evaluate_intelligence_validation(bundle, [])
        d = card.dimension(ValidationDimension.UNSUPPORTED_CLAIMS)
        assert set(d.contributing_control_ids) == set(QMS_CONTROL_MAP[QMSCategory.NO_UNSUPPORTED_CLAIMS])

    def test_consistency_reuses_qms_control_map(self):
        bundle = _empty_bundle()
        card = evaluate_intelligence_validation(bundle, [])
        d = card.dimension(ValidationDimension.CONSISTENCY)
        assert set(d.contributing_control_ids) == set(QMS_CONTROL_MAP[QMSCategory.CONSISTENCY])

    def test_analytical_completeness_reuses_tier_downgrade_frozenset(self):
        bundle = _empty_bundle()
        card = evaluate_intelligence_validation(bundle, [])
        d = card.dimension(ValidationDimension.ANALYTICAL_COMPLETENESS)
        assert set(d.contributing_control_ids) == set(PREMIUM_COMPLETENESS_CONTROLS)


class TestBinaryDimensionFailurePropagation:
    def test_a_failed_contributing_control_fails_its_dimension(self):
        bundle = _empty_bundle()
        results = _controls(("cross_section_consistency", "FAIL"))
        card = evaluate_intelligence_validation(bundle, results)
        d = card.dimension(ValidationDimension.CONSISTENCY)
        assert d.status == "FAIL"
        assert d.score is not None and d.score < 100

    def test_all_blocked_contributing_controls_block_the_dimension(self):
        bundle = _empty_bundle()
        results = _controls(("cross_section_consistency", "BLOCKED"))
        card = evaluate_intelligence_validation(bundle, results)
        assert card.dimension(ValidationDimension.CONSISTENCY).status == "BLOCKED"

    def test_no_contributing_controls_present_blocks_the_dimension(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        assert card.dimension(ValidationDimension.CONSISTENCY).status == "BLOCKED"

    def test_a_fail_never_reads_as_pass_even_with_partial_credit(self):
        # 2/3 controls PASS is a real 67-ish score, but ANY fail in a
        # correctness-derived dimension must still gate FAIL -- never let a
        # numeric average launder a known defect into an apparent PASS.
        bundle = _empty_bundle()
        results = _controls(
            ("threat_type_schema_correctness", "PASS"),
            ("temporal_integrity", "PASS"),
            ("detection_evidence_discipline", "FAIL"),
        )
        card = evaluate_intelligence_validation(bundle, results)
        d = card.dimension(ValidationDimension.TECHNICAL_ACCURACY)
        assert d.status == "FAIL"
        assert 0 < d.score < 100


class TestSourceReliability:
    def _graph_with_source(self, reliability: Reliability, cited: bool) -> EvidenceGraph:
        graph = EvidenceGraph()
        graph.add_source(SourceRecord(
            source_id="s1", url="https://example.test/a", publisher="Example",
            source_type=SourceType.OTHER, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
            retrieved_at="2026-08-18T00:00:00Z", reliability=reliability,
        ))
        if cited:
            graph.add_claim(Claim(
                claim_id="c1", claim_type=ClaimType.VULNERABILITY_FACT, text="x",
                status=EpistemicState.REPORTED, source_refs=["s1"],
            ))
        return graph

    def test_blocked_when_no_source_is_cited_by_any_claim(self):
        bundle = _empty_bundle(graph=self._graph_with_source(Reliability.HIGH, cited=False))
        card = evaluate_intelligence_validation(bundle, [])
        assert card.dimension(ValidationDimension.SOURCE_RELIABILITY).status == "BLOCKED"

    def test_high_reliability_scores_above_low_reliability(self):
        high_bundle = _empty_bundle(graph=self._graph_with_source(Reliability.HIGH, cited=True))
        low_bundle = _empty_bundle(graph=self._graph_with_source(Reliability.LOW, cited=True))
        high_score = evaluate_intelligence_validation(high_bundle, []).dimension(ValidationDimension.SOURCE_RELIABILITY).score
        low_score = evaluate_intelligence_validation(low_bundle, []).dimension(ValidationDimension.SOURCE_RELIABILITY).score
        assert high_score > low_score


class TestInformationCredibility:
    def _graph_with_claim(self, status: EpistemicState, corroboration: CorroborationState) -> EvidenceGraph:
        graph = EvidenceGraph()
        claim = Claim(claim_id="c1", claim_type=ClaimType.VULNERABILITY_FACT, text="x", status=status)
        claim.corroboration_state = corroboration
        graph.claims["c1"] = claim
        return graph

    def test_blocked_when_no_assertive_state_claims(self):
        graph = self._graph_with_claim(EpistemicState.NOT_ASSESSED, CorroborationState.UNCORROBORATED)
        card = evaluate_intelligence_validation(_empty_bundle(graph=graph), [])
        assert card.dimension(ValidationDimension.INFORMATION_CREDIBILITY).status == "BLOCKED"

    def test_confirmed_and_independently_corroborated_outranks_reported_uncorroborated(self):
        strong = self._graph_with_claim(EpistemicState.CONFIRMED, CorroborationState.MULTI_SOURCE_INDEPENDENT)
        weak = self._graph_with_claim(EpistemicState.REPORTED, CorroborationState.UNCORROBORATED)
        strong_score = evaluate_intelligence_validation(_empty_bundle(graph=strong), []).dimension(
            ValidationDimension.INFORMATION_CREDIBILITY).score
        weak_score = evaluate_intelligence_validation(_empty_bundle(graph=weak), []).dimension(
            ValidationDimension.INFORMATION_CREDIBILITY).score
        assert strong_score > weak_score

    def test_disputed_claims_score_lower_than_confirmed(self):
        disputed = self._graph_with_claim(EpistemicState.DISPUTED, CorroborationState.UNCORROBORATED)
        confirmed = self._graph_with_claim(EpistemicState.CONFIRMED, CorroborationState.MULTI_SOURCE_INDEPENDENT)
        disputed_score = evaluate_intelligence_validation(_empty_bundle(graph=disputed), []).dimension(
            ValidationDimension.INFORMATION_CREDIBILITY).score
        confirmed_score = evaluate_intelligence_validation(_empty_bundle(graph=confirmed), []).dimension(
            ValidationDimension.INFORMATION_CREDIBILITY).score
        assert confirmed_score > disputed_score


class TestMitreAttackJustification:
    def test_blocked_when_no_technique_ids_cited(self):
        bundle = _empty_bundle()
        card = evaluate_intelligence_validation(bundle, [])
        assert card.dimension(ValidationDimension.MITRE_ATTACK_JUSTIFICATION).status == "BLOCKED"

    def test_invalid_technique_id_is_unjustified(self):
        bundle = _empty_bundle(
            rendered_text="This references T9999 somewhere in the prose.",
            detection_rules=[DetectionRule(rule_id="r1", technique_id="T9999", format="sigma",
                                            validation_state=DetectionValidationState.SYNTAX_VALIDATED, body="x")],
        )
        card = evaluate_intelligence_validation(bundle, [])
        d = card.dimension(ValidationDimension.MITRE_ATTACK_JUSTIFICATION)
        assert d.status == "FAIL"
        assert d.score == 0

    def test_valid_but_unevidenced_technique_id_is_unjustified(self):
        bundle = _empty_bundle(
            rendered_text="No mention of that technique anywhere in this report body.",
            detection_rules=[DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                                            validation_state=DetectionValidationState.SYNTAX_VALIDATED, body="x")],
        )
        card = evaluate_intelligence_validation(bundle, [])
        assert card.dimension(ValidationDimension.MITRE_ATTACK_JUSTIFICATION).status == "FAIL"

    def test_valid_and_evidenced_technique_id_is_justified(self):
        bundle = _empty_bundle(
            rendered_text="The observed activity is consistent with ransomware that encrypts files (T1486).",
            detection_rules=[DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                                            validation_state=DetectionValidationState.SYNTAX_VALIDATED, body="x")],
        )
        card = evaluate_intelligence_validation(bundle, [])
        d = card.dimension(ValidationDimension.MITRE_ATTACK_JUSTIFICATION)
        assert d.status == "PASS"
        assert d.score == 100

    def test_extracts_the_real_id_out_of_a_descriptive_composer_style_label(self):
        # Regression test for the real shape automation/report_renderer.py
        # actually produces: DetectionRule.technique_id is not always a bare
        # "Txxxx" string -- extract_technique_ids() must pull the ID out of
        # a full conditional-analytical-aid label either way.
        label = "Execution → Command and Scripting Interpreter (T1059), conditional on observed child-process execution."
        bundle = _empty_bundle(
            rendered_text=f"<div>{label}</div>",
            detection_rules=[DetectionRule(rule_id="r1", technique_id=label, format="sigma",
                                            validation_state=DetectionValidationState.SYNTAX_VALIDATED, body="x")],
        )
        card = evaluate_intelligence_validation(bundle, [])
        d = card.dimension(ValidationDimension.MITRE_ATTACK_JUSTIFICATION)
        assert d.status == "PASS"
        assert "T1059" in d.rationale or d.score == 100


class TestSupplementalEvidenceDrivenDimensions:
    def test_threat_hunting_guidance_blocked_when_no_hypotheses_supplied(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        assert card.dimension(ValidationDimension.THREAT_HUNTING_GUIDANCE).status == "BLOCKED"

    def test_threat_hunting_guidance_scores_complete_hypotheses_higher_than_incomplete(self):
        complete = HuntHypothesis(
            hypothesis_id="H1", statement="s", required_telemetry=("edr",), pivot_opportunities=("p",),
            expected_observations=("e",), negative_indicators=("n",), false_positive_considerations=("f",),
            validation_steps=("v",), success_criteria="done",
        )
        incomplete = HuntHypothesis(
            hypothesis_id="H2", statement="s", required_telemetry=(), pivot_opportunities=(),
            expected_observations=(), negative_indicators=(), false_positive_considerations=(),
            validation_steps=(), success_criteria="",
        )
        complete_card = evaluate_intelligence_validation(
            _empty_bundle(), [], supplemental=SupplementalEvidence(hunt_hypotheses=(complete,)))
        incomplete_card = evaluate_intelligence_validation(
            _empty_bundle(), [], supplemental=SupplementalEvidence(hunt_hypotheses=(incomplete,)))
        assert complete_card.dimension(ValidationDimension.THREAT_HUNTING_GUIDANCE).score == 100
        assert incomplete_card.dimension(ValidationDimension.THREAT_HUNTING_GUIDANCE).score == 0

    def test_executive_decision_support_blocked_without_role_decisions(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        assert card.dimension(ValidationDimension.EXECUTIVE_DECISION_SUPPORT).status == "BLOCKED"

    def test_executive_decision_support_rewards_evidence_grounded_decisions(self):
        grounded = RoleDecision(role=RoleAudience.CEO_BOARD, decision="d", rationale="r",
                                 evidence_claim_ids=("c1",))
        generic = RoleDecision(role=RoleAudience.CISO_CIO, decision="d", rationale="r", evidence_claim_ids=())
        card = evaluate_intelligence_validation(
            _empty_bundle(), [], supplemental=SupplementalEvidence(role_decisions=(grounded, generic)))
        d = card.dimension(ValidationDimension.EXECUTIVE_DECISION_SUPPORT)
        assert d.score == 50

    def test_business_context_blends_regulatory_control_and_sector_impact(self):
        results = _controls(("regulatory_specificity", "PASS"))
        assessed = SectorImpact(sector="Finance", applicability=SectorApplicability.ASSESSED, exposure_note="x")
        not_assessed = SectorImpact(sector="Energy", applicability=SectorApplicability.NOT_ASSESSED, exposure_note="x")
        card = evaluate_intelligence_validation(
            _empty_bundle(), results, supplemental=SupplementalEvidence(sector_impacts=(assessed, not_assessed)))
        d = card.dimension(ValidationDimension.BUSINESS_CONTEXT)
        assert d.status != "BLOCKED"
        assert 0 < d.score < 100

    def test_business_context_hard_fails_on_unsupported_regulatory_determination(self):
        results = _controls(("regulatory_specificity", "FAIL"))
        card = evaluate_intelligence_validation(_empty_bundle(), results)
        assert card.dimension(ValidationDimension.BUSINESS_CONTEXT).status == "FAIL"


class TestDetectionEngineering:
    def test_blocked_when_no_detection_rules(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        assert card.dimension(ValidationDimension.DETECTION_ENGINEERING).status == "BLOCKED"

    def test_validated_rules_score_higher_than_draft_rules(self):
        results = _controls(("detection_evidence_discipline", "PASS"))
        validated_bundle = _empty_bundle(detection_rules=[
            DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                          validation_state=DetectionValidationState.SYNTAX_VALIDATED, body="x"),
        ])
        draft_bundle = _empty_bundle(detection_rules=[
            DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                          validation_state=DetectionValidationState.DRAFT, body="x"),
        ])
        validated_score = evaluate_intelligence_validation(validated_bundle, results).dimension(
            ValidationDimension.DETECTION_ENGINEERING).score
        draft_score = evaluate_intelligence_validation(draft_bundle, results).dimension(
            ValidationDimension.DETECTION_ENGINEERING).score
        assert validated_score > draft_score


class TestForecastQuality:
    def test_blocked_when_no_forecasts(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        assert card.dimension(ValidationDimension.FORECAST_QUALITY).status == "BLOCKED"

    def test_withheld_forecast_gets_full_richness_credit(self):
        results = _controls(("forecast_methodology", "PASS"))
        bundle = _empty_bundle(forecasts=[WithheldForecast(topic="t", reason="insufficient evidence")])
        card = evaluate_intelligence_validation(bundle, results)
        assert card.dimension(ValidationDimension.FORECAST_QUALITY).score == 100

    def test_richer_forecast_scores_higher_than_minimally_adequate_one(self):
        results = _controls(("forecast_methodology", "PASS"))
        thin = Forecast(judgment="j", time_horizon="72h", supporting_observation_claim_ids=("c1",),
                         confidence="LOW", confidence_rationale="one weak signal")
        rich = Forecast(judgment="j", time_horizon="72h", supporting_observation_claim_ids=("c1",),
                         confidence="HIGH", confidence_rationale="multiple corroborated signals",
                         historical_baseline_claim_ids=("c2",), assumptions=("a",),
                         counter_evidence_claim_ids=("c3",), alternative_scenarios=("s",),
                         indicators_to_watch=("i",), what_would_change_assessment=("w",))
        thin_score = evaluate_intelligence_validation(_empty_bundle(forecasts=[thin]), results).dimension(
            ValidationDimension.FORECAST_QUALITY).score
        rich_score = evaluate_intelligence_validation(_empty_bundle(forecasts=[rich]), results).dimension(
            ValidationDimension.FORECAST_QUALITY).score
        assert rich_score > thin_score

    def test_a_fail_stays_a_fail_regardless_of_richness(self):
        results = _controls(("forecast_methodology", "FAIL"))
        bundle = _empty_bundle(forecasts=[Forecast(judgment="j", time_horizon="72h",
                                                     supporting_observation_claim_ids=(), confidence_rationale="")])
        card = evaluate_intelligence_validation(bundle, results)
        assert card.dimension(ValidationDimension.FORECAST_QUALITY).status == "FAIL"


class TestWritingEditorialAndDuplicateDetection:
    def test_blocked_dimensions_when_no_rendered_text(self):
        card = evaluate_intelligence_validation(_empty_bundle(rendered_text=""), [])
        assert card.dimension(ValidationDimension.WRITING_QUALITY).status == "BLOCKED"
        assert card.dimension(ValidationDimension.DUPLICATE_DETECTION).status == "BLOCKED"

    def test_writing_quality_penalizes_duplicate_paragraphs_not_editorial(self):
        paragraph = "This is a long enough paragraph to trigger the duplicate-paragraph QA check reliably."
        text = f"{paragraph}\n\n{paragraph}\n\nSome other unrelated closing sentence for the report body."
        results = _controls(("grammar_synthesis_qa", "PASS"))
        card = evaluate_intelligence_validation(_empty_bundle(rendered_text=text), results)
        assert card.dimension(ValidationDimension.WRITING_QUALITY).score < 100
        assert card.dimension(ValidationDimension.EDITORIAL_QUALITY).status == "PASS"

    def test_duplicate_detection_blocked_status_when_cross_report_not_checked(self):
        card = evaluate_intelligence_validation(_empty_bundle(rendered_text="Clean text with no repeats."), [])
        d = card.dimension(ValidationDimension.DUPLICATE_DETECTION)
        assert d.status == "BLOCKED"
        assert d.score is None  # never a number that isn't actually gate-authoritative

    def test_duplicate_detection_fails_when_cross_report_similarity_found(self):
        finding = TemplateRepetitionFinding(report_id_a="rb-synthetic", report_id_b="other", section_name="Forecast",
                                             similarity=0.95)
        card = evaluate_intelligence_validation(
            _empty_bundle(rendered_text="Clean text."), [],
            supplemental=SupplementalEvidence(cross_report_similarity_findings=(finding,)))
        assert card.dimension(ValidationDimension.DUPLICATE_DETECTION).status == "FAIL"

    def test_duplicate_detection_passes_when_cross_report_checked_and_clean(self):
        card = evaluate_intelligence_validation(
            _empty_bundle(rendered_text="Clean text."), [],
            supplemental=SupplementalEvidence(cross_report_similarity_findings=()))
        assert card.dimension(ValidationDimension.DUPLICATE_DETECTION).status == "PASS"


class TestScorecardAssembly:
    def test_coverage_reflects_fraction_of_non_blocked_dimensions(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        n_blocked = sum(1 for d in card.dimension_scores if d.status == "BLOCKED")
        assert card.coverage == round((20 - n_blocked) / 20, 10) or abs(card.coverage - (20 - n_blocked) / 20) < 1e-9

    def test_publication_ineligible_when_coverage_below_minimum(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        assert card.publication_eligible is False
        assert any("coverage" in r for r in card.blocking_reasons)

    def test_publication_ineligible_when_any_scored_dimension_fails(self):
        results = _controls(("cross_section_consistency", "FAIL"))
        thresholds = ValidationThresholds(minimum_coverage=0.0, overall_minimum=0)
        card = evaluate_intelligence_validation(_empty_bundle(), results, thresholds=thresholds)
        assert card.publication_eligible is False
        assert any(r.startswith("Consistency:") for r in card.blocking_reasons)

    def test_publication_eligible_when_everything_gated_passes_and_thresholds_are_lenient(self):
        results = _controls(("cross_section_consistency", "PASS"))
        thresholds = ValidationThresholds(minimum_coverage=0.0, overall_minimum=0)
        card = evaluate_intelligence_validation(_empty_bundle(), results, thresholds=thresholds)
        assert card.publication_eligible is True
        assert card.blocking_reasons == ()

    def test_custom_per_dimension_minimum_can_fail_an_otherwise_passing_dimension(self):
        results = _controls(("cross_section_consistency", "PASS"))
        strict = ValidationThresholds(minimum_coverage=0.0, overall_minimum=0,
                                       per_dimension_minimum={ValidationDimension.CONSISTENCY: 101})
        # 101 is unreachable (scores clamp at 100), so this dimension must FAIL
        # even though its underlying control PASSED -- proves the threshold
        # comparison genuinely runs, not just the hard_fail flag.
        card = evaluate_intelligence_validation(_empty_bundle(), results, thresholds=strict)
        assert card.dimension(ValidationDimension.CONSISTENCY).status == "FAIL"


class TestRenderAndSerialization:
    def test_markdown_includes_every_dimension_name_and_a_verdict(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        text = render_scorecard_markdown(card)
        for dimension in ValidationDimension:
            assert dimension.value in text
        assert "VERDICT" in text

    def test_to_dict_round_trips_through_json(self):
        card = evaluate_intelligence_validation(_empty_bundle(), [])
        serialized = json.dumps(card.to_dict())
        restored = json.loads(serialized)
        assert len(restored["dimension_scores"]) == 20
        assert restored["report_id"] == "rb-synthetic"


class TestIntegrationAgainstARealComposedReport:
    def test_scorecard_never_crashes_and_every_status_is_valid(self):
        composed = compose_report(_cve_article(), CONFIG)
        card = evaluate_intelligence_validation(composed.bundle, composed.control_results)
        assert len(card.dimension_scores) == 20
        for d in card.dimension_scores:
            assert d.status in ("PASS", "FAIL", "BLOCKED")
            if d.status == "BLOCKED":
                assert d.score is None
            else:
                assert d.score is not None and 0 <= d.score <= 100

    def test_scorecard_is_json_serializable_for_a_real_bundle(self):
        composed = compose_report(_cve_article(), CONFIG)
        card = evaluate_intelligence_validation(composed.bundle, composed.control_results)
        json.dumps(card.to_dict())  # must not raise

    def test_flash_tier_report_is_blocked_not_failed_on_premium_only_dimensions(self):
        # Round 6 fix: a routine FLASH-tier bundle was never asked to carry
        # premium-only completeness (30-40 page depth, the 22-control
        # Fortune-500 roll-up) -- commercial_readiness.py computes those
        # controls as a raw content fact regardless of tier, so scoring a
        # lean report against them is a tier-calibration mismatch, not a
        # real defect (the same distinction tier_downgrade.py already draws
        # for this exact control set). BLOCKED (not applicable at this
        # tier), never FAILED (a claimed defect this report doesn't have).
        composed = compose_report(_cve_article(), CONFIG)
        assert composed.bundle.is_premium_tier is False
        card = evaluate_intelligence_validation(composed.bundle, composed.control_results)
        assert card.dimension(ValidationDimension.ANALYTICAL_COMPLETENESS).status == "BLOCKED"
        assert card.dimension(ValidationDimension.PRODUCTION_READINESS).status == "BLOCKED"

    def test_non_premium_tier_report_is_blocked_not_failed_even_when_premium_controls_fail(self):
        # Direct unit-level regression for the Round 6 fix, independent of
        # the full compose_report() integration path above.
        bundle = _empty_bundle(is_premium_tier=False)
        results = _controls(("premium_depth", "FAIL"), ("fortune_500_commercial_deliverable", "FAIL"))
        card = evaluate_intelligence_validation(bundle, results)
        ac = card.dimension(ValidationDimension.ANALYTICAL_COMPLETENESS)
        pr = card.dimension(ValidationDimension.PRODUCTION_READINESS)
        assert ac.status == "BLOCKED" and ac.score is None
        assert pr.status == "BLOCKED" and pr.score is None

    def test_premium_tier_report_still_genuinely_fails_incomplete_premium_dimensions(self):
        # Tier-awareness must never launder an actual premium-dossier defect
        # into a no-op -- a report that IS targeting a premium tier keeps
        # the real, unchanged PASS/FAIL signal.
        bundle = _empty_bundle(is_premium_tier=True)
        results = _controls(("premium_depth", "FAIL"), ("fortune_500_commercial_deliverable", "FAIL"))
        card = evaluate_intelligence_validation(bundle, results)
        assert card.dimension(ValidationDimension.ANALYTICAL_COMPLETENESS).status == "FAIL"
        assert card.dimension(ValidationDimension.PRODUCTION_READINESS).status == "FAIL"

    def test_premium_tier_report_with_complete_premium_controls_passes(self):
        bundle = _empty_bundle(is_premium_tier=True)
        results = _controls(*[(cid, "PASS") for cid in PREMIUM_COMPLETENESS_CONTROLS],
                             ("fortune_500_commercial_deliverable", "PASS"))
        card = evaluate_intelligence_validation(bundle, results)
        assert card.dimension(ValidationDimension.ANALYTICAL_COMPLETENESS).status == "PASS"
        assert card.dimension(ValidationDimension.PRODUCTION_READINESS).status == "PASS"


class TestEvaluateFromExport:
    def test_round_trips_through_the_existing_export_artifact_shape(self):
        from sentinel_engine.reportx.bundle_io import export_report_json

        composed = compose_report(_cve_article(), CONFIG)
        export = export_report_json(composed.bundle)
        card = evaluate_from_export(export)
        assert card.report_id == composed.bundle.report_id
        assert len(card.dimension_scores) == 20
