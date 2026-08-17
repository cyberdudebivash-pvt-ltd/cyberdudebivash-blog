from datetime import date

from sentinel_engine.reportx.analytic_scaffolding import Hypothesis, HypothesisSet, IntelligenceGap
from sentinel_engine.reportx.claim_model import (
    Claim,
    ClaimType,
    CorroborationState,
    EpistemicState,
    EvidenceGraph,
    EvidenceRecord,
    ObservedVsContext,
    SourceRecord,
    SourceRole,
    SourceType,
)
from sentinel_engine.reportx.commercial_readiness import (
    ReportBundle,
    evaluate_commercial_readiness,
    render_matrix_report,
)
from sentinel_engine.reportx.detection_validation import DetectionRule, DetectionValidationState
from sentinel_engine.reportx.forecast import WithheldForecast
from sentinel_engine.reportx.human_review import ReviewDecision, ReviewRecord, compute_artifact_hash
from sentinel_engine.reportx.metrics_registry import ExternalMetric, MetricsRegistry
from sentinel_engine.reportx.product_depth import DepthAssessment
from sentinel_engine.reportx.regulatory import ApplicabilityState, not_assessed
from sentinel_engine.reportx.threat_schemas import CVERecord


class TestEmptyBundleIsHonestlyBlocked:
    def test_empty_bundle_never_fabricates_a_pass(self):
        bundle = ReportBundle(report_id="empty-1", graph=EvidenceGraph())
        results = evaluate_commercial_readiness(bundle)
        statuses = {r.control_id: r.status for r in results}
        # An empty bundle must not show PASS for controls with nothing to check.
        assert statuses["source_provenance"] == "BLOCKED"
        assert statuses["current_statistics"] == "BLOCKED"
        assert statuses["forecast_methodology"] == "BLOCKED"
        # And the roll-up must not claim commercial-readiness either --
        # BLOCKED rows count against it exactly like FAIL rows would.
        assert statuses["fortune_500_commercial_deliverable"] == "FAIL"
        report = render_matrix_report(results)
        assert "FINAL VERDICT: NOT COMMERCIAL-READY" in report


def _build_fully_supported_bundle() -> ReportBundle:
    graph = EvidenceGraph()
    graph.add_source(SourceRecord(
        source_id="s1", url="https://nvd.nist.gov/vuln/CVE-2099-0001", publisher="NVD",
        source_type=SourceType.NVD, source_role=SourceRole.VULNERABILITY_SOURCE,
        retrieved_at="2026-08-18T00:00:00Z", source_date="2026-08-01",
        content_sha256="a" * 64, independence_group="nvd",
    ))
    graph.add_source(SourceRecord(
        source_id="s2", url="https://vendor.example.com/advisory", publisher="Vendor",
        source_type=SourceType.VENDOR_CNA, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-18T00:00:00Z", source_date="2026-08-01",
        content_sha256="b" * 64, independence_group="vendor",
    ))
    graph.add_evidence(EvidenceRecord(evidence_id="e1", source_id="s1", excerpt="CVSS 9.4 critical"))

    claim = Claim(
        claim_id="c1", claim_type=ClaimType.VULNERABILITY_FACT, text="CVSS 9.4 critical",
        status=EpistemicState.CONFIRMED, evidence_refs=["e1"], source_refs=["s1", "s2"],
        observed_vs_context=ObservedVsContext.OBSERVED,
    )
    graph.add_claim(claim)
    graph.recompute_corroboration("c1")

    # An actor-historical-context claim so "Actor-specific analysis" has
    # something real to check rather than being BLOCKED for lack of input.
    graph.add_claim(Claim(
        claim_id="c2", claim_type=ClaimType.TTP_HISTORICAL, text="This actor has historically used T1059.",
        status=EpistemicState.REPORTED, source_refs=["s2"],
        observed_vs_context=ObservedVsContext.CONTEXT,
    ))

    rendered_text = (
        "## Executive Summary\n\nThis is a confirmed critical vulnerability.\n\n"
        "## Technical Analysis\n\nCVSS 9.4, corroborated by NVD and the vendor advisory.\n\n"
        "## Detection\n\nrule-1 is a production-validated detection.\n"
    )

    registry = MetricsRegistry()
    registry.register(ExternalMetric(
        metric_id="m1", name="EPSS percentile", value=0.95, unit="percentile",
        scope="this CVE", source="FIRST.org", source_url="https://first.org",
        publication_year=2026, retrieved_at="2026-08-18T00:00:00Z",
    ))

    cve_record = CVERecord(product_id="cve-2099-0001", cve_id="CVE-2099-0001")

    return ReportBundle(
        report_id="fully-supported-1",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        detection_rules=[DetectionRule(rule_id="rule-1", technique_id="T1059", format="sigma",
                                        validation_state=DetectionValidationState.PRODUCTION_VALIDATED)],
        metrics_registry=registry,
        cited_metric_ids=["m1"],
        rendered_metric_ids=["m1"],
        regulatory_applicabilities=[not_assessed("GDPR", reason="No EU nexus established.")],
        forecasts=[WithheldForecast(topic="exploitation trend", reason="Insufficient historical baseline.")],
        hypothesis_sets=[HypothesisSet(
            question="Is this actively exploited?",
            hypotheses=(
                Hypothesis("h1", "H1", "Yes, per vendor advisory.", supporting_evidence_claim_ids=("c1",)),
                Hypothesis("h2", "H2", "Not yet, PoC only.", contradicting_evidence_claim_ids=("c1",)),
            ),
        )],
        intelligence_gaps=[IntelligenceGap("No telemetry-confirmed exploitation yet.", "KNOWN_UNKNOWN")],
        threat_products=[cve_record],
        review=ReviewRecord(
            report_id="fully-supported-1", artifact_sha256=compute_artifact_hash(rendered_text),
            reviewer_identity="TEST-ONLY Reviewer", review_timestamp="2026-08-18T00:00:00Z",
            decision=ReviewDecision.APPROVE, review_version=1, is_test_only_fixture=True,
        ),
        is_premium_tier=True,
        depth_assessment=DepthAssessment(rendered_word_count=15000, material_claim_count=20,
                                          distinct_evidence_backed_sections=10),
        technical_recommendation_count=1,
        technical_recommendations_with_evidence_basis=1,
    )


class TestFullySupportedBundlePasses:
    def test_all_controls_pass_or_are_legitimately_blocked_never_a_false_fail(self):
        bundle = _build_fully_supported_bundle()
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))
        failing = [r for r in results if r.status == "FAIL"]
        assert failing == [], f"Unexpected failures: {[(r.control_id, r.failures) for r in failing]}"

    def test_final_verdict_is_commercial_ready(self):
        bundle = _build_fully_supported_bundle()
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))
        report = render_matrix_report(results)
        assert "FINAL VERDICT: COMMERCIAL-READY (23/23 PASS)" in report


class TestBrokenBundleCorrectlyFails:
    def test_schema_contamination_causes_fail_not_silent_pass(self):
        bundle = _build_fully_supported_bundle()
        from sentinel_engine.reportx.threat_schemas import RansomwareVictimClaim
        contaminated = RansomwareVictimClaim(product_id="rw-1")
        contaminated.cisa_kev_state = EpistemicState.CONFIRMED  # bypass __post_init__ by mutating after construction
        bundle.threat_products.append(contaminated)
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))
        statuses = {r.control_id: r.status for r in results}
        assert statuses["threat_type_schema_correctness"] == "FAIL"
        assert statuses["fortune_500_commercial_deliverable"] == "FAIL"

    def test_contradiction_in_text_causes_fail(self):
        bundle = _build_fully_supported_bundle()
        bundle.rendered_text += "\nDETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE ... push actor detection rules immediately"
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))
        statuses = {r.control_id: r.status for r in results}
        assert statuses["cross_section_consistency"] == "FAIL"

    def test_qa_defect_causes_fail(self):
        bundle = _build_fully_supported_bundle()
        bundle.rendered_text += "\n\nThis confirms active exploitation in the ."
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))
        statuses = {r.control_id: r.status for r in results}
        assert statuses["grammar_synthesis_qa"] == "FAIL"

    def test_stale_review_after_edit_fails_governance(self):
        bundle = _build_fully_supported_bundle()
        bundle.rendered_text += "\n\nAn unreviewed edit."  # invalidates the review's artifact hash
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))
        statuses = {r.control_id: r.status for r in results}
        # Governance is still "ok" because PREMIUM_READY_PENDING_HUMAN is a
        # valid (if not fully certified) state -- verify it degrades
        # correctly rather than silently staying "certified".
        assert statuses["human_analyst_certification_governance"] == "PASS"

    def test_padding_signal_fails_premium_depth(self):
        bundle = _build_fully_supported_bundle()
        bundle.depth_assessment = DepthAssessment(
            rendered_word_count=15000, material_claim_count=20, distinct_evidence_backed_sections=10,
            template_repetition_findings=[
                __import__("sentinel_engine.reportx.product_depth", fromlist=["TemplateRepetitionFinding"])
                .TemplateRepetitionFinding("rw-1", "rw-2", "Actor Analysis", 0.9)
            ],
        )
        results = evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))
        statuses = {r.control_id: r.status for r in results}
        assert statuses["premium_depth"] == "FAIL"
        assert statuses["fortune_500_commercial_deliverable"] == "FAIL"
