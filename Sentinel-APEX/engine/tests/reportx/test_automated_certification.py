"""Tests for sentinel_engine.reportx.automated_certification (P0
Release-Certification layer).

Uses a hand-built 23-row PASS control list for most scenarios (this
module's job is to react correctly to ControlResult data, not to
re-validate commercial_readiness.py's own row-by-row logic -- that's
test_commercial_readiness.py's job) and the real, certified release from
test_release_certification.py's fixtures where a genuinely-certified
release is needed as an input.
"""

from __future__ import annotations

import inspect
import json

import pytest

from sentinel_engine.reportx.automated_certification import (
    EscalationReason,
    certify_report_automated,
    collect_derivable_escalations,
    derive_detection_state_escalation,
    derive_source_integrity_escalation,
    render_automated_certification_block,
    render_human_reviewed_certification_block,
)
from sentinel_engine.reportx.commercial_readiness import ControlResult
from sentinel_engine.reportx.human_review import (
    CertificationState,
    ReviewDecision,
    ReviewRecord,
    compute_artifact_hash,
)
from sentinel_engine.reportx.release_certification import (
    REQUIRED_CANARY_IDS,
    CanaryCertificationInput,
    ReleaseState,
    SuiteResult,
    certify_release,
    default_repo_root,
)
from sentinel_engine.reportx.tier_downgrade import CORRECTNESS_CONTROLS, PREMIUM_COMPLETENESS_CONTROLS

# Deliberately self-contained (no cross-test-file import -- tests/reportx/
# has no __init__.py, so this repo's convention is each test file loads its
# own fixtures, same as test_reportx_review_cli.py's own FIXTURES_DIR).
_EXPORTS_DIR = default_repo_root() / "reportx-canary" / "exports"
_CANARY_EXPORT_FILES = {
    "qilin-spoonful-of-comfort-premium-canary": "qilin-spoonful-of-comfort-premium-canary-export.json",
    "medusalocker-bija-industrie-premium-canary": "medusalocker-bija-industrie-premium-canary-export.json",
    "dragonforce-vermont-xcenter-premium-canary": "dragonforce-vermont-xcenter-premium-canary-export.json",
    "cve-2025-62593-ray-canary": "cve-2025-62593-ray-canary-export.json",
}


def _load_export(canary_id: str) -> dict:
    with open(_EXPORTS_DIR / _CANARY_EXPORT_FILES[canary_id], encoding="utf-8") as fh:
        return json.load(fh)


def _canary_input(canary_id: str, *, approved: bool) -> CanaryCertificationInput:
    export = _load_export(canary_id)
    rendered_text = export["bundle"]["rendered_text"]
    cr = export["commercial_readiness"]
    review = None
    if approved:
        review = ReviewRecord(
            report_id=canary_id, artifact_sha256=compute_artifact_hash(rendered_text),
            reviewer_identity="TEST-ONLY Fixture Reviewer", review_timestamp="2026-08-18T00:00:00Z",
            decision=ReviewDecision.APPROVE, review_version=1, reviewer_role="TEST-ONLY",
            is_test_only_fixture=True,
        )
    return CanaryCertificationInput(
        canary_id=canary_id, artifact_sha256=compute_artifact_hash(rendered_text), rendered_text=rendered_text,
        commercial_readiness_pass_count=cr["pass_count"], commercial_readiness_total_count=cr["total_count"],
        review=review,
    )

ALL_CONTROL_IDS = [
    "source_provenance", "evidence_hash", "automated_review_disclosure", "source_specific_facts",
    "cross_source_corroboration", "threat_type_schema_correctness", "cross_section_consistency",
    "actor_specific_analysis", "victim_specific_analysis", "current_statistics", "regulatory_specificity",
    "technical_recommendations", "detection_evidence_discipline", "temporal_integrity", "grammar_synthesis_qa",
    "forecast_methodology", "evidence_ledger", "alternative_hypotheses", "intelligence_gaps",
    "report_specific_bibliography", "human_analyst_certification_governance", "premium_depth",
    "fortune_500_commercial_deliverable",
]
assert len(ALL_CONTROL_IDS) == 23


def _all_pass() -> list[ControlResult]:
    return [ControlResult(cid, cid, "PASS", "ok") for cid in ALL_CONTROL_IDS]


def _with_status(control_id: str, status: str) -> list[ControlResult]:
    return [
        ControlResult(cid, cid, status if cid == control_id else "PASS", "x", ["induced failure"] if cid == control_id and status != "PASS" else [])
        for cid in ALL_CONTROL_IDS
    ]


def _certified_release_manifest():
    canaries = [_canary_input(cid, approved=True) for cid in REQUIRED_CANARY_IDS]
    return certify_release(
        release_id="test-release-for-automated-cert", canaries=canaries,
        test_results=[SuiteResult("engine", 649, 0)],
        render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
        reviewer_identity="TEST-ONLY Release Operator",
    )


class TestCertifiedReleaseIssuesAutomatedCertification:
    """Section 17 test #4."""

    def test_23_of_23_under_certified_release_is_automated_certified(self):
        manifest = _certified_release_manifest()
        result = certify_report_automated("new-report", manifest, _all_pass())
        assert result.certification_state == CertificationState.PREMIUM_AUTOMATED_CERTIFIED
        assert result.is_automated_certified
        assert not result.refusal_reasons


class TestAutomatedCertificationNeverCreatesAReviewRecord:
    """Section 17 test #5 -- structural, not just behavioural."""

    def test_module_source_never_constructs_a_reviewrecord(self):
        import sentinel_engine.reportx.automated_certification as mod
        source = inspect.getsource(mod)
        assert "ReviewRecord(" not in source
        assert "import ReviewRecord" not in source and "ReviewRecord\n" not in source.split("\n\n")[0]

    def test_result_object_has_no_reviewrecord_field(self):
        from dataclasses import fields
        from sentinel_engine.reportx.automated_certification import AutomatedCertificationResult
        for f in fields(AutomatedCertificationResult):
            assert "review" not in f.name.lower() or f.type in (str, "str")

    def test_refused_and_certified_paths_alike_produce_no_reviewrecord(self):
        manifest = _certified_release_manifest()
        for control_results in (_all_pass(), _with_status("cross_section_consistency", "FAIL"), []):
            result = certify_report_automated("r", manifest, control_results)
            assert not hasattr(result, "review")
            assert not hasattr(result, "reviewer_identity")


class TestAutomatedReportNeverSaysHumanReviewed:
    """Section 17 test #6 -- the two rendered certification blocks."""

    def test_automated_block_never_contains_forbidden_phrases(self):
        block = render_automated_certification_block("report-1", "release-1", 23, 23)
        assert "NOT INDIVIDUALLY HUMAN REVIEWED" in block
        for forbidden in ("HUMAN REVIEWED\n", "ANALYST APPROVED", "APPROVED\n"):
            assert forbidden not in block
        assert "PREMIUM_CERTIFIED" not in block
        assert "AUTOMATED PREMIUM CERTIFIED" in block

    def test_human_reviewed_block_says_approved_with_reviewer_and_artifact(self):
        block = render_human_reviewed_certification_block(23, 23, "Bivash Nayak", "a" * 64)
        assert "APPROVED" in block
        assert "Bivash Nayak" in block
        assert "PREMIUM CERTIFIED" in block
        assert "NOT INDIVIDUALLY HUMAN REVIEWED" not in block

    def test_blocks_never_share_their_defining_language(self):
        automated = render_automated_certification_block("r", "rel", 23, 23)
        human = render_human_reviewed_certification_block(23, 23, "Someone", "b" * 64)
        assert "NOT INDIVIDUALLY HUMAN REVIEWED" not in human
        assert "Human Review:\nAPPROVED" not in automated


class Test22of23CannotReceiveAutomatedPremiumCertification:
    """Section 17 test #8."""

    def test_one_failed_control_refuses_automated_certification(self):
        manifest = _certified_release_manifest()
        results = _with_status("technical_recommendations", "FAIL")
        result = certify_report_automated("r", manifest, results)
        assert result.certification_state != CertificationState.PREMIUM_AUTOMATED_CERTIFIED
        assert result.commercial_readiness_pass_count == 22
        assert result.commercial_readiness_total_count == 23
        assert result.refusal_reasons


class TestContradictionForcesRefusalOrEscalation:
    """Section 17 test #9 -- cross_section_consistency is a correctness
    control (tier_downgrade.CORRECTNESS_CONTROLS), so a contradiction
    fail-closed-downgrades all the way to PUBLIC_REFERENCE_DRAFT, never to
    PREMIUM_AUTOMATED_CERTIFIED or any premium tier."""

    def test_contradiction_bottoms_out_at_public_reference_draft(self):
        assert "cross_section_consistency" in CORRECTNESS_CONTROLS
        manifest = _certified_release_manifest()
        results = _with_status("cross_section_consistency", "FAIL")
        result = certify_report_automated("r", manifest, results)
        assert result.certification_state == CertificationState.PUBLIC_REFERENCE_DRAFT
        assert result.certification_state != CertificationState.PREMIUM_AUTOMATED_CERTIFIED


class TestUnsupportedClaimForcesRefusalOrDowngrade:
    """Section 17 test #10 -- source_specific_facts / victim_specific_analysis
    (unsupported-claim controls) are also correctness controls."""

    @pytest.mark.parametrize("control_id", ["source_specific_facts", "victim_specific_analysis", "evidence_ledger"])
    def test_unsupported_claim_control_bottoms_out_at_public_reference_draft(self, control_id):
        assert control_id in CORRECTNESS_CONTROLS
        manifest = _certified_release_manifest()
        results = _with_status(control_id, "FAIL")
        result = certify_report_automated("r", manifest, results)
        assert result.certification_state == CertificationState.PUBLIC_REFERENCE_DRAFT


class TestHumanEscalationProducesPendingHuman:
    """Section 17 test #11."""

    def test_23_of_23_with_an_escalation_signal_is_pending_human_not_automated(self):
        manifest = _certified_release_manifest()
        result = certify_report_automated(
            "r", manifest, _all_pass(), escalation_reasons=[EscalationReason.CRITICAL_ATTRIBUTION],
        )
        assert result.certification_state == CertificationState.PREMIUM_READY_PENDING_HUMAN
        assert EscalationReason.CRITICAL_ATTRIBUTION in result.escalation_reasons
        assert result.certification_state != CertificationState.PREMIUM_AUTOMATED_CERTIFIED

    def test_multiple_escalation_reasons_are_all_preserved(self):
        manifest = _certified_release_manifest()
        reasons = [EscalationReason.CRITICAL_ATTRIBUTION, EscalationReason.EXTREME_SEVERITY]
        result = certify_report_automated("r", manifest, _all_pass(), escalation_reasons=reasons)
        assert set(result.escalation_reasons) == set(reasons)


class TestRefusalWhenReleaseNotCertified:
    def test_none_manifest_refuses(self):
        result = certify_report_automated("r", None, _all_pass())
        assert result.certification_state == CertificationState.PREMIUM_READY_PENDING_HUMAN
        assert result.release_id == ""
        assert result.refusal_reasons

    def test_not_certified_manifest_refuses(self):
        canaries = [_canary_input(cid, approved=False) for cid in REQUIRED_CANARY_IDS]
        manifest = certify_release(
            release_id="uncertified", canaries=canaries, test_results=[SuiteResult("engine", 649, 0)],
            render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
            reviewer_identity="TEST-ONLY",
        )
        assert manifest.release_decision != ReleaseState.REPORTX_RELEASE_CERTIFIED
        result = certify_report_automated("r", manifest, _all_pass())
        assert result.certification_state == CertificationState.PREMIUM_READY_PENDING_HUMAN


class TestDerivableEscalationSignals:
    def test_detection_state_promotion_is_derived_from_real_gate(self):
        from sentinel_engine.reportx.detection_validation import DetectionRule, DetectionValidationState
        rule = DetectionRule(rule_id="r1", technique_id="T1486", format="sigma",
                              validation_state=DetectionValidationState.SYNTAX_VALIDATED)
        clean_text = "This rule is syntax-validated."
        promoted_text = "This rule is production-validated and ready for immediate deployment."
        assert derive_detection_state_escalation([rule], clean_text) == []
        assert derive_detection_state_escalation([rule], promoted_text) == [EscalationReason.DETECTION_STATE_PROMOTION]

    def test_source_integrity_fallback_escalation_derived_from_real_gate(self):
        from sentinel_engine.reportx.claim_model import SourceRecord, SourceType, SourceRole
        sources_ok = [
            SourceRecord(source_id=f"s{i}", url=f"https://example.com/{i}", publisher="X",
                         source_type=SourceType.OTHER, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
                         retrieved_at="2026-08-18T00:00:00Z", content_sha256="a" * 64)
            for i in range(10)
        ]
        assert derive_source_integrity_escalation(sources_ok) == []

        mostly_fallback = [
            SourceRecord(source_id=f"s{i}", url=f"https://example.com/{i}", publisher="X",
                         source_type=SourceType.OTHER, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
                         retrieved_at="2026-08-18T00:00:00Z",
                         excerpt_fingerprint_sha256="b" * 64, fingerprint_fallback_reason="access-blocked")
            for i in range(10)
        ]
        assert derive_source_integrity_escalation(mostly_fallback) == [EscalationReason.SOURCE_INTEGRITY_FALLBACK_THRESHOLD]

    def test_collect_derivable_escalations_is_empty_for_clean_input(self):
        from sentinel_engine.reportx.claim_model import SourceRecord, SourceType, SourceRole
        sources = [SourceRecord(source_id="s1", url="https://example.com", publisher="X",
                                 source_type=SourceType.OTHER, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
                                 retrieved_at="2026-08-18T00:00:00Z", content_sha256="a" * 64)]
        reasons = collect_derivable_escalations("r", detection_rules=[], rendered_text="clean text", sources=sources)
        assert reasons == []
