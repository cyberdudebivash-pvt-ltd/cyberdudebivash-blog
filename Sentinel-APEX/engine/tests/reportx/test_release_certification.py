"""Tests for sentinel_engine.reportx.release_certification (P0
Release-Certification layer).

Every "canary" test here loads a REAL canary export artifact
(reportx-canary/exports/*.json, the same four this repo's own
REPORTX-CANARY-CERTIFICATION.md documents) rather than a synthetic bundle --
Section 17 test #1/#2/#3 are specifically about real-artifact behaviour.
Every ReviewRecord constructed in this file is explicitly marked
``is_test_only_fixture=True`` and uses a reviewer identity beginning
"TEST-ONLY" (same convention as test_reportx_review_cli.py) -- none of
these is, or is meant to look like, a real operator approval.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel_engine.reportx.human_review import (
    CertificationState,
    ReviewDecision,
    ReviewRecord,
    compute_artifact_hash,
    is_review_valid_for_artifact,
    resolve_certification_state,
)
from sentinel_engine.reportx.release_certification import (
    REQUIRED_CANARY_IDS,
    CanaryCertificationInput,
    ReleaseState,
    SuiteResult,
    apply_drift_check,
    certify_release,
    compute_component_hashes,
    default_repo_root,
    detect_drift,
    manifest_from_dict,
    render_release_report,
)

REPO_ROOT = default_repo_root()
EXPORTS_DIR = REPO_ROOT / "reportx-canary" / "exports"

CANARY_EXPORT_FILES = {
    "qilin-spoonful-of-comfort-premium-canary": "qilin-spoonful-of-comfort-premium-canary-export.json",
    "medusalocker-bija-industrie-premium-canary": "medusalocker-bija-industrie-premium-canary-export.json",
    "dragonforce-vermont-xcenter-premium-canary": "dragonforce-vermont-xcenter-premium-canary-export.json",
    "cve-2025-62593-ray-canary": "cve-2025-62593-ray-canary-export.json",
}


def _load_export(canary_id: str) -> dict:
    path = EXPORTS_DIR / CANARY_EXPORT_FILES[canary_id]
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _test_only_approve(canary_id: str, rendered_text: str, reviewer: str = "TEST-ONLY Fixture Reviewer") -> ReviewRecord:
    return ReviewRecord(
        report_id=canary_id, artifact_sha256=compute_artifact_hash(rendered_text),
        reviewer_identity=reviewer, review_timestamp="2026-08-18T00:00:00Z",
        decision=ReviewDecision.APPROVE, review_version=1, reviewer_role="TEST-ONLY",
        is_test_only_fixture=True,
    )


def _canary_input(canary_id: str, *, approved: bool) -> CanaryCertificationInput:
    export = _load_export(canary_id)
    bundle = export["bundle"]
    cr = export["commercial_readiness"]
    rendered_text = bundle["rendered_text"]
    review = _test_only_approve(canary_id, rendered_text) if approved else None
    return CanaryCertificationInput(
        canary_id=canary_id, artifact_sha256=compute_artifact_hash(rendered_text), rendered_text=rendered_text,
        commercial_readiness_pass_count=cr["pass_count"], commercial_readiness_total_count=cr["total_count"],
        review=review,
    )


def _all_four_certified_manifest(release_id: str = "test-release"):
    canaries = [_canary_input(cid, approved=True) for cid in REQUIRED_CANARY_IDS]
    return certify_release(
        release_id=release_id, canaries=canaries, test_results=[SuiteResult("engine", 649, 0)],
        render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
        reviewer_identity="TEST-ONLY Release Operator",
    )


class TestRealCanaryArtifactsAreActually23of23:
    """Sanity precondition for everything else in this file: the exported
    artifacts this repo ships really do carry a 23/23 commercial-readiness
    result today (independent of whether they're human-reviewed)."""

    @pytest.mark.parametrize("canary_id", REQUIRED_CANARY_IDS)
    def test_export_is_23_of_23(self, canary_id):
        export = _load_export(canary_id)
        cr = export["commercial_readiness"]
        assert cr["pass_count"] == cr["total_count"] == 23


class TestFourApprovedCanariesResolvePremiumCertified:
    """Section 17 test #1."""

    @pytest.mark.parametrize("canary_id", REQUIRED_CANARY_IDS)
    def test_each_canary_with_its_own_valid_review_is_premium_certified(self, canary_id):
        c = _canary_input(canary_id, approved=True)
        assert c.resolved_certification_state() == CertificationState.PREMIUM_CERTIFIED

    def test_release_certifies_when_all_four_are_approved(self):
        manifest = _all_four_certified_manifest()
        assert manifest.release_decision == ReleaseState.REPORTX_RELEASE_CERTIFIED
        assert manifest.is_certified
        assert not manifest.failed_requirements
        assert set(manifest.certified_canary_ids) == set(REQUIRED_CANARY_IDS)


class TestApprovedCanaryACannotApproveCanaryB:
    """Section 17 test #2 -- a real ReviewRecord for one canary's exact
    artifact hash must not validate against a different canary's text, and
    must not carry that canary to PREMIUM_CERTIFIED."""

    def test_canary_a_review_does_not_validate_against_canary_b_text(self):
        export_a = _load_export("qilin-spoonful-of-comfort-premium-canary")
        export_b = _load_export("medusalocker-bija-industrie-premium-canary")
        review_for_a = _test_only_approve("qilin-spoonful-of-comfort-premium-canary", export_a["bundle"]["rendered_text"])
        assert not is_review_valid_for_artifact(review_for_a, export_b["bundle"]["rendered_text"])

    def test_release_certification_rejects_canary_b_carrying_canary_as_review(self):
        export_a = _load_export("qilin-spoonful-of-comfort-premium-canary")
        review_for_a = _test_only_approve("qilin-spoonful-of-comfort-premium-canary", export_a["bundle"]["rendered_text"])

        export_b = _load_export("medusalocker-bija-industrie-premium-canary")
        cr_b = export_b["commercial_readiness"]
        canary_b_with_wrong_review = CanaryCertificationInput(
            canary_id="medusalocker-bija-industrie-premium-canary",
            artifact_sha256=compute_artifact_hash(export_b["bundle"]["rendered_text"]),
            rendered_text=export_b["bundle"]["rendered_text"],
            commercial_readiness_pass_count=cr_b["pass_count"], commercial_readiness_total_count=cr_b["total_count"],
            review=review_for_a,  # WRONG review, deliberately, for this artifact
        )
        assert canary_b_with_wrong_review.resolved_certification_state() != CertificationState.PREMIUM_CERTIFIED
        assert canary_b_with_wrong_review.resolved_certification_state() == CertificationState.PREMIUM_READY_PENDING_HUMAN

        others = [_canary_input(cid, approved=True) for cid in REQUIRED_CANARY_IDS
                  if cid != "medusalocker-bija-industrie-premium-canary"]
        manifest = certify_release(
            release_id="cross-canary-attempt", canaries=[canary_b_with_wrong_review, *others],
            test_results=[SuiteResult("engine", 649, 0)],
            render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
            reviewer_identity="TEST-ONLY Release Operator",
        )
        assert manifest.release_decision == ReleaseState.NOT_CERTIFIED
        assert any("not PREMIUM_CERTIFIED" in f for f in manifest.failed_requirements)


class TestCanaryReviewCannotCertifyANewArtifact:
    """Section 17 test #3 -- Section 5's core distinction: an approved
    canary certifies the RELEASE, never a future report's own content."""

    def test_canary_review_does_not_validate_against_unrelated_new_text(self):
        export = _load_export("cve-2025-62593-ray-canary")
        review = _test_only_approve("cve-2025-62593-ray-canary", export["bundle"]["rendered_text"])
        brand_new_report_text = "# A completely different, newly generated production report\n\nNot the canary."
        assert not is_review_valid_for_artifact(review, brand_new_report_text)
        state = resolve_certification_state(
            automated_gates_passed=True, is_premium_tier=True, review=review,
            current_artifact_text=brand_new_report_text,
        )
        assert state == CertificationState.PREMIUM_READY_PENDING_HUMAN


class TestMaterialDriftInvalidatesReleaseCertification:
    """Section 17 test #7."""

    def test_no_drift_immediately_after_certification(self):
        manifest = _all_four_certified_manifest()
        assert not detect_drift(manifest).drifted
        assert apply_drift_check(manifest).release_decision == ReleaseState.REPORTX_RELEASE_CERTIFIED

    def test_tampered_component_hash_is_detected_as_drift(self):
        import dataclasses
        manifest = _all_four_certified_manifest()
        tampered = dataclasses.replace(
            manifest, component_hashes={**manifest.component_hashes, "commercial_validator": "0" * 64},
        )
        drift = detect_drift(tampered)
        assert drift.drifted
        assert "commercial_validator" in drift.changed_components

    def test_drift_flips_release_to_review_required(self):
        import dataclasses
        manifest = _all_four_certified_manifest()
        tampered = dataclasses.replace(
            manifest, component_hashes={**manifest.component_hashes, "quality_gates": "1" * 64},
        )
        checked = apply_drift_check(tampered)
        assert checked.release_decision == ReleaseState.REPORTX_RELEASE_REVIEW_REQUIRED
        assert any("drift" in f.lower() for f in checked.failed_requirements)

    def test_never_certified_release_has_nothing_to_drift_from(self):
        canaries = [_canary_input(cid, approved=False) for cid in REQUIRED_CANARY_IDS]
        manifest = certify_release(
            release_id="never-certified", canaries=canaries, test_results=[SuiteResult("engine", 649, 0)],
            render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
            reviewer_identity="TEST-ONLY",
        )
        assert manifest.release_decision == ReleaseState.NOT_CERTIFIED
        # apply_drift_check is a no-op on a manifest that was never certified
        assert apply_drift_check(manifest).release_decision == ReleaseState.NOT_CERTIFIED


class TestCertifyReleaseBooleanAndLogic:
    def test_missing_regression_test_results_blocks_certification(self):
        canaries = [_canary_input(cid, approved=True) for cid in REQUIRED_CANARY_IDS]
        manifest = certify_release(
            release_id="no-tests", canaries=canaries, test_results=[],
            render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
            reviewer_identity="TEST-ONLY",
        )
        assert manifest.release_decision == ReleaseState.NOT_CERTIFIED

    def test_a_failed_regression_suite_blocks_certification(self):
        canaries = [_canary_input(cid, approved=True) for cid in REQUIRED_CANARY_IDS]
        manifest = certify_release(
            release_id="failed-suite", canaries=canaries, test_results=[SuiteResult("engine", 648, 1)],
            render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
            reviewer_identity="TEST-ONLY",
        )
        assert manifest.release_decision == ReleaseState.NOT_CERTIFIED
        assert any("regression suites" in f for f in manifest.failed_requirements)

    @pytest.mark.parametrize("flag", ["render_qa_passed", "system5_tests_passed", "anti_padding_passed", "npm_audit_passed"])
    def test_each_boolean_gate_independently_blocks_certification(self, flag):
        canaries = [_canary_input(cid, approved=True) for cid in REQUIRED_CANARY_IDS]
        kwargs = dict(
            render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
        )
        kwargs[flag] = False
        manifest = certify_release(
            release_id=f"gate-{flag}", canaries=canaries, test_results=[SuiteResult("engine", 649, 0)],
            reviewer_identity="TEST-ONLY", **kwargs,
        )
        assert manifest.release_decision == ReleaseState.NOT_CERTIFIED

    def test_missing_required_canary_blocks_certification(self):
        canaries = [_canary_input(cid, approved=True) for cid in REQUIRED_CANARY_IDS[:3]]  # only 3 of 4
        manifest = certify_release(
            release_id="missing-canary", canaries=canaries, test_results=[SuiteResult("engine", 649, 0)],
            render_qa_passed=True, system5_tests_passed=True, anti_padding_passed=True, npm_audit_passed=True,
            reviewer_identity="TEST-ONLY",
        )
        assert manifest.release_decision == ReleaseState.NOT_CERTIFIED
        assert any("missing required canaries" in f for f in manifest.failed_requirements)


class TestManifestSerializationAndHashing:
    def test_round_trips_through_dict_with_identical_manifest_hash(self):
        manifest = _all_four_certified_manifest()
        restored = manifest_from_dict(manifest.to_dict())
        assert restored.manifest_hash() == manifest.manifest_hash()
        assert restored.release_decision == manifest.release_decision

    def test_manifest_hash_changes_when_content_changes(self):
        import dataclasses
        manifest = _all_four_certified_manifest()
        changed = dataclasses.replace(manifest, reviewer_identity="Someone Else")
        assert changed.manifest_hash() != manifest.manifest_hash()

    def test_render_release_report_shows_decision_and_hash(self):
        manifest = _all_four_certified_manifest()
        report = render_release_report(manifest)
        assert "REPORTX_RELEASE_CERTIFIED" in report
        assert manifest.manifest_hash() in report


class TestComponentHashing:
    def test_real_tracked_files_all_hash_successfully(self):
        hashes = compute_component_hashes(REPO_ROOT)
        missing = [name for name, h in hashes.items() if h is None]
        assert not missing, f"tracked components missing from disk: {missing}"

    def test_nonexistent_file_hashes_to_none_not_a_fabricated_value(self):
        hashes = compute_component_hashes(REPO_ROOT, paths={"ghost": "this/file/does/not/exist.py"})
        assert hashes["ghost"] is None

    def test_hash_is_stable_across_repeated_calls(self):
        h1 = compute_component_hashes(REPO_ROOT)
        h2 = compute_component_hashes(REPO_ROOT)
        assert h1 == h2
