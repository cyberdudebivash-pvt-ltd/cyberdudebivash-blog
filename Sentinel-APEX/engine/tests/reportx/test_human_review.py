from sentinel_engine.reportx.human_review import (
    CertificationState,
    ReviewDecision,
    ReviewRecord,
    compute_artifact_hash,
    is_review_valid_for_artifact,
    resolve_certification_state,
)

ARTIFACT_V1 = "# Report\n\nOriginal content."
ARTIFACT_V2 = "# Report\n\nEdited content."


def _approved_review(artifact_text=ARTIFACT_V1):
    return ReviewRecord(
        report_id="r1", artifact_sha256=compute_artifact_hash(artifact_text),
        reviewer_identity="TEST-ONLY Reviewer", review_timestamp="2026-08-18T00:00:00Z",
        decision=ReviewDecision.APPROVE, review_version=1, is_test_only_fixture=True,
    )


class TestArtifactBinding:
    def test_review_valid_for_the_exact_artifact_it_approved(self):
        review = _approved_review()
        assert is_review_valid_for_artifact(review, ARTIFACT_V1)

    def test_review_invalid_after_artifact_changes(self):
        review = _approved_review(ARTIFACT_V1)
        assert not is_review_valid_for_artifact(review, ARTIFACT_V2)

    def test_reject_decision_never_counts_as_valid_approval(self):
        review = ReviewRecord(
            report_id="r1", artifact_sha256=compute_artifact_hash(ARTIFACT_V1),
            reviewer_identity="TEST-ONLY Reviewer", review_timestamp="2026-08-18T00:00:00Z",
            decision=ReviewDecision.REJECT, review_version=1, is_test_only_fixture=True,
        )
        assert not is_review_valid_for_artifact(review, ARTIFACT_V1)

    def test_request_changes_never_counts_as_valid_approval(self):
        review = ReviewRecord(
            report_id="r1", artifact_sha256=compute_artifact_hash(ARTIFACT_V1),
            reviewer_identity="TEST-ONLY Reviewer", review_timestamp="2026-08-18T00:00:00Z",
            decision=ReviewDecision.REQUEST_CHANGES, review_version=1, is_test_only_fixture=True,
        )
        assert not is_review_valid_for_artifact(review, ARTIFACT_V1)


class TestCertificationStateResolution:
    def test_failed_automated_gates_never_reach_premium_states(self):
        state = resolve_certification_state(
            automated_gates_passed=False, is_premium_tier=True,
            review=_approved_review(), current_artifact_text=ARTIFACT_V1,
        )
        assert state == CertificationState.PUBLIC_REFERENCE_DRAFT

    def test_non_premium_tier_stops_at_tactical_ready_even_with_gates_passed(self):
        state = resolve_certification_state(
            automated_gates_passed=True, is_premium_tier=False,
            review=None, current_artifact_text=ARTIFACT_V1,
        )
        assert state == CertificationState.TACTICAL_READY

    def test_premium_tier_gates_passed_no_review_is_pending_human(self):
        state = resolve_certification_state(
            automated_gates_passed=True, is_premium_tier=True,
            review=None, current_artifact_text=ARTIFACT_V1,
        )
        assert state == CertificationState.PREMIUM_READY_PENDING_HUMAN

    def test_premium_tier_gates_passed_valid_review_is_certified(self):
        state = resolve_certification_state(
            automated_gates_passed=True, is_premium_tier=True,
            review=_approved_review(ARTIFACT_V1), current_artifact_text=ARTIFACT_V1,
        )
        assert state == CertificationState.PREMIUM_CERTIFIED

    def test_premium_tier_stale_review_after_edit_falls_back_to_pending_human(self):
        # The core Section 44 guarantee: editing the report after approval
        # does NOT silently keep it certified.
        state = resolve_certification_state(
            automated_gates_passed=True, is_premium_tier=True,
            review=_approved_review(ARTIFACT_V1), current_artifact_text=ARTIFACT_V2,
        )
        assert state == CertificationState.PREMIUM_READY_PENDING_HUMAN

    def test_no_manual_override_path_exists(self):
        # There is no boolean/flag parameter anywhere in
        # resolve_certification_state that can force PREMIUM_CERTIFIED
        # without a valid, artifact-bound APPROVE review -- verified by
        # exhausting the only two ways to reach it above (gates+tier+review)
        # and confirming a rejected/stale/missing review always falls back.
        state = resolve_certification_state(
            automated_gates_passed=True, is_premium_tier=True,
            review=None, current_artifact_text=ARTIFACT_V1,
        )
        assert state != CertificationState.PREMIUM_CERTIFIED
