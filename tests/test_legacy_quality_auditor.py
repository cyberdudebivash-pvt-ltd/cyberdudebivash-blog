from datetime import datetime, timezone
from unittest.mock import Mock

from automation.legacy_quality_auditor import (
    audit_recent_posts,
    build_quarantine_notice,
    inspect_legacy_post,
)


def _post(content: str, title: str = "CVE-2026-1000 Advisory", labels=None) -> dict:
    return {
        "id": "123",
        "title": title,
        "url": "https://example.blogspot.com/post",
        "published": "2026-08-12T00:00:00Z",
        "updated": "2026-08-12T00:00:00Z",
        "labels": labels or ["Vulnerabilities"],
        "content": content,
    }


def test_detects_structural_kev_contradiction_and_preserves_source():
    finding = inspect_legacy_post(
        _post("<!-- Source: https://source.example/a?x=1&amp;y=2 --><p>CISA KEV — NOT LISTED</p><p>ACTIVE EXPLOITATION CONFIRMED</p>")
    )
    assert finding.reasons == ["kev_exploitation_contradiction"]
    assert finding.source_url == "https://source.example/a?x=1&y=2"
    assert finding.eligible_for_quarantine is True


def test_detects_family_schema_contamination_and_human_attribution():
    finding = inspect_legacy_post(
        _post(
            "<p>Pre-exploitation phase</p><p>Sigma Detection Rule</p><p>Bivash Kumar Nayak — Chief Security Architect</p>",
            title="Ransomware group claims Example Corp",
            labels=["Ransomware"],
        )
    )
    assert finding.reasons == ["ransomware_schema_contamination", "unverified_human_attribution"]


def test_new_evidence_safe_report_is_not_a_quarantine_candidate():
    finding = inspect_legacy_post(
        _post('<article data-report-id="CDB-CTI-2026-ABC123"><p>Automated intelligence synthesis — not human reviewed</p></article>')
    )
    assert finding.reasons == []
    assert finding.legacy_control_missing is False
    assert finding.eligible_for_quarantine is False
    # The pre-fix disclaimer was never false, just outdated framing -- it
    # must be tracked (P0-AI-NATIVE-CERTIFICATION-2026-08-19 backfill
    # scoping) without making an otherwise-clean legacy report quarantine
    # eligible.
    assert finding.stale_disclaimer_language is True


def test_stale_disclaimer_language_never_affects_quarantine_eligibility():
    # A real objective defect (KEV contradiction) alongside the stale-but-
    # accurate disclaimer: eligibility must come from the real defect only,
    # and the disclaimer must never appear in `reasons`.
    finding = inspect_legacy_post(
        _post(
            "<p>CISA KEV — NOT LISTED</p><p>ACTIVE EXPLOITATION CONFIRMED</p>"
            "<p>Automated intelligence synthesis — not human reviewed</p>"
        )
    )
    assert finding.reasons == ["kev_exploitation_contradiction"]
    assert finding.eligible_for_quarantine is True
    assert finding.stale_disclaimer_language is True
    assert "stale_disclaimer_language" not in finding.reasons


def test_current_positive_disclaimer_is_not_flagged_as_stale():
    finding = inspect_legacy_post(
        _post("<p>AI-Native Automated Intelligence — Evidence-Graph Verified</p>")
    )
    assert finding.stale_disclaimer_language is False


def test_quarantine_notice_contains_hash_reasons_and_withdrawal_boundary():
    finding = inspect_legacy_post(_post("<p>Not Found Sector</p>"))
    notice = build_quarantine_notice(finding, "2026-08-12T10:00:00Z")
    assert finding.original_content_sha256 in notice
    assert "Placeholder Output" in notice
    assert "not approved for operational or customer use" in notice
    assert "not a claim that the cited security event is false" in notice


def test_dry_run_is_read_only_and_reports_exact_candidates():
    publisher = Mock()
    publisher.list_recent_posts.return_value = [
        _post("<p>CISA KEV NOT LISTED — ACTIVE EXPLOITATION CONFIRMED</p>"),
        {**_post("<p>Clean legacy content</p>"), "id": "456"},
    ]
    report = audit_recent_posts(
        publisher,
        50,
        apply=False,
        now=datetime(2026, 8, 12, 10, tzinfo=timezone.utc),
    )
    assert report["posts_scanned"] == 2
    assert report["quarantine_candidates"] == 1
    assert report["quarantined"] == 0
    publisher.update_post.assert_not_called()


def test_stale_disclaimer_language_count_is_aggregated_read_only():
    publisher = Mock()
    publisher.list_recent_posts.return_value = [
        {**_post("<p>Automated intelligence synthesis — not human reviewed</p>"), "id": "101"},
        {**_post("<p>Automated intelligence synthesis — not human reviewed</p>"), "id": "102"},
        {**_post("<p>AI-Native Automated Intelligence — Evidence-Graph Verified</p>"), "id": "103"},
    ]
    report = audit_recent_posts(
        publisher,
        50,
        apply=False,
        now=datetime(2026, 8, 12, 10, tzinfo=timezone.utc),
    )
    assert report["stale_disclaimer_language_count"] == 2
    assert report["quarantine_candidates"] == 0
    publisher.update_post.assert_not_called()


def test_apply_backs_up_original_body_before_quarantine():
    publisher = Mock()
    original = "<p>CISA KEV NOT LISTED — ACTIVE EXPLOITATION CONFIRMED</p>"
    publisher.list_recent_posts.return_value = [_post(original)]
    report = audit_recent_posts(
        publisher,
        10,
        apply=True,
        now=datetime(2026, 8, 12, 10, tzinfo=timezone.utc),
    )
    assert report["quarantined"] == 1
    assert report["findings"][0]["original_content"] == original
    publisher.update_post.assert_called_once()
    assert "WITHDRAWN" in publisher.update_post.call_args.kwargs["content"]
