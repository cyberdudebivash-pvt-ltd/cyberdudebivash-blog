"""
Tests for backfill_social_previews — legacy Blogger social-preview
remediation: defect detection, surgical repair, and the dry-run-first
CLI orchestration (manifest, resume, apply, per-post failure isolation).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from automation.backfill_social_previews import (
    _severity_from_cvss,
    compute_repair,
    detect_defects,
    run,
)
from automation.config import Config


def _make_config() -> Config:
    cfg = Config()
    cfg.blogger_client_id = "test-id"
    cfg.blogger_client_secret = "test-secret"
    cfg.blogger_refresh_token = "test-token"
    cfg.blogger_blog_id = "12345"
    cfg.retry_attempts = 3
    cfg.retry_base_delay = 0.01
    return cfg


class TestSeverityFromCvss(unittest.TestCase):
    def test_critical_threshold(self):
        self.assertEqual(_severity_from_cvss("9.5"), "CRITICAL")

    def test_high_threshold(self):
        self.assertEqual(_severity_from_cvss("7.2"), "HIGH")

    def test_medium_threshold(self):
        self.assertEqual(_severity_from_cvss("5.0"), "MEDIUM")

    def test_low_threshold(self):
        self.assertEqual(_severity_from_cvss("2.1"), "LOW")

    def test_missing_defaults_high(self):
        self.assertEqual(_severity_from_cvss(None), "HIGH")
        self.assertEqual(_severity_from_cvss(""), "HIGH")

    def test_unparseable_defaults_high(self):
        self.assertEqual(_severity_from_cvss("not-a-number"), "HIGH")


class TestDetectDefects(unittest.TestCase):
    def test_clean_post_has_no_defects(self):
        content = '<img src="https://blog.cyberdudebivash.in/api/og?x" alt="x"/><p>body</p>'
        self.assertEqual(detect_defects(content), [])

    def test_data_uri_image_detected(self):
        content = '<img src="data:image/svg+xml;base64,QUJD" alt="x"/><p>body</p>'
        self.assertEqual(detect_defects(content), ["DATA_URI_IMAGE"])

    def test_missing_image_detected(self):
        content = "<p>no image tag here at all</p>"
        self.assertEqual(detect_defects(content), ["MISSING_IMAGE"])

    def test_non_https_image_detected(self):
        content = '<img src="http://insecure.example/x.png"/><p>body</p>'
        self.assertEqual(detect_defects(content), ["NON_HTTPS_IMAGE"])

    def test_blogspot_leak_detected_alongside_image_defect(self):
        content = (
            '<img src="data:image/svg+xml;base64,QUJD"/>'
            '<script>{"sameAs":["https://cyberbivash.blogspot.com"]}</script>'
        )
        defects = detect_defects(content)
        self.assertIn("DATA_URI_IMAGE", defects)
        self.assertIn("BLOGSPOT_CANONICAL_LEAK", defects)

    def test_empty_content_is_missing_image(self):
        self.assertEqual(detect_defects(""), ["MISSING_IMAGE"])


class TestComputeRepair(unittest.TestCase):
    def setUp(self):
        self.config = _make_config()

    def test_replaces_only_first_img_src_leaves_rest_untouched(self):
        post = {
            "title": "CVE-2026-1234 — CVSS 9.1 Critical",
            "labels": ["Vulnerabilities"],
            "content": (
                '<img src="data:image/svg+xml;base64,QUJD" alt="old" width="1200"/>'
                '<p data-report-id="CDB-CTI-2026-DEADBEEF0000">Untouched body content.</p>'
                '<img src="https://example.com/second-image-in-body.png"/>'
            ),
        }
        repair = compute_repair(post, self.config)
        self.assertNotIn("data:image", repair["content"])
        self.assertIn("Untouched body content.", repair["content"])
        self.assertIn('data-report-id="CDB-CTI-2026-DEADBEEF0000"', repair["content"])
        # The SECOND <img> in the body (not Blogger's first-image target)
        # must be left completely alone.
        self.assertIn("https://example.com/second-image-in-body.png", repair["content"])

    def test_reuses_existing_report_id_never_invents_a_new_one(self):
        post = {
            "title": "Some Report",
            "labels": [],
            "content": '<img src="data:x"/><p data-report-id="CDB-CTI-2026-ABCDEF012345">body</p>',
        }
        repair = compute_repair(post, self.config)
        self.assertIn("reportId=CDB-CTI-2026-ABCDEF012345", repair["content"])

    def test_no_report_id_in_content_means_no_report_id_in_url(self):
        post = {"title": "Some Report", "labels": [], "content": '<img src="data:x"/><p>body, no marker</p>'}
        repair = compute_repair(post, self.config)
        self.assertNotIn("reportId=", repair["content"])

    def test_derives_cve_and_severity_from_title_and_content(self):
        post = {
            "title": "CVE-2026-5555 — CVSS 9.9 Critical Severity",
            "labels": ["Vulnerabilities"],
            "content": '<img src="data:x"/><p>body</p>',
        }
        repair = compute_repair(post, self.config)
        self.assertIn("cve=CVE-2026-5555", repair["content"])
        self.assertIn("severity=CRITICAL", repair["content"])
        self.assertIn("cvss=9.9", repair["content"])

    def test_inserts_lead_image_when_entirely_missing(self):
        post = {"title": "No Image Post", "labels": [], "content": "<p>just prose, no img tag</p>"}
        repair = compute_repair(post, self.config)
        self.assertTrue(repair["content"].startswith("<img"))
        self.assertIn("just prose, no img tag", repair["content"])
        self.assertIn("inserted missing lead <img>", repair["changes"][0])

    def test_fixes_blogspot_leak_without_touching_image(self):
        post = {
            "title": "Clean Image Post",
            "labels": [],
            "content": (
                '<img src="https://blog.cyberdudebivash.in/api/og?x"/>'
                '<script>{"sameAs":["https://cyberbivash.blogspot.com"]}</script>'
            ),
        }
        repair = compute_repair(post, self.config)
        self.assertIn('src="https://blog.cyberdudebivash.in/api/og?x"', repair["content"])
        self.assertNotIn("cyberbivash.blogspot.com", repair["content"])
        self.assertIn(self.config.public_cti_url, repair["content"])

    def test_clean_post_produces_no_changes(self):
        post = {"title": "Clean Post", "labels": [], "content": '<img src="https://blog.cyberdudebivash.in/api/og?x"/><p>body</p>'}
        repair = compute_repair(post, self.config)
        self.assertEqual(repair["changes"], [])
        self.assertEqual(repair["defects_found"], [])
        self.assertEqual(repair["content"], post["content"])


class TestRunOrchestration(unittest.TestCase):
    def setUp(self):
        self.config = _make_config()
        self.tmpdir = tempfile.mkdtemp()
        self.manifest_path = str(Path(self.tmpdir) / "manifest.json")

    def _legacy_post(self, post_id="post-1"):
        return {
            "id": post_id,
            "url": f"https://cti.cyberdudebivash.in/2026/08/{post_id}.html",
            "title": "CVE-2026-1234 — Critical",
            "published": "2026-08-01T00:00:00Z",
            "labels": ["Vulnerabilities"],
            "content": '<img src="data:image/svg+xml;base64,QUJD"/><p>body</p>',
            "images": [],
        }

    def test_dry_run_never_calls_patch(self):
        with patch("automation.blogger_publisher.BloggerPublisher.get_post", return_value=self._legacy_post()):
            with patch("automation.blogger_publisher.BloggerPublisher.patch_post_preview") as mock_patch:
                report = run(
                    self.config, post_id="post-1", limit=1, apply=False,
                    resume=False, manifest_path=self.manifest_path, sleep_seconds=0,
                )
        mock_patch.assert_not_called()
        self.assertEqual(report["repaired_dry_run"], 1)
        self.assertEqual(report["applied"], 0)

    def test_apply_calls_patch_and_verifies_fetch_back(self):
        legacy = self._legacy_post()
        fixed = dict(legacy)
        fixed["content"] = legacy["content"].replace(
            '<img src="data:image/svg+xml;base64,QUJD"/>',
            '<img src="https://blog.cyberdudebivash.in/api/og?x"/>',
        )
        with patch("automation.blogger_publisher.BloggerPublisher.get_post", side_effect=[legacy, fixed]):
            with patch("automation.blogger_publisher.BloggerPublisher.patch_post_preview",
                       return_value={"images": [{"url": "https://blog.cyberdudebivash.in/api/og?x"}]}) as mock_patch:
                report = run(
                    self.config, post_id="post-1", limit=1, apply=True,
                    resume=False, manifest_path=self.manifest_path, sleep_seconds=0,
                )
        mock_patch.assert_called_once()
        self.assertEqual(report["applied"], 1)
        manifest = json.loads(Path(self.manifest_path).read_text())
        entry = manifest["entries"]["post-1"]
        self.assertEqual(entry["status"], "applied")
        self.assertTrue(entry["verification"]["verified"])
        self.assertIn("before_content_sha256", entry)
        self.assertIn("after_content_sha256", entry)

    def test_apply_flags_unverified_when_fetch_back_still_shows_defect(self):
        legacy = self._legacy_post()
        with patch("automation.blogger_publisher.BloggerPublisher.get_post", side_effect=[legacy, legacy]):
            with patch("automation.blogger_publisher.BloggerPublisher.patch_post_preview", return_value={}):
                report = run(
                    self.config, post_id="post-1", limit=1, apply=True,
                    resume=False, manifest_path=self.manifest_path, sleep_seconds=0,
                )
        manifest = json.loads(Path(self.manifest_path).read_text())
        self.assertEqual(manifest["entries"]["post-1"]["status"], "applied_unverified")
        self.assertEqual(report["errors"], [f"post-1: patch applied but fetch-back still shows ['DATA_URI_IMAGE']"])

    def test_clean_post_is_skipped_not_patched(self):
        clean = self._legacy_post()
        clean["content"] = '<img src="https://blog.cyberdudebivash.in/api/og?x"/><p>body</p>'
        with patch("automation.blogger_publisher.BloggerPublisher.get_post", return_value=clean):
            with patch("automation.blogger_publisher.BloggerPublisher.patch_post_preview") as mock_patch:
                report = run(
                    self.config, post_id="post-1", limit=1, apply=True,
                    resume=False, manifest_path=self.manifest_path, sleep_seconds=0,
                )
        mock_patch.assert_not_called()
        self.assertEqual(report["clean"], 1)

    def test_one_post_failure_does_not_abort_batch(self):
        good = self._legacy_post("post-good")
        bad = self._legacy_post("post-bad")
        with patch("automation.blogger_publisher.BloggerPublisher.list_posts_page",
                   return_value={"items": [bad, good]}):
            with patch("automation.backfill_social_previews.compute_repair",
                       side_effect=[Exception("boom"), {"content": good["content"], "changes": [], "defects_found": []}]):
                report = run(
                    self.config, post_id=None, limit=2, apply=False,
                    resume=False, manifest_path=self.manifest_path, sleep_seconds=0,
                )
        self.assertEqual(report["scanned"], 2)
        self.assertEqual(report["failed"], 1)
        self.assertEqual(report["clean"], 1)
        self.assertIn("post-bad: boom", report["errors"][0])

    def test_resume_skips_already_applied_posts(self):
        manifest = {"version": 1, "entries": {"post-1": {"status": "applied"}}}
        Path(self.manifest_path).write_text(json.dumps(manifest))
        with patch("automation.blogger_publisher.BloggerPublisher.get_post", return_value=self._legacy_post()):
            with patch("automation.blogger_publisher.BloggerPublisher.patch_post_preview") as mock_patch:
                report = run(
                    self.config, post_id="post-1", limit=1, apply=True,
                    resume=True, manifest_path=self.manifest_path, sleep_seconds=0,
                )
        mock_patch.assert_not_called()
        self.assertEqual(report["skipped_resume"], 1)

    def test_manifest_preserves_before_content_hash_for_rollback(self):
        with patch("automation.blogger_publisher.BloggerPublisher.get_post",
                   side_effect=[self._legacy_post(), self._legacy_post()]):
            with patch("automation.blogger_publisher.BloggerPublisher.patch_post_preview", return_value={}):
                run(
                    self.config, post_id="post-1", limit=1, apply=True,
                    resume=False, manifest_path=self.manifest_path, sleep_seconds=0,
                )
        manifest = json.loads(Path(self.manifest_path).read_text())
        entry = manifest["entries"]["post-1"]
        # Rollback path: re-PATCH the pre-repair content back in, keyed by
        # this hash for verification — must never be dropped once applied.
        self.assertTrue(entry["before_content_sha256"])
        self.assertEqual(len(entry["before_content_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
