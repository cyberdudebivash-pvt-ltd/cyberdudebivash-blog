"""
Integration tests — full pipeline simulation with mocked external services.
"""

import email.utils
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.content_discovery import ContentDiscoveryEngine, _compute_hash
from automation.main import run_pipeline


# Content discovery drops anything older than config.max_article_age_hours
# (72h) — pubDates must stay relative to "now" or this fixture silently goes
# stale and every discovery-dependent test starts finding 0 articles.
_PUBDATE_1 = email.utils.format_datetime(datetime.now(timezone.utc) - timedelta(hours=2))
_PUBDATE_2 = email.utils.format_datetime(datetime.now(timezone.utc) - timedelta(hours=3))

MOCK_RSS = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CYBERDUDEBIVASH® SENTINEL APEX</title>
    <link>https://blog.cyberdudebivash.in</link>
    <item>
      <title>CVE-2026-9999 Critical Windows IKE RCE — CVSS 9.8 PATCH NOW</title>
      <link>https://blog.cyberdudebivash.in/posts/cve-2026-9999</link>
      <description>A critical remote code execution vulnerability in the Windows IKE service allows unauthenticated attackers to execute code at SYSTEM level.</description>
      <pubDate>{_PUBDATE_1}</pubDate>
      <category>Zero-Day</category>
    </item>
    <item>
      <title>LockBit 4.0 Ransomware Hits Healthcare Sector — 47 Victims</title>
      <link>https://blog.cyberdudebivash.in/posts/lockbit-healthcare-2026</link>
      <description>LockBit 4.0 ransomware group has claimed 47 healthcare victims in a coordinated campaign targeting hospital systems.</description>
      <pubDate>{_PUBDATE_2}</pubDate>
      <category>Ransomware</category>
    </item>
  </channel>
</rss>"""

MOCK_BLOGGER_POST = {
    "id": "integration-post-123",
    "url": "https://cyberbivash.blogspot.com/2026/06/test.html",
    "title": "Integration Test Post",
    "status": "LIVE",
}

MOCK_TOKEN_RESPONSE = {
    "access_token": "integration-test-token",
    "expires_in": 3600,
    "token_type": "Bearer",
}

MOCK_BLOG_INFO = {
    "id": "test-blog-id",
    "name": "CYBERDUDEBIVASH Research",
    "url": "https://cyberbivash.blogspot.com",
}


def _make_config(tmpdir: str) -> Config:
    cfg = Config()
    cfg.blogger_client_id = "test-client-id"
    cfg.blogger_client_secret = "test-secret"
    cfg.blogger_refresh_token = "test-refresh"
    cfg.blogger_blog_id = "test-blog-id"
    cfg.anthropic_api_key = ""
    cfg.state_file = os.path.join(tmpdir, "state.json")
    cfg.logs_dir = os.path.join(tmpdir, "logs")
    cfg.max_posts_per_run = 3
    cfg.retry_attempts = 2
    cfg.retry_base_delay = 0.01
    return cfg


class TestFullPipelineDryRun(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)

    def test_dry_run_discovers_and_transforms_without_publishing(self):
        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post"):
                report = run_pipeline(self.config, dry_run=True)

        self.assertEqual(report["dry_run"], True)
        self.assertEqual(report["published"], 0)
        self.assertGreater(report["discovered"], 0)
        self.assertEqual(report["failed"], 0)

    def test_dry_run_no_state_changes(self):
        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=rss_resp):
            run_pipeline(self.config, dry_run=True)

        # State file should reflect no publications
        if os.path.exists(self.config.state_file):
            with open(self.config.state_file) as f:
                state = json.load(f)
            self.assertEqual(state["total_published"], 0)


class TestFullPipelinePublish(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)

    def _make_get_mock(self):
        """Return mock that serves RSS on first call, blog info on subsequent."""
        responses = []

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()
        rss_resp.status_code = 200

        blog_resp = MagicMock()
        blog_resp.raise_for_status = MagicMock()
        blog_resp.json.return_value = MOCK_BLOG_INFO
        blog_resp.status_code = 200

        return [rss_resp, blog_resp, blog_resp]

    def test_full_pipeline_publishes_articles(self):
        token_resp = MagicMock()
        token_resp.ok = True
        token_resp.json.return_value = MOCK_TOKEN_RESPONSE

        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.raise_for_status = MagicMock()
        post_resp.json.return_value = MOCK_BLOGGER_POST

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()
        rss_resp.status_code = 200

        # Token is cached after first refresh — only 1 token POST, then N article POSTs
        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post", side_effect=[token_resp, post_resp, post_resp]):
                with patch("time.sleep"):
                    report = run_pipeline(self.config, dry_run=False)

        self.assertGreater(report["published"], 0)
        self.assertEqual(report["failed"], 0)

    def test_published_articles_tracked_in_state(self):
        token_resp = MagicMock()
        token_resp.ok = True
        token_resp.json.return_value = MOCK_TOKEN_RESPONSE

        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.raise_for_status = MagicMock()
        post_resp.json.return_value = MOCK_BLOGGER_POST

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post", side_effect=[
                token_resp, post_resp, token_resp, post_resp, token_resp, post_resp
            ]):
                with patch("time.sleep"):
                    report = run_pipeline(self.config, dry_run=False)

        if report["published"] > 0:
            with open(self.config.state_file) as f:
                state = json.load(f)
            self.assertGreater(state["total_published"], 0)

    def test_missing_credentials_returns_error(self):
        bad_config = Config()
        bad_config.state_file = os.path.join(self.tmpdir, "state.json")
        bad_config.logs_dir = self.tmpdir
        # No credentials set
        report = run_pipeline(bad_config, dry_run=False)
        self.assertGreater(len(report["errors"]), 0)
        self.assertEqual(report["published"], 0)

    def test_run_report_written_to_logs(self):
        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post"):
                run_pipeline(self.config, dry_run=True)

        log_files = list(os.scandir(self.config.logs_dir))
        run_reports = [f for f in log_files if f.name.startswith("run-") and f.name.endswith(".json")]
        self.assertGreater(len(run_reports), 0)


class TestPipelineDeduplication(unittest.TestCase):
    """Verify second pipeline run skips already-published articles."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)

    def test_second_run_skips_already_published(self):
        from automation.content_discovery import PublicationState, _compute_hash, DiscoveredArticle

        # Pre-populate state with both articles from MOCK_RSS
        state = PublicationState(self.config.state_file)
        for url, title in [
            ("https://blog.cyberdudebivash.in/posts/cve-2026-9999",
             "CVE-2026-9999 Critical Windows IKE RCE — CVSS 9.8 PATCH NOW"),
            ("https://blog.cyberdudebivash.in/posts/lockbit-healthcare-2026",
             "LockBit 4.0 Ransomware Hits Healthcare Sector — 47 Victims"),
        ]:
            a = DiscoveredArticle(
                url=url, title=title, summary="...",
                published_at=datetime.now(timezone.utc).isoformat(),
                content_hash=_compute_hash(url, title),
                labels=["Threat Intelligence"], source="rss",
            )
            state.mark_published(a, f"post-{hash(url)}", f"https://blogger.com/{hash(url)}")

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post"):
                report = run_pipeline(self.config, dry_run=True)

        self.assertEqual(report["discovered"], 0)
        self.assertEqual(report["published"], 0)
        self.assertEqual(report["failed"], 0)


class TestRateLimitCircuitBreaker(unittest.TestCase):
    """
    Verify the pipeline stops attempting further articles once the first
    one exhausts its retries on HTTP 429 — rather than retry-storming every
    remaining article against an already-exhausted quota (see
    automation/blogger_publisher.py's category='rate_limited' and
    automation/main.py's circuit breaker).
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)

    def _rate_limited_resp(self):
        resp = MagicMock()
        resp.status_code = 429
        resp.text = "Resource has been exhausted (e.g. check quota)."
        resp.headers = {}
        resp.ok = False
        return resp

    def test_circuit_breaker_stops_after_first_article_rate_limited(self):
        token_resp = MagicMock()
        token_resp.ok = True
        token_resp.json.return_value = MOCK_TOKEN_RESPONSE

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS  # 2 articles
        rss_resp.raise_for_status = MagicMock()

        # retry_attempts=2 (see _make_config) -> exactly 2 POST calls for the
        # first article, then the circuit breaker must trip before any POST
        # is attempted for the second article. side_effect has exactly
        # 3 entries (token + 2 rate-limited attempts); a 4th call raises
        # StopIteration, which would fail this test if the breaker didn't work.
        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post", side_effect=[
                token_resp, self._rate_limited_resp(), self._rate_limited_resp(),
            ]):
                with patch("time.sleep"):
                    report = run_pipeline(self.config, dry_run=False)

        self.assertEqual(report["published"], 0)
        self.assertEqual(report["failed"], 1)
        self.assertEqual(report["skipped"], 1)
        self.assertTrue(report["circuit_breaker_tripped"])
        self.assertEqual(report["failure_categories"].get("rate_limited"), 1)
        self.assertEqual(report["posts"][0]["failure_category"], "rate_limited")

    def test_circuit_breaker_requeues_untried_articles(self):
        token_resp = MagicMock()
        token_resp.ok = True
        token_resp.json.return_value = MOCK_TOKEN_RESPONSE

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post", side_effect=[
                token_resp, self._rate_limited_resp(), self._rate_limited_resp(),
            ]):
                with patch("time.sleep"):
                    run_pipeline(self.config, dry_run=False)

        with open(self.config.state_file) as f:
            state = json.load(f)
        retry_queue = state.get("retry_queue", [])
        # The 2nd article (never attempted) should be queued for retry.
        self.assertTrue(any("lockbit-healthcare" in item["url"] for item in retry_queue))


if __name__ == "__main__":
    unittest.main()
