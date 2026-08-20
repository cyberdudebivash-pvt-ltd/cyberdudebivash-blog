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

from automation.authority_transformer import AuthorityTransformer
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

    def test_fetch_back_discrepancy_is_recorded_but_does_not_fail_the_publish(self):
        # ReportX Phase 1Q wiring: fetch-back is observability, not a gate
        # -- a post is already live by the time it runs, so a detected
        # discrepancy must be recorded (report["fetch_back_discrepancies"],
        # post_result["fetch_back"]) without affecting published/failed
        # counts. Mocked at the fetch_back_and_verify() boundary (not raw
        # HTTP) since the real transformer's generated content isn't known
        # ahead of time -- this test verifies the wiring, not the
        # comparison logic itself (see test_publication_verifier.py for
        # that).
        from automation.publication_verifier import FetchBackResult

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

        discrepant = FetchBackResult(
            post_id="integration-post-123", fetched=True, verified=False,
            defects=("title_mismatch",),
        )

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post", side_effect=[token_resp, post_resp, post_resp]):
                with patch("time.sleep"):
                    with patch("automation.main.fetch_back_and_verify", return_value=discrepant) as mock_fb:
                        report = run_pipeline(self.config, dry_run=False)

        self.assertGreater(report["published"], 0)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["fetch_back_discrepancies"], report["published"])
        published_posts = [p for p in report["posts"] if p["status"] == "published"]
        self.assertTrue(all(p["fetch_back"]["verified"] is False for p in published_posts))
        self.assertTrue(all(p["fetch_back"]["defects"] == ["title_mismatch"] for p in published_posts))
        self.assertGreater(mock_fb.call_count, 0)

    def test_clean_fetch_back_is_recorded_and_does_not_count_as_a_discrepancy(self):
        from automation.publication_verifier import FetchBackResult

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

        clean = FetchBackResult(post_id="integration-post-123", fetched=True, verified=True, exact_content_match=True)

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post", side_effect=[token_resp, post_resp, post_resp]):
                with patch("time.sleep"):
                    with patch("automation.main.fetch_back_and_verify", return_value=clean):
                        report = run_pipeline(self.config, dry_run=False)

        self.assertGreater(report["published"], 0)
        self.assertEqual(report["fetch_back_discrepancies"], 0)
        published_posts = [p for p in report["posts"] if p["status"] == "published"]
        self.assertTrue(all(p["fetch_back"]["verified"] is True for p in published_posts))

    def test_certified_artifact_hash_mismatch_blocks_publication(self):
        # RX-P1-ARTIFACT-BINDING adversarial test: simulates exactly the
        # scenario mandate Section 17/34 exists to prevent -- report
        # content mutated after transform()'s own fail-closed gate
        # certified a different artifact. Uses the REAL transform() (so
        # every other field stays realistic), tampering only
        # certified_artifact_hash afterward -- the publish step must
        # recompute the real hash of the real content, find it doesn't
        # match, and block before ever calling Blogger's publish endpoint.
        real_transform = AuthorityTransformer.transform

        def _tampered_transform(self, article):
            result = real_transform(self, article)
            result["certified_artifact_hash"] = "0" * 64  # deliberately wrong
            return result

        token_resp = MagicMock()
        token_resp.ok = True
        token_resp.json.return_value = MOCK_TOKEN_RESPONSE

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=rss_resp):
            with patch("requests.post", return_value=token_resp) as mock_post:
                with patch("time.sleep"):
                    with patch.object(AuthorityTransformer, "transform", _tampered_transform):
                        report = run_pipeline(self.config, dry_run=False)

        self.assertEqual(report["published"], 0)
        self.assertGreater(report["integrity_blocked"], 0)
        self.assertTrue(all(p["status"] == "integrity_blocked" for p in report["posts"]))
        self.assertTrue(all("certified artifact hash mismatch" in p["error"] for p in report["posts"]))
        # The Blogger publish endpoint itself must never be reached -- only
        # the (cached, single) OAuth token refresh call is allowed through.
        published_post_calls = [
            c for c in mock_post.call_args_list
            if c.args and "posts" in str(c.args[0]) and "oauth2" not in str(c.args[0])
        ]
        self.assertEqual(published_post_calls, [])

    def test_llm_attempts_reaches_the_persisted_report(self):
        # Real production evidence (GPOCIP v1) showed llm_attempts was None
        # on every post despite authority_transformer.transform() correctly
        # returning it — main.py never copied it from transformed into
        # post_result, a wiring gap that unit tests on call_llm() and
        # _requeue_unattempted() in isolation couldn't catch, since neither
        # exercises the real run_pipeline() -> transform() -> post_result
        # path. This runs the actual pipeline end to end instead.
        #
        # RX-STABILIZATION-1: restored verbatim from before 0a4b2df, which
        # had rewritten this to assert llm_attempts == [] and
        # content_source == "evidence_safe_template" — encoding the
        # regression (LLM never attempted, thin renderer only) as a test
        # requirement. transform() once again tries call_llm() first per
        # mission Section 7.
        #
        # RX-PR2: content_source now falls back to "reportx_composer" (the
        # evidence-graph-backed, gate-checked Intelligence Factory composer)
        # when no provider key is set and this run's clean synthetic
        # evidence clears the composer's own fail-closed tier ladder — the
        # legacy "template" renderer remains the deprecated-not-deleted
        # fallback for evidence the composer's gate declines.
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
            with patch("requests.post", side_effect=[token_resp, post_resp, post_resp]):
                with patch("time.sleep"):
                    report = run_pipeline(self.config, dry_run=False)

        self.assertGreater(len(report["posts"]), 0)
        for post in report["posts"]:
            self.assertIn("llm_attempts", post)
            self.assertIsInstance(post["llm_attempts"], list)
            self.assertGreater(len(post["llm_attempts"]), 0)
            self.assertEqual(post["content_source"], "reportx_composer")
            # No API key configured (see _make_config) — every provider
            # attempt must be recorded as a no_api_key skip, not silently
            # dropped.
            for attempt in post["llm_attempts"]:
                self.assertEqual(attempt["error"], "no_api_key")
                self.assertFalse(attempt["ok"])

    def test_rate_limit_exhaustion_stops_run_without_attempting_remaining_articles(self):
        token_resp = MagicMock()
        token_resp.ok = True
        token_resp.json.return_value = MOCK_TOKEN_RESPONSE

        rate_limited_resp = MagicMock()
        rate_limited_resp.status_code = 429
        rate_limited_resp.text = "quota exceeded"

        rss_resp = MagicMock()
        rss_resp.text = MOCK_RSS
        rss_resp.raise_for_status = MagicMock()

        # retry_attempts=2 (see _make_config) — both attempts on the FIRST
        # article are rate limited, exhausting its retries. If the run stops
        # there as intended, requests.post is never called for the second
        # discovered article; side_effect having only these 3 entries makes
        # any further call raise StopIteration and fail the test.
        with patch("requests.get", return_value=rss_resp):
            with patch(
                "requests.post",
                side_effect=[token_resp, rate_limited_resp, rate_limited_resp],
            ):
                with patch("time.sleep"):
                    report = run_pipeline(self.config, dry_run=False)

        self.assertEqual(report["published"], 0)
        self.assertEqual(report["failed"], 1)
        self.assertEqual(len(report["posts"]), 1)
        self.assertEqual(report["posts"][0]["status"], "rate_limited")

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


if __name__ == "__main__":
    unittest.main()
