"""
Tests for blogger_publisher — OAuth flow, API calls, retry logic.
"""

import unittest
from unittest.mock import MagicMock, patch, call

from automation.blogger_publisher import (
    BloggerPublisher,
    BloggerAuthError,
    BloggerPublishError,
    BloggerRateLimitError,
)
from automation.config import Config


def _make_config() -> Config:
    cfg = Config()
    cfg.blogger_client_id = "test-client-id"
    cfg.blogger_client_secret = "test-client-secret"
    cfg.blogger_refresh_token = "test-refresh-token"
    cfg.blogger_blog_id = "12345"
    cfg.retry_attempts = 3
    cfg.retry_base_delay = 0.01  # Fast for tests
    return cfg


class TestBloggerAuth(unittest.TestCase):
    def setUp(self):
        self.config = _make_config()
        self.publisher = BloggerPublisher(self.config)

    def test_successful_token_refresh(self):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"access_token": "new-token-abc", "expires_in": 3600}

        with patch("requests.post", return_value=mock_resp):
            token = self.publisher._get_access_token()

        self.assertEqual(token, "new-token-abc")

    def test_auth_failure_raises_error(self):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 401
        mock_resp.text = "Invalid credentials"

        with patch("requests.post", return_value=mock_resp):
            with self.assertRaises(BloggerAuthError):
                self.publisher._get_access_token()

    def test_token_cached_within_expiry(self):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"access_token": "cached-token", "expires_in": 3600}

        with patch("requests.post", return_value=mock_resp) as mock_post:
            self.publisher._get_access_token()
            self.publisher._get_access_token()
            # Should only call refresh once
            self.assertEqual(mock_post.call_count, 1)

    def test_token_refreshed_after_expiry(self):
        import time
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.side_effect = [
            {"access_token": "token-1", "expires_in": 0},  # Expires immediately
            {"access_token": "token-2", "expires_in": 3600},
        ]

        with patch("requests.post", return_value=mock_resp) as mock_post:
            self.publisher._access_token = None
            token1 = self.publisher._get_access_token()
            self.publisher._token_expiry = 0  # Simulate expiry
            token2 = self.publisher._get_access_token()
            self.assertEqual(mock_post.call_count, 2)


class TestBloggerPublish(unittest.TestCase):
    def setUp(self):
        self.config = _make_config()
        self.publisher = BloggerPublisher(self.config)
        # Pre-set access token to skip auth in publish tests
        self.publisher._access_token = "valid-token"
        self.publisher._token_expiry = float("inf")

    def _mock_publish_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "id": "post-abc-123",
            "url": "https://cyberbivash.blogspot.com/test-post",
            "title": "Test Post",
        }
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_successful_publish_returns_post_data(self):
        with patch("requests.post", return_value=self._mock_publish_success()):
            result = self.publisher.publish_post(
                title="Test Article",
                content="<p>Content</p>",
                labels=["Test"],
            )
        self.assertEqual(result["id"], "post-abc-123")
        self.assertIn("url", result)

    def test_rate_limit_triggers_retry(self):
        rate_limited = MagicMock()
        rate_limited.status_code = 429

        success = self._mock_publish_success()

        with patch("requests.post", side_effect=[rate_limited, success]):
            with patch("time.sleep"):
                result = self.publisher.publish_post(
                    title="Test", content="<p>x</p>", labels=[]
                )
        self.assertEqual(result["id"], "post-abc-123")

    def test_rate_limit_exhaustion_raises_rate_limit_error(self):
        rate_limited = MagicMock()
        rate_limited.status_code = 429

        with patch("requests.post", return_value=rate_limited):
            with patch("time.sleep"):
                with self.assertRaises(BloggerRateLimitError):
                    self.publisher.publish_post("Title", "<p>x</p>", [])

    def test_rate_limit_error_is_a_publish_error(self):
        # Subclassing means existing `except BloggerPublishError` callers
        # keep working unchanged even though a more specific type is raised.
        rate_limited = MagicMock()
        rate_limited.status_code = 429

        with patch("requests.post", return_value=rate_limited):
            with patch("time.sleep"):
                with self.assertRaises(BloggerPublishError):
                    self.publisher.publish_post("Title", "<p>x</p>", [])

    def test_network_error_retries_and_raises(self):
        import requests as req_lib
        with patch("requests.post", side_effect=req_lib.RequestException("Connection refused")):
            with patch("time.sleep"):
                with self.assertRaises(BloggerPublishError):
                    self.publisher.publish_post("Title", "<p>x</p>", [])

    def test_draft_flag_passed_in_params(self):
        with patch("requests.post", return_value=self._mock_publish_success()) as mock_post:
            self.publisher.publish_post("Title", "<p>x</p>", [], is_draft=True)
            _, kwargs = mock_post.call_args
            self.assertEqual(kwargs["params"]["isDraft"], "true")

    def test_publish_flag_default_false(self):
        with patch("requests.post", return_value=self._mock_publish_success()) as mock_post:
            self.publisher.publish_post("Title", "<p>x</p>", [])
            _, kwargs = mock_post.call_args
            self.assertEqual(kwargs["params"]["isDraft"], "false")

    def test_image_url_sent_via_real_images_field_when_provided(self):
        # Verified against the live Blogger API v3 discovery schema
        # (blogger.googleapis.com/$discovery/rest?version=v3): Post.images
        # is a real, non-readOnly field shaped [{url: string}] — this is
        # the one metadata channel Blogger's API actually exposes for a
        # branded social card (searchDescription/og-tag/twitter-card fields
        # do not exist on the resource at all).
        with patch("requests.post", return_value=self._mock_publish_success()) as mock_post:
            self.publisher.publish_post(
                "Title", "<p>x</p>", [],
                image_url="https://blog.cyberdudebivash.in/api/og?title=Test&severity=HIGH&type=CVE_REPORT",
            )
            _, kwargs = mock_post.call_args
            self.assertEqual(
                kwargs["json"]["images"],
                [{"url": "https://blog.cyberdudebivash.in/api/og?title=Test&severity=HIGH&type=CVE_REPORT"}],
            )

    def test_image_url_omitted_from_payload_when_not_provided(self):
        # Backward compatible: existing callers that don't pass image_url
        # must produce byte-identical payloads to before this change.
        with patch("requests.post", return_value=self._mock_publish_success()) as mock_post:
            self.publisher.publish_post("Title", "<p>x</p>", [])
            _, kwargs = mock_post.call_args
            self.assertNotIn("images", kwargs["json"])

    def test_update_post_retries_rate_limit_and_preserves_payload(self):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.text = "quota"
        success = self._mock_publish_success()

        with patch("requests.put", side_effect=[rate_limited, success]) as mock_put:
            with patch("time.sleep"):
                result = self.publisher.update_post("post-abc-123", "Title", "<p>safe</p>", ["Review"])

        self.assertEqual(result["id"], "post-abc-123")
        self.assertEqual(mock_put.call_count, 2)
        self.assertEqual(mock_put.call_args.kwargs["json"]["content"], "<p>safe</p>")

    def test_update_post_rate_limit_exhaustion_is_explicit(self):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.text = "quota"

        with patch("requests.put", return_value=rate_limited):
            with patch("time.sleep"):
                with self.assertRaises(BloggerRateLimitError):
                    self.publisher.update_post("post-abc-123", "Title", "<p>safe</p>", [])

    # -- patch_post_preview() (P0 social-preview-trust-v2) -------------------

    def test_patch_post_preview_uses_patch_method_with_narrow_payload(self):
        with patch("requests.patch", return_value=self._mock_publish_success()) as mock_patch:
            self.publisher.patch_post_preview(
                "post-abc-123", content="<p>fixed</p>", image_url="https://blog.cyberdudebivash.in/api/og?x",
            )
        self.assertEqual(mock_patch.call_count, 1)
        payload = mock_patch.call_args.kwargs["json"]
        self.assertEqual(payload["content"], "<p>fixed</p>")
        self.assertEqual(payload["images"], [{"url": "https://blog.cyberdudebivash.in/api/og?x"}])
        # A PATCH is a narrow update — title/labels must never appear, unlike
        # update_post()'s PUT (which requires them or risks clearing them).
        self.assertNotIn("title", payload)
        self.assertNotIn("labels", payload)

    def test_patch_post_preview_image_only_omits_content(self):
        with patch("requests.patch", return_value=self._mock_publish_success()) as mock_patch:
            self.publisher.patch_post_preview("post-abc-123", image_url="https://blog.cyberdudebivash.in/api/og?x")
        payload = mock_patch.call_args.kwargs["json"]
        self.assertNotIn("content", payload)
        self.assertEqual(payload["images"], [{"url": "https://blog.cyberdudebivash.in/api/og?x"}])

    def test_patch_post_preview_requires_at_least_one_field(self):
        with self.assertRaises(ValueError):
            self.publisher.patch_post_preview("post-abc-123")

    def test_patch_post_preview_retries_rate_limit(self):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.text = "quota"
        success = self._mock_publish_success()

        with patch("requests.patch", side_effect=[rate_limited, success]) as mock_patch:
            with patch("time.sleep"):
                result = self.publisher.patch_post_preview("post-abc-123", content="<p>x</p>")

        self.assertEqual(result["id"], "post-abc-123")
        self.assertEqual(mock_patch.call_count, 2)

    def test_patch_post_preview_rate_limit_exhaustion_is_explicit(self):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.text = "quota"

        with patch("requests.patch", return_value=rate_limited):
            with patch("time.sleep"):
                with self.assertRaises(BloggerRateLimitError):
                    self.publisher.patch_post_preview("post-abc-123", content="<p>x</p>")

    def test_patch_post_preview_refreshes_token_once_on_401(self):
        unauthorized = MagicMock()
        unauthorized.status_code = 401
        unauthorized.text = "expired"
        success = self._mock_publish_success()
        refreshed_token = MagicMock()
        refreshed_token.ok = True
        refreshed_token.json.return_value = {"access_token": "refreshed-token", "expires_in": 3600}

        with patch("requests.patch", side_effect=[unauthorized, success]):
            with patch("requests.post", return_value=refreshed_token):
                with patch("time.sleep"):
                    result = self.publisher.patch_post_preview("post-abc-123", content="<p>x</p>")
        self.assertEqual(result["id"], "post-abc-123")

    def test_patch_post_preview_second_401_is_fatal(self):
        unauthorized = MagicMock()
        unauthorized.status_code = 401
        unauthorized.text = "expired"
        refreshed_token = MagicMock()
        refreshed_token.ok = True
        refreshed_token.json.return_value = {"access_token": "refreshed-token", "expires_in": 3600}

        with patch("requests.patch", return_value=unauthorized):
            with patch("requests.post", return_value=refreshed_token):
                with patch("time.sleep"):
                    with self.assertRaises(BloggerAuthError):
                        self.publisher.patch_post_preview("post-abc-123", content="<p>x</p>")

    # -- list_posts_page() (P0 social-preview-trust-v2) -----------------------

    def test_list_posts_page_first_page_omits_page_token(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"items": [{"id": "1"}], "nextPageToken": "abc"}
        with patch("requests.get", return_value=mock_resp) as mock_get:
            result = self.publisher.list_posts_page(max_results=10)
        self.assertNotIn("pageToken", mock_get.call_args.kwargs["params"])
        self.assertEqual(result["nextPageToken"], "abc")

    def test_list_posts_page_forwards_page_token(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"items": []}
        with patch("requests.get", return_value=mock_resp) as mock_get:
            self.publisher.list_posts_page(page_token="xyz", max_results=10)
        self.assertEqual(mock_get.call_args.kwargs["params"]["pageToken"], "xyz")

    def test_list_posts_page_last_page_has_no_next_token(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"items": [{"id": "1"}]}
        with patch("requests.get", return_value=mock_resp):
            result = self.publisher.list_posts_page()
        self.assertNotIn("nextPageToken", result)

    def test_get_post_returns_full_body(self):
        # ReportX Phase 1Q: unlike publish_post()'s own create response
        # (fetchBody=false), get_post() must return the real, full content
        # Blogger currently serves for this post.
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "id": "post-abc-123", "title": "Live Title", "content": "<p>Live content</p>",
            "labels": ["Vulnerabilities"], "status": "LIVE",
        }
        with patch("requests.get", return_value=mock_resp) as mock_get:
            result = self.publisher.get_post("post-abc-123")
        self.assertEqual(result["content"], "<p>Live content</p>")
        args, kwargs = mock_get.call_args
        self.assertIn("posts/post-abc-123", args[0])

    def test_get_post_raises_on_http_error(self):
        import requests as req_lib
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = req_lib.HTTPError("404 Not Found")
        with patch("requests.get", return_value=mock_resp):
            with self.assertRaises(req_lib.HTTPError):
                self.publisher.get_post("missing-post")

    def test_publish_raises_when_response_reports_non_live_status(self):
        # ReportX Phase 1P hard gate: HTTP 200 alone must not be trusted --
        # if Blogger's own response says the post isn't LIVE for a
        # non-draft publish request, that is a real, detectable failure
        # (e.g. a quota/permission edge case silently downgrading to a
        # draft) that raise_for_status() alone can never catch.
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "id": "post-abc-123", "url": "https://cyberbivash.blogspot.com/x", "status": "DRAFT",
        }
        with patch("requests.post", return_value=mock_resp):
            with self.assertRaises(BloggerPublishError):
                self.publisher.publish_post("Title", "<p>x</p>", [], is_draft=False)

    def test_publish_succeeds_when_response_reports_live_status(self):
        mock_resp = self._mock_publish_success()
        mock_resp.json.return_value = {**mock_resp.json.return_value, "status": "LIVE"}
        with patch("requests.post", return_value=mock_resp):
            result = self.publisher.publish_post("Title", "<p>x</p>", [], is_draft=False)
        self.assertEqual(result["status"], "LIVE")

    def test_publish_permissive_when_response_has_no_status_field(self):
        # Backward compatible: every existing caller/test whose mocked (or
        # real) response has no "status" key at all -- including
        # test_successful_publish_returns_post_data above -- must keep
        # working exactly as before. The hard gate only fires when the
        # field is present and explicitly says something other than LIVE.
        with patch("requests.post", return_value=self._mock_publish_success()):
            result = self.publisher.publish_post("Title", "<p>x</p>", [], is_draft=False)
        self.assertEqual(result["id"], "post-abc-123")

    def test_publish_gate_does_not_apply_to_draft_requests(self):
        mock_resp = self._mock_publish_success()
        mock_resp.json.return_value = {**mock_resp.json.return_value, "status": "DRAFT"}
        with patch("requests.post", return_value=mock_resp):
            result = self.publisher.publish_post("Title", "<p>x</p>", [], is_draft=True)
        self.assertEqual(result["status"], "DRAFT")

    def test_health_check_passes(self):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"name": "My Blog", "id": "12345"}

        with patch("requests.get", return_value=mock_resp):
            ok = self.publisher.health_check()
        self.assertTrue(ok)

    def test_health_check_fails_gracefully(self):
        import requests as req_lib
        with patch("requests.get", side_effect=req_lib.RequestException("Failed")):
            ok = self.publisher.health_check()
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
