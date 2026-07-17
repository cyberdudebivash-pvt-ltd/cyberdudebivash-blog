"""
Tests for blogger_publisher — OAuth flow, API calls, retry logic.
"""

import unittest
from unittest.mock import MagicMock, patch, call

from automation.blogger_publisher import (
    BloggerPublisher, BloggerAuthError, BloggerPublishError, _retry_after_seconds,
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


class TestBloggerPublishErrorCategory(unittest.TestCase):
    def test_default_category_is_unknown(self):
        err = BloggerPublishError("something failed")
        self.assertEqual(err.category, "unknown")

    def test_category_can_be_set(self):
        err = BloggerPublishError("rate limited", category="rate_limited")
        self.assertEqual(err.category, "rate_limited")
        self.assertEqual(str(err), "rate limited")


class TestRetryAfterHeader(unittest.TestCase):
    def _resp_with_headers(self, headers: dict):
        resp = MagicMock()
        resp.headers = headers
        return resp

    def test_returns_none_when_header_absent(self):
        self.assertIsNone(_retry_after_seconds(self._resp_with_headers({})))

    def test_parses_numeric_seconds(self):
        self.assertEqual(_retry_after_seconds(self._resp_with_headers({"Retry-After": "30"})), 30.0)

    def test_parses_http_date(self):
        import email.utils
        from datetime import datetime, timedelta, timezone
        future = datetime.now(timezone.utc) + timedelta(seconds=45)
        header_val = email.utils.format_datetime(future)
        result = _retry_after_seconds(self._resp_with_headers({"Retry-After": header_val}))
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result, 45, delta=5)

    def test_returns_none_for_garbage_value(self):
        self.assertIsNone(_retry_after_seconds(self._resp_with_headers({"Retry-After": "not-a-value"})))

    def test_never_returns_negative(self):
        import email.utils
        from datetime import datetime, timedelta, timezone
        past = datetime.now(timezone.utc) - timedelta(seconds=100)
        header_val = email.utils.format_datetime(past)
        result = _retry_after_seconds(self._resp_with_headers({"Retry-After": header_val}))
        self.assertEqual(result, 0.0)


class TestPublishFailureCategorization(unittest.TestCase):
    def setUp(self):
        self.config = _make_config()
        self.publisher = BloggerPublisher(self.config)
        self.publisher._access_token = "valid-token"
        self.publisher._token_expiry = float("inf")

    def _rate_limited_resp(self):
        resp = MagicMock()
        resp.status_code = 429
        resp.text = "quota exceeded"
        resp.headers = {}
        return resp

    def test_exhausted_rate_limit_retries_raise_with_rate_limited_category(self):
        with patch("requests.post", return_value=self._rate_limited_resp()):
            with patch("time.sleep"):
                with self.assertRaises(BloggerPublishError) as ctx:
                    self.publisher.publish_post("Title", "<p>x</p>", [])
        self.assertEqual(ctx.exception.category, "rate_limited")

    def test_rate_limited_retry_honors_retry_after_header(self):
        limited = self._rate_limited_resp()
        limited.headers = {"Retry-After": "7"}
        success = MagicMock()
        success.status_code = 200
        success.ok = True
        success.json.return_value = {"id": "x", "url": "https://example.com", "title": "t"}
        success.raise_for_status = MagicMock()

        with patch("requests.post", side_effect=[limited, success]):
            with patch("time.sleep") as mock_sleep:
                self.publisher.publish_post("Title", "<p>x</p>", [])
        mock_sleep.assert_called_once_with(7.0)

    def test_network_error_category_is_network_error(self):
        import requests as req_lib
        with patch("requests.post", side_effect=req_lib.RequestException("Connection refused")):
            with patch("time.sleep"):
                with self.assertRaises(BloggerPublishError) as ctx:
                    self.publisher.publish_post("Title", "<p>x</p>", [])
        self.assertEqual(ctx.exception.category, "network_error")


if __name__ == "__main__":
    unittest.main()
