"""
Tests for the social amplification module — Twitter/X posting.
"""

import unittest
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.social_amplifier import SocialAmplifier, _extract_cves


def _config(**kwargs) -> Config:
    cfg = Config()
    for k, v in kwargs.items():
        setattr(cfg, k, v)
    return cfg


def _twitter_cfg() -> Config:
    return _config(
        twitter_api_key="consumer_key",
        twitter_api_secret="consumer_secret",
        twitter_access_token="access_token",
        twitter_access_secret="access_secret",
    )


class TestSocialAmplifierNotConfigured(unittest.TestCase):
    def test_amplify_skips_when_no_twitter_keys(self):
        amp = SocialAmplifier(Config())
        result = amp.amplify({"title": "Test", "blogger_url": "https://ex.com", "labels": []})
        self.assertNotIn("twitter", result)

    def test_post_to_twitter_returns_none_when_not_configured(self):
        amp = SocialAmplifier(Config())
        self.assertIsNone(amp.post_to_twitter({"title": "Test", "labels": []}))

    def test_twitter_not_configured_partial_keys(self):
        amp = SocialAmplifier(_config(twitter_api_key="key"))
        self.assertFalse(amp._twitter_configured())

    def test_twitter_configured_with_all_keys(self):
        amp = SocialAmplifier(_twitter_cfg())
        self.assertTrue(amp._twitter_configured())


class TestExtractCves(unittest.TestCase):
    def test_extracts_standard_cve(self):
        cves = _extract_cves("Alert for CVE-2026-1234 — patch now")
        self.assertEqual(cves, ["CVE-2026-1234"])

    def test_extracts_long_cve(self):
        cves = _extract_cves("CVE-2026-123456 CRITICAL")
        self.assertEqual(cves, ["CVE-2026-123456"])

    def test_extracts_multiple_cves(self):
        cves = _extract_cves("CVE-2026-1111 and CVE-2026-2222")
        self.assertEqual(len(cves), 2)

    def test_no_cves(self):
        cves = _extract_cves("Ransomware attack hits enterprise")
        self.assertEqual(cves, [])


class TestTweetTextBuilder(unittest.TestCase):
    def setUp(self):
        self.amp = SocialAmplifier(Config())

    def test_cisa_kev_gets_emergency_prefix(self):
        text = self.amp._build_tweet_text({
            "title": "CISA KEV Alert: CVE-2026-1234",
            "labels": ["CISA KEV", "Vulnerabilities"],
            "blogger_url": "",
            "blogger_title": "CISA KEV Alert: CVE-2026-1234",
        })
        self.assertIn("CISA KEV ALERT", text)

    def test_ransomware_gets_lock_prefix(self):
        text = self.amp._build_tweet_text({
            "title": "Major Ransomware Campaign Active",
            "labels": ["Ransomware"],
            "blogger_url": "",
            "blogger_title": "Major Ransomware Campaign Active",
        })
        self.assertIn("🔒", text)

    def test_apt_gets_target_prefix(self):
        text = self.amp._build_tweet_text({
            "title": "APT41 New Campaign",
            "labels": ["APT"],
            "blogger_url": "",
            "blogger_title": "APT41 New Campaign",
        })
        self.assertIn("🎯", text)

    def test_ai_security_prefix(self):
        text = self.amp._build_tweet_text({
            "title": "AI Security Vulnerability Discovered",
            "labels": ["AI Security"],
            "blogger_url": "",
            "blogger_title": "AI Security Vulnerability Discovered",
        })
        self.assertIn("🤖", text)

    def test_tweet_always_under_280_chars(self):
        long_title = "CVE-2026-99999 — CVSS 9.8 CRITICAL Severity — This is a Very Long Title That Could Easily Exceed the 280 Character Twitter Limit If Not Handled Properly By The Tweet Builder"
        text = self.amp._build_tweet_text({
            "title": long_title,
            "labels": ["Critical CVE", "Vulnerabilities"],
            "blogger_url": "https://cyberbivash.blogspot.com/2026/06/cve-2026-99999-cvss-98-critical.html",
            "blogger_title": long_title,
        })
        self.assertLessEqual(len(text), 280)

    def test_includes_hashtags(self):
        text = self.amp._build_tweet_text({
            "title": "Test Title",
            "labels": ["Vulnerabilities"],
            "blogger_url": "",
            "blogger_title": "Test Title",
        })
        self.assertIn("#CyberSecurity", text)

    def test_includes_blogger_url(self):
        url = "https://cyberbivash.blogspot.com/test-post"
        text = self.amp._build_tweet_text({
            "title": "Test",
            "labels": [],
            "blogger_url": url,
            "blogger_title": "Test",
        })
        self.assertIn(url, text)

    def test_uses_blogger_title_over_title(self):
        text = self.amp._build_tweet_text({
            "title": "Original Title",
            "blogger_title": "Optimized Blogger Title",
            "labels": [],
            "blogger_url": "",
        })
        self.assertIn("Optimized Blogger Title", text)


class TestTwitterPostWithMock(unittest.TestCase):
    def test_post_to_twitter_returns_tweet_id(self):
        amp = SocialAmplifier(_twitter_cfg())

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"id": "1234567890"}}
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp):
            result = amp.post_to_twitter({
                "title": "CVE-2026-1234 — CVSS 9.8 CRITICAL",
                "blogger_title": "CVE-2026-1234 — CVSS 9.8 CRITICAL",
                "labels": ["Critical CVE"],
                "blogger_url": "https://test.com/post",
            })

        self.assertEqual(result, "1234567890")

    def test_post_to_twitter_api_error_returns_none(self):
        amp = SocialAmplifier(_twitter_cfg())

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 403 Forbidden")

        with patch("requests.post", return_value=mock_resp):
            result = amp.post_to_twitter({
                "title": "Test", "blogger_title": "Test",
                "labels": [], "blogger_url": "",
            })

        self.assertIsNone(result)

    def test_amplify_returns_twitter_result(self):
        amp = SocialAmplifier(_twitter_cfg())

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"id": "tw-999"}}
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp):
            results = amp.amplify({
                "title": "Threat Alert",
                "blogger_title": "Threat Alert",
                "labels": ["Vulnerabilities"],
                "blogger_url": "https://test.com",
            })

        self.assertIn("twitter", results)
        self.assertEqual(results["twitter"], "tw-999")

    def test_amplify_empty_when_no_credentials(self):
        amp = SocialAmplifier(Config())
        results = amp.amplify({"title": "Test", "blogger_title": "Test", "labels": [], "blogger_url": ""})
        self.assertEqual(results, {})

    def test_twitter_api_url_is_v2(self):
        amp = SocialAmplifier(_twitter_cfg())

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"id": "1"}}
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp) as mock_post:
            amp.post_to_twitter({
                "title": "Test", "blogger_title": "Test",
                "labels": [], "blogger_url": "",
            })

        call_url = mock_post.call_args[0][0]
        self.assertIn("twitter.com/2/tweets", call_url)

    def test_oauth_header_contains_authorization(self):
        amp = SocialAmplifier(_twitter_cfg())

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"id": "1"}}
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp) as mock_post:
            amp.post_to_twitter({
                "title": "Test", "blogger_title": "Test",
                "labels": [], "blogger_url": "",
            })

        headers_sent = mock_post.call_args[1]["headers"]
        self.assertIn("Authorization", headers_sent)
        self.assertTrue(headers_sent["Authorization"].startswith("OAuth "))


if __name__ == "__main__":
    unittest.main()
