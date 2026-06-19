"""
Tests for NVDCVESource — parsing, filtering, deduplication, label enforcement.
"""

import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

from automation.config import Config
from automation.content_discovery import DiscoveredArticle, PublicationState, _compute_hash
from automation.nvd_source import NVDCVESource


MOCK_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-5678",
                "published": "2026-06-19T06:00:00.000",
                "lastModified": "2026-06-19T06:00:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "A critical vulnerability in Example Corp Widget allows "
                            "remote code execution."
                        ),
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-78"}]}
                ],
                "configurations": [],
            }
        }
    ],
}

EMPTY_NVD_RESPONSE = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": [],
}


def _make_config(tmpdir: str) -> Config:
    cfg = Config()
    cfg.state_file = os.path.join(tmpdir, "state.json")
    cfg.max_article_age_hours = 48
    cfg.max_posts_per_run = 10
    return cfg


def _make_mock_response(json_data: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.json.return_value = json_data
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


class TestNVDCVESource(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.state = PublicationState(self.config.state_file)
        self.source = NVDCVESource(self.config)

    def test_returns_empty_on_network_failure(self):
        with patch("requests.get", side_effect=Exception("Connection refused")):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_parses_critical_cve(self):
        # CRITICAL returns data, HIGH returns empty
        responses = [
            _make_mock_response(MOCK_NVD_RESPONSE),  # CRITICAL call
            _make_mock_response(EMPTY_NVD_RESPONSE),  # HIGH call
        ]
        with patch("requests.get", side_effect=responses):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        article = result[0]
        self.assertIn("CVE-2026-5678", article.title)
        self.assertIn("9.8", article.title)

    def test_source_field_is_nvd(self):
        responses = [
            _make_mock_response(MOCK_NVD_RESPONSE),
            _make_mock_response(EMPTY_NVD_RESPONSE),
        ]
        with patch("requests.get", side_effect=responses):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].source, "nvd")

    def test_url_points_to_nvd(self):
        responses = [
            _make_mock_response(MOCK_NVD_RESPONSE),
            _make_mock_response(EMPTY_NVD_RESPONSE),
        ]
        with patch("requests.get", side_effect=responses):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        self.assertIn("nvd.nist.gov", result[0].url)
        self.assertIn("CVE-2026-5678", result[0].url)

    def test_skips_already_published(self):
        cve_id = "CVE-2026-5678"
        title = f"{cve_id} — CVSS 9.8 CRITICAL Severity | Patch Required"
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        content_hash = _compute_hash(url, cve_id + title)
        dummy = DiscoveredArticle(
            url=url,
            title=title,
            summary="",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=content_hash,
            labels=["Vulnerabilities"],
            source="nvd",
        )
        self.state.mark_published(dummy, "post-456", "https://blogger.com/post-456")

        responses = [
            _make_mock_response(MOCK_NVD_RESPONSE),
            _make_mock_response(EMPTY_NVD_RESPONSE),
        ]
        with patch("requests.get", side_effect=responses):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_labels_include_vulnerabilities(self):
        responses = [
            _make_mock_response(MOCK_NVD_RESPONSE),
            _make_mock_response(EMPTY_NVD_RESPONSE),
        ]
        with patch("requests.get", side_effect=responses):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        labels = result[0].labels
        self.assertIn("Vulnerabilities", labels)
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)

    def test_critical_cve_label_added_for_critical(self):
        responses = [
            _make_mock_response(MOCK_NVD_RESPONSE),  # CRITICAL
            _make_mock_response(EMPTY_NVD_RESPONSE),  # HIGH
        ]
        with patch("requests.get", side_effect=responses):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        self.assertIn("Critical CVE", result[0].labels)

    def test_uses_nvd_api_key_in_header(self):
        self.config.nvd_api_key = "test-nvd-key-12345"
        source = NVDCVESource(self.config)

        responses = [
            _make_mock_response(EMPTY_NVD_RESPONSE),
            _make_mock_response(EMPTY_NVD_RESPONSE),
        ]
        with patch("requests.get", side_effect=responses) as mock_get:
            source.discover(self.state)

        # Verify at least one call included the apiKey header
        calls = mock_get.call_args_list
        self.assertGreater(len(calls), 0)
        headers_used = calls[0][1].get("headers", {})
        self.assertEqual(headers_used.get("apiKey"), "test-nvd-key-12345")


if __name__ == "__main__":
    unittest.main()
