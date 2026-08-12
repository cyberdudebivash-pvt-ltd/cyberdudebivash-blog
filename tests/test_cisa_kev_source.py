"""
Tests for CISAKEVSource — parsing, filtering, deduplication, label enforcement.
"""

import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.content_discovery import PublicationState, _compute_hash
from automation.cisa_kev_source import CISAKEVSource

_TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
_YESTERDAY = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")

MOCK_KEV_RESPONSE = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": _TODAY,
    "dateReleased": f"{_TODAY}T00:00:00Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1234",
            "vendorProject": "Microsoft",
            "product": "Windows IKE",
            "vulnerabilityName": "Microsoft Windows IKE Remote Code Execution Vulnerability",
            "dateAdded": _YESTERDAY,
            "shortDescription": (
                "Microsoft Windows IKE contains a remote code execution vulnerability "
                "that allows unauthenticated attackers to execute code at SYSTEM level."
            ),
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2026-07-10",
            "notes": "This vulnerability is being actively exploited in the wild.",
        }
    ],
}


def _make_config(tmpdir: str) -> Config:
    cfg = Config()
    cfg.state_file = os.path.join(tmpdir, "state.json")
    cfg.max_article_age_hours = 48
    cfg.max_posts_per_run = 5
    return cfg


def _make_mock_response(json_data: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.json.return_value = json_data
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


class TestCISAKEVSource(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.state = PublicationState(self.config.state_file)
        self.source = CISAKEVSource(self.config)

    def test_returns_empty_on_network_failure(self):
        with patch("requests.get", side_effect=Exception("Connection refused")):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_parses_valid_kev_entry(self):
        with patch("requests.get", return_value=_make_mock_response(MOCK_KEV_RESPONSE)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        article = result[0]
        self.assertIn("CVE-2026-1234", article.title)
        self.assertIn("Active Exploitation Confirmed", article.title)

    def test_skips_old_entries(self):
        old_response = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2025-0001",
                    "vendorProject": "OldVendor",
                    "product": "OldProduct",
                    "vulnerabilityName": "Old Vulnerability",
                    "dateAdded": "2025-01-01",  # 100+ days ago
                    "shortDescription": "An old vulnerability.",
                    "requiredAction": "Apply updates.",
                    "dueDate": "2025-02-01",
                    "notes": "",
                }
            ]
        }
        with patch("requests.get", return_value=_make_mock_response(old_response)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_includes_required_labels(self):
        with patch("requests.get", return_value=_make_mock_response(MOCK_KEV_RESPONSE)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        labels = result[0].labels
        self.assertIn("CISA KEV", labels)
        self.assertIn("Vulnerabilities", labels)
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)

    def test_skips_already_published(self):
        # Pre-mark the article as published
        cve_id = "CVE-2026-1234"
        title = (
            f"CISA KEV Alert: {cve_id} — Microsoft Windows IKE Remote Code Execution Vulnerability"
            " | Active Exploitation Confirmed"
        )
        content_hash = _compute_hash(f"cisa-kev-{cve_id}", cve_id)
        from automation.content_discovery import DiscoveredArticle
        dummy = DiscoveredArticle(
            url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
            title=title,
            summary="",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=content_hash,
            labels=["CISA KEV"],
            source="cisa_kev",
        )
        self.state.mark_published(dummy, "post-123", "https://blogger.com/post-123")

        with patch("requests.get", return_value=_make_mock_response(MOCK_KEV_RESPONSE)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_existing_nvd_advisory_does_not_suppress_material_kev_update(self):
        from automation.content_discovery import DiscoveredArticle

        nvd_article = DiscoveredArticle(
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
            title="CVE-2026-1234 NVD vulnerability record",
            summary="A vulnerability record.",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash="nvd-specific-hash",
            labels=["Vulnerabilities"],
            source="nvd_cve",
        )
        self.state.mark_published(nvd_article, "post-nvd", "https://blogger.com/post-nvd")

        with patch("requests.get", return_value=_make_mock_response(MOCK_KEV_RESPONSE)):
            result = self.source.discover(self.state)

        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].kev_listed)

    def test_full_content_contains_kev_fields(self):
        with patch("requests.get", return_value=_make_mock_response(MOCK_KEV_RESPONSE)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        fc = result[0].full_content
        self.assertIsNotNone(fc)
        self.assertIn("CVE-2026-1234", fc)
        self.assertIn("2026-07-10", fc)  # Federal Remediation Deadline
        self.assertIn("Apply updates per vendor instructions.", fc)  # Required Action

    def test_source_field_is_cisa_kev(self):
        with patch("requests.get", return_value=_make_mock_response(MOCK_KEV_RESPONSE)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].source, "cisa_kev")


if __name__ == "__main__":
    unittest.main()
