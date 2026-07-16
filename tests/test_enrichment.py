"""
Tests for automation.enrichment — EPSS + CISA KEV attachment, graceful
degradation, and the "never fabricate" contract.
"""

import unittest
from unittest.mock import MagicMock, patch

from automation.content_discovery import DiscoveredArticle
from automation.enrichment import enrich_articles, fetch_epss_batch, fetch_kev_catalog


def _article(**kwargs) -> DiscoveredArticle:
    defaults = {
        "url": "https://example.com/a",
        "title": "CVE-2026-9999 Critical RCE",
        "summary": "A critical vulnerability.",
        "published_at": "2026-07-16T00:00:00+00:00",
        "content_hash": "abc123",
        "labels": ["Vulnerabilities"],
        "source": "nvd",
    }
    defaults.update(kwargs)
    return DiscoveredArticle(**defaults)


class TestFetchEpssBatch(unittest.TestCase):
    def test_empty_input_returns_empty_without_network_call(self):
        with patch("requests.get") as mock_get:
            result = fetch_epss_batch([])
        self.assertEqual(result, {})
        mock_get.assert_not_called()

    def test_parses_valid_response(self):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {
            "data": [{"cve": "cve-2026-9999", "epss": "0.87654", "percentile": "0.99123"}]
        }
        with patch("requests.get", return_value=resp):
            result = fetch_epss_batch(["CVE-2026-9999"])
        self.assertIn("CVE-2026-9999", result)
        self.assertAlmostEqual(result["CVE-2026-9999"]["epss_score"], 0.87654)
        self.assertAlmostEqual(result["CVE-2026-9999"]["epss_percentile"], 0.99123)

    def test_network_failure_returns_empty(self):
        import requests as req_lib
        with patch("requests.get", side_effect=req_lib.RequestException("timeout")):
            result = fetch_epss_batch(["CVE-2026-9999"])
        self.assertEqual(result, {})

    def test_malformed_entry_skipped_not_raised(self):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"data": [{"cve": "CVE-2026-1111", "epss": "not-a-number"}]}
        with patch("requests.get", return_value=resp):
            result = fetch_epss_batch(["CVE-2026-1111"])
        self.assertEqual(result, {})


class TestFetchKevCatalog(unittest.TestCase):
    def test_parses_catalog_into_dict_keyed_by_cve(self):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "cve-2026-2222",
                    "dateAdded": "2026-07-01",
                    "dueDate": "2026-07-15",
                    "requiredAction": "Apply the patch.",
                }
            ]
        }
        with patch("requests.get", return_value=resp):
            catalog = fetch_kev_catalog()
        self.assertIn("CVE-2026-2222", catalog)
        self.assertEqual(catalog["CVE-2026-2222"]["kev_due_date"], "2026-07-15")

    def test_network_failure_returns_empty(self):
        import requests as req_lib
        with patch("requests.get", side_effect=req_lib.RequestException("timeout")):
            catalog = fetch_kev_catalog()
        self.assertEqual(catalog, {})


class TestEnrichArticles(unittest.TestCase):
    def test_no_cve_no_network_call(self):
        articles = [_article(title="Generic ransomware news", summary="No CVE here")]
        with patch("requests.get") as mock_get:
            result = enrich_articles(articles)
        mock_get.assert_not_called()
        self.assertIsNone(result[0].epss_score)

    def test_attaches_epss_and_kev(self):
        epss_resp = MagicMock()
        epss_resp.raise_for_status = MagicMock()
        epss_resp.json.return_value = {
            "data": [{"cve": "CVE-2026-9999", "epss": "0.5", "percentile": "0.6"}]
        }
        kev_resp = MagicMock()
        kev_resp.raise_for_status = MagicMock()
        kev_resp.json.return_value = {
            "vulnerabilities": [
                {"cveID": "CVE-2026-9999", "dateAdded": "2026-07-01", "dueDate": "2026-07-15", "requiredAction": "Patch."}
            ]
        }
        articles = [_article()]
        with patch("requests.get", side_effect=[epss_resp, kev_resp]):
            result = enrich_articles(articles)
        self.assertEqual(result[0].cve_id, "CVE-2026-9999")
        self.assertEqual(result[0].epss_score, 0.5)
        self.assertTrue(result[0].kev_listed)
        self.assertEqual(result[0].kev_due_date, "2026-07-15")

    def test_kev_fetch_failure_leaves_unknown_not_false(self):
        """A failed KEV catalog fetch must never assert a false negative."""
        import requests as req_lib
        epss_resp = MagicMock()
        epss_resp.raise_for_status = MagicMock()
        epss_resp.json.return_value = {"data": []}
        articles = [_article()]
        with patch("requests.get", side_effect=[epss_resp, req_lib.RequestException("down")]):
            result = enrich_articles(articles)
        self.assertIsNone(result[0].kev_listed)

    def test_cve_confirmed_absent_from_kev_catalog_is_false(self):
        epss_resp = MagicMock()
        epss_resp.raise_for_status = MagicMock()
        epss_resp.json.return_value = {"data": []}
        kev_resp = MagicMock()
        kev_resp.raise_for_status = MagicMock()
        kev_resp.json.return_value = {"vulnerabilities": [{"cveID": "CVE-0000-0000", "dateAdded": "2020-01-01"}]}
        articles = [_article()]
        with patch("requests.get", side_effect=[epss_resp, kev_resp]):
            result = enrich_articles(articles)
        self.assertFalse(result[0].kev_listed)

    def test_source_populated_kev_never_overwritten(self):
        """CISAKEVSource already sets kev_listed=True at the source — must not be touched."""
        epss_resp = MagicMock()
        epss_resp.raise_for_status = MagicMock()
        epss_resp.json.return_value = {"data": []}
        kev_resp = MagicMock()
        kev_resp.raise_for_status = MagicMock()
        kev_resp.json.return_value = {"vulnerabilities": []}  # catalog says nothing about this CVE
        articles = [_article(source="cisa_kev", cve_id="CVE-2026-9999", kev_listed=True,
                              kev_date_added="2026-06-01", kev_due_date="2026-06-15")]
        with patch("requests.get", side_effect=[epss_resp, kev_resp]):
            result = enrich_articles(articles)
        self.assertTrue(result[0].kev_listed)
        self.assertEqual(result[0].kev_due_date, "2026-06-15")

    def test_enrichment_error_does_not_raise(self):
        """content_discovery.py wraps this in try/except, but the function itself
        should also not explode on a completely broken response shape."""
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.side_effect = ValueError("not json")
        articles = [_article()]
        with patch("requests.get", return_value=resp):
            result = enrich_articles(articles)  # must not raise
        self.assertIsNone(result[0].epss_score)


if __name__ == "__main__":
    unittest.main()
