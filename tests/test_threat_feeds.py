"""
Tests for threat_feeds module — CISA advisories, ransomware, breach, and
threat-actor intel sources. Covers network failures, malformed payloads,
recency filtering, deduplication, and required-label enforcement.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.content_discovery import DiscoveredArticle, PublicationState, _compute_hash
from automation.threat_feeds import (
    CISAAdvisoriesSource,
    DataBreachIntelSource,
    RansomwareIntelSource,
    ThreatActorIntelSource,
)


def _make_config(tmpdir: str) -> Config:
    cfg = Config()
    cfg.state_file = os.path.join(tmpdir, "state.json")
    cfg.max_article_age_hours = 48
    return cfg


def _make_json_response(data) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.json.return_value = data
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


def _make_text_response(text: str) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.text = text
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


def _recent_pub_date() -> str:
    import email.utils
    return email.utils.format_datetime(datetime.now(timezone.utc))


def _recent_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ─────────────────────────────────────────────────────────────────────────────
# CISA Advisories
# ─────────────────────────────────────────────────────────────────────────────

MOCK_ADVISORY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CISA Cybersecurity Advisories</title>
    <item>
      <title>ICSA-26-170-01 Critical Manufacturing Control System Vulnerability</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-170-01</link>
      <description>CISA has released an advisory for a critical vulnerability affecting industrial control systems.</description>
      <pubDate>{pub_date}</pubDate>
    </item>
  </channel>
</rss>"""


class TestCISAAdvisoriesSource(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.state = PublicationState(self.config.state_file)
        self.source = CISAAdvisoriesSource(self.config)

    def test_returns_empty_on_network_failure(self):
        with patch("requests.get", side_effect=Exception("Connection refused")):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_returns_empty_on_malformed_xml(self):
        with patch("requests.get", return_value=_make_text_response("NOT VALID XML <<<")):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_parses_valid_advisory(self):
        xml = MOCK_ADVISORY_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_text_response(xml)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].source, "cisa_advisory")
        self.assertIn("ICSA-26-170-01", result[0].title)

    def test_required_labels_present(self):
        xml = MOCK_ADVISORY_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_text_response(xml)):
            result = self.source.discover(self.state)
        labels = result[0].labels
        self.assertIn("CISA Advisory", labels)
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)

    def test_old_entries_filtered(self):
        xml = MOCK_ADVISORY_XML.format(pub_date="Mon, 01 Jan 2024 00:00:00 +0000")
        with patch("requests.get", return_value=_make_text_response(xml)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_already_published_filtered(self):
        url = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-170-01"
        title = "ICSA-26-170-01 Critical Manufacturing Control System Vulnerability"
        content_hash = _compute_hash(url, title)
        dummy = DiscoveredArticle(
            url=url, title=title, summary="",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=content_hash, labels=["CISA Advisory"], source="cisa_advisory",
        )
        self.state.mark_published(dummy, "post-1", "https://blogger.com/post-1")

        xml = MOCK_ADVISORY_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_text_response(xml)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])


# ─────────────────────────────────────────────────────────────────────────────
# Ransomware Intel
# ─────────────────────────────────────────────────────────────────────────────

class TestRansomwareIntelSource(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.state = PublicationState(self.config.state_file)
        self.source = RansomwareIntelSource(self.config)

    def test_returns_empty_on_network_failure(self):
        with patch("requests.get", side_effect=Exception("Connection refused")):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_returns_empty_on_non_list_response(self):
        with patch("requests.get", return_value=_make_json_response({"unexpected": "shape"})):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_parses_valid_victim_entry(self):
        victims = [{
            "victim": "Example Manufacturing Corp",
            "group": "LockBit",
            "discovered": _recent_iso(),
            "country": "US",
            "activity": "Manufacturing",
            "post_url": "https://leaksite.example/example-manufacturing-corp",
        }]
        with patch("requests.get", return_value=_make_json_response(victims)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        article = result[0]
        self.assertEqual(article.source, "ransomware_intel")
        self.assertIn("LockBit", article.title)
        self.assertIn("Example Manufacturing Corp", article.title)

    def test_required_labels_present(self):
        victims = [{
            "victim": "Acme Co",
            "group": "BlackCat",
            "discovered": _recent_iso(),
            "activity": "Retail",
        }]
        with patch("requests.get", return_value=_make_json_response(victims)):
            result = self.source.discover(self.state)
        labels = result[0].labels
        self.assertIn("Ransomware", labels)
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)

    def test_missing_victim_name_skipped(self):
        victims = [{"victim": "", "group": "LockBit", "discovered": _recent_iso()}]
        with patch("requests.get", return_value=_make_json_response(victims)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_old_victim_filtered(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")
        victims = [{"victim": "Old Co", "group": "LockBit", "discovered": old_date}]
        with patch("requests.get", return_value=_make_json_response(victims)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_already_published_filtered(self):
        victims = [{
            "victim": "Repeat Co",
            "group": "LockBit",
            "discovered": _recent_iso(),
            "activity": "Finance",
        }]
        # First call to compute the hash exactly as the source would
        with patch("requests.get", return_value=_make_json_response(victims)):
            first = self.source.discover(self.state)
        self.assertEqual(len(first), 1)
        self.state.mark_published(first[0], "post-1", "https://blogger.com/post-1")

        with patch("requests.get", return_value=_make_json_response(victims)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_non_dict_entries_skipped(self):
        with patch("requests.get", return_value=_make_json_response(["not-a-dict", 123])):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])


# ─────────────────────────────────────────────────────────────────────────────
# Data Breach Intel
# ─────────────────────────────────────────────────────────────────────────────

class TestDataBreachIntelSource(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.state = PublicationState(self.config.state_file)
        self.source = DataBreachIntelSource(self.config)

    def test_returns_empty_on_network_failure(self):
        with patch("requests.get", side_effect=Exception("Connection refused")):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_returns_empty_on_non_list_response(self):
        with patch("requests.get", return_value=_make_json_response({"unexpected": "shape"})):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_parses_recently_added_breach(self):
        breaches = [{
            "Name": "ExampleBreachCo",
            "Title": "Example Breach Co",
            "Domain": "examplebreach.com",
            "BreachDate": "2019-01-01",
            "AddedDate": _recent_iso(),
            "PwnCount": 1500000,
            "DataClasses": ["Email addresses", "Passwords"],
        }]
        with patch("requests.get", return_value=_make_json_response(breaches)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)
        article = result[0]
        self.assertEqual(article.source, "breach_intel")
        self.assertIn("Example Breach Co", article.title)
        self.assertIn("1,500,000", article.title)

    def test_old_breach_date_but_recently_added_still_surfaced(self):
        """BreachDate can be years old — what matters is AddedDate (newly disclosed)."""
        breaches = [{
            "Name": "LegacyBreach",
            "Title": "Legacy Breach",
            "BreachDate": "2015-01-01",
            "AddedDate": _recent_iso(),
            "PwnCount": 1000,
            "DataClasses": ["Email addresses"],
        }]
        with patch("requests.get", return_value=_make_json_response(breaches)):
            result = self.source.discover(self.state)
        self.assertEqual(len(result), 1)

    def test_breach_added_long_ago_filtered(self):
        old_added = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat().replace("+00:00", "Z")
        breaches = [{
            "Name": "AncientBreach",
            "Title": "Ancient Breach",
            "BreachDate": "2015-01-01",
            "AddedDate": old_added,
            "PwnCount": 1000,
            "DataClasses": ["Email addresses"],
        }]
        with patch("requests.get", return_value=_make_json_response(breaches)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_required_labels_present(self):
        breaches = [{
            "Name": "LabelTestBreach",
            "Title": "Label Test Breach",
            "AddedDate": _recent_iso(),
            "PwnCount": 500,
            "DataClasses": ["Email addresses"],
        }]
        with patch("requests.get", return_value=_make_json_response(breaches)):
            result = self.source.discover(self.state)
        labels = result[0].labels
        self.assertIn("Data Breach", labels)
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)

    def test_missing_name_skipped(self):
        breaches = [{"Name": "", "Title": "No Name", "AddedDate": _recent_iso(), "PwnCount": 1}]
        with patch("requests.get", return_value=_make_json_response(breaches)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_already_published_filtered(self):
        breaches = [{
            "Name": "RepeatBreach",
            "Title": "Repeat Breach",
            "AddedDate": _recent_iso(),
            "PwnCount": 42,
            "DataClasses": ["Email addresses"],
        }]
        with patch("requests.get", return_value=_make_json_response(breaches)):
            first = self.source.discover(self.state)
        self.assertEqual(len(first), 1)
        self.state.mark_published(first[0], "post-1", "https://blogger.com/post-1")

        with patch("requests.get", return_value=_make_json_response(breaches)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])


# ─────────────────────────────────────────────────────────────────────────────
# Threat Actor Intel (AlienVault OTX)
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatActorIntelSource(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.state = PublicationState(self.config.state_file)

    def test_noop_when_key_not_configured(self):
        self.config.alienvault_otx_key = ""
        source = ThreatActorIntelSource(self.config)
        with patch("requests.get") as mock_get:
            result = source.discover(self.state)
        self.assertEqual(result, [])
        mock_get.assert_not_called()

    def test_returns_empty_on_network_failure(self):
        self.config.alienvault_otx_key = "test-otx-key"
        source = ThreatActorIntelSource(self.config)
        with patch("requests.get", side_effect=Exception("Connection refused")):
            result = source.discover(self.state)
        self.assertEqual(result, [])

    def test_returns_empty_on_non_dict_response(self):
        self.config.alienvault_otx_key = "test-otx-key"
        source = ThreatActorIntelSource(self.config)
        with patch("requests.get", return_value=_make_json_response(["unexpected", "list"])):
            result = source.discover(self.state)
        self.assertEqual(result, [])

    def test_parses_valid_pulse(self):
        self.config.alienvault_otx_key = "test-otx-key"
        source = ThreatActorIntelSource(self.config)
        data = {
            "results": [{
                "id": "abc123",
                "name": "APT41 Targeting Telecom Sector",
                "description": "New campaign attributed to APT41 targeting telecom infrastructure.",
                "adversary": "APT41",
                "tags": ["apt41", "telecom", "espionage"],
                "created": _recent_iso(),
            }]
        }
        with patch("requests.get", return_value=_make_json_response(data)):
            result = source.discover(self.state)
        self.assertEqual(len(result), 1)
        article = result[0]
        self.assertEqual(article.source, "threat_actor_intel")
        self.assertIn("APT41", article.title)

    def test_required_labels_present(self):
        self.config.alienvault_otx_key = "test-otx-key"
        source = ThreatActorIntelSource(self.config)
        data = {
            "results": [{
                "id": "abc124",
                "name": "Test Pulse",
                "description": "Test description.",
                "created": _recent_iso(),
            }]
        }
        with patch("requests.get", return_value=_make_json_response(data)):
            result = source.discover(self.state)
        labels = result[0].labels
        self.assertIn("APT", labels)
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)

    def test_sends_api_key_header(self):
        self.config.alienvault_otx_key = "secret-otx-key-999"
        source = ThreatActorIntelSource(self.config)
        with patch("requests.get", return_value=_make_json_response({"results": []})) as mock_get:
            source.discover(self.state)
        self.assertTrue(mock_get.called)
        headers_used = mock_get.call_args[1].get("headers", {})
        self.assertEqual(headers_used.get("X-OTX-API-KEY"), "secret-otx-key-999")

    def test_already_published_filtered(self):
        self.config.alienvault_otx_key = "test-otx-key"
        source = ThreatActorIntelSource(self.config)
        data = {
            "results": [{
                "id": "repeat-1",
                "name": "Repeat Pulse",
                "description": "desc",
                "created": _recent_iso(),
            }]
        }
        with patch("requests.get", return_value=_make_json_response(data)):
            first = source.discover(self.state)
        self.assertEqual(len(first), 1)
        self.state.mark_published(first[0], "post-1", "https://blogger.com/post-1")

        with patch("requests.get", return_value=_make_json_response(data)):
            result = source.discover(self.state)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
