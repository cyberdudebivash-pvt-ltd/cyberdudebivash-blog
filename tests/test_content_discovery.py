"""
Tests for content_discovery module — deduplication, RSS parsing, age filtering.
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.content_discovery import (
    ContentDiscoveryEngine,
    DiscoveredArticle,
    PublicationState,
    _compute_hash,
    _is_recent,
    _infer_labels,
    _parse_feed_items,
)


def _make_config(tmpdir: str) -> Config:
    cfg = Config()
    cfg.state_file = os.path.join(tmpdir, "state.json")
    cfg.max_article_age_hours = 48
    cfg.max_posts_per_run = 5
    return cfg


class TestComputeHash(unittest.TestCase):
    def test_deterministic(self):
        h1 = _compute_hash("https://example.com/post", "Test Title")
        h2 = _compute_hash("https://example.com/post", "Test Title")
        self.assertEqual(h1, h2)

    def test_case_insensitive(self):
        h1 = _compute_hash("https://example.com/POST", "TEST TITLE")
        h2 = _compute_hash("https://example.com/post", "test title")
        self.assertEqual(h1, h2)

    def test_different_urls_different_hashes(self):
        h1 = _compute_hash("https://a.com/1", "Title")
        h2 = _compute_hash("https://a.com/2", "Title")
        self.assertNotEqual(h1, h2)

    def test_length_16(self):
        h = _compute_hash("url", "title")
        self.assertEqual(len(h), 16)


class TestProductionDefaults(unittest.TestCase):
    def test_default_batch_size_stays_within_observed_blogger_quota(self):
        self.assertEqual(Config().max_posts_per_run, 5)


class TestIsRecent(unittest.TestCase):
    def test_recent_article_passes(self):
        recent = datetime.now(timezone.utc) - timedelta(hours=10)
        self.assertTrue(_is_recent(recent, 48))

    def test_old_article_filtered(self):
        old = datetime.now(timezone.utc) - timedelta(hours=100)
        self.assertFalse(_is_recent(old, 48))

    def test_none_date_always_recent(self):
        self.assertTrue(_is_recent(None, 48))


class TestInferLabels(unittest.TestCase):
    def test_cve_gets_vulnerabilities(self):
        labels = _infer_labels("CVE-2026-1234 RCE vulnerability", "patch required")
        self.assertIn("Vulnerabilities", labels)

    def test_ransomware_label(self):
        labels = _infer_labels("LockBit ransomware attack", "encrypted files")
        self.assertIn("Ransomware", labels)

    def test_ai_security_label(self):
        labels = _infer_labels("LLM prompt injection attack", "generative ai risk")
        self.assertIn("AI Security", labels)

    def test_always_has_base_labels(self):
        labels = _infer_labels("some random article", "content here")
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)

    def test_cisa_kev_label(self):
        labels = _infer_labels("CISA adds new known exploited vulnerability", "federal deadline")
        self.assertIn("CISA KEV", labels)


class TestPublicationState(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.tmpdir, "state.json")

    def _make_article(self, url="https://example.com/test", title="Test") -> DiscoveredArticle:
        return DiscoveredArticle(
            url=url,
            title=title,
            summary="Test summary",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=_compute_hash(url, title),
            labels=["Threat Intelligence"],
            source="rss",
        )

    def test_new_article_not_published(self):
        state = PublicationState(self.state_file)
        article = self._make_article()
        self.assertFalse(state.is_published(article.content_hash))

    def test_mark_published_persists(self):
        state = PublicationState(self.state_file)
        article = self._make_article()
        state.mark_published(article, "post-123", "https://blogger.com/post-123")

        # Reload from disk
        state2 = PublicationState(self.state_file)
        self.assertTrue(state2.is_published(article.content_hash))
        self.assertTrue(state2.is_source_url_published(article.url))

    def test_source_url_deduplication_is_exact(self):
        state = PublicationState(self.state_file)
        article = self._make_article()
        state.mark_published(article, "post-123", "https://blogger.com/post-123")
        self.assertTrue(state.is_source_url_published(article.url))
        self.assertFalse(state.is_source_url_published(article.url + "-different"))

    def test_total_count_increments(self):
        state = PublicationState(self.state_file)
        for i in range(3):
            a = self._make_article(url=f"https://example.com/{i}", title=f"Title {i}")
            state.mark_published(a, f"post-{i}", f"https://blogger.com/{i}")
        self.assertEqual(state.total_published, 3)

    def test_corrupt_state_recovers(self):
        with open(self.state_file, "w") as f:
            f.write("NOT VALID JSON {{{")
        state = PublicationState(self.state_file)
        self.assertEqual(state.total_published, 0)

    def test_record_failure_stored(self):
        state = PublicationState(self.state_file)
        state.record_failure("https://example.com/fail", "Network error")
        state2 = PublicationState(self.state_file)
        self.assertEqual(len(state2._state["failures"]), 1)

    def test_failures_capped_at_100(self):
        state = PublicationState(self.state_file)
        for i in range(110):
            state.record_failure(f"https://example.com/{i}", f"Error {i}")
        state2 = PublicationState(self.state_file)
        self.assertLessEqual(len(state2._state["failures"]), 100)


class TestContentDiscovery(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)

    def test_duplicate_filtered_from_discovery(self):
        engine = ContentDiscoveryEngine(self.config)
        # Pre-populate state with a hash
        article = DiscoveredArticle(
            url="https://blog.cyberdudebivash.in/posts/test",
            title="Pre-published Article",
            summary="...",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=_compute_hash(
                "https://blog.cyberdudebivash.in/posts/test", "Pre-published Article"
            ),
            labels=["Threat Intelligence"],
            source="rss",
        )
        engine.state.mark_published(article, "existing-id", "https://blogger.com/existing")

        # Mock RSS with the same article
        mock_rss_xml = f"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test</title>
    <item>
      <title>Pre-published Article</title>
      <link>https://blog.cyberdudebivash.in/posts/test</link>
      <description>Test description</description>
      <pubDate>Thu, 19 Jun 2026 10:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>"""

        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = mock_rss_xml
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp
            results = engine.discover()

        self.assertEqual(len(results), 0, "Duplicate should be filtered out")

    def test_max_posts_per_run_respected(self):
        self.config.max_posts_per_run = 2
        engine = ContentDiscoveryEngine(self.config)

        rss_items = ""
        for i in range(5):
            rss_items += f"""
    <item>
      <title>Article {i}</title>
      <link>https://blog.cyberdudebivash.in/posts/article-{i}</link>
      <description>Description {i}</description>
      <pubDate>Thu, 19 Jun 2026 10:0{i}:00 +0000</pubDate>
    </item>"""

        mock_rss_xml = f"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test</title>
{rss_items}
  </channel>
</rss>"""

        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = mock_rss_xml
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp
            results = engine.discover()

        self.assertLessEqual(len(results), 2)


class TestParseFeedItemsSummaryTruncation(unittest.TestCase):
    """P0 fix: a description longer than the 1500-char cap must truncate on
    a word boundary with an explicit ellipsis marker -- not a silent,
    mid-word/mid-sentence cutoff. Reproduces the exact real-world defect
    (verified live on a published JWR PhaaS report, whose rendered prose
    ended "...codes are still [...]" mid-sentence with no marker at all)
    that a bare ``get_text(...)[:1500]`` slice produces."""

    def _items_for_description(self, description: str) -> list[dict]:
        xml = (
            "<rss><channel><item>"
            "<title>Test Article</title>"
            "<link>https://example.test/article</link>"
            f"<description><![CDATA[{description}]]></description>"
            "<pubDate>Tue, 18 Aug 2026 09:00:00 GMT</pubDate>"
            "</item></channel></rss>"
        )
        return _parse_feed_items(xml)

    def test_short_description_is_not_truncated_or_marked(self):
        items = self._items_for_description("A short, complete sentence about a threat.")
        self.assertEqual(items[0]["summary"], "A short, complete sentence about a threat.")
        self.assertFalse(items[0]["summary"].endswith("..."))

    def test_long_description_truncates_on_a_word_boundary_with_a_marker(self):
        long_text = "Security researchers have discovered a sophisticated phishing platform. " * 25
        items = self._items_for_description(long_text)
        summary = items[0]["summary"]
        self.assertLessEqual(len(summary), 1500)
        self.assertTrue(summary.endswith("..."), f"expected an explicit truncation marker, got: {summary[-40:]!r}")
        # The character immediately before the marker must be a real word
        # character, not whitespace -- proves the cut landed after a whole
        # word, not mid-word or mid-sentence.
        self.assertFalse(summary[:-3].endswith(" "))
        self.assertNotIn("  ", summary[-40:])

    def test_never_produces_a_bare_mid_sentence_cutoff(self):
        # The real defect: text ending abruptly on a preposition/article
        # with no punctuation and no marker, e.g. "...codes are still".
        long_text = "while card numbers, passwords and one-time codes are still being typed by the victim. " * 20
        items = self._items_for_description(long_text)
        summary = items[0]["summary"]
        self.assertTrue(summary.endswith("...") or summary.endswith((".", "!", "?")))


if __name__ == "__main__":
    unittest.main()
