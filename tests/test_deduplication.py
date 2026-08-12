"""
Tests for deduplication — end-to-end duplicate prevention across runs.
"""

import os
import tempfile
import unittest
from datetime import datetime, timezone

from automation.content_discovery import (
    DiscoveredArticle,
    PublicationState,
    _compute_hash,
    _extract_cve_ids_from_text,
)


def _article(i: int = 0) -> DiscoveredArticle:
    url = f"https://blog.cyberdudebivash.in/posts/article-{i}"
    title = f"Threat Article Number {i}"
    return DiscoveredArticle(
        url=url,
        title=title,
        summary=f"Summary of article {i}",
        published_at=datetime.now(timezone.utc).isoformat(),
        content_hash=_compute_hash(url, title),
        labels=["Threat Intelligence"],
        source="rss",
    )


class TestDeduplication(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.tmpdir, "state.json")

    def test_article_not_duplicate_when_not_published(self):
        state = PublicationState(self.state_file)
        a = _article(1)
        self.assertFalse(state.is_published(a.content_hash))

    def test_article_is_duplicate_after_marking(self):
        state = PublicationState(self.state_file)
        a = _article(1)
        state.mark_published(a, "post-1", "https://blogger.com/1")
        self.assertTrue(state.is_published(a.content_hash))

    def test_different_articles_not_duplicate(self):
        state = PublicationState(self.state_file)
        a1 = _article(1)
        a2 = _article(2)
        state.mark_published(a1, "post-1", "https://blogger.com/1")
        self.assertFalse(state.is_published(a2.content_hash))

    def test_state_persists_across_instances(self):
        """Simulates two separate pipeline runs."""
        # Run 1
        state1 = PublicationState(self.state_file)
        a = _article(99)
        state1.mark_published(a, "post-99", "https://blogger.com/99")

        # Run 2 (new instance, same file)
        state2 = PublicationState(self.state_file)
        self.assertTrue(state2.is_published(a.content_hash))

    def test_100_articles_all_tracked(self):
        state = PublicationState(self.state_file)
        articles = [_article(i) for i in range(100)]
        for i, a in enumerate(articles):
            state.mark_published(a, f"post-{i}", f"https://blogger.com/{i}")

        state2 = PublicationState(self.state_file)
        for a in articles:
            self.assertTrue(state2.is_published(a.content_hash))
        self.assertEqual(state2.total_published, 100)

    def test_same_url_different_title_different_hash(self):
        """URL canonicalised with title — title change = new hash."""
        url = "https://blog.cyberdudebivash.in/posts/article"
        h1 = _compute_hash(url, "Original Title")
        h2 = _compute_hash(url, "Updated Title")
        self.assertNotEqual(h1, h2)

    def test_hash_stable_with_url_whitespace(self):
        h1 = _compute_hash("https://example.com/post ", "Title")
        h2 = _compute_hash("https://example.com/post", "Title")
        self.assertEqual(h1, h2)

    def test_hash_stable_with_title_case(self):
        h1 = _compute_hash("https://example.com/post", "CRITICAL CVE ALERT")
        h2 = _compute_hash("https://example.com/post", "critical cve alert")
        self.assertEqual(h1, h2)

    def test_failure_recording_does_not_mark_published(self):
        state = PublicationState(self.state_file)
        a = _article(50)
        state.record_failure(a.url, "Network error")
        self.assertFalse(state.is_published(a.content_hash))

    def test_published_count_accurate_after_reload(self):
        state = PublicationState(self.state_file)
        for i in range(7):
            a = _article(i)
            state.mark_published(a, f"post-{i}", f"https://blogger.com/{i}")

        state2 = PublicationState(self.state_file)
        self.assertEqual(state2.total_published, 7)


class TestCVEDeduplication(unittest.TestCase):
    """Cross-source CVE deduplication — same CVE from NVD + CISA KEV."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.tmpdir, "state.json")

    def _cve_article(self, cve_id: str, source: str) -> DiscoveredArticle:
        url = f"https://source.example.com/{cve_id.lower()}-{source}"
        title = f"{cve_id} — CVSS 9.8 CRITICAL Severity | Patch Required"
        return DiscoveredArticle(
            url=url,
            title=title,
            summary=f"Description of {cve_id} vulnerability.",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=_compute_hash(url, title),
            labels=["Vulnerabilities", "Critical CVE"],
            source=source,
        )

    def test_is_cve_published_returns_false_initially(self):
        state = PublicationState(self.state_file)
        self.assertFalse(state.is_cve_published("CVE-2026-1234"))

    def test_is_cve_published_returns_true_after_mark(self):
        state = PublicationState(self.state_file)
        article = self._cve_article("CVE-2026-5678", "nvd")
        state.mark_published(article, "post-1", "https://blogger.com/1")
        self.assertTrue(state.is_cve_published("CVE-2026-5678"))

    def test_is_cve_published_case_insensitive(self):
        state = PublicationState(self.state_file)
        article = self._cve_article("CVE-2026-9999", "cisa_kev")
        state.mark_published(article, "post-2", "https://blogger.com/2")
        self.assertTrue(state.is_cve_published("cve-2026-9999"))
        self.assertTrue(state.is_cve_published("CVE-2026-9999"))

    def test_different_cve_not_considered_published(self):
        state = PublicationState(self.state_file)
        article = self._cve_article("CVE-2026-1111", "nvd")
        state.mark_published(article, "post-3", "https://blogger.com/3")
        self.assertFalse(state.is_cve_published("CVE-2026-2222"))

    def test_extract_cve_ids_from_title(self):
        cves = _extract_cve_ids_from_text("CVE-2026-1234 — CVSS 9.8 CRITICAL")
        self.assertEqual(cves, ["CVE-2026-1234"])

    def test_extract_multiple_cve_ids(self):
        cves = _extract_cve_ids_from_text("CVE-2026-1111 and CVE-2026-2222")
        self.assertEqual(len(cves), 2)
        self.assertIn("CVE-2026-1111", cves)

    def test_extract_cve_ids_deduped(self):
        cves = _extract_cve_ids_from_text("CVE-2026-1234 and CVE-2026-1234 again")
        self.assertEqual(cves.count("CVE-2026-1234"), 1)

    def test_cve_ids_stored_on_mark_published(self):
        state = PublicationState(self.state_file)
        article = self._cve_article("CVE-2026-3333", "nvd")
        state.mark_published(article, "post-4", "https://blogger.com/4")

        state2 = PublicationState(self.state_file)
        self.assertTrue(state2.is_cve_published("CVE-2026-3333"))


class TestRetryQueue(unittest.TestCase):
    """Retry queue for failed publication attempts."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.tmpdir, "state.json")

    def _article(self, i: int = 0) -> DiscoveredArticle:
        url = f"https://example.com/article-{i}"
        title = f"Article {i}"
        return DiscoveredArticle(
            url=url,
            title=title,
            summary=f"Summary {i}",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=_compute_hash(url, title),
            labels=["Vulnerabilities"],
            source="nvd",
        )

    def test_retry_queue_empty_initially(self):
        state = PublicationState(self.state_file)
        self.assertEqual(state.get_retry_queue(), [])

    def test_add_to_retry_queue(self):
        state = PublicationState(self.state_file)
        a = self._article(1)
        state.add_to_retry_queue(a, "HTTP 503")
        queue = state.get_retry_queue()
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["content_hash"], a.content_hash)
        self.assertEqual(queue[0]["last_error"], "HTTP 503")

    def test_retry_queue_persists_across_instances(self):
        state = PublicationState(self.state_file)
        a = self._article(2)
        state.add_to_retry_queue(a, "timeout")

        state2 = PublicationState(self.state_file)
        queue = state2.get_retry_queue()
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["url"], a.url)

    def test_retry_queue_cleared_on_success(self):
        state = PublicationState(self.state_file)
        a = self._article(3)
        state.add_to_retry_queue(a, "error")
        state.mark_published(a, "post-x", "https://blogger.com/x")

        state2 = PublicationState(self.state_file)
        self.assertEqual(len(state2.get_retry_queue()), 0)

    def test_success_clears_stale_retry_with_same_url_and_different_hash(self):
        state = PublicationState(self.state_file)
        stale = self._article(30)
        state.add_to_retry_queue(stale, "legacy placeholder")

        fresh = self._article(30)
        fresh.title = "Normalized title"
        fresh.content_hash = _compute_hash(fresh.url, fresh.title)
        state.mark_published(fresh, "post-normalized", "https://blogger.com/normalized")

        state2 = PublicationState(self.state_file)
        self.assertEqual(state2.get_retry_queue(), [])

    def test_retry_queue_max_3_attempts(self):
        state = PublicationState(self.state_file)
        a = self._article(4)
        # Simulate 4 attempts
        for i in range(4):
            state.add_to_retry_queue(a, f"error attempt {i+1}")

        # get_retry_queue filters items with attempts > 3
        queue = state.get_retry_queue()
        self.assertEqual(len(queue), 0)

    def test_different_articles_in_queue(self):
        state = PublicationState(self.state_file)
        a1 = self._article(10)
        a2 = self._article(11)
        state.add_to_retry_queue(a1, "error")
        state.add_to_retry_queue(a2, "error")
        self.assertEqual(len(state.get_retry_queue()), 2)


if __name__ == "__main__":
    unittest.main()
