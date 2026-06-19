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


if __name__ == "__main__":
    unittest.main()
