"""Tests for main.py's early-break requeue safeguard.

Analysis of logs/run-*.json (4019 historical run reports) showed the
publish loop's `break` on BloggerRateLimitError/BloggerAuthError only ever
queued the one article that triggered the error for retry — every other
discovered-but-not-yet-attempted article in that run's batch was silently
dropped from the report, relying on being rediscovered from its original
source on a later run (not guaranteed for sources with a small rolling
window, e.g. RSS feeds). 21.5% of all runs hit this path historically;
effectively 100% of the most recent 100 runs did, since Blogger's rate
limit is now hit before every discovered batch is exhausted.
"""
from unittest.mock import Mock

from automation.content_discovery import DiscoveredArticle
from automation.main import _merge_retry_and_fresh, _pipeline_exit_code, _requeue_unattempted


def _article(n):
    return DiscoveredArticle(
        url=f"https://example.com/{n}",
        title=f"Article {n}",
        summary="summary",
        published_at="2026-07-28T00:00:00Z",
        content_hash=f"hash{n}",
        labels=["Threat Intelligence"],
        source="global_rss",
    )


def test_requeues_every_remaining_article_with_the_triggering_error():
    state = Mock()
    remaining = [_article(1), _article(2), _article(3)]

    count = _requeue_unattempted(remaining, state, "HTTP 429 rate limited")

    assert count == 3
    assert state.add_to_retry_queue.call_count == 3
    for call, article in zip(state.add_to_retry_queue.call_args_list, remaining):
        called_article, called_reason = call.args
        assert called_article is article
        assert called_reason == "not attempted — pipeline stopped early: HTTP 429 rate limited"


def test_empty_remaining_list_is_a_no_op():
    state = Mock()
    count = _requeue_unattempted([], state, "some error")
    assert count == 0
    state.add_to_retry_queue.assert_not_called()


def test_partial_success_still_returns_failure_exit_code():
    assert _pipeline_exit_code({"published": 2, "failed": 1}) == 1


def test_clean_run_returns_success_exit_code():
    assert _pipeline_exit_code({"published": 2, "failed": 0}) == 0


def test_fresh_article_replaces_stale_retry_with_same_source_url():
    stale = _article(1)
    stale.content_hash = "old-template-hash"
    fresh = _article(1)
    fresh.title = "Article 1 without placeholder taxonomy"
    fresh.content_hash = "new-template-hash"
    state = Mock()
    state.is_published.return_value = False
    state.is_source_url_published.return_value = False

    merged = _merge_retry_and_fresh([stale], [fresh], state)

    assert merged == [fresh]


def test_published_source_url_suppresses_legacy_retry_hash():
    stale = _article(2)
    stale.content_hash = "legacy-hash"
    state = Mock()
    state.is_published.return_value = False
    state.is_source_url_published.return_value = True

    assert _merge_retry_and_fresh([stale], [], state) == []
