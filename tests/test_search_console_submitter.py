"""Regression tests for standards-compliant search discovery."""

from automation.config import Config
from automation.search_console_submitter import SearchConsoleSubmitter


def test_generic_cti_url_uses_no_deprecated_or_ineligible_google_api(monkeypatch):
    """A normal CTI article must not call sitemap ping or Indexing API."""
    def forbidden(*args, **kwargs):
        raise AssertionError("search discovery attempted an external HTTP submission")

    # Guard against future reintroduction through requests, even though the
    # current coordinator intentionally has no requests dependency.
    import requests
    monkeypatch.setattr(requests, "get", forbidden)
    monkeypatch.setattr(requests, "post", forbidden)

    config = Config(
        google_search_console_key="not-used-for-generic-cti",
        source_sitemap_url="https://blog.cyberdudebivash.in/sitemap.xml",
    )
    submitter = SearchConsoleSubmitter(config)

    assert submitter.submit_url(
        "https://cti.cyberdudebivash.in/2026/09/example-threat-report.html"
    ) is True


def test_invalid_url_fails_local_discovery_contract():
    submitter = SearchConsoleSubmitter(Config())
    assert submitter.submit_url("not-a-public-url") is False
    assert submitter.submit_url("") is False


def test_batch_preserves_success_failure_accounting_without_sleep(monkeypatch):
    submitter = SearchConsoleSubmitter(Config())

    def forbidden_sleep(*args, **kwargs):
        raise AssertionError("network-free discovery batch should not sleep by default")

    monkeypatch.setattr("automation.search_console_submitter.time.sleep", forbidden_sleep)
    result = submitter.submit_batch([
        "https://cti.cyberdudebivash.in/report-a.html",
        "bad-url",
        "https://cti.cyberdudebivash.in/report-b.html",
    ])

    assert result == {
        "success": [
            "https://cti.cyberdudebivash.in/report-a.html",
            "https://cti.cyberdudebivash.in/report-b.html",
        ],
        "failed": ["bad-url"],
    }
