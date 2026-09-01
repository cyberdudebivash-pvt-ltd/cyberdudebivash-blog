"""
CYBERDUDEBIVASH® SENTINEL APEX — Search Discovery Coordinator

Generic CTI/news articles must not be pushed through Google's Indexing API:
Google documents that API for JobPosting and BroadcastEvent/VideoObject pages.
Google's unauthenticated sitemap ping endpoint is also retired and returns 404.

For normal threat-intelligence publication, discovery is therefore delegated to
standards-compliant surfaces already owned by this repository: sitemap.xml,
robots.txt (which advertises that sitemap), and RSS.  ``submit_url`` remains as
an API-compatible post-publication hook so the publisher does not need a risky
or noisy network call after every Blogger write.
"""

import time
from urllib.parse import urlparse

from .config import Config
from .logger import setup_logger

logger = setup_logger("search_console_submitter")


class SearchConsoleSubmitter:
    """Coordinate search discovery for newly published generic CTI pages.

    The historical implementation attempted two unsupported/deprecated paths:

    * ``https://www.google.com/ping`` — Google's sitemap ping endpoint is
      retired and intentionally returns HTTP 404.
    * Google Indexing API — documented for pages containing ``JobPosting`` or
      ``BroadcastEvent`` embedded in ``VideoObject``, not ordinary CTI/news
      articles.

    The production-safe contract is now deliberately network-free.  The site
    publishes ``sitemap.xml`` and advertises it from ``robots.txt``; Google can
    discover the canonical URLs through those surfaces without a per-article
    submission request.  Keeping this hook lets callers preserve sequencing and
    observability while avoiding false failures and policy-inappropriate API
    traffic.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    @staticmethod
    def _is_valid_public_url(url: str) -> bool:
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def submit_url(self, url: str) -> bool:
        """Record that a valid published URL is ready for crawler discovery.

        No external request is issued.  ``True`` means the URL passed the local
        discovery contract and is expected to be discoverable through the
        site's sitemap/RSS surfaces; it does **not** claim that Google indexed
        the URL or accepted a submission.
        """
        if not self._is_valid_public_url(url):
            logger.warning("Search discovery skipped for invalid URL", extra={"url": url})
            return False

        logger.info(
            "Search discovery delegated to sitemap/RSS",
            extra={
                "url": url,
                "sitemap": self.config.source_sitemap_url,
                "mode": "standards_discovery",
            },
        )
        return True

    def submit_batch(self, urls: list[str], delay_seconds: float = 0.0) -> dict:
        """Validate a batch for sitemap/RSS discovery without network pings."""
        results = {"success": [], "failed": []}
        for url in urls:
            if self.submit_url(url):
                results["success"].append(url)
            else:
                results["failed"].append(url)
            if delay_seconds > 0 and len(urls) > 1:
                time.sleep(delay_seconds)
        logger.info(
            "Search discovery batch prepared",
            extra={"success": len(results["success"]), "failed": len(results["failed"])},
        )
        return results
