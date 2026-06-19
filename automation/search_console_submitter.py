"""
CYBERDUDEBIVASH® SENTINEL APEX — Google Search Console Submitter
Submits newly published Blogger URLs to Google Indexing API and pings sitemap.
"""

import json
import time
from typing import Optional

import requests

from .config import Config
from .logger import setup_logger

logger = setup_logger("search_console_submitter")

INDEXING_API_URL = "https://indexing.googleapis.com/v3/urlNotifications:publish"
SITEMAP_PING_URL = "https://www.google.com/ping"


class SearchConsoleSubmitter:
    """Submits new Blogger URLs to Google for rapid indexing."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def submit_url(self, url: str) -> bool:
        """
        Submit a URL to Google Indexing API.
        Requires GOOGLE_SEARCH_CONSOLE_KEY (service account key JSON or API key).
        Falls back to sitemap ping if API key unavailable.
        """
        if self.config.google_search_console_key:
            return self._submit_via_indexing_api(url)
        return self._submit_via_sitemap_ping(url)

    def _submit_via_indexing_api(self, url: str) -> bool:
        """Submit via Google Indexing API (fastest indexing path)."""
        try:
            payload = {"url": url, "type": "URL_UPDATED"}
            resp = requests.post(
                INDEXING_API_URL,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.config.google_search_console_key}",
                },
                timeout=15,
            )
            if resp.ok:
                logger.info("Google Indexing API submission success", extra={"url": url})
                return True
            logger.warning(
                "Indexing API returned non-OK",
                extra={"url": url, "status": resp.status_code, "body": resp.text[:200]},
            )
            return False
        except Exception as e:
            logger.warning("Indexing API failed", extra={"url": url, "error": str(e)})
            return False

    def _submit_via_sitemap_ping(self, url: str) -> bool:
        """Fallback: ping Google with the Blogger sitemap URL."""
        blog_sitemap = f"{self.config.target_blog_url}/sitemap.xml"
        try:
            resp = requests.get(
                SITEMAP_PING_URL,
                params={"sitemap": blog_sitemap},
                timeout=10,
            )
            logger.info(
                "Sitemap ping sent",
                extra={"sitemap": blog_sitemap, "status": resp.status_code},
            )
            return resp.status_code < 400
        except Exception as e:
            logger.warning("Sitemap ping failed", extra={"error": str(e)})
            return False

    def submit_batch(self, urls: list[str], delay_seconds: float = 1.0) -> dict:
        """Submit multiple URLs with rate limiting."""
        results = {"success": [], "failed": []}
        for url in urls:
            if self.submit_url(url):
                results["success"].append(url)
            else:
                results["failed"].append(url)
            if len(urls) > 1:
                time.sleep(delay_seconds)
        logger.info(
            "Batch submission complete",
            extra={"success": len(results["success"]), "failed": len(results["failed"])},
        )
        return results
