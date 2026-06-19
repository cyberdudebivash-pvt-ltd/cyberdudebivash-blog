"""CYBERDUDEBIVASH® SENTINEL APEX — Global Threat Intelligence RSS Aggregator

Polls 25+ of the world's leading cybersecurity publishers and vendor research
blogs in parallel, surfacing breaking CVEs, malware/ransomware campaigns,
APT activity, and security news for analyst-grade syndication.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests

from .config import Config
from .content_discovery import (
    DiscoveredArticle,
    PublicationState,
    _compute_hash,
    _infer_labels,
    _is_recent,
    _parse_feed_items,
    _parse_rfc_date,
)
from .logger import setup_logger

logger = setup_logger("rss_aggregator")

_FEED_TIMEOUT_SECONDS = 7
_MAX_ITEMS_PER_FEED = 4
_MAX_WORKERS = 10


@dataclass(frozen=True)
class _Feed:
    name: str
    url: str


_GLOBAL_FEEDS: tuple[_Feed, ...] = (
    _Feed("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    _Feed("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    _Feed("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    _Feed("Dark Reading", "https://www.darkreading.com/rss.xml"),
    _Feed("SecurityWeek", "https://www.securityweek.com/feed/"),
    _Feed("Security Affairs", "https://securityaffairs.com/feed"),
    _Feed("The Record", "https://therecord.media/feed"),
    _Feed("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/"),
    _Feed("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    _Feed("GBHackers Security", "https://gbhackers.com/feed/"),
    _Feed("HackRead", "https://www.hackread.com/feed/"),
    _Feed("CyberScoop", "https://cyberscoop.com/feed/"),
    _Feed("SC Media", "https://www.scmagazine.com/feed/"),
    _Feed("CSO Online", "https://www.csoonline.com/index.rss"),
    _Feed("Schneier on Security", "https://www.schneier.com/feed/atom/"),
    _Feed("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed_full.xml"),
    _Feed("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    _Feed("Google Security Blog", "https://security.googleblog.com/feeds/posts/default"),
    _Feed("Cisco Talos Intelligence", "https://blog.talosintelligence.com/rss/"),
    _Feed("Palo Alto Unit42", "https://unit42.paloaltonetworks.com/feed/"),
    _Feed("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/"),
    _Feed("Kaspersky Securelist", "https://securelist.com/feed/"),
    _Feed("ESET WeLiveSecurity", "https://www.welivesecurity.com/feed/"),
    _Feed("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml"),
    _Feed("Sophos News", "https://news.sophos.com/en-us/feed/"),
    _Feed("Tripwire State of Security", "https://www.tripwire.com/state-of-security/feed"),
    _Feed("Reddit r/netsec", "https://www.reddit.com/r/netsec/.rss"),
)


class GlobalRSSAggregator:
    """Fetches breaking cybersecurity news from 25+ global publishers in parallel."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        """Return new DiscoveredArticle entries gathered from all global feeds."""
        articles: list[DiscoveredArticle] = []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._fetch_feed, feed): feed for feed in _GLOBAL_FEEDS
            }
            for future in as_completed(futures):
                feed = futures[future]
                try:
                    items = future.result()
                except Exception as e:
                    logger.warning("Global feed failed", extra={"feed": feed.name, "error": str(e)})
                    continue
                for item in items:
                    article = self._to_article(feed, item, state)
                    if article is not None:
                        articles.append(article)

        logger.info(
            "Global RSS aggregation complete",
            extra={"feeds_polled": len(_GLOBAL_FEEDS), "new_articles": len(articles)},
        )
        return articles

    def _fetch_feed(self, feed: _Feed) -> list[dict]:
        """Fetch and parse a single feed; returns [] on any network/parse failure."""
        try:
            resp = requests.get(
                feed.url,
                timeout=_FEED_TIMEOUT_SECONDS,
                headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
            )
            resp.raise_for_status()
        except Exception as e:
            logger.warning("Feed fetch failed", extra={"feed": feed.name, "error": str(e)})
            return []

        try:
            items = _parse_feed_items(resp.text)
        except Exception as e:
            logger.warning("Feed parse failed", extra={"feed": feed.name, "error": str(e)})
            return []

        return items[:_MAX_ITEMS_PER_FEED]

    def _to_article(self, feed: _Feed, item: dict, state: PublicationState) -> Optional[DiscoveredArticle]:
        url = item.get("url", "")
        title = item.get("title", "")
        if not url or not title:
            return None

        pub_date = _parse_rfc_date(item.get("pub_date", ""))
        if not _is_recent(pub_date, self.config.max_article_age_hours):
            return None

        content_hash = _compute_hash(url, title)
        if state.is_published(content_hash):
            return None

        summary = item.get("summary", "")
        labels = _infer_labels(title, summary)
        for required_label in ["CYBERDUDEBIVASH", "Threat Intelligence", "Global Intel"]:
            if required_label not in labels:
                labels.append(required_label)

        pub_iso = pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()
        full_content = f"Source Publisher: {feed.name}\nOriginal Article: {url}\n\n{summary}"

        return DiscoveredArticle(
            url=url,
            title=title,
            summary=summary,
            published_at=pub_iso,
            content_hash=content_hash,
            labels=labels,
            source="global_rss",
            full_content=full_content,
        )
