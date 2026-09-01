"""Local canonical RSS handoff for Blogger syndication.

The primary Sentinel pipeline writes ``rss.xml`` in the same repository before
Blogger syndication runs.  Reading that artifact locally removes an unnecessary
CDN/deployment-propagation dependency while preserving the exact semantic shape
of the existing remote own-RSS discovery path (same source discriminator,
content identity, recency policy, and evidence summary).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

from bs4 import BeautifulSoup

from .config import Config
from .content_discovery import (
    DiscoveredArticle,
    PublicationState,
    _compute_hash,
    _infer_labels,
    _is_recent,
    _parse_rfc_date,
)
from .logger import setup_logger
from .seo_optimizer import _truncate

logger = setup_logger("canonical_rss")


def _text(item: ET.Element, tag: str) -> str:
    element = item.find(tag)
    return (element.text or "").strip() if element is not None else ""


def discover_local_canonical_rss(
    config: Config,
    state: PublicationState,
    rss_path: str | Path = "rss.xml",
    max_items: int = 100,
) -> list[DiscoveredArticle]:
    """Return unpublished articles from the checked-out canonical ``rss.xml``.

    Missing or malformed local RSS fails open to the existing remote discovery
    path; this helper never performs a network request and never marks state.
    """
    path = Path(rss_path)
    if not path.is_file():
        logger.info("Canonical local RSS unavailable; remote RSS remains fallback", extra={"path": str(path)})
        return []

    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ET.ParseError) as exc:
        logger.warning(
            "Canonical local RSS unreadable; remote RSS remains fallback",
            extra={"path": str(path), "error": str(exc)},
        )
        return []

    articles: list[DiscoveredArticle] = []
    for item in root.findall(".//item")[: max(1, int(max_items))]:
        title = _text(item, "title")
        url = _text(item, "link")
        if not title or not url:
            continue

        pub_date = _parse_rfc_date(_text(item, "pubDate"))
        if not _is_recent(pub_date, config.max_article_age_hours):
            continue

        raw_summary = _text(item, "description")
        summary = _truncate(
            BeautifulSoup(raw_summary, "lxml").get_text(separator=" ", strip=True),
            1500,
        )
        content_hash = _compute_hash(url, title)
        if state.is_published(content_hash) or state.is_source_url_published(url):
            continue

        labels = _infer_labels(title, summary)
        for category in item.findall("category"):
            value = (category.text or "").strip()
            if value and value not in labels:
                labels.append(value)
        for required in ("CYBERDUDEBIVASH", "Threat Intelligence"):
            if required not in labels:
                labels.append(required)

        pub_iso = (
            pub_date.isoformat()
            if pub_date is not None
            else datetime.now(timezone.utc).isoformat()
        )
        articles.append(
            DiscoveredArticle(
                url=url,
                title=title,
                summary=summary,
                published_at=pub_iso,
                content_hash=content_hash,
                labels=labels,
                # Preserve the existing own-RSS semantic contract.  This is
                # only a transport/handoff improvement, not a new evidence
                # source type.
                source="rss",
                source_publisher="CYBERDUDEBIVASH",
            )
        )

    articles.sort(key=lambda article: article.published_at, reverse=True)
    logger.info(
        "Canonical local RSS parsed",
        extra={"path": str(path), "new": len(articles)},
    )
    return articles
