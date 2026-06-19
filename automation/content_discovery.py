"""
CYBERDUDEBIVASH® SENTINEL APEX — Content Discovery Engine
Detects new threat intelligence content via RSS, sitemap, and live feed.
Tracks published state to prevent duplicate syndication.
"""

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import xml.etree.ElementTree as ET

import requests
from bs4 import BeautifulSoup

from .config import Config
from .logger import setup_logger

logger = setup_logger("content_discovery")


@dataclass
class DiscoveredArticle:
    url: str
    title: str
    summary: str
    published_at: str
    content_hash: str
    labels: list
    source: str
    full_content: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class PublicationState:
    """Persistent store preventing duplicate publications."""

    def __init__(self, state_file: str) -> None:
        self.state_file = Path(state_file)
        self._state: dict = self._load()

    def _load(self) -> dict:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("State file corrupt, starting fresh", extra={"error": str(e)})
        return {
            "version": "1.0",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_published": 0,
            "posts": {},
            "failures": [],
        }

    def save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2, ensure_ascii=False)
        logger.info("State saved", extra={"total_published": self._state["total_published"]})

    def is_published(self, content_hash: str) -> bool:
        return content_hash in self._state["posts"]

    def mark_published(self, article: DiscoveredArticle, blogger_post_id: str, blogger_url: str) -> None:
        self._state["posts"][article.content_hash] = {
            "source_url": article.url,
            "source_title": article.title,
            "blogger_post_id": blogger_post_id,
            "blogger_url": blogger_url,
            "published_at": datetime.now(timezone.utc).isoformat(),
            "labels": article.labels,
            "content_hash": article.content_hash,
        }
        self._state["total_published"] = len(self._state["posts"])
        self.save()

    def record_failure(self, url: str, error: str) -> None:
        self._state["failures"].append({
            "url": url,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        # Keep only last 100 failures
        self._state["failures"] = self._state["failures"][-100:]
        self.save()

    @property
    def total_published(self) -> int:
        return self._state["total_published"]


def _compute_hash(url: str, title: str) -> str:
    """Stable content identity hash from URL + title."""
    key = f"{url.strip().lower()}||{title.strip().lower()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _parse_rfc_date(date_str: str) -> Optional[datetime]:
    """Parse RSS/Atom date strings robustly."""
    if not date_str:
        return None
    try:
        import email.utils
        parsed = email.utils.parsedate_to_datetime(date_str)
        return parsed.astimezone(timezone.utc)
    except Exception:
        pass
    try:
        from dateutil import parser as dateutil_parser
        return dateutil_parser.parse(date_str).astimezone(timezone.utc)
    except Exception:
        return None


def _is_recent(pub_date: Optional[datetime], max_age_hours: int) -> bool:
    if pub_date is None:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    return pub_date >= cutoff


def _infer_labels(title: str, summary: str) -> list[str]:
    """Map content to Blogger labels based on keywords."""
    text = (title + " " + summary).lower()
    labels = ["CYBERDUDEBIVASH", "Threat Intelligence"]

    mapping = {
        "cve": "Vulnerabilities",
        "zero-day": "Zero-Day",
        "zero day": "Zero-Day",
        "ransomware": "Ransomware",
        "malware": "Malware Research",
        "apt": "APT",
        "nation-state": "APT",
        "phishing": "Phishing",
        "ai security": "AI Security",
        "llm": "AI Security",
        "prompt injection": "AI Security",
        "owasp": "AI Security",
        "mitre att&ck": "Detection Engineering",
        "sigma": "Detection Engineering",
        "yara": "Detection Engineering",
        "soc": "SOC Operations",
        "cloud": "Cloud Security",
        "devsecops": "DevSecOps",
        "supply chain": "Supply Chain",
        "cisa kev": "CISA KEV",
        "known exploited": "CISA KEV",
        "federal deadline": "CISA KEV",
        "patch tuesday": "Patch Tuesday",
        "breach": "Data Breach",
        "incident": "Incident Response",
        "iot": "IoT Security",
    }

    for keyword, label in mapping.items():
        if keyword in text and label not in labels:
            labels.append(label)

    return labels


def _fetch_article_content(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch and extract readable text content from an article page."""
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"
        })
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        # Remove script/style noise
        for tag in soup.find_all(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        # Try to find main content area
        for selector in ["article", "main", ".post-body", ".entry-content", "#content"]:
            el = soup.select_one(selector)
            if el:
                return el.get_text(separator="\n", strip=True)[:8000]

        return soup.get_text(separator="\n", strip=True)[:8000]
    except Exception as e:
        logger.warning("Could not fetch full article content", extra={"url": url, "error": str(e)})
        return None


class ContentDiscoveryEngine:
    """Discovers new content from SENTINEL APEX sources."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.state = PublicationState(config.state_file)

    def discover(self) -> list[DiscoveredArticle]:
        """Return new, unsynced articles ready for publication."""
        candidates = self._discover_from_rss()
        if not candidates:
            logger.info("RSS returned no items, trying live-intel.json fallback")
            candidates = self._discover_from_live_intel()

        new_articles = []
        for article in candidates:
            if self.state.is_published(article.content_hash):
                logger.debug("Skipping already-published article", extra={"url": article.url})
                continue
            new_articles.append(article)

        new_articles.sort(key=lambda a: a.published_at, reverse=True)
        result = new_articles[: self.config.max_posts_per_run]

        logger.info(
            "Discovery complete",
            extra={
                "candidates": len(candidates),
                "new": len(new_articles),
                "to_publish": len(result),
            },
        )
        return result

    def _discover_from_rss(self) -> list[DiscoveredArticle]:
        """Parse RSS feed from blog.cyberdudebivash.in using stdlib XML parser."""
        logger.info("Fetching RSS feed", extra={"url": self.config.source_rss_url})
        try:
            resp = requests.get(
                self.config.source_rss_url,
                timeout=20,
                headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.error("RSS fetch failed", extra={"error": str(e)})
            return []

        articles = []
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as e:
            logger.error("RSS XML parse error", extra={"error": str(e)})
            return []

        # Handle both RSS 2.0 and Atom feeds
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = root.findall(".//item") or root.findall(".//atom:entry", ns)

        for item in items:
            def _text(tag: str) -> str:
                # Use explicit None check — ET elements with text but no children are falsy
                el = item.find(tag)
                if el is None:
                    el = item.find(f"atom:{tag}", ns)
                return (el.text or "").strip() if el is not None else ""

            # Handle Atom link element (attribute-based)
            url = _text("link")
            if not url:
                link_el = item.find("atom:link", ns)
                if link_el is not None:
                    url = link_el.get("href", "")

            title = _text("title")
            summary = _text("description") or _text("summary") or _text("content")

            if not url or not title:
                continue

            soup = BeautifulSoup(summary, "lxml")
            clean_summary = soup.get_text(separator=" ", strip=True)[:1500]

            pub_date_raw = _text("pubDate") or _text("published") or _text("updated")
            pub_date = _parse_rfc_date(pub_date_raw)

            if not _is_recent(pub_date, self.config.max_article_age_hours):
                continue

            content_hash = _compute_hash(url, title)
            labels = _infer_labels(title, clean_summary)
            pub_iso = pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()

            articles.append(DiscoveredArticle(
                url=url,
                title=title,
                summary=clean_summary,
                published_at=pub_iso,
                content_hash=content_hash,
                labels=labels,
                source="rss",
            ))

        logger.info("RSS parsed", extra={"items": len(articles)})
        return articles

    def _discover_from_live_intel(self) -> list[DiscoveredArticle]:
        """Fallback: parse live-intel.json for new items."""
        logger.info("Fetching live-intel.json", extra={"url": self.config.source_live_intel_url})
        try:
            resp = requests.get(self.config.source_live_intel_url, timeout=20)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("live-intel.json fetch failed", extra={"error": str(e)})
            return []

        items = data if isinstance(data, list) else data.get("items", [])
        articles = []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.config.max_article_age_hours)

        for item in items[:50]:
            title = item.get("title", "") or ""
            url = item.get("url", "") or item.get("link", "") or ""
            summary = item.get("summary", "") or item.get("description", "") or item.get("content", "") or ""

            if not title or not url:
                continue

            added_at_str = item.get("_addedAt", "") or item.get("published", "")
            pub_date = _parse_rfc_date(added_at_str)
            if pub_date and pub_date < cutoff:
                continue

            clean_summary = BeautifulSoup(str(summary), "lxml").get_text(separator=" ", strip=True)[:1500]
            content_hash = _compute_hash(url, title)
            labels = _infer_labels(title, clean_summary)
            pub_iso = pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()

            articles.append(DiscoveredArticle(
                url=url,
                title=title,
                summary=clean_summary,
                published_at=pub_iso,
                content_hash=content_hash,
                labels=labels,
                source="live_intel",
            ))

        logger.info("live-intel parsed", extra={"items": len(articles)})
        return articles
