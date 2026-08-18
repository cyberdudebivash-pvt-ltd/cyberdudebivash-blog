"""
CYBERDUDEBIVASH® SENTINEL APEX — Content Discovery Engine
Detects new threat intelligence content via RSS, sitemap, and live feed.
Tracks published state to prevent duplicate syndication.
"""

import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import xml.etree.ElementTree as ET

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _extract_cve_ids_from_text(text: str) -> list[str]:
    """Return unique CVE IDs found in text, normalised to uppercase."""
    found = _CVE_RE.findall(text)
    seen: set[str] = set()
    result = []
    for cve in found:
        upper = cve.upper()
        if upper not in seen:
            seen.add(upper)
            result.append(upper)
    return result

import requests
from bs4 import BeautifulSoup

from .config import Config
from .logger import setup_logger
from .seo_optimizer import _truncate

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
    # The real publisher/outlet (e.g. "Dark Reading"), distinct from
    # `source` (the ingestion connector, e.g. "global_rss") -- populated by
    # rss_aggregator.py from its curated, named feed list. None for
    # connectors where `source` already names a specific, singular
    # authoritative system (nvd, cisa_kev, ...) rather than an aggregator
    # covering many distinct outlets.
    source_publisher: Optional[str] = None

    # Structured vulnerability data — populated by source modules (NVD, CISA
    # KEV) when available, and backfilled by automation/enrichment.py for
    # any article whose CVE ID can be identified regardless of source.
    # Left None (never fabricated) when a real value isn't known.
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_ids: Optional[list] = None
    affected_vendor: Optional[str] = None
    affected_product: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_listed: Optional[bool] = None
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_required_action: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "DiscoveredArticle":
        """Rehydrate only declared fields from persisted retry/state data."""
        allowed = {field.name for field in fields(cls)}
        return cls(**{key: item for key, item in value.items() if key in allowed})


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

    def is_source_url_published(self, source_url: str) -> bool:
        """Return True when the canonical source record already has a post."""
        normalized = source_url.strip()
        return bool(normalized) and any(
            str(entry.get("source_url") or "").strip() == normalized
            for entry in self._state.get("posts", {}).values()
        )

    def is_cve_published(self, cve_id: str) -> bool:
        """Return True if this CVE was already published from any source."""
        cve_norm = cve_id.upper()
        for entry in self._state.get("posts", {}).values():
            if cve_norm in entry.get("cves", []):
                return True
        return False

    def mark_published(
        self,
        article: DiscoveredArticle,
        blogger_post_id: str,
        blogger_url: str,
        publication_metadata: Optional[dict] = None,
    ) -> None:
        cves = _extract_cve_ids_from_text(article.title + " " + article.summary)
        entry = {
            "source_url": article.url,
            "source_title": article.title,
            "blogger_post_id": blogger_post_id,
            "blogger_url": blogger_url,
            "published_at": datetime.now(timezone.utc).isoformat(),
            "labels": article.labels,
            "content_hash": article.content_hash,
            "cves": cves,
            # COMMERCIAL-QUALITY-2026-08-18 Round 7: real publisher identity,
            # persisted so a later report on the same CVE can tell "a
            # genuinely different outlet already corroborated this" from "the
            # same feed was re-crawled" -- see internal_linker.
            # find_independent_prior_source(). Purely additive; older
            # entries simply lack these two keys, which every reader of this
            # file already treats as "unknown," never a fabricated value.
            "source": article.source,
            "source_publisher": article.source_publisher,
        }
        if publication_metadata:
            safe_fields = {
                "report_id",
                "source_record_hash",
                "report_family",
                "review_status",
                "certification_status",
                "detection_status",
                "generated_at",
            }
            entry.update({key: publication_metadata[key] for key in safe_fields if key in publication_metadata})
        self._state["posts"][article.content_hash] = entry
        self._state["total_published"] = len(self._state["posts"])
        # Remove from retry queue on success
        self._remove_from_retry_queue(article.content_hash, article.url)
        self.save()

    def record_failure(self, url: str, error: str) -> None:
        self._state["failures"].append({
            "url": url,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._state["failures"] = self._state["failures"][-100:]
        self.save()

    # ── Retry Queue ──────────────────────────────────────────────────────────

    def add_to_retry_queue(self, article: DiscoveredArticle, error: str) -> None:
        """Queue a failed article for retry on the next pipeline run (max 3 attempts)."""
        queue: list[dict] = self._state.setdefault("retry_queue", [])
        # Remove any existing entry for the same article to reset attempt count
        queue = [q for q in queue if q.get("content_hash") != article.content_hash]
        existing_attempts = next(
            (q.get("attempts", 1) for q in self._state.get("retry_queue", [])
             if q.get("content_hash") == article.content_hash),
            0,
        )
        queue.append({
            **article.to_dict(),
            "last_error": error,
            "attempts": existing_attempts + 1,
            "added_at": datetime.now(timezone.utc).isoformat(),
        })
        self._state["retry_queue"] = queue[-20:]  # Keep last 20 items max
        self.save()

    def get_retry_queue(self) -> list[dict]:
        """Return all queued retry items (up to 3 past attempts)."""
        return [
            item for item in self._state.get("retry_queue", [])
            if item.get("attempts", 1) <= 3
        ]

    def _remove_from_retry_queue(self, content_hash: str, source_url: Optional[str] = None) -> None:
        queue = self._state.get("retry_queue", [])
        self._state["retry_queue"] = [
            q for q in queue
            if q.get("content_hash") != content_hash
            and (not source_url or q.get("url") != source_url)
        ]

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


def _parse_feed_items(xml_text: str) -> list[dict]:
    """Parse RSS 2.0 or Atom XML into raw item dicts: title, url, summary, pub_date.

    Shared by the own-blog RSS reader and every external RSS-based source
    (global news aggregator, CISA advisories) so feed-format quirks are
    handled in exactly one place. Raises ET.ParseError on malformed XML —
    callers are responsible for catching it and degrading gracefully.
    """
    root = ET.fromstring(xml_text)

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    raw_items = root.findall(".//item") or root.findall(".//atom:entry", ns)

    parsed: list[dict] = []
    for item in raw_items:
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

        if not url or not title:
            continue

        summary_raw = _text("description") or _text("summary") or _text("content")
        clean_summary = (
            _truncate(BeautifulSoup(summary_raw, "lxml").get_text(separator=" ", strip=True), 1500)
            if summary_raw
            else ""
        )
        pub_date_raw = _text("pubDate") or _text("published") or _text("updated")

        parsed.append({
            "title": title,
            "url": url,
            "summary": clean_summary,
            "pub_date": pub_date_raw,
        })

    return parsed


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
        """Return new articles from all sources, priority-ordered by source authority."""
        from .cisa_kev_source import CISAKEVSource
        from .nvd_source import NVDCVESource
        from .rss_aggregator import GlobalRSSAggregator
        from .threat_feeds import (
            CISAAdvisoriesSource,
            DataBreachIntelSource,
            RansomwareIntelSource,
            ThreatActorIntelSource,
        )

        all_new: list[DiscoveredArticle] = []

        # Authoritative structured sources, highest authority first. Each is
        # independently sandboxed — a failure in one never blocks the others.
        sources = [
            ("CISA KEV", CISAKEVSource),
            ("NVD", NVDCVESource),
            ("CISA Advisories", CISAAdvisoriesSource),
            ("Ransomware Intel", RansomwareIntelSource),
            ("Data Breach Intel", DataBreachIntelSource),
            ("Threat Actor Intel", ThreatActorIntelSource),
            ("Global RSS", GlobalRSSAggregator),
        ]
        for label, source_cls in sources:
            try:
                found = source_cls(self.config).discover(self.state)
                all_new.extend(found)
                logger.info(f"{label} source", extra={"new": len(found)})
            except Exception as e:
                logger.error(f"{label} source failed", extra={"error": str(e)})

        # Own RSS feed
        rss = self._discover_from_rss()
        for a in rss:
            if not self.state.is_published(a.content_hash):
                all_new.append(a)

        # live-intel fallback only if nothing found yet
        if not all_new:
            live = self._discover_from_live_intel()
            for a in live:
                if not self.state.is_published(a.content_hash):
                    all_new.append(a)

        # Sort: by source priority first (stable), then by date within each source
        _SOURCE_PRIORITY = {
            "cisa_kev": 0,
            "nvd": 1,
            "cisa_advisory": 2,
            "ransomware_intel": 3,
            "breach_intel": 4,
            "threat_actor_intel": 5,
            "global_rss": 6,
            "rss": 7,
            "live_intel": 8,
        }
        all_new.sort(key=lambda a: a.published_at, reverse=True)
        all_new.sort(key=lambda a: _SOURCE_PRIORITY.get(a.source, 9))

        # Exact-hash dedup: independent sources (global RSS mirrors, CISA
        # advisories, own RSS) can surface the identical (url, title) pair.
        # Keep only the first (highest-priority) occurrence of each hash.
        seen_hashes: set[str] = set()
        hash_deduped: list[DiscoveredArticle] = []
        for article in all_new:
            if article.content_hash in seen_hashes:
                continue
            seen_hashes.add(article.content_hash)
            hash_deduped.append(article)

        # Cross-source CVE dedup: if same CVE ID appears in CISA KEV + NVD, keep highest-priority only.
        # CISA KEV (priority 0) always wins over NVD (priority 1) for the same CVE.
        seen_cves: set[str] = set()
        deduped: list[DiscoveredArticle] = []
        for article in hash_deduped:
            article_cves = _extract_cve_ids_from_text(article.title + " " + article.summary)
            # Check if any CVE in this article was already seen in a higher-priority source
            if article_cves and any(c in seen_cves for c in article_cves):
                logger.info(
                    "Cross-source CVE duplicate skipped",
                    extra={"title": article.title[:60], "cves": article_cves},
                )
                continue
            deduped.append(article)
            seen_cves.update(article_cves)

        result = deduped[: self.config.max_posts_per_run]

        # Attach real EPSS + CISA KEV data (never fabricated — see
        # automation/enrichment.py). Scoped to the trimmed result so this
        # never exceeds 2 network calls regardless of how many candidates
        # were discovered upstream.
        from .enrichment import enrich_articles
        try:
            result = enrich_articles(result)
        except Exception as e:
            logger.warning("Enrichment failed — continuing without it", extra={"error": str(e)})

        logger.info(
            "Discovery complete",
            extra={
                "total_new": len(all_new),
                "after_hash_dedup": len(hash_deduped),
                "after_cve_dedup": len(deduped),
                "to_publish": len(result),
                "sources": list({a.source for a in all_new}),
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

        try:
            items = _parse_feed_items(resp.text)
        except ET.ParseError as e:
            logger.error("RSS XML parse error", extra={"error": str(e)})
            return []

        articles = []
        for item in items:
            url = item["url"]
            title = item["title"]
            pub_date = _parse_rfc_date(item["pub_date"])

            if not _is_recent(pub_date, self.config.max_article_age_hours):
                continue

            content_hash = _compute_hash(url, title)
            labels = _infer_labels(title, item["summary"])
            pub_iso = pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()

            articles.append(DiscoveredArticle(
                url=url,
                title=title,
                summary=item["summary"],
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

            clean_summary = _truncate(BeautifulSoup(str(summary), "lxml").get_text(separator=" ", strip=True), 1500)
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
