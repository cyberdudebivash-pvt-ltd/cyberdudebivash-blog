"""CYBERDUDEBIVASH® SENTINEL APEX — Global Threat Feeds

Four authoritative intelligence sources beyond CVEs and core news:
CISA cybersecurity advisories, live ransomware victim disclosures,
newly-disclosed data breaches, and (when configured) subscribed
AlienVault OTX threat-actor pulses.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import quote

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

logger = setup_logger("threat_feeds")

_CISA_ADVISORIES_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
_RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2/recentvictims"
_HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
_OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


def _safe_str(value: object) -> str:
    """Coerce a possibly non-string external API field to a stripped string."""
    return str(value).strip() if value is not None else ""


_PLACEHOLDER_TAXONOMY = {
    "unknown",
    "not found",
    "not found sector",
    "unspecified",
    "unspecified sector",
    "n/a",
    "na",
    "none",
    "null",
    "-",
}


def _clean_taxonomy(value: object, *, kind: str) -> str:
    """Reject source placeholders and malformed sector/country labels."""
    cleaned = _safe_str(value)
    lowered = cleaned.casefold()
    if not cleaned or lowered in _PLACEHOLDER_TAXONOMY:
        return ""
    if lowered.startswith("not found") or lowered.startswith(f"{kind} of "):
        return ""
    if len(cleaned) > 100 or not any(ch.isalpha() for ch in cleaned):
        return ""
    return cleaned


class CISAAdvisoriesSource:
    """Fetches CISA cybersecurity advisories (ICS, vendor, and general alerts)."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        try:
            resp = requests.get(
                _CISA_ADVISORIES_URL,
                timeout=15,
                headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
            )
            resp.raise_for_status()
        except Exception as e:
            logger.error("CISA advisories fetch failed", extra={"error": str(e)})
            return []

        try:
            items = _parse_feed_items(resp.text)
        except Exception as e:
            logger.error("CISA advisories parse failed", extra={"error": str(e)})
            return []

        articles: list[DiscoveredArticle] = []
        for item in items[:10]:
            url = item.get("url", "")
            title = item.get("title", "")
            if not url or not title:
                continue

            pub_date = _parse_rfc_date(item.get("pub_date", ""))
            if not _is_recent(pub_date, self.config.max_article_age_hours):
                continue

            content_hash = _compute_hash(url, title)
            if state.is_published(content_hash):
                continue

            summary = item.get("summary", "")
            labels = _infer_labels(title, summary)
            for required_label in ["CISA Advisory", "CYBERDUDEBIVASH", "Threat Intelligence"]:
                if required_label not in labels:
                    labels.append(required_label)

            pub_iso = pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()
            full_content = f"CISA Advisory: {title}\nSource: {url}\n\n{summary}"

            articles.append(DiscoveredArticle(
                url=url,
                title=title,
                summary=summary,
                published_at=pub_iso,
                content_hash=content_hash,
                labels=labels,
                source="cisa_advisory",
                full_content=full_content,
            ))

        logger.info("CISA advisories parsed", extra={"new_entries": len(articles)})
        return articles


class RansomwareIntelSource:
    """Fetches recently disclosed ransomware victims from ransomware.live."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        try:
            resp = requests.get(
                _RANSOMWARE_LIVE_URL,
                timeout=20,
                headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("Ransomware intel fetch failed", extra={"error": str(e)})
            return []

        victims = data if isinstance(data, list) else []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.config.max_article_age_hours)

        articles: list[DiscoveredArticle] = []
        for v in victims[:20]:
            if not isinstance(v, dict):
                continue

            victim_name = _safe_str(v.get("victim"))
            group = _safe_str(v.get("group")) or "Unknown Group"
            if not victim_name:
                continue

            date_str = v.get("discovered") or v.get("attackdate") or v.get("published") or ""
            attack_date = _parse_rfc_date(date_str)
            if attack_date is None:
                try:
                    attack_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except Exception:
                    attack_date = None
            if attack_date and attack_date < cutoff:
                continue

            sector = _clean_taxonomy(v.get("activity") or v.get("sector"), kind="sector")
            country = _clean_taxonomy(v.get("country"), kind="country")
            post_url = _safe_str(v.get("post_url") or v.get("url"))

            title = f"{group} Ransomware Claims New Victim: {victim_name}"
            if sector:
                title += f" | {sector} Sector"
            summary_parts = [
                f"{group} has listed {victim_name} as a new victim on its leak site.",
            ]
            if sector:
                summary_parts.append(f"Reported sector: {sector}.")
            if country:
                summary_parts.append(f"Country: {country}.")
            summary = " ".join(summary_parts)

            url = post_url or f"https://ransomware.live/group/{quote(group.lower().replace(' ', '-'))}#{quote(victim_name.lower().replace(' ', '-'))}"
            content_hash = _compute_hash(url, title)
            if state.is_published(content_hash):
                continue

            labels = _infer_labels(title, summary)
            for required_label in ["Ransomware", "CYBERDUDEBIVASH", "Threat Intelligence"]:
                if required_label not in labels:
                    labels.append(required_label)

            pub_iso = attack_date.isoformat() if attack_date else datetime.now(timezone.utc).isoformat()
            full_content = (
                f"Ransomware Group: {group}\nVictim: {victim_name}\n"
                f"Sector: {sector or 'Not supplied by source'}\n"
                f"Country: {country or 'Not supplied by source'}\nLeak Site: {url}"
            )

            articles.append(DiscoveredArticle(
                url=url,
                title=title,
                summary=summary,
                published_at=pub_iso,
                content_hash=content_hash,
                labels=labels,
                source="ransomware_intel",
                full_content=full_content,
                ransomware_group=group,
                ransomware_sector=sector,
                ransomware_country=country,
            ))

        logger.info("Ransomware intel parsed", extra={"new_entries": len(articles)})
        return articles


class DataBreachIntelSource:
    """Fetches newly-disclosed data breaches from the Have I Been Pwned catalog."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        try:
            resp = requests.get(
                _HIBP_BREACHES_URL,
                timeout=20,
                headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("Breach intel fetch failed", extra={"error": str(e)})
            return []

        breaches = data if isinstance(data, list) else []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.config.max_article_age_hours)

        articles: list[DiscoveredArticle] = []
        for b in breaches:
            if not isinstance(b, dict):
                continue

            name = _safe_str(b.get("Name"))
            display_title = _safe_str(b.get("Title")) or name
            if not name:
                continue

            added_date = _parse_rfc_date(b.get("AddedDate", ""))
            if added_date is None:
                try:
                    added_date = datetime.fromisoformat(str(b.get("AddedDate", "")).replace("Z", "+00:00"))
                except Exception:
                    added_date = None
            # Breach catalog spans years — only surface breaches newly ADDED to HIBP, not just newly attacked.
            if added_date is None or added_date < cutoff:
                continue

            pwn_count = b.get("PwnCount", 0) or 0
            raw_classes = b.get("DataClasses", [])
            data_classes = raw_classes if isinstance(raw_classes, list) else []
            domain = _safe_str(b.get("Domain"))

            title = f"Data Breach Disclosed: {display_title} — {pwn_count:,} Accounts Exposed"
            classes_str = ", ".join(data_classes[:6]) if data_classes else "account data"
            summary = (
                f"{display_title}{' (' + domain + ')' if domain else ''} has been added to the "
                f"public breach disclosure record, exposing {pwn_count:,} accounts. "
                f"Compromised data includes: {classes_str}."
            )

            url = f"https://haveibeenpwned.com/PwnedWebsites#{name}"
            content_hash = _compute_hash(url, title)
            if state.is_published(content_hash):
                continue

            labels = _infer_labels(title, summary)
            for required_label in ["Data Breach", "CYBERDUDEBIVASH", "Threat Intelligence"]:
                if required_label not in labels:
                    labels.append(required_label)

            pub_iso = added_date.isoformat()
            full_content = (
                f"Breach Name: {display_title}\nDomain: {domain or 'Not disclosed'}\n"
                f"Accounts Exposed: {pwn_count:,}\nCompromised Data: {classes_str}"
            )

            articles.append(DiscoveredArticle(
                url=url,
                title=title,
                summary=summary,
                published_at=pub_iso,
                content_hash=content_hash,
                labels=labels,
                source="breach_intel",
                full_content=full_content,
            ))

        logger.info("Breach intel parsed", extra={"new_entries": len(articles)})
        return articles


class ThreatActorIntelSource:
    """Fetches subscribed AlienVault OTX threat-actor pulses (requires API key)."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def _configured(self) -> bool:
        return bool(self.config.alienvault_otx_key)

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        if not self._configured():
            logger.info("AlienVault OTX key not configured — skipping threat actor intel")
            return []

        try:
            resp = requests.get(
                _OTX_PULSES_URL,
                timeout=20,
                headers={
                    "X-OTX-API-KEY": self.config.alienvault_otx_key,
                    "User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0",
                },
                params={"limit": 20},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("Threat actor intel fetch failed", extra={"error": str(e)})
            return []

        pulses = data.get("results", []) if isinstance(data, dict) else []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.config.max_article_age_hours)

        articles: list[DiscoveredArticle] = []
        for p in pulses[:20]:
            if not isinstance(p, dict):
                continue

            name = _safe_str(p.get("name"))
            if not name:
                continue

            created = _parse_rfc_date(p.get("created", ""))
            if created and created < cutoff:
                continue

            description = _safe_str(p.get("description"))
            raw_tags = p.get("tags", [])
            tags = raw_tags if isinstance(raw_tags, list) else []
            adversary = _safe_str(p.get("adversary"))
            pulse_id = p.get("id", "")

            title = f"Threat Actor Pulse: {name}" + (f" — Tagged Adversary: {adversary}" if adversary else "")
            summary = description or f"Subscribed OTX pulse covering {', '.join(tags[:5]) if tags else 'emerging threat activity'}."

            url = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else f"https://otx.alienvault.com/browse/pulses?q={quote(name)}"
            content_hash = _compute_hash(url, title)
            if state.is_published(content_hash):
                continue

            labels = _infer_labels(title, summary)
            for required_label in ["APT", "CYBERDUDEBIVASH", "Threat Intelligence"]:
                if required_label not in labels:
                    labels.append(required_label)

            pub_iso = created.isoformat() if created else datetime.now(timezone.utc).isoformat()
            full_content = (
                f"Pulse: {name}\nAdversary: {adversary or 'Unattributed'}\n"
                f"Tags: {', '.join(tags[:10])}\n\n{description}"
            )

            articles.append(DiscoveredArticle(
                url=url,
                title=title,
                summary=summary,
                published_at=pub_iso,
                content_hash=content_hash,
                labels=labels,
                source="threat_actor_intel",
                full_content=full_content,
            ))

        logger.info("Threat actor intel parsed", extra={"new_entries": len(articles)})
        return articles
