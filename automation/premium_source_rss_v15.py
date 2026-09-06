"""P1 v15 source-rich RSS ingestion for SENTINEL APEX premium reports.

The global RSS path historically collapsed every external item to the shared
1,500-character ``summary`` field even when the publisher's feed supplied a
full ``content:encoded`` or Atom ``content`` body.  That was safe for previews,
but it destroyed trusted source depth before the premium evidence compiler and
capacity allocator could evaluate the candidate.

This module is intentionally narrow:

* it patches only ``automation.rss_aggregator``'s parser alias, so first-party
  canonical RSS continues to use the existing summary-only handoff and cannot
  accidentally reclassify previously generated report prose as raw evidence;
* it keeps the existing 1,500-character summary contract unchanged;
* it preserves a sanitized, bounded source body from the *external feed itself*;
* it never fetches article pages, follows redirects, or introduces new network
  requests;
* it never lowers any ReportX/Dossier/publication quality or evidence gate.

The full body is therefore provenance-equivalent to material already returned
by the configured publisher RSS endpoint, while materially improving the pool
of provider-independent candidates during LLM quota saturation.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Optional

from bs4 import BeautifulSoup

from . import rss_aggregator as _rss
from .logger import setup_logger
from .seo_optimizer import _truncate

logger = setup_logger("premium_source_rss_v15")

MARKER = "CDB-PREMIUM-SOURCE-RSS-V15"
MAX_SOURCE_BODY_CHARS = 32_000
SUMMARY_LIMIT_CHARS = 1_500

_ORIGINAL_PARSE = None
_ORIGINAL_TO_ARTICLE = None
_INSTALLED = False

_RUNTIME = {
    "items_parsed": 0,
    "full_body_items": 0,
    "body_chars_preserved": 0,
    "body_words_preserved": 0,
    "articles_enriched": 0,
}


def _local_name(tag: object) -> str:
    value = str(tag or "")
    return value.rsplit("}", 1)[-1].lower()


def _direct_child_text(item: ET.Element, *names: str) -> str:
    wanted = {name.lower() for name in names}
    for child in list(item):
        if _local_name(child.tag) in wanted:
            return (child.text or "").strip()
    return ""


def _atom_link(item: ET.Element) -> str:
    # Prefer rel=alternate or unspecified links; ignore enclosure/self links.
    fallback = ""
    for child in list(item):
        if _local_name(child.tag) != "link":
            continue
        href = str(child.attrib.get("href") or "").strip()
        if not href:
            # RSS <link>https://...</link>
            text = (child.text or "").strip()
            if text:
                return text
            continue
        rel = str(child.attrib.get("rel") or "alternate").strip().lower()
        if rel in {"", "alternate"}:
            return href
        if not fallback:
            fallback = href
    return fallback


def _sanitize_feed_body(raw: str) -> str:
    if not raw:
        return ""
    soup = BeautifulSoup(raw, "lxml")
    for node in soup(["script", "style", "noscript", "iframe", "object", "embed", "form"]):
        node.decompose()
    text = soup.get_text(separator="\n", strip=True)
    # Normalize horizontal whitespace while retaining paragraph/line structure.
    lines = [re.sub(r"[\t\r\f\v ]+", " ", line).strip() for line in text.splitlines()]
    text = "\n".join(line for line in lines if line)
    if len(text) <= MAX_SOURCE_BODY_CHARS:
        return text

    # Bounded evidence capture with an explicit truncation marker. Do not make
    # a silent mid-word cut because source provenance/audit tooling must be able
    # to distinguish a complete feed body from a bounded capture.
    clipped = text[: MAX_SOURCE_BODY_CHARS - 3].rstrip()
    boundary = clipped.rfind(" ")
    if boundary >= int(MAX_SOURCE_BODY_CHARS * 0.90):
        clipped = clipped[:boundary].rstrip()
    return clipped + "..."


def parse_source_rich_feed_items(xml_text: str) -> list[dict]:
    """Parse RSS/Atom while preserving publisher-supplied full feed content.

    ``summary`` remains backward-compatible and capped at 1,500 characters.
    ``full_feed_content`` is an additive field consumed only by the external
    global RSS aggregator.
    """
    root = ET.fromstring(xml_text)
    raw_items = [el for el in root.iter() if _local_name(el.tag) in {"item", "entry"}]

    parsed: list[dict] = []
    for item in raw_items:
        title = _direct_child_text(item, "title")
        url = _atom_link(item)
        if not title or not url:
            continue

        description_raw = _direct_child_text(item, "description")
        summary_element_raw = _direct_child_text(item, "summary")
        atom_content_raw = _direct_child_text(item, "content")
        encoded_raw = _direct_child_text(item, "encoded")

        # Preserve the legacy preview preference exactly: description first,
        # then summary, then Atom content. content:encoded is intentionally not
        # promoted into summary because many feeds put the entire article there.
        summary_raw = description_raw or summary_element_raw or atom_content_raw or encoded_raw
        clean_summary = (
            _truncate(
                BeautifulSoup(summary_raw, "lxml").get_text(separator=" ", strip=True),
                SUMMARY_LIMIT_CHARS,
            )
            if summary_raw
            else ""
        )

        # content:encoded is the strongest conventional RSS full-body signal;
        # Atom content is second. Fall back to description/summary only when a
        # publisher does not expose a distinct full body.
        full_raw = encoded_raw or atom_content_raw or description_raw or summary_element_raw
        full_content = _sanitize_feed_body(full_raw)
        body_kind = (
            "content:encoded" if encoded_raw
            else "atom:content" if atom_content_raw
            else "description" if description_raw
            else "summary" if summary_element_raw
            else "none"
        )

        pub_date_raw = _direct_child_text(item, "pubDate", "published", "updated")
        parsed.append({
            "title": title,
            "url": url,
            "summary": clean_summary,
            "pub_date": pub_date_raw,
            "full_feed_content": full_content,
            "full_feed_content_kind": body_kind,
        })

        _RUNTIME["items_parsed"] += 1
        if full_content:
            _RUNTIME["full_body_items"] += 1
            _RUNTIME["body_chars_preserved"] += len(full_content)
            _RUNTIME["body_words_preserved"] += len(full_content.split())

    return parsed


def _source_rich_to_article(feed, item: dict, state):
    if _ORIGINAL_TO_ARTICLE is None:
        raise RuntimeError("source-rich RSS runtime is not installed")

    article = _ORIGINAL_TO_ARTICLE(feed, item, state)
    if article is None:
        return None

    body = str(item.get("full_feed_content") or "").strip()
    if not body:
        return article

    article.full_content = (
        f"Source Publisher: {feed.name}\n"
        f"Original Article: {article.url}\n"
        f"Feed Evidence Type: {item.get('full_feed_content_kind') or 'unknown'}\n\n"
        f"{body}"
    )
    _RUNTIME["articles_enriched"] += 1
    return article


def source_rss_telemetry() -> dict:
    return {
        "marker": MARKER,
        "max_source_body_chars": MAX_SOURCE_BODY_CHARS,
        **{key: int(value) for key, value in _RUNTIME.items()},
    }


def install_source_rich_rss_v15() -> None:
    """Patch external global RSS only; never the first-party canonical parser."""
    global _ORIGINAL_PARSE, _ORIGINAL_TO_ARTICLE, _INSTALLED
    if _INSTALLED:
        return

    if _rss._parse_feed_items is parse_source_rich_feed_items:
        _INSTALLED = True
        return

    _ORIGINAL_PARSE = _rss._parse_feed_items
    _ORIGINAL_TO_ARTICLE = _rss.GlobalRSSAggregator._to_article
    _rss._parse_feed_items = parse_source_rich_feed_items
    _rss.GlobalRSSAggregator._to_article = _source_rich_to_article
    _INSTALLED = True

    logger.info(
        "P1 source-rich external RSS ingestion installed",
        extra={
            "marker": MARKER,
            "summary_contract_chars": SUMMARY_LIMIT_CHARS,
            "max_source_body_chars": MAX_SOURCE_BODY_CHARS,
            "external_only": True,
            "new_network_requests": 0,
        },
    )
