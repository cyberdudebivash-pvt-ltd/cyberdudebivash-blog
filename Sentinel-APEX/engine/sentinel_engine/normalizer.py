"""Source normalization: raw inbound material -> evidence-only NormalizedDoc.

Strips site chrome / syndication noise, then runs the deterministic
extractors. The output contains only what the source supports.
"""

from __future__ import annotations

import re

from .attack_mapper import map_techniques
from .entities import extract_entities
from .ioc_extractor import extract_cves, extract_iocs
from .models import NormalizedDoc, SourceDocument

# Markers of aggregator/scraper noise that must never survive into analysis.
NOISE_PATTERNS = (
    re.compile(r"submitted by\s+/u/\S+", re.IGNORECASE),
    re.compile(r"\[link\]\s*\[comments\]", re.IGNORECASE),
    re.compile(r"read more(?: at)?\s*(?:»|>|\.\.\.)\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"the post .{0,120} appeared first on .{0,80}\.", re.IGNORECASE),
    re.compile(r"this article has been indexed from .{0,120}$", re.IGNORECASE | re.MULTILINE),
)

# Exact lines of site chrome observed in scraped pages (menus, CTAs, footers).
CHROME_LINES = {
    "cyberdudebivash",
    "sentinel apex",
    "ecosystem hub",
    "core platforms",
    "developer apis",
    "knowledge base",
    "book consultation",
    "run query_search...",
    "$",
}

CHROME_PREFIXES = (
    "💡", "🛡", "⎋", "▲", "🔌", "💎", "📚", "📡", "🏛", "🛠", "🔑", "📅", "⚡", "►", "■", "△", "◆", "▶",
    "special rate:",
    "shop official",
    "sentinel apex v",
)

# All-caps short lines are nav categories ("BREAKING THREATS", "AI SECURITY"...)
_RE_NAV_CAPS = re.compile(r"^[A-Z0-9 &/\-]{2,40}$")


def strip_noise(text: str) -> str:
    """Remove aggregator markers and site chrome while preserving content."""
    out = text
    for pattern in NOISE_PATTERNS:
        out = pattern.sub("", out)

    kept: list[str] = []
    for line in out.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if low in CHROME_LINES:
            continue
        if any(low.startswith(p) for p in CHROME_PREFIXES):
            continue
        if _RE_NAV_CAPS.match(stripped) and len(stripped.split()) <= 4:
            continue
        kept.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()


def has_scraper_noise(text: str) -> bool:
    return any(p.search(text) for p in NOISE_PATTERNS)


def normalize(doc: SourceDocument) -> NormalizedDoc:
    text = strip_noise(doc.raw_text)
    return NormalizedDoc(
        title=doc.title or _infer_title(text),
        text=text,
        source_url=doc.source_url,
        source_name=doc.source_name,
        published=doc.published,
        iocs=extract_iocs(text),
        cves=extract_cves(text),
        techniques=map_techniques(text),
        entities=extract_entities(text),
    )


def _infer_title(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if 20 <= len(line) <= 160:
            return line
    return text.strip().splitlines()[0][:120] if text.strip() else ""
