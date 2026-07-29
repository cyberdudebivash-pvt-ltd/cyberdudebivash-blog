"""Deterministic IOC extraction, categorization, defanging and refanging.

Extraction is regex-based and conservative: a value only becomes an IOC when
it matches a strict pattern AND survives the false-positive filters (private
IP ranges, infrastructure/reference domains, non-routable TLD lookalikes).
"""

from __future__ import annotations

import ipaddress
import re

from .models import IOC, IOCType

# Domains that are platform infrastructure or common reference material —
# they are never indicators when they appear in our own content.
DEFAULT_ALLOWLIST = {
    "cyberdudebivash.com",
    "cyberdudebivash.in",
    "blog.cyberdudebivash.in",
    "intel.cyberdudebivash.com",
    "attack.mitre.org",
    "atlas.mitre.org",
    "nvd.nist.gov",
    "cve.org",
    "www.cve.org",
    "cisa.gov",
    "www.cisa.gov",
    "first.org",
    "api.first.org",
    "github.com",
    "reddit.com",
    "www.reddit.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "www.linkedin.com",
    "google.com",
    "microsoft.com",
    "schema.org",
}

# Real technology/product names shaped like a domain (word.tld) but never an
# indicator when they appear in report prose -- a different, open-ended
# category from DEFAULT_ALLOWLIST's citation/reference infrastructure, which
# a caller can legitimately override via extract_iocs()'s `allowlist`
# parameter. This one always applies regardless of what allowlist is
# passed, since "ASP.NET is not a domain" is a fact about the world, not a
# citation policy. Seeded with the one real, evidenced case
# (platform/open-issues.md Issue 9: "ASP.NET," the credential-theft
# mechanism named throughout SA-2026-0001, misclassified as a domain IOC) --
# extend only with confirmed real instances, not a speculative list.
TECH_NAME_ALLOWLIST = {
    "asp.net",
}

# TLDs accepted for bare-domain extraction. Deliberately restrictive to keep
# filenames ("report.txt") and code identifiers out of the IOC set.
_TLDS = (
    "com|net|org|io|in|ru|cn|de|uk|co|us|eu|me|cc|tv|su|info|biz|xyz|top|"
    "online|site|club|app|dev|gg|to|ws|pw|link|click|live|shop|store|icu|"
    "cyou|rest|fun|monster|sbs|onion|zip|mov"
)

_REFANG_PAIRS = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("[at]", "@"),
    ("[://]", "://"),
)

_RE_URL = re.compile(r"\bhttps?://[^\s<>\"'\]\)]+", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:%s))\b" % _TLDS, re.IGNORECASE
)
_RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
_RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
_RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_REGKEY = re.compile(r"\bHK(?:LM|CU|CR|U|EY_[A-Z_]+)\\[^\s,;\"']+", re.IGNORECASE)

# A standalone "Sources:" / "References:" line (optionally an ATX heading or
# bold) marks the start of a citation list. URLs after this point are the
# analyst's own reference material, not indicators observed in the wild —
# without this, every cited news article becomes a false-positive IOC.
_RE_CITATION_MARKER = re.compile(
    r"^[ \t]*#{0,6}[ \t]*\*{0,2}[ \t]*(?:sources?|references?)[ \t]*:?[ \t]*\*{0,2}[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


def refang(text: str) -> str:
    """Convert defanged notation back to its live form (for analysis only)."""
    out = text
    for defanged, live in _REFANG_PAIRS:
        out = out.replace(defanged, live).replace(defanged.upper(), live)
    return out


def defang(value: str, ioc_type: IOCType) -> str:
    """Render an IOC safe for publication."""
    if ioc_type in (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4):
        out = value.replace("http", "hxxp").replace("HTTP", "hxxp")
        return out.replace(".", "[.]")
    if ioc_type == IOCType.EMAIL:
        return value.replace("@", "[@]").replace(".", "[.]")
    return value


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _context(text: str, match: re.Match, width: int = 60) -> str:
    start = max(0, match.start() - width)
    end = min(len(text), match.end() + width)
    return " ".join(text[start:end].split())


def extract_iocs(
    text: str, allowlist: set[str] | None = None, include_context: bool = True
) -> list[IOC]:
    """Extract and categorize IOCs from text (defanged input is handled)."""
    allow = DEFAULT_ALLOWLIST if allowlist is None else allowlist
    live = refang(text)
    found: dict[tuple, IOC] = {}

    citation_marker = _RE_CITATION_MARKER.search(live)
    citation_start = citation_marker.start() if citation_marker else None

    def _add(value: str, ioc_type: IOCType, match: re.Match) -> None:
        ioc = IOC(
            value=value,
            type=ioc_type,
            context=_context(live, match) if include_context else "",
        )
        found.setdefault(ioc.key(), ioc)

    hash_spans: list[tuple[int, int]] = []
    for regex, ioc_type in (
        (_RE_SHA256, IOCType.SHA256),
        (_RE_SHA1, IOCType.SHA1),
        (_RE_MD5, IOCType.MD5),
    ):
        for m in regex.finditer(live):
            # skip if this hex run sits inside a longer, already-claimed one
            if any(s <= m.start() and m.end() <= e for s, e in hash_spans):
                continue
            hash_spans.append((m.start(), m.end()))
            _add(m.group(0).lower(), ioc_type, m)

    url_spans: list[tuple[int, int]] = []
    for m in _RE_URL.finditer(live):
        url = m.group(0).rstrip(".,;:!?")
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]
        host = host.split(":")[0].lower()
        url_spans.append((m.start(), m.end()))
        if host in allow or _strip_www(host) in allow:
            continue
        if citation_start is not None and m.start() >= citation_start:
            continue
        _add(url, IOCType.URL, m)

    for m in _RE_IPV4.finditer(live):
        if _is_public_ip(m.group(0)):
            _add(m.group(0), IOCType.IPV4, m)

    for m in _RE_EMAIL.finditer(live):
        email = m.group(0).lower()
        if email.split("@")[1] not in allow:
            _add(email, IOCType.EMAIL, m)

    for m in _RE_DOMAIN.finditer(live):
        # domains inside URLs are already covered by the URL indicator
        if any(s <= m.start() and m.end() <= e for s, e in url_spans):
            continue
        domain = m.group(1).lower()
        if domain in TECH_NAME_ALLOWLIST:
            continue
        if domain in allow or _strip_www(domain) in allow:
            continue
        # skip if it's the host part of an extracted email
        if any(
            i.type == IOCType.EMAIL and i.value.endswith("@" + domain)
            for i in found.values()
        ):
            continue
        _add(domain, IOCType.DOMAIN, m)

    for m in _RE_CVE.finditer(live):
        _add(m.group(0).upper(), IOCType.CVE, m)

    for m in _RE_REGKEY.finditer(live):
        _add(m.group(0), IOCType.REGISTRY_KEY, m)

    return sorted(found.values(), key=lambda i: (i.type.value, i.value))


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def extract_cves(text: str) -> list[str]:
    return sorted({m.group(0).upper() for m in _RE_CVE.finditer(text)})
