"""
CYBERDUDEBIVASH® SENTINEL APEX — Internal Linking Engine
Generates contextual internal links to related reports, CVEs, and platform pages.
"""

import html
import json
import re
from typing import Optional

from .config import Config

# Curated high-authority internal link targets
PLATFORM_LINKS = [
    {
        "text": "SENTINEL APEX Intelligence Platform",
        "url_key": "sentinel_apex_url",
        "keywords": ["threat intelligence", "cti", "intel platform", "live feed"],
    },
    {
        "text": "Threat Intelligence API",
        "url_key": "api_url",
        "keywords": ["api", "feed", "integration", "siem", "splunk", "elastic"],
    },
    {
        "text": "Security Tools Hub",
        "url_key": "tools_url",
        "keywords": ["security tool", "scanner", "analyzer", "encoder", "lookup"],
    },
    {
        "text": "AI Security Hub",
        "url_key": "corporate_url",
        "keywords": ["ai security", "llm security", "prompt injection", "ai governance", "ai risk"],
    },
]

# COMMERCIAL-QUALITY-2026-08-18: labels every article carries unconditionally
# (content_discovery._infer_labels()'s own base list, plus rss_aggregator.py's
# required-labels list for RSS-sourced articles) -- independently verified
# live (and separately flagged in the same terms by an external review) that
# build_correlation_block()'s "shared labels" match always fired on these,
# since every two articles share at least them, making the fallback
# functionally "most recent post, any topic" rather than real correlation.
# Excluded from the match set below so only genuinely topic/actor/campaign
# -specific labels ("Ransomware", "qilin", "AI Security", ...) count.
#
# COMMERCIAL-QUALITY-2026-08-19: "Vulnerabilities" is the same defect,
# unaddressed within the CVE-report population specifically. content_
# discovery._infer_labels() maps every "cve"-keyword title to "Vulnerabilities"
# unconditionally (same mechanism as the three labels above), so two
# unrelated CVEs -- different vendor, different product, different CVE ID --
# still "match" on that single shared label. Independently verified live:
# CVE-2026-60698 (Oracle WebLogic) and CVE-2026-75912 (CodeWhale) each show
# five "Related Intelligence Reports" that are just the five most recent
# other CVE posts, not genuinely related vulnerabilities.
_NON_DISCRIMINATING_LABELS = frozenset(
    {"CYBERDUDEBIVASH", "Threat Intelligence", "Global Intel", "Vulnerabilities"}
)

# Authoritative external cybersecurity references
EXTERNAL_REFERENCES = {
    "mitre att&ck": "https://attack.mitre.org/",
    "owasp llm top 10": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "cisa kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "nist ai rmf": "https://airc.nist.gov/Home",
    "nist csf": "https://www.nist.gov/cyberframework",
}

# PHASE-1-DATA-MODEL-2026-08-19: structured relationship typing for
# "related intelligence," replacing the previous flat cve-match-then-
# label-match priority with an explicit classification every candidate
# gets, in descending strength. RECENCY_ONLY is a real, named outcome --
# it means nothing stronger than publication order connects the two
# reports -- and per design must never be surfaced in the customer-facing
# block as if it were a real correlation (build_correlation_block excludes
# it entirely, same as the "no real relationship" case it already handled).
RELATION_DIRECT = "DIRECT_RELATION"
RELATION_CAMPAIGN = "CAMPAIGN_RELATION"
RELATION_TACTICAL = "TACTICAL_SIMILARITY"
RELATION_SECTOR = "SECTOR_RELATION"
RELATION_RECENCY_ONLY = "RECENCY_ONLY"

_RELATION_LABELS = {
    RELATION_DIRECT: "Same vulnerability",
    RELATION_CAMPAIGN: "Same threat actor",
    RELATION_TACTICAL: "Related topic",
    RELATION_SECTOR: "Same sector/region",
}

# PHASE-1-DATA-MODEL-2026-08-19 (adversarial testing, before certification):
# threat_feeds.RansomwareIntelSource falls back to the literal placeholder
# "Unknown Group" whenever the source record has no named actor. Two
# unrelated claims from two different, genuinely unidentified actors would
# both carry this exact string, and a naive equality check would classify
# them as CAMPAIGN_RELATION ("Same threat actor") -- a real false positive,
# not merely a weak match. Same failure shape as _AGGREGATING_CONNECTORS
# above: a placeholder is not an identity.
_PLACEHOLDER_ACTOR_NAMES = frozenset({"Unknown Group"})


def _classify_relation(
    article_cve_set: set,
    article_label_set: set,
    article_ransomware_group: str,
    article_ransomware_sector: str,
    article_ransomware_country: str,
    entry: dict,
) -> str:
    """Classify a candidate's relationship to the current article using
    only fields already real and already persisted in published_posts.json
    -- never inferred or fabricated. Checked strongest-first; the first
    match wins, since a candidate sharing a real CVE is a stronger
    relationship than one only sharing a sector, even if both are true."""
    entry_cves = {c.upper() for c in entry.get("cves", [])}
    if article_cve_set and entry_cves & article_cve_set:
        return RELATION_DIRECT

    entry_group = entry.get("ransomware_group") or ""
    if (
        article_ransomware_group
        and entry_group
        and article_ransomware_group == entry_group
        and article_ransomware_group not in _PLACEHOLDER_ACTOR_NAMES
    ):
        return RELATION_CAMPAIGN

    entry_label_set = set(entry.get("labels", [])) - _NON_DISCRIMINATING_LABELS
    if article_label_set and entry_label_set & article_label_set:
        return RELATION_TACTICAL

    entry_sector = entry.get("ransomware_sector") or ""
    entry_country = entry.get("ransomware_country") or ""
    if (article_ransomware_sector and entry_sector and article_ransomware_sector == entry_sector) or (
        article_ransomware_country and entry_country and article_ransomware_country == entry_country
    ):
        return RELATION_SECTOR

    return RELATION_RECENCY_ONLY


class InternalLinker:
    """Generates internal link sections for syndicated posts."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def build_related_resources_block(self, title: str, summary: str, labels: list[str]) -> str:
        """Generate an HTML block of related platform resources."""
        text = (title + " " + summary).lower()
        matched = []

        for link in PLATFORM_LINKS:
            if any(kw in text for kw in link["keywords"]):
                matched.append(link)

        # Always include Sentinel APEX
        sentinel_link = PLATFORM_LINKS[0]
        if sentinel_link not in matched:
            matched.insert(0, sentinel_link)

        urls = {
            "sentinel_apex_url": self.config.sentinel_apex_url,
            "api_url": self.config.api_url,
            "tools_url": self.config.tools_url,
            "corporate_url": self.config.corporate_url,
        }

        items_html = ""
        for link in matched[:4]:
            url = urls.get(link["url_key"], self.config.sentinel_apex_url)
            items_html += f'<li><a href="{url}" target="_blank" rel="noopener">→ {link["text"]}</a></li>\n'

        # Add label-specific links
        label_links = self._label_specific_links(labels)
        for text_link, url in label_links[:3]:
            items_html += f'<li><a href="{url}" target="_blank" rel="noopener">→ {text_link}</a></li>\n'

        if not items_html:
            return ""

        return f"""
<div style="margin:24px 0;padding:18px 20px;background:#0a0f1e;border:1px solid #1e3a5f;border-radius:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <h4 style="margin:0 0 12px;font-size:13px;font-weight:700;color:#00d4ff;text-transform:uppercase;letter-spacing:1px">🔗 Related Intelligence Resources</h4>
  <ul style="margin:0;padding:0 0 0 16px;color:#a0b3cc;font-size:13px;line-height:1.8">
{items_html}  </ul>
</div>
""".strip()

    def _label_specific_links(self, labels: list[str]) -> list[tuple[str, str]]:
        result = []
        label_set = set(labels)

        if "Detection Engineering" in label_set or "SOC Operations" in label_set:
            result.append(("MITRE ATT&CK Detection Hub — 14 Tactics + 28 Sigma Rules",
                           f"{self.config.source_base_url}/attack/"))
        if "AI Security" in label_set:
            result.append(("OWASP LLM Top 10 Security Hub",
                           f"{self.config.source_base_url}/ai-security/"))
        if "Vulnerabilities" in label_set or "Zero-Day" in label_set or "CISA KEV" in label_set:
            result.append(("Live CVE Intelligence Feed — CISA KEV Tracker",
                           self.config.sentinel_apex_url))
        if "Ransomware" in label_set or "Malware Research" in label_set:
            result.append(("Malware & Ransomware Campaign Tracker",
                           f"{self.config.source_base_url}/malware/"))

        return result

    def build_correlation_block(
        self, article_labels: list, article_cves: list,
        exclude_hash: Optional[str] = None, max_results: int = 5,
        article_ransomware_group: str = "", article_ransomware_sector: str = "",
        article_ransomware_country: str = "",
    ) -> str:
        """
        Real cross-references against previously published reports — read
        from data/published_posts.json (the same file the syndication
        pipeline already writes; every entry's blogger_url is a real, live
        link, never fabricated). Every candidate is classified by
        _classify_relation() into one of DIRECT_RELATION (shared CVE),
        CAMPAIGN_RELATION (shared threat actor), TACTICAL_SIMILARITY (shared
        discriminating label -- see _NON_DISCRIMINATING_LABELS),
        SECTOR_RELATION (shared sector/country), or RECENCY_ONLY, in that
        descending-strength order; sorted most-recent-first only as the
        tiebreaker within each tier, never as the primary criterion.
        RECENCY_ONLY candidates are never surfaced here (PHASE-1-DATA-MODEL-
        2026-08-19: "do not expose RECENCY_ONLY as meaningful intelligence
        correlation" -- the same discipline COMMERCIAL-QUALITY-2026-08-18
        already established for "no real relationship at all"). Returns ""
        if the state file is unavailable, has no usable entries, or this
        article shares no real relationship with anything previously
        published.
        """
        try:
            with open(self.config.state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError):
            return ""

        posts = state.get("posts", {})
        if not posts:
            return ""

        article_cve_set = {c.upper() for c in article_cves}
        article_label_set = set(article_labels) - _NON_DISCRIMINATING_LABELS

        by_tier: dict = {RELATION_DIRECT: [], RELATION_CAMPAIGN: [], RELATION_TACTICAL: [], RELATION_SECTOR: []}
        for content_hash, entry in posts.items():
            if content_hash == exclude_hash:
                continue
            blogger_url = entry.get("blogger_url")
            title = entry.get("source_title")
            if not blogger_url or not title:
                continue

            relation = _classify_relation(
                article_cve_set, article_label_set,
                article_ransomware_group, article_ransomware_sector, article_ransomware_country,
                entry,
            )
            if relation == RELATION_RECENCY_ONLY:
                continue

            published_at = entry.get("published_at", "")
            by_tier[relation].append((published_at, title, blogger_url, relation))

        combined = []
        for tier in (RELATION_DIRECT, RELATION_CAMPAIGN, RELATION_TACTICAL, RELATION_SECTOR):
            by_tier[tier].sort(reverse=True)
            combined.extend(by_tier[tier])
        combined = combined[:max_results]

        if not combined:
            return ""

        items_html = "".join(
            f'<li><span style="color:#64748b;font-size:11px">{html.escape(_RELATION_LABELS[relation])}:</span> '
            f'<a href="{html.escape(str(url), quote=True)}" target="_blank" rel="noopener">{html.escape(str(title)[:90])}</a></li>\n'
            for _, title, url, relation in combined
        )
        return f"""
<div style="margin:24px 0;padding:18px 20px;background:#0a0f1e;border:1px solid #1e3a5f;border-radius:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <h4 style="margin:0 0 12px;font-size:13px;font-weight:700;color:#00d4ff;text-transform:uppercase;letter-spacing:1px">🔗 Related Intelligence Reports</h4>
  <ul style="margin:0;padding:0 0 0 16px;color:#a0b3cc;font-size:13px;line-height:1.9">
{items_html}  </ul>
</div>
""".strip()

    def build_external_references(self, title: str, summary: str) -> str:
        """Generate relevant external authority references."""
        text = (title + " " + summary).lower()
        matched = []

        for keyword, url in EXTERNAL_REFERENCES.items():
            if keyword in text:
                matched.append((keyword.title(), url))

        if not matched:
            return ""

        items_html = "".join(
            f'<li><a href="{url}" target="_blank" rel="noopener noreferrer">{text}</a></li>\n'
            for text, url in matched[:5]
        )

        return f"""
<div style="margin:20px 0;padding:16px 20px;background:#050d1a;border-left:3px solid #64748b;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <h4 style="margin:0 0 10px;font-size:12px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px">External References</h4>
  <ul style="margin:0;padding:0 0 0 16px;color:#94a3b8;font-size:12px;line-height:1.8">
{items_html}  </ul>
</div>
""".strip()

    def build_hashtag_block(self, labels: list[str]) -> str:
        """Build a hashtag block for social visibility."""
        base_tags = ["#CyberSecurity", "#ThreatIntelligence", "#CyberDudeBivash", "#SentinelAPEX"]
        label_tags = {
            "Zero-Day": ["#ZeroDay", "#CyberThreat"],
            "Ransomware": ["#Ransomware", "#CyberDefense"],
            "AI Security": ["#AISecurity", "#LLMSecurity", "#OWASPTop10"],
            "APT": ["#APT", "#NationState", "#ThreatHunting"],
            "CISA KEV": ["#CISAKEV", "#PatchNow"],
            "Detection Engineering": ["#DetectionEngineering", "#SigmaRules", "#MITREATTACK"],
            "Cloud Security": ["#CloudSecurity", "#ZeroTrust"],
            "SOC Operations": ["#SOC", "#SIEM", "#ThreatHunting"],
        }

        tags = list(base_tags)
        for label in labels:
            for tag in label_tags.get(label, []):
                if tag not in tags:
                    tags.append(tag)

        return f'<p style="margin:20px 0;font-size:12px;color:#64748b;font-family:monospace">{" ".join(tags[:15])}</p>'


# COMMERCIAL-QUALITY-2026-08-18 Round 7 follow-up (CodeRabbit review):
# "global_rss" is an AGGREGATION CONNECTOR covering ~40 distinct real
# outlets, not a publisher identity -- unlike "nvd"/"cisa_kev"/etc., which
# each genuinely name one single, specific authority. Falling back to it
# as if it were a specific publisher made an entry with a genuinely
# UNKNOWN outlet look "different, therefore independent" from anything,
# purely because the generic connector label rarely matches a real named
# outlet -- the exact same-publisher-treated-as-independent risk this
# function's own docstring already promises to avoid.
_AGGREGATING_CONNECTORS = frozenset({"global_rss"})


def _effective_publisher(entry: dict) -> str:
    """The real, specific identity this entry actually establishes --
    never the bare connector name for a connector that aggregates many
    distinct outlets. Shared by both sides of the independence comparison
    in ``find_independent_prior_source`` (Single Source of Truth): the
    same rule must decide "do we actually know who this is" whichever
    side (current article or historical candidate) it's asked about."""
    publisher = entry.get("source_publisher")
    if publisher:
        return publisher
    source = entry.get("source") or ""
    return "" if source in _AGGREGATING_CONNECTORS else source


def find_independent_prior_source(cve_id: str, exclude_publisher: str, state_file: str) -> Optional[dict]:
    """Real, already-persisted evidence of independent corroboration for a
    CVE -- never a live network fetch. Searches ``data/published_posts.json``
    (the same file ``InternalLinker.build_correlation_block`` already reads)
    for an earlier entry reporting this exact CVE ID from a genuinely
    different publisher.

    Fails closed, never fabricates a match: returns ``None`` when the state
    file is unavailable, no entry shares this exact CVE ID, or every
    matching entry's publisher is unknown or the same as ``exclude_publisher``
    (a same-outlet re-crawl or syndicated repost is not independent
    corroboration). Older entries persisted before this field existed have
    no ``source_publisher``/``source`` key at all -- treated the same as an
    unknown publisher, not assumed independent -- and so does a candidate
    whose only identity is a generic aggregating connector name
    (``_effective_publisher``): we cannot tell it apart from
    ``exclude_publisher`` just because the strings differ.

    Module-level, not an ``InternalLinker`` method: the caller
    (``sentinel_engine.reportx.discovery_bridge``) needs a plain path-based
    lookup, not a full ``Config``-bound instance."""
    if not cve_id:
        return None
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    cve_norm = cve_id.upper()
    candidates = [
        entry for entry in state.get("posts", {}).values()
        if cve_norm in {c.upper() for c in entry.get("cves", [])}
        and _effective_publisher(entry) not in ("", exclude_publisher)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda e: e.get("published_at", ""))
    return candidates[0]
