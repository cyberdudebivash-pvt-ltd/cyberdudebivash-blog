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
_NON_DISCRIMINATING_LABELS = frozenset({"CYBERDUDEBIVASH", "Threat Intelligence", "Global Intel"})

# Authoritative external cybersecurity references
EXTERNAL_REFERENCES = {
    "mitre att&ck": "https://attack.mitre.org/",
    "owasp llm top 10": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "cisa kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "nist ai rmf": "https://airc.nist.gov/Home",
    "nist csf": "https://www.nist.gov/cyberframework",
}


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
    ) -> str:
        """
        Real cross-references against previously published reports — read
        from data/published_posts.json (the same file the syndication
        pipeline already writes; every entry's blogger_url is a real, live
        link, never fabricated). Shared CVEs rank highest, then shared
        DISCRIMINATING labels (actor, campaign, malware, vulnerability
        family -- see _NON_DISCRIMINATING_LABELS), sorted most-recent-first
        only as the tiebreaker within each match tier, never as the primary
        criterion. Returns "" if the state file is unavailable, has no
        usable entries, or -- as important a case as finding real matches --
        this article shares no real relationship with anything previously
        published (COMMERCIAL-QUALITY-2026-08-18: previously fell through to
        "any post sharing a universal label," which every post always does,
        making this functionally a recency feed rather than correlation).
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

        cve_matches, label_matches = [], []
        for content_hash, entry in posts.items():
            if content_hash == exclude_hash:
                continue
            blogger_url = entry.get("blogger_url")
            title = entry.get("source_title")
            if not blogger_url or not title:
                continue

            entry_cves = {c.upper() for c in entry.get("cves", [])}
            entry_labels = set(entry.get("labels", [])) - _NON_DISCRIMINATING_LABELS
            published_at = entry.get("published_at", "")

            if article_cve_set and entry_cves & article_cve_set:
                cve_matches.append((published_at, title, blogger_url))
            elif article_label_set & entry_labels:
                label_matches.append((published_at, title, blogger_url))

        cve_matches.sort(reverse=True)
        label_matches.sort(reverse=True)
        combined = cve_matches + label_matches
        combined = combined[:max_results]

        if not combined:
            return ""

        items_html = "".join(
            f'<li><a href="{html.escape(str(url), quote=True)}" target="_blank" rel="noopener">{html.escape(str(title)[:90])}</a></li>\n'
            for _, title, url in combined
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
