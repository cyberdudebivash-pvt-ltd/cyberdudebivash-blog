"""
CYBERDUDEBIVASH® SENTINEL APEX — SEO Optimization Module
Generates metadata, schema markup, and OG tags for syndicated articles.
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional

from .config import Config
from .logger import setup_logger

logger = setup_logger("seo_optimizer")

# High-value cybersecurity SEO keywords
BASE_KEYWORDS = [
    "cybersecurity", "threat intelligence", "AI security", "zero-day",
    "CVE", "CISA KEV", "ransomware", "malware", "SOC", "SIEM",
    "MITRE ATT&CK", "OWASP LLM", "sentinel apex", "cyberdudebivash",
    "cyber threat intelligence", "endpoint security", "cloud security",
]


def _extract_cve_ids(text: str) -> list[str]:
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)))


def _extract_cvss(text: str) -> Optional[str]:
    match = re.search(r"CVSS[: ]+(\d+\.?\d*)", text, re.IGNORECASE)
    return match.group(1) if match else None


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3].rsplit(" ", 1)[0] + "..."


class SEOOptimizer:
    """Generates SEO-optimised metadata for syndicated posts."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def generate(self, title: str, summary: str, url: str, labels: list[str],
                 published_at: str) -> dict:
        """Return full SEO payload for a syndicated article."""
        cves = _extract_cve_ids(title + " " + summary)
        cvss = _extract_cvss(title + " " + summary)

        meta_title = self._build_meta_title(title, cves)
        meta_description = self._build_meta_description(summary, cves, cvss)
        keywords = self._build_keywords(title, summary, labels, cves)

        result = {
            "meta_title": meta_title,
            "meta_description": meta_description,
            "keywords": keywords,
            "og_tags": self._build_og_tags(meta_title, meta_description, url),
            "twitter_card": self._build_twitter_card(meta_title, meta_description, url),
            "json_ld": self._build_json_ld(meta_title, meta_description, url, labels, published_at, cves),
        }

        logger.info("SEO metadata generated", extra={"title": title[:80], "cves": cves})
        return result

    def _build_meta_title(self, title: str, cves: list[str]) -> str:
        base = title
        suffix = " | CYBERDUDEBIVASH® SENTINEL APEX"
        if len(base) + len(suffix) > 65:
            base = _truncate(base, 65 - len(suffix))
        return base + suffix

    def _build_meta_description(self, summary: str, cves: list[str], cvss: Optional[str]) -> str:
        clean = re.sub(r"\s+", " ", summary).strip()
        prefix = ""
        if cves:
            prefix = f"{', '.join(cves[:2])} — "
        if cvss:
            prefix += f"CVSS {cvss} — "
        full = prefix + clean
        return _truncate(full, 160)

    def _build_keywords(self, title: str, summary: str, labels: list[str],
                        cves: list[str]) -> list[str]:
        words = set(BASE_KEYWORDS)
        for label in labels:
            words.add(label)
        for cve in cves[:5]:
            words.add(cve)
        # Extract significant title words
        for word in re.findall(r"[A-Za-z]{5,}", title):
            if word.lower() not in {"about", "which", "their", "those", "these"}:
                words.add(word)
        return sorted(words)[:25]

    def _build_og_tags(self, title: str, description: str, url: str) -> dict:
        return {
            "og:type": "article",
            "og:title": title,
            "og:description": description,
            "og:url": url,
            "og:image": f"{self.config.source_base_url}/og-image.png",
            "og:site_name": "CYBERDUDEBIVASH® SENTINEL APEX",
        }

    def _build_twitter_card(self, title: str, description: str, url: str) -> dict:
        return {
            "twitter:card": "summary_large_image",
            "twitter:site": "@CyberDudeBivash",
            "twitter:title": title,
            "twitter:description": description,
            "twitter:image": f"{self.config.source_base_url}/og-image.png",
        }

    def _build_json_ld(self, title: str, description: str, url: str,
                       labels: list[str], published_at: str, cves: list[str]) -> dict:
        return {
            "@context": "https://schema.org",
            "@graph": [
                {
                    "@type": "Article",
                    "headline": title,
                    "description": description,
                    "url": url,
                    "datePublished": published_at,
                    "dateModified": datetime.now(timezone.utc).isoformat(),
                    "author": {
                        "@type": "Organization",
                        "name": "CYBERDUDEBIVASH® Threat Intelligence Team",
                        "url": self.config.brand_url,
                    },
                    "publisher": {
                        "@type": "Organization",
                        "name": "CyberDudeBivash Pvt. Ltd.",
                        "url": self.config.brand_url,
                        "logo": {
                            "@type": "ImageObject",
                            "url": f"{self.config.source_base_url}/og-image.png",
                        },
                    },
                    "keywords": ", ".join(labels),
                    "articleSection": labels[0] if labels else "Threat Intelligence",
                    "about": [{"@type": "Thing", "name": cve} for cve in cves],
                },
                {
                    "@type": "Organization",
                    "@id": self.config.brand_url,
                    "name": "CYBERDUDEBIVASH®",
                    "url": self.config.brand_url,
                    "description": "AI-Powered Cyber Threat Intelligence & Enterprise Security",
                    "sameAs": [
                        "https://intel.cyberdudebivash.com",
                        "https://cyberdudebivash.in",
                        "https://tools.cyberdudebivash.com",
                    ],
                },
                {
                    "@type": "BreadcrumbList",
                    "itemListElement": [
                        {"@type": "ListItem", "position": 1,
                         "name": "CYBERDUDEBIVASH", "item": self.config.brand_url},
                        {"@type": "ListItem", "position": 2,
                         "name": "Threat Intelligence", "item": self.config.sentinel_apex_url},
                        {"@type": "ListItem", "position": 3,
                         "name": title[:60], "item": url},
                    ],
                },
            ],
        }

    def build_faq_schema(self, title: str, summary: str, labels: list[str]) -> dict:
        """Generate FAQ schema based on article content signals."""
        questions = []
        text = (title + " " + summary).lower()

        if "cve" in text or "vulnerability" in text:
            questions.append({
                "@type": "Question",
                "name": f"What is the impact of {title[:80]}?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": f"This vulnerability requires immediate attention. {summary[:300]} For full analysis see CYBERDUDEBIVASH® SENTINEL APEX.",
                },
            })
        if "ransomware" in text:
            questions.append({
                "@type": "Question",
                "name": "How can organizations protect against this ransomware threat?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "Organizations should implement immutable backups, network segmentation, EDR solutions, and monitor CYBERDUDEBIVASH® SENTINEL APEX for real-time threat intelligence.",
                },
            })
        if "ai security" in text or "llm" in text or "prompt injection" in text:
            questions.append({
                "@type": "Question",
                "name": "How does this affect enterprise AI deployments?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "Enterprise AI systems must be assessed using the OWASP LLM Top 10 framework. CYBERDUDEBIVASH® AI Security Hub provides enterprise-grade AI security assessments.",
                },
            })

        if not questions:
            return {}

        return {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": questions,
        }
