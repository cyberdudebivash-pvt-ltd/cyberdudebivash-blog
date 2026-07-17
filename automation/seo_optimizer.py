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
    return sorted({m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)})


def _extract_cvss(text: str) -> Optional[str]:
    match = re.search(r"CVSS[: ]+(\d+\.?\d*)", text, re.IGNORECASE)
    return match.group(1) if match else None


def _extract_cwe_ids(text: str) -> list[str]:
    """Real CWE IDs only — NVD-sourced summaries include a flattened
    "CWE: CWE-79, CWE-89" line (see nvd_source.py); other sources won't
    match, and that's correct — never invent a CWE that wasn't reported."""
    return sorted({m.upper() for m in re.findall(r"CWE-\d{1,5}", text, re.IGNORECASE)})


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
        cwes = _extract_cwe_ids(title + " " + summary)

        meta_title = self._build_meta_title(title, cves)
        meta_description = self._build_meta_description(summary, cves, cvss)
        keywords = self._build_keywords(title, summary, labels, cves)

        result = {
            "meta_title": meta_title,
            "meta_description": meta_description,
            "keywords": keywords,
            "og_tags": self._build_og_tags(meta_title, meta_description, url),
            "twitter_card": self._build_twitter_card(meta_title, meta_description, url),
            "json_ld": self._build_json_ld(meta_title, meta_description, url, labels, published_at, cves, cwes),
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
                       labels: list[str], published_at: str, cves: list[str],
                       cwes: Optional[list[str]] = None) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        text_lower = title.lower()
        # Use TechArticle for CVE/vulnerability content — better Google News eligibility
        article_type = "TechArticle" if (cves or "vulnerability" in text_lower or "cve" in text_lower) else "NewsArticle"
        og_image_url = f"{self.config.source_base_url}/og-image.png"

        article_node = {
            "@type": article_type,
            "@id": f"{url}#article",
            "headline": title[:110],
            "description": description,
            "url": url,
            "mainEntityOfPage": {"@type": "WebPage", "@id": url},
            "datePublished": published_at,
            "dateModified": now,
            "author": {
                "@type": "Organization",
                "@id": f"{self.config.brand_url}#org",
                "name": "CYBERDUDEBIVASH® Threat Intelligence Team",
                "url": self.config.brand_url,
            },
            "publisher": {
                "@type": "Organization",
                "@id": f"{self.config.brand_url}#org",
                "name": "CYBERDUDEBIVASH® SENTINEL APEX",
                "url": self.config.brand_url,
                "logo": {
                    "@type": "ImageObject",
                    "url": og_image_url,
                    "width": 1200,
                    "height": 630,
                },
            },
            "image": {
                "@type": "ImageObject",
                "url": og_image_url,
                "width": 1200,
                "height": 630,
            },
            "keywords": ", ".join(labels + cves),
            "articleSection": labels[0] if labels else "Threat Intelligence",
            "inLanguage": "en-US",
            "about": (
                [{"@type": "Thing", "name": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"} for cve in cves]
                + [{"@type": "Thing", "name": cwe, "url": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"} for cwe in (cwes or [])]
            ),
            "mentions": [
                {"@type": "SoftwareApplication", "name": "CYBERDUDEBIVASH® SENTINEL APEX",
                 "url": self.config.sentinel_apex_url},
            ],
        }
        if article_type == "TechArticle":
            article_node["proficiencyLevel"] = "Expert"
            article_node["dependencies"] = "MITRE ATT&CK, CISA KEV, NVD"

        return {
            "@context": "https://schema.org",
            "@graph": [
                article_node,
                {
                    "@type": "Organization",
                    "@id": f"{self.config.brand_url}#org",
                    "name": "CYBERDUDEBIVASH®",
                    "url": self.config.brand_url,
                    "description": "AI-Powered Cyber Threat Intelligence & Enterprise Security Platform",
                    "foundingDate": "2024",
                    "contactPoint": {
                        "@type": "ContactPoint",
                        "contactType": "customer support",
                        "email": self.config.contact_email,
                    },
                    "sameAs": [
                        "https://intel.cyberdudebivash.com",
                        "https://cyberdudebivash.in",
                        "https://tools.cyberdudebivash.com",
                        "https://cyberbivash.blogspot.com",
                    ],
                },
                {
                    "@type": "BreadcrumbList",
                    "itemListElement": [
                        {"@type": "ListItem", "position": 1,
                         "name": "CYBERDUDEBIVASH®", "item": self.config.brand_url},
                        {"@type": "ListItem", "position": 2,
                         "name": "Threat Intelligence", "item": f"{self.config.brand_url}/threat-intelligence"},
                        {"@type": "ListItem", "position": 3,
                         "name": title[:60], "item": url},
                    ],
                },
                {
                    "@type": "WebSite",
                    "@id": f"{self.config.brand_url}#website",
                    "url": self.config.brand_url,
                    "name": "CYBERDUDEBIVASH® Intelligence Blog",
                    "description": "Enterprise Cybersecurity Intelligence, CVE Analysis, Threat Hunting, and Detection Engineering",
                    "publisher": {"@id": f"{self.config.brand_url}#org"},
                    "potentialAction": {
                        "@type": "SearchAction",
                        "target": {
                            "@type": "EntryPoint",
                            "urlTemplate": f"{self.config.brand_url}/?s={{search_term_string}}",
                        },
                        "query-input": "required name=search_term_string",
                    },
                },
            ],
        }

    def build_faq_schema(self, title: str, summary: str, labels: list[str]) -> dict:
        """Generate FAQ schema with 3-5 questions for rich results eligibility."""
        questions = []
        text = (title + " " + summary).lower()
        cves = _extract_cve_ids(title + " " + summary)
        cvss = _extract_cvss(title + " " + summary)

        if cves or "vulnerability" in text:
            cve_ref = cves[0] if cves else "this vulnerability"
            cvss_note = f" with CVSS {cvss}" if cvss else ""
            questions.append({
                "@type": "Question",
                "name": f"What is the severity and impact of {cve_ref}?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": f"{cve_ref}{cvss_note} poses a significant risk to enterprise environments. {summary[:350].rstrip('.')}. Immediate patch application and IOC monitoring is recommended. Full analysis available at CYBERDUDEBIVASH® SENTINEL APEX.",
                },
            })
            questions.append({
                "@type": "Question",
                "name": f"How can SOC teams detect exploitation of {cve_ref}?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": f"SOC teams should monitor Windows Security Event IDs 4688 (process creation), 4698 (scheduled task), and web server access logs for exploitation patterns related to {cve_ref}. CYBERDUDEBIVASH® SENTINEL APEX provides production-ready Sigma and YARA detection rules for immediate SIEM deployment.",
                },
            })

        if "ransomware" in text:
            questions.append({
                "@type": "Question",
                "name": "What are the immediate steps to protect against this ransomware threat?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "Immediate actions: (1) Verify immutable backup integrity and test restoration procedures, (2) Enable network segmentation to limit lateral movement, (3) Enforce MFA on all privileged accounts, (4) Monitor for vssadmin/wbadmin shadow copy deletion commands in SIEM. CYBERDUDEBIVASH® SENTINEL APEX provides real-time ransomware IOC feeds and Sigma detection rules.",
                },
            })
            questions.append({
                "@type": "Question",
                "name": "Which MITRE ATT&CK techniques does this ransomware use?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "This ransomware campaign maps to MITRE ATT&CK techniques including: T1566 (Phishing), T1059.001 (PowerShell), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), and T1041 (Exfiltration Over C2 Channel). CYBERDUDEBIVASH® SENTINEL APEX provides full MITRE ATT&CK coverage mapping and detection guidance.",
                },
            })

        if "ai" in text or "llm" in text or "prompt injection" in text:
            questions.append({
                "@type": "Question",
                "name": "How does this threat impact enterprise AI and LLM deployments?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "Enterprise AI deployments face risks including prompt injection (OWASP LLM01), sensitive information disclosure (LLM06), and excessive agency exploitation (LLM08). Organizations should assess AI systems against OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF 1.0. CYBERDUDEBIVASH® AI Security Hub provides enterprise AI security assessments.",
                },
            })

        if "apt" in text or "nation-state" in text:
            questions.append({
                "@type": "Question",
                "name": "How should enterprises respond to this nation-state APT threat?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "Enterprise response to APT activity should include: immediate threat hunt across all endpoints for persistence indicators, audit of privileged account activity, egress traffic analysis for C2 communication, and engagement of a specialized threat intelligence provider. CYBERDUDEBIVASH® SENTINEL APEX APT tracking provides real-time campaign intelligence and detection guidance.",
                },
            })

        if "supply chain" in text or "npm" in text or "pypi" in text or "dependency" in text or (cves and "patch" in text):
            cve_ref = cves[0] if cves else "this issue"
            questions.append({
                "@type": "Question",
                "name": f"What should developers do about {cve_ref}?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": f"Developers should check dependency manifests and lockfiles for the affected package/component version, pin to a patched release, and add a CI/CD policy check (software composition analysis) to prevent regression. Rotate any secrets that may have been exposed in affected build environments.",
                },
            })

        # Always add a general SENTINEL APEX FAQ for conversion
        questions.append({
            "@type": "Question",
            "name": "How does CYBERDUDEBIVASH® SENTINEL APEX help defend against this threat?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "CYBERDUDEBIVASH® SENTINEL APEX provides: real-time CVE and threat intelligence feeds, 2,400+ Sigma/YARA detection rules, MITRE ATT&CK correlation engine, threat hunting workbench, and MSSP-grade intelligence APIs. Enterprise security teams use SENTINEL APEX to reduce detection gaps and respond to threats before they escalate.",
            },
        })

        if len(questions) < 2:
            return {}

        return {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": questions[:5],
        }

    def build_howto_schema(self, title: str, summary: str, labels: list[str]) -> dict:
        """Generate HowTo schema for the response-steps content every report
        already carries (SOC Analyst Playbook). Category-derived the same
        way build_faq_schema() is — no fabricated steps beyond what the
        report itself already publishes for that category."""
        text = (title + " " + summary).lower()
        cves = _extract_cve_ids(title + " " + summary)

        if "ransomware" in text:
            name = "How to Respond to a Ransomware Incident"
            steps = [
                ("Isolate affected hosts", "Immediately isolate affected hosts via VLAN quarantine or firewall ACL block. Do not power off — preserve volatile memory for forensic imaging."),
                ("Identify patient zero", "Use EDR lateral movement timeline to find the earliest infected host and block associated C2 indicators at the perimeter firewall and DNS resolver."),
                ("Verify backup integrity", "Confirm immutable backups are accessible, unaffected by encryption, and that restoration has been tested within the past 90 days."),
                ("Activate incident response", "Engage an incident response partner and begin forensic preservation of confirmed and suspected affected systems."),
                ("Assess notification obligations", "Determine mandatory regulatory breach notification requirements (GDPR 72-hour window, HIPAA 60-day window, applicable state laws)."),
            ]
        elif cves or "vulnerability" in text:
            cve_ref = cves[0] if cves else "the vulnerability"
            name = f"How to Remediate {cve_ref}"
            steps = [
                ("Confirm exposure", f"Identify all systems running the affected component to determine {cve_ref} exposure across your environment."),
                ("Apply the vendor patch", "Apply the vendor-issued patch immediately on all affected instances."),
                ("Deploy compensating controls", "If a patch is not available within 4 hours, implement WAF virtual patching or restrict access to authenticated users only."),
                ("Search for prior exploitation", "Query SIEM, WAF, and web logs retroactively for exploitation payload patterns to rule out pre-patch compromise."),
                ("Verify remediation", "Re-scan affected systems to confirm the patch was applied successfully and the vulnerability is closed."),
            ]
        else:
            return {}

        return {
            "@context": "https://schema.org",
            "@type": "HowTo",
            "name": name,
            "step": [
                {"@type": "HowToStep", "position": i + 1, "name": step_name, "text": step_text}
                for i, (step_name, step_text) in enumerate(steps)
            ],
        }

    def build_glossary_schema(self, title: str, summary: str) -> dict:
        """DefinedTermSet for the standard threat-intel metrics every report
        references (CVE, CVSS, EPSS, CISA KEV) — only includes terms
        actually mentioned in this article, real schema.org definitions,
        not fabricated content."""
        text = (title + " " + summary).lower()
        term_defs = [
            ("CVE", "Common Vulnerabilities and Exposures — a standardized identifier for a publicly disclosed cybersecurity vulnerability, maintained by MITRE.", ["cve"]),
            ("CVSS", "Common Vulnerability Scoring System — an industry-standard 0-10 severity score for a vulnerability's technical impact and exploitability.", ["cvss"]),
            ("EPSS", "Exploit Prediction Scoring System — a data-driven score (0-100%) estimating the probability a vulnerability will be exploited in the wild within the next 30 days, maintained by FIRST.org.", ["epss"]),
            ("CISA KEV", "CISA Known Exploited Vulnerabilities Catalog — a U.S. government-maintained list of vulnerabilities confirmed to be actively exploited, with mandatory remediation deadlines for federal agencies.", ["cisa kev", "known exploited"]),
        ]

        matched = [
            {"@type": "DefinedTerm", "name": name, "description": desc}
            for name, desc, keywords in term_defs
            if any(kw in text for kw in keywords)
        ]

        if not matched:
            return {}

        return {
            "@context": "https://schema.org",
            "@type": "DefinedTermSet",
            "name": "Threat Intelligence Glossary",
            "hasDefinedTerm": matched,
        }
