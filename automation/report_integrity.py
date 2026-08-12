"""Evidence model and fail-closed publication gate for CTI reports.

The syndication pipeline consumes heterogeneous public sources.  This module
normalises the small set of facts that may be asserted in a public report and
blocks output that crosses those evidence boundaries.
"""

from __future__ import annotations

import hashlib
import html as html_lib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .content_discovery import DiscoveredArticle


REVIEW_STATUS = "Automated intelligence synthesis — not human reviewed"
CERTIFICATION_STATUS = "Public reference draft — not a certified customer deliverable"


class PublicationIntegrityError(ValueError):
    """Raised when a report fails a mandatory evidence-integrity gate."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        super().__init__("Publication blocked: " + "; ".join(issues))


@dataclass(frozen=True)
class ReportContext:
    report_id: str
    source_record_hash: str
    generated_at: str
    family: str
    family_label: str
    exploitation_status: str
    exploitation_label: str
    patch_status: str
    patch_label: str
    vulnerability_class: str
    review_status: str = REVIEW_STATUS
    certification_status: str = CERTIFICATION_STATUS


_CONFIRMED_EXPLOITATION_PATTERNS = (
    r"\bactively exploited\b",
    r"\bexploited in the wild\b",
    r"\bobserved exploitation\b",
    r"\bconfirmed exploitation\b",
    r"\bexploitation (?:has been|was) observed\b",
)

_PATCH_AVAILABLE_PATTERNS = (
    r"\bpatch (?:is )?available\b",
    r"\bvendor (?:has )?released (?:a |an )?(?:patch|fix|update)\b",
    r"\bfixed in (?:version|release)\b",
    r"\bupgrade to (?:version|release)\b",
    r"\bapply (?:the )?(?:vendor )?(?:patch|update)\b",
)


def _source_text(article: DiscoveredArticle) -> str:
    return " ".join(
        part for part in (article.title, article.summary, article.full_content or "") if part
    )


def _record_hash(article: DiscoveredArticle) -> str:
    """Hash the canonical source record, not the generated report HTML."""
    record = {
        "url": article.url,
        "title": article.title,
        "summary": article.summary,
        "published_at": article.published_at,
        "source": article.source,
        "full_content": article.full_content,
        "cve_id": article.cve_id,
        "cvss_score": article.cvss_score,
        "cvss_vector": article.cvss_vector,
        "cwe_ids": article.cwe_ids,
        "affected_vendor": article.affected_vendor,
        "affected_product": article.affected_product,
        "epss_score": article.epss_score,
        "epss_percentile": article.epss_percentile,
        "kev_listed": article.kev_listed,
        "kev_date_added": article.kev_date_added,
        "kev_due_date": article.kev_due_date,
        "kev_required_action": article.kev_required_action,
    }
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _family(article: DiscoveredArticle) -> tuple[str, str]:
    text = _source_text(article).lower()
    labels = {str(label).strip().lower() for label in article.labels}

    if article.source == "cisa_kev" or article.kev_listed is True:
        return "cisa_kev", "CISA KEV Alert"
    if article.source == "ransomware_intel":
        return "ransomware_claim", "Ransomware Claim Intelligence"
    if article.source == "breach_intel":
        return "breach_notice", "Public Breach Record"
    if article.source == "cisa_advisory":
        return "cisa_advisory", "CISA Security Advisory"
    if article.source == "threat_actor_intel":
        return "threat_actor", "Threat Actor Intelligence"
    if article.cve_id or re.search(r"\bCVE-\d{4}-\d{4,}\b", text, re.IGNORECASE):
        return "cve_advisory", "CVE Vulnerability Advisory"
    if "ai security" in labels or re.search(
        r"\b(?:AI|LLM|large language model|generative AI|model safety|prompt injection)\b",
        _source_text(article),
        re.IGNORECASE,
    ):
        return "ai_security", "AI Security Intelligence"
    if "ransomware" in labels or "ransomware" in text:
        return "ransomware_reporting", "Ransomware Intelligence"
    return "general_intelligence", "Cyber Threat Intelligence"


def _exploitation(article: DiscoveredArticle, family: str) -> tuple[str, str]:
    if family == "ransomware_claim":
        return "third_party_claim", "Third-party actor claim — independently unverified"
    if article.kev_listed is True:
        return "confirmed", "Confirmed — CISA KEV listed"

    text = _source_text(article)
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in _CONFIRMED_EXPLOITATION_PATTERNS):
        return "confirmed", "Confirmed by the cited source record"
    if article.kev_listed is False:
        return "not_confirmed", "Not confirmed by available evidence; not in verified KEV snapshot"
    if family in {"cve_advisory", "cisa_advisory"}:
        return "unknown", "Unknown — source record does not confirm active exploitation"
    return "not_applicable", "Not applicable to this intelligence format"


def _patch(article: DiscoveredArticle, family: str) -> tuple[str, str]:
    if family not in {"cisa_kev", "cve_advisory", "cisa_advisory"}:
        return "not_applicable", "Not applicable to this intelligence format"
    if article.kev_required_action:
        return "required_action", f"CISA required action: {article.kev_required_action.strip()}"

    text = _source_text(article)
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in _PATCH_AVAILABLE_PATTERNS):
        return "available", "Remediation update referenced by the cited source"
    return "unconfirmed", "Availability not established in the source record — verify vendor guidance"


_CWE_CLASS = {
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-79": "cross_site_scripting",
    "CWE-89": "sql_injection",
    "CWE-119": "memory_corruption",
    "CWE-200": "information_disclosure",
    "CWE-269": "privilege_escalation",
    "CWE-287": "authentication_failure",
    "CWE-352": "cross_site_request_forgery",
    "CWE-400": "denial_of_service",
    "CWE-787": "memory_corruption",
    "CWE-862": "authorization_failure",
    "CWE-918": "server_side_request_forgery",
}


def _vulnerability_class(article: DiscoveredArticle) -> str:
    for cwe in article.cwe_ids or []:
        if str(cwe).upper() in _CWE_CLASS:
            return _CWE_CLASS[str(cwe).upper()]

    patterns = (
        ("denial_of_service", r"denial[- ]of[- ]service|\bdos\b|resource exhaustion|service crash"),
        ("sql_injection", r"sql injection"),
        ("command_injection", r"command injection|os command|remote code execution|\brce\b|deserialization"),
        ("path_traversal", r"path traversal|directory traversal|arbitrary file (?:read|write)"),
        ("privilege_escalation", r"privilege escalation|elevation of privilege|\blpe\b"),
        ("spoofing", r"spoofing|identity confusion"),
        ("authentication_failure", r"authentication bypass|missing authentication|auth bypass"),
        ("authorization_failure", r"authorization bypass|access control|improper authorization"),
        ("information_disclosure", r"information disclosure|sensitive information|data exposure"),
        ("server_side_request_forgery", r"server[- ]side request forgery|\bssrf\b"),
        ("cross_site_scripting", r"cross[- ]site scripting|\bxss\b"),
    )
    # Prefer the concise identifying fields. Long-form source material may
    # mention related CVEs or background attack classes and must not override
    # an explicit title/summary classification.
    primary_text = f"{article.title} {article.summary}".lower()
    secondary_text = str(article.full_content or "").lower()
    for corpus in (primary_text, secondary_text):
        for name, pattern in patterns:
            if re.search(pattern, corpus, re.IGNORECASE):
                return name
    return "unclassified"


def build_report_context(
    article: DiscoveredArticle,
    generated_at: Optional[datetime] = None,
) -> ReportContext:
    generated = generated_at or datetime.now(timezone.utc)
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    generated_iso = generated.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    source_hash = _record_hash(article)
    try:
        report_year = datetime.fromisoformat(article.published_at.replace("Z", "+00:00")).year
    except (TypeError, ValueError, AttributeError):
        report_year = generated.year

    family, family_label = _family(article)
    exploitation_status, exploitation_label = _exploitation(article, family)
    patch_status, patch_label = _patch(article, family)

    return ReportContext(
        report_id=f"CDB-CTI-{report_year}-{source_hash[:12].upper()}",
        source_record_hash=source_hash,
        generated_at=generated_iso,
        family=family,
        family_label=family_label,
        exploitation_status=exploitation_status,
        exploitation_label=exploitation_label,
        patch_status=patch_status,
        patch_label=patch_label,
        vulnerability_class=_vulnerability_class(article),
    )


_PLACEHOLDER_PATTERNS = (
    r"\bnot found sector\b",
    r"\bcountry of ai\b",
    r"\bpatch unconfirmed\b",
    r"00000000-0000-0000-0000-000000000000",
    r"\b(?:change[_ -]?me|todo|tbd)\b",
)

_UNSUPPORTED_COMMERCIAL_PATTERNS = (
    r"\b2,400\+",
    r"\b10,000\+",
    r"\b40\+ TI sources\b",
    r"\btrusted by \d[\d,]*\+",
)


def validate_publication(article: DiscoveredArticle, context: ReportContext, html: str) -> None:
    """Fail closed on provenance, contradiction, placeholder, and schema defects."""
    issues: list[str] = []
    lower = html.lower()

    required = {
        "report identifier": context.report_id,
        "source-record hash": context.source_record_hash,
        "source URL": article.url,
        "generation timestamp": context.generated_at,
        "review status": context.review_status,
        "certification status": context.certification_status,
    }
    for label, value in required.items():
        if value not in html and html_lib.escape(value, quote=True) not in html:
            issues.append(f"missing {label}")

    if len(html) < 3000:
        issues.append("report body is below minimum production length")

    for pattern in _PLACEHOLDER_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            issues.append(f"placeholder output matched /{pattern}/")

    for pattern in _UNSUPPORTED_COMMERCIAL_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            issues.append(f"unsupported commercial claim matched /{pattern}/")

    if context.exploitation_status != "confirmed":
        forbidden = (
            "active exploitation confirmed",
            "exploitation is confirmed active",
            "actively exploited in the wild",
            "exploitation confirmed?</strong> — yes",
        )
        for phrase in forbidden:
            if phrase in lower:
                issues.append(f"unverified exploitation assertion: {phrase}")

    if article.kev_listed is False:
        for phrase in ("cisa has added this", "already listed in the cisa", "cisa kev inclusion"):
            if phrase in lower:
                issues.append(f"false KEV assertion: {phrase}")

    if context.family == "ransomware_claim":
        for phrase in (
            "pre-exploitation",
            "patch availability",
            'data-section="cve-analysis"',
            'data-section="web-application-exploitation"',
        ):
            if phrase in lower:
                issues.append(f"ransomware schema contamination: {phrase}")

    if context.family == "ai_security" and not article.cve_id:
        for phrase in ("sigma detection rule", "office application shell spawn", "phishing detection logic"):
            if phrase in lower:
                issues.append(f"AI intelligence schema contamination: {phrase}")

    if "bivash kumar nayak — chief security architect" in lower:
        issues.append("human analyst attribution present without a review event")

    if issues:
        raise PublicationIntegrityError(sorted(set(issues)))
