"""Strict structural + semantic guard for premium-yield recovery.

Production run 33746008715 proved that the P0.1 recovery preflight could still
accept an HTTP-successful LLM response that looked complete to the recovery
layer but could never pass the authoritative premium publication gate.  The
live gate requires not only adequate words/core headings, but independent
section headings plus substantive paragraph/list density.  Composite or
malformed headings could also satisfy substring-based mandatory-heading
matching while collapsing to only a handful of real headings after HTML
sanitization.

This module keeps the platform fail closed.  It does not lower any public,
ReportX, evidence, product-tier, LLM-authorship, artifact-binding, or Blogger
fetch-back requirement.  Instead it makes recovery use the same structural
semantics as publication before it stops model failover, while preserving the
existing terminal-only recovery exception for Executive Recommendations and
References.
"""

from __future__ import annotations

import html as html_lib
import re
from urllib.parse import urlsplit

from . import premium_incident_recovery as _recovery
from . import premium_publication as _premium
from . import premium_yield_hardening as _hardening
from .logger import setup_logger

logger = setup_logger("premium_yield_contract_guard")

_MANDATORY_HEADINGS = (
    "Executive Summary",
    "Key Judgements",
    "Verified Facts",
    "Threat Classification",
    "Threat Severity Assessment",
    "Evidence & Source Assessment",
    "Timeline & Chronology",
    "Business Impact",
    "Enterprise Exposure Assessment",
    "Technical Analysis",
    "Report-Type Deep Dive",
    "MITRE ATT&CK Assessment",
    "Indicators & Observables",
    "Detection Engineering Guidance",
    "Detection Validation & Required Telemetry",
    "Threat Hunting Queries",
    "SOC Analyst Playbook",
    "Incident Response & Containment Decision Plan",
    "Remediation & Validation Plan",
    "Executive Decision Matrix",
    "Executive Recommendations",
    "Intelligence Gaps & Collection Requirements",
    "Analytic Confidence & Limitations",
    "Forecast / Outlook",
    "References",
)
_MANDATORY_NORMALIZED = frozenset(_premium._normalized_heading(value) for value in _MANDATORY_HEADINGS)
_TAIL_REPAIRABLE = frozenset({"executive recommendations", "references"})
_LATE_SECTION_ORDER = (
    "intelligence gaps collection requirements",
    "analytic confidence limitations",
    "forecast outlook",
    "references",
)
_NUMBERED_HEADING_PREFIX_RE = re.compile(r"^(?:section\s+)?\d+(?:\s+\d+)?\s+", re.IGNORECASE)


def _canonical_heading(value: str) -> str:
    """Normalize one independent heading while allowing numeric prefixes."""
    normalized = _premium._normalized_heading(value)
    return _NUMBERED_HEADING_PREFIX_RE.sub("", normalized, count=1).strip()


def _normalized_heading_set(content: str) -> set[str]:
    headings: set[str] = set()
    for value in _premium._headings(content):
        canonical = _canonical_heading(value)
        if canonical:
            headings.add(canonical)
    return headings


def _mandatory_hits(content: str) -> set[str]:
    # Exact one-heading-to-one-section accounting.  A composite heading such
    # as "Executive Summary / Verified Facts / Technical Analysis" matches no
    # mandatory section rather than being counted three times.
    return _normalized_heading_set(content).intersection(_MANDATORY_NORMALIZED)


def _missing_mandatory(content: str) -> set[str]:
    return set(_MANDATORY_NORMALIZED) - _mandatory_hits(content)


def _semantic_metrics(content: str) -> dict[str, int]:
    headings = _normalized_heading_set(content)
    paragraphs, list_items = _premium._semantic_counts(content)
    return {
        "visible_words": _premium._word_count(content),
        "distinct_headings": len(headings),
        "mandatory_headings": len(_mandatory_hits(content)),
        "substantive_paragraphs": paragraphs,
        "substantive_list_items": list_items,
    }


def strict_raw_contract_metrics(content: str) -> tuple[int, int, int]:
    """Compatibility metrics used by recovery logs and candidate selection."""
    metrics = _semantic_metrics(content)
    return (
        metrics["visible_words"],
        metrics["distinct_headings"],
        metrics["mandatory_headings"],
    )


def _tail_list_items_added(missing: set[str]) -> int:
    # Executive Recommendations emits four substantive list items; References
    # emits one.  Terminal recovery adds no paragraphs.
    return (4 if "executive recommendations" in missing else 0) + (1 if "references" in missing else 0)


def _public_semantic_ready(content: str) -> bool:
    metrics = _semantic_metrics(content)
    return bool(
        metrics["visible_words"] >= _premium.MIN_VISIBLE_WORDS
        and metrics["distinct_headings"] >= _premium.MIN_DISTINCT_HEADINGS
        and metrics["substantive_paragraphs"] >= _premium.MIN_PARAGRAPHS
        and metrics["substantive_list_items"] >= _premium.MIN_LIST_ITEMS
    )


def strict_yield_contract_complete(content: str) -> bool:
    """Stop model failover only for a genuinely publishable semantic shape.

    A fully complete response must already contain all 25 mandatory headings
    as independent headings and satisfy the public word/heading/paragraph/list
    floors.  A tail-repairable response may miss only Executive
    Recommendations and/or References; it must already satisfy every metric
    that terminal recovery cannot legitimately improve, and its projected
    list/heading counts after that bounded repair must reach the public floor.
    """
    metrics = _semantic_metrics(content)
    missing = _missing_mandatory(content)

    if not missing:
        return bool(
            metrics["mandatory_headings"] == len(_MANDATORY_NORMALIZED)
            and _public_semantic_ready(content)
        )

    if not missing.issubset(_TAIL_REPAIRABLE):
        return False

    projected_headings = metrics["distinct_headings"] + len(missing)
    projected_list_items = metrics["substantive_list_items"] + _tail_list_items_added(missing)
    return bool(
        metrics["mandatory_headings"] + len(missing) == len(_MANDATORY_NORMALIZED)
        and metrics["visible_words"] >= _premium.MIN_VISIBLE_WORDS
        and projected_headings >= _premium.MIN_DISTINCT_HEADINGS
        and metrics["substantive_paragraphs"] >= _premium.MIN_PARAGRAPHS
        and projected_list_items >= _premium.MIN_LIST_ITEMS
    )


def strict_candidate_score(content: str) -> tuple[int, int, int, int, int, int, int]:
    """Rank incomplete model responses by distance from the real public gate."""
    metrics = _semantic_metrics(content)
    return (
        int(strict_yield_contract_complete(content)),
        metrics["mandatory_headings"],
        min(metrics["distinct_headings"], len(_MANDATORY_NORMALIZED)),
        min(metrics["substantive_paragraphs"], _premium.MIN_PARAGRAPHS),
        min(metrics["substantive_list_items"], _premium.MIN_LIST_ITEMS),
        min(metrics["visible_words"], 3200),
        -len(_missing_mandatory(content)),
    )


def _first_late_section_offset(content: str) -> int | None:
    """Return the first existing section-22+ heading offset for ordered insertion."""
    for match in re.finditer(r"<h3\b[^>]*>.*?</h3>", content, flags=re.IGNORECASE | re.DOTALL):
        normalized = _canonical_heading(_premium._visible_text(match.group(0)))
        if normalized in _LATE_SECTION_ORDER:
            return match.start()
    return None


def _validated_http_url(value: str) -> str | None:
    """Return a canonical link candidate only for safe HTTP(S) absolute URLs."""
    candidate = str(value or "").strip()
    if not candidate or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return None
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    return candidate


def _executive_recommendations_html(family: str, exploitation_status: str) -> str:
    if family == "ransomware_claim":
        recommendations = (
            "<li><strong>Claim handling:</strong> Treat the leak-site or actor statement as a third-party claim until independent internal or external evidence establishes compromise, encryption, theft, or exfiltration.</li>"
            "<li><strong>Exposure validation:</strong> Check authoritative asset, identity, endpoint, network, SaaS, and backup telemetry for source-specific evidence before declaring an incident.</li>"
            "<li><strong>Evidence preservation:</strong> Preserve relevant logs and forensic artifacts so the claim can be confirmed or refuted without destroying chronology.</li>"
            "<li><strong>Escalation:</strong> Escalate containment and notification decisions from verified organizational evidence and applicable obligations, not from the actor claim alone.</li>"
        )
    else:
        exploitation_clause = (
            " Do not represent exploitation as active unless a cited source or verified KEV evidence establishes it."
            if exploitation_status and exploitation_status != "confirmed"
            else ""
        )
        recommendations = (
            "<li><strong>Exposure decision:</strong> Validate affected assets, software, identities, dependencies, or services against authoritative inventory and telemetry before treating this intelligence record as evidence of compromise.</li>"
            f"<li><strong>Evidence boundary:</strong> Keep source-reported facts, analyst assessment, and internal enterprise evidence separate.{exploitation_clause}</li>"
            "<li><strong>Remediation governance:</strong> Apply only remediation or mitigations established by the cited source or authoritative vendor guidance; otherwise use compensating controls and verify the change path before production rollout.</li>"
            "<li><strong>Validation:</strong> Preserve pre-change telemetry and perform post-change verification so remediation effectiveness and residual exposure can be demonstrated.</li>"
        )
    return f"<h3>Executive Recommendations</h3><ul>{recommendations}</ul>\n"


def strict_tail_sections(content: str, prompt: str) -> tuple[str, int]:
    """Repair only observed terminal truncation and only to a gate-ready shape."""
    missing = _missing_mandatory(content)
    if not missing or not missing.issubset(_TAIL_REPAIRABLE):
        return content, 0
    if not strict_yield_contract_complete(content):
        return content, 0

    source_url = _hardening._prompt_value(prompt, "SOURCE URL")
    source_title = _hardening._prompt_value(prompt, "SOURCE TITLE") or "Primary cited source"
    family = _hardening._prompt_value(prompt, "CDB_EVIDENCE_FAMILY").lower()
    exploitation_status = _hardening._prompt_value(prompt, "CDB_EXPLOITATION_STATUS").lower()

    repaired = content
    added = 0

    if "executive recommendations" in missing:
        section = _executive_recommendations_html(family, exploitation_status)
        offset = _first_late_section_offset(repaired)
        if offset is None:
            repaired = repaired.rstrip() + "\n" + section
        else:
            repaired = repaired[:offset] + section + repaired[offset:]
        added += 1

    if "references" in missing:
        validated_url = _validated_http_url(source_url)
        if validated_url is None:
            # Atomic fail closed: do not retain a partial Executive
            # Recommendations repair when References cannot be safely built.
            return content, 0
        safe_url = html_lib.escape(validated_url, quote=True)
        safe_title = html_lib.escape(source_title)
        repaired = repaired.rstrip() + (
            "\n<h3>References</h3><ul>"
            f'<li><strong>Primary cited source:</strong> <a href="{safe_url}" target="_blank" rel="noopener">{safe_title}</a></li>'
            "</ul>\n"
        )
        added += 1

    if _missing_mandatory(repaired) or not _public_semantic_ready(repaired):
        return content, 0

    logger.info(
        "Strict terminal-section recovery completed",
        extra={"sections_added": added, **_semantic_metrics(repaired)},
    )
    return repaired, added


def install_yield_contract_guard() -> None:
    """Patch premium recovery/preflight functions for the production process."""
    _hardening.yield_contract_complete = strict_yield_contract_complete
    _hardening._tail_sections = strict_tail_sections
    _hardening.authoritative_raw_contract_metrics = strict_raw_contract_metrics
    _recovery._raw_contract_metrics = strict_raw_contract_metrics
    _recovery._raw_contract_complete = strict_yield_contract_complete
    _recovery._candidate_score = strict_candidate_score
