"""Strict structural guard for premium-yield recovery.

The yield-hardening layer may repair only the two terminal publication
sections that production has actually observed truncated: Executive
Recommendations and References.  This guard prevents that bounded repair
from being generalized into a way to paper over other missing sections.

It deliberately does not lower or replace any downstream premium, ReportX,
evidence-integrity, product-tier, or Blogger fetch-back gate.  It only makes
the preflight/recovery policy stricter and preserves the prompt's declared
25-section contract and ordering.
"""

from __future__ import annotations

import html as html_lib
import re

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


def _normalized_heading_set(content: str) -> set[str]:
    return {_premium._normalized_heading(value) for value in _premium._headings(content)}


def _mandatory_hits(content: str) -> set[str]:
    headings = _normalized_heading_set(content)
    return {
        required
        for required in _MANDATORY_NORMALIZED
        if any(required == heading or required in heading for heading in headings)
    }


def _missing_mandatory(content: str) -> set[str]:
    return set(_MANDATORY_NORMALIZED) - _mandatory_hits(content)


def strict_yield_contract_complete(content: str) -> bool:
    """Prefer a fully complete report, or one missing only the two tail sections.

    A tail-repairable response must already contain every other mandatory
    section and clear the public 2,200-word floor.  This is intentionally
    stricter than the public gate's minimum 18-heading floor: recovery is a
    convenience for a known terminal truncation pattern, not permission to
    synthesize arbitrary missing report structure.
    """
    words = _premium._word_count(content)
    missing = _missing_mandatory(content)

    if not missing:
        return words >= _recovery._RAW_MIN_VISIBLE_WORDS

    return bool(
        missing.issubset(_TAIL_REPAIRABLE)
        and words >= _premium.MIN_VISIBLE_WORDS
        and len(_mandatory_hits(content)) + len(missing) == len(_MANDATORY_NORMALIZED)
    )


def _first_late_section_offset(content: str) -> int | None:
    """Return the first existing section-22+ heading offset for ordered insertion."""
    for match in re.finditer(r"<h3\b[^>]*>.*?</h3>", content, flags=re.IGNORECASE | re.DOTALL):
        normalized = _premium._normalized_heading(_premium._visible_text(match.group(0)))
        if any(required == normalized or required in normalized for required in _LATE_SECTION_ORDER):
            return match.start()
    return None


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
    """Repair only observed terminal truncation while preserving section order."""
    missing = _missing_mandatory(content)
    if not missing or not missing.issubset(_TAIL_REPAIRABLE):
        return content, 0
    if _premium._word_count(content) < _premium.MIN_VISIBLE_WORDS:
        return content, 0
    if len(_mandatory_hits(content)) + len(missing) != len(_MANDATORY_NORMALIZED):
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
        if not source_url:
            # References cannot be manufactured without the actual canonical
            # source.  Leave the artifact incomplete so existing fail-closed
            # gates reject it rather than synthesizing a citation.
            return content, 0
        safe_url = html_lib.escape(source_url, quote=True)
        safe_title = html_lib.escape(source_title)
        repaired = repaired.rstrip() + (
            "\n<h3>References</h3><ul>"
            f'<li><strong>Primary cited source:</strong> <a href="{safe_url}" target="_blank" rel="noopener">{safe_title}</a></li>'
            "</ul>\n"
        )
        added += 1

    if _missing_mandatory(repaired):
        # Defensive invariant: a programming/markup drift bug in this repair
        # must never be allowed to masquerade as successful completion.
        return content, 0

    logger.info(
        "Strict terminal-section recovery completed",
        extra={"sections_added": added, "visible_words": _premium._word_count(repaired)},
    )
    return repaired, added


def install_yield_contract_guard() -> None:
    """Patch only the premium recovery/preflight functions for this process."""
    _hardening.yield_contract_complete = strict_yield_contract_complete
    _hardening._tail_sections = strict_tail_sections
    _recovery._raw_contract_complete = strict_yield_contract_complete
