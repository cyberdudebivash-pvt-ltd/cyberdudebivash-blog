"""Executive-product renderers for the Intelligence Factory (P0
architecture, ``REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md``).

Four small, focused additions the MISSION standard needs that no existing
ReportX module produces yet — deliberately built as thin renderers over
data the caller already evidenced, never as a second evidence model:

1. Admiralty-style source-reliability display over the existing
   ``claim_model.Reliability`` field (no schema change).
2. Threat-hunting hypotheses (``HuntPackage``) — the same evidentiary
   shape as ``analytic_scaffolding.Hypothesis``, extended with the
   hunt-specific fields (telemetry, pivots, negative indicators,
   false-positive considerations, validation steps, success criteria)
   Sections 15/Detection engineering's ``DetectionPackage`` doesn't cover.
3. Role-differentiated executive decisions (``RoleDecision``) — replaces
   a single generic "Executive Decision Matrix" with distinct,
   claim-grounded guidance per stakeholder role. A role with nothing
   evidence-grounded to say is omitted, never padded to a boilerplate
   filler sentence.
4. Sector impact matrix (``SectorImpact``) — one row per sector actually
   assessed; unassessed sectors are recorded ``NOT_ASSESSED`` with a
   reason, never silently dropped or defaulted to a shared paragraph.

Every dataclass here carries ``evidence_claim_ids`` (or equivalent) back
into the caller's own ``EvidenceGraph`` — this module renders, it does not
originate claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .claim_model import Reliability

_ADMIRALTY_LABELS: dict[Reliability, str] = {
    Reliability.HIGH: "A/B — Reliable (completely or usually reliable source)",
    Reliability.MODERATE: "C — Fairly Reliable (has been valid in the past, some doubt)",
    Reliability.LOW: "D/E — Not Usually / Cannot Be Judged Reliable",
    Reliability.UNKNOWN: "F — Reliability Cannot Be Judged",
}


def admiralty_label(reliability: Reliability) -> str:
    """Presentation-only mapping of the existing 4-tier ``Reliability``
    field onto Admiralty-Code-adjacent language. This is a documented
    simplification of the full independent 2-axis Admiralty matrix (Source
    Reliability A-F x Information Credibility 1-6) — see
    ``REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md``'s "Source reliability
    display" section for why the second axis is a real, separate follow-up
    rather than silently approximated here."""
    return _ADMIRALTY_LABELS[reliability]


class RoleAudience(str, Enum):
    CEO_BOARD = "CEO_BOARD"
    CISO_CIO = "CISO_CIO"
    SOC_MANAGER = "SOC_MANAGER"
    IR_MANAGER = "IR_MANAGER"
    THREAT_HUNTER = "THREAT_HUNTER"
    VULNERABILITY_MANAGER = "VULNERABILITY_MANAGER"
    CLOUD_TEAM = "CLOUD_TEAM"
    OT_TEAM = "OT_TEAM"
    LEGAL_COMPLIANCE_PRIVACY = "LEGAL_COMPLIANCE_PRIVACY"
    BUSINESS_CONTINUITY_SUPPLY_CHAIN = "BUSINESS_CONTINUITY_SUPPLY_CHAIN"
    MSSP = "MSSP"


# COMMERCIAL-QUALITY-2026-08-18: independently verified live (and separately
# flagged in the same terms by an external review) that
# ``role.value.replace('_', ' ').title()`` renders acronym-bearing roles
# wrong -- "Ir Manager", "Soc Manager", "Ciso Cio", "Ot Team", "Mssp" --
# because str.title() capitalizes only the first letter of each
# underscore-delimited word, with no notion of an acronym. Single source of
# truth for every renderer that displays a RoleAudience, so the fix can't
# drift between them.
ROLE_DISPLAY_LABELS: dict[RoleAudience, str] = {
    RoleAudience.CEO_BOARD: "CEO / Board",
    RoleAudience.CISO_CIO: "CISO / CIO",
    RoleAudience.SOC_MANAGER: "SOC Manager",
    RoleAudience.IR_MANAGER: "IR Manager",
    RoleAudience.THREAT_HUNTER: "Threat Hunter",
    RoleAudience.VULNERABILITY_MANAGER: "Vulnerability Manager",
    RoleAudience.CLOUD_TEAM: "Cloud Team",
    RoleAudience.OT_TEAM: "OT Team",
    RoleAudience.LEGAL_COMPLIANCE_PRIVACY: "Legal / Compliance / Privacy",
    RoleAudience.BUSINESS_CONTINUITY_SUPPLY_CHAIN: "Business Continuity / Supply Chain",
    RoleAudience.MSSP: "MSSP",
}


def role_display_label(role: RoleAudience) -> str:
    return ROLE_DISPLAY_LABELS[role]


@dataclass(frozen=True)
class RoleDecision:
    role: RoleAudience
    decision: str
    rationale: str
    evidence_claim_ids: tuple[str, ...]
    timeline: str = ""

    def to_dict(self) -> dict:
        return {
            "role": self.role.value, "decision": self.decision, "rationale": self.rationale,
            "evidence_claim_ids": list(self.evidence_claim_ids), "timeline": self.timeline,
        }


def render_role_decisions(decisions: list[RoleDecision]) -> str:
    if not decisions:
        return ""
    lines = ["## Role-Based Executive Decisions", ""]
    for d in decisions:
        lines.append(f"### {role_display_label(d.role)}")
        lines.append("")
        lines.append(f"**Decision:** {d.decision}")
        if d.timeline:
            lines.append(f"**Timeline:** {d.timeline}")
        lines.append(f"**Rationale:** {d.rationale}")
        lines.append(f"**Evidence:** {', '.join(d.evidence_claim_ids)}")
        lines.append("")
    return "\n".join(lines)


@dataclass(frozen=True)
class HuntHypothesis:
    hypothesis_id: str
    statement: str
    required_telemetry: tuple[str, ...]
    pivot_opportunities: tuple[str, ...]
    expected_observations: tuple[str, ...]
    negative_indicators: tuple[str, ...]
    false_positive_considerations: tuple[str, ...]
    validation_steps: tuple[str, ...]
    success_criteria: str
    evidence_claim_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id, "statement": self.statement,
            "required_telemetry": list(self.required_telemetry),
            "pivot_opportunities": list(self.pivot_opportunities),
            "expected_observations": list(self.expected_observations),
            "negative_indicators": list(self.negative_indicators),
            "false_positive_considerations": list(self.false_positive_considerations),
            "validation_steps": list(self.validation_steps),
            "success_criteria": self.success_criteria,
            "evidence_claim_ids": list(self.evidence_claim_ids),
        }


def render_hunt_package(hypotheses: list[HuntHypothesis]) -> str:
    if not hypotheses:
        return ""
    lines = ["## Threat Hunting", ""]
    for h in hypotheses:
        lines.append(f"### Hypothesis {h.hypothesis_id}")
        lines.append("")
        lines.append(f"**Statement:** {h.statement}")
        lines.append("")
        lines.append("**Required telemetry:**")
        lines += [f"- {t}" for t in h.required_telemetry]
        lines.append("")
        lines.append("**Pivot opportunities:**")
        lines += [f"- {p}" for p in h.pivot_opportunities]
        lines.append("")
        lines.append("**Expected observations if true:**")
        lines += [f"- {e}" for e in h.expected_observations]
        lines.append("")
        lines.append("**Negative indicators (hypothesis likely false if observed):**")
        lines += [f"- {n}" for n in h.negative_indicators]
        lines.append("")
        lines.append("**False-positive considerations:**")
        lines += [f"- {f}" for f in h.false_positive_considerations]
        lines.append("")
        lines.append("**Validation steps:**")
        lines += [f"{i + 1}. {v}" for i, v in enumerate(h.validation_steps)]
        lines.append("")
        lines.append(f"**Success criteria:** {h.success_criteria}")
        lines.append("")
        lines.append(f"**Evidence:** {', '.join(h.evidence_claim_ids) if h.evidence_claim_ids else 'none — this is a forward-looking hunt, not a retrospective claim'}")
        lines.append("")
    return "\n".join(lines)


class SectorApplicability(str, Enum):
    ASSESSED = "ASSESSED"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True)
class SectorImpact:
    sector: str
    applicability: SectorApplicability
    exposure_note: str
    regulatory_note: str = ""
    evidence_claim_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "sector": self.sector, "applicability": self.applicability.value,
            "exposure_note": self.exposure_note, "regulatory_note": self.regulatory_note,
            "evidence_claim_ids": list(self.evidence_claim_ids),
        }


def render_sector_impact_matrix(rows: list[SectorImpact]) -> str:
    if not rows:
        return ""
    lines = [
        "## Sector Impact Matrix", "",
        "| Sector | Applicability | Exposure | Regulatory note |",
        "|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r.sector} | {r.applicability.value} | {r.exposure_note} | {r.regulatory_note or '—'} |")
    lines.append("")
    return "\n".join(lines)
