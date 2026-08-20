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

from ..models import Confidence
from .claim_model import CorroborationState, Reliability

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
    Reliability A-F x Information Credibility 1-6) -- kept as the plain,
    single-axis summary for any caller that only has a ``Reliability``
    value and no claim graph to derive credibility from. Where both are
    available, prefer ``two_axis_reliability()`` below, which is the real
    2-axis model this function's own docstring named as a follow-up."""
    return _ADMIRALTY_LABELS[reliability]


# COMMERCIAL-QUALITY-2026-08-18: the follow-up admiralty_label() itself
# named -- implements the real, independent 2-axis Admiralty matrix instead
# of the single blended label ("A/B — Reliable") an external review
# correctly flagged as non-standard and as underutilizing information this
# platform already computes. Source Reliability grades the PUBLISHER
# (Reliability, already populated by discovery_bridge.source_reliability());
# Information Credibility grades THIS SPECIFIC CLAIM's corroboration
# (CorroborationState, already computed by
# EvidenceGraph.recompute_corroboration() -- never invented here, only
# read). The two are independent on purpose: a reliable publisher can still
# report an uncorroborated claim, and vice versa.
_RELIABILITY_GRADE: dict[Reliability, str] = {
    Reliability.HIGH: "B",
    Reliability.MODERATE: "C",
    Reliability.LOW: "D",
    Reliability.UNKNOWN: "F",
}

# CorroborationState -> Admiralty Information Credibility (1-6). Deliberately
# conservative: MULTI_SOURCE_DEPENDENT (sources exist but share an
# independence_group -- i.e. syndicated copies of the same original report)
# is graded the same as a single, undisputed source, not treated as
# confirmation, since it isn't independent confirmation.
_CORROBORATION_CREDIBILITY: dict[CorroborationState, int] = {
    CorroborationState.MULTI_SOURCE_INDEPENDENT: 1,
    CorroborationState.MULTI_SOURCE_DEPENDENT: 3,
    CorroborationState.SINGLE_SOURCE: 3,
    CorroborationState.UNCORROBORATED: 6,
}

_CREDIBILITY_LABELS: dict[int, str] = {
    1: "Confirmed by other independent sources",
    2: "Probably True",
    3: "Possibly True",
    4: "Doubtful",
    5: "Improbable",
    6: "Cannot Be Judged",
}


def source_reliability_grade(reliability: Reliability) -> str:
    return _RELIABILITY_GRADE[reliability]


def information_credibility(state: CorroborationState) -> tuple[int, str]:
    number = _CORROBORATION_CREDIBILITY[state]
    return number, _CREDIBILITY_LABELS[number]


def overall_analytical_confidence(reliability: Reliability, credibility_number: int) -> str:
    """A high confidence claim requires BOTH a track-recorded publisher AND
    real corroboration -- neither axis alone is sufficient. Deliberately
    conservative given today's pipeline has no active corroboration engine
    yet, so most reports honestly land at MEDIUM (well-sourced, unconfirmed)
    or LOW (unassessed), not HIGH -- that is the correct, honest signal for
    the platform's current real capability, not a defect to paper over."""
    if credibility_number >= 5 or reliability in (Reliability.LOW, Reliability.UNKNOWN):
        return "LOW"
    if reliability == Reliability.HIGH and credibility_number <= 2:
        return "HIGH"
    return "MEDIUM"


_CORROBORATION_SEVERITY_ORDER = (
    CorroborationState.MULTI_SOURCE_INDEPENDENT,
    CorroborationState.MULTI_SOURCE_DEPENDENT,
    CorroborationState.SINGLE_SOURCE,
    CorroborationState.UNCORROBORATED,
)


def worst_corroboration_state(states) -> CorroborationState:
    """The most conservative (least-corroborated) state among a set of
    claims -- a report's corroboration standing is only as strong as its
    weakest material fact, not its best-supported one. Defaults to
    UNCORROBORATED (the safe assumption) when given no claims at all,
    matching ``Claim.corroboration_state``'s own field default."""
    states = list(states)
    if not states:
        return CorroborationState.UNCORROBORATED
    return max(states, key=_CORROBORATION_SEVERITY_ORDER.index)


def two_axis_reliability(reliability: Reliability, corroboration_state: CorroborationState) -> str:
    """The full replacement for the single blended admiralty_label() output
    -- three separate, correctly-labeled lines instead of one conflated
    "A/B — Reliable" string."""
    credibility_number, credibility_label = information_credibility(corroboration_state)
    confidence = overall_analytical_confidence(reliability, credibility_number)
    return (
        f"Source Reliability: {source_reliability_grade(reliability)}\n"
        f"Information Credibility: {credibility_number} ({credibility_label})\n"
        f"Overall Analytical Confidence: {confidence}"
    )


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


_HUNT_PROPOSED = "PROPOSED"
_HUNT_VALIDATED = "VALIDATED"
# RX-P1I: this pipeline has no mechanism anywhere that learns whether a SOC
# actually ran a hunt and what it found -- every hypothesis this pipeline
# can ever produce is honestly PROPOSED, never VALIDATED. VALIDATED exists
# in the vocabulary (not omitted) so a future increment that DOES ingest
# real hunt-execution feedback has somewhere honest to put it, rather than
# needing a new field bolted on later.
HUNT_MATURITY_STATES = (_HUNT_PROPOSED, _HUNT_VALIDATED)


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
    # RX-P1I additions -- mandate Section 12's remaining 4 fields. Defaults
    # keep every existing construction of this dataclass (real callers and
    # test fixtures alike) working unchanged.
    escalation_criteria: str = ""
    confidence: Confidence = Confidence.MEDIUM
    limitations: str = ""
    maturity: str = _HUNT_PROPOSED

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
            "escalation_criteria": self.escalation_criteria,
            "confidence": self.confidence.value,
            "limitations": self.limitations,
            "maturity": self.maturity,
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
        if h.escalation_criteria:
            lines.append(f"**Escalation criteria:** {h.escalation_criteria}")
            lines.append("")
        lines.append(f"**Confidence:** {h.confidence.value}")
        lines.append("")
        if h.limitations:
            lines.append(f"**Limitations:** {h.limitations}")
            lines.append("")
        lines.append(f"**Maturity:** {h.maturity} — not independently confirmed by execution against real telemetry.")
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
