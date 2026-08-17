"""Claim-support matrix and its commercial gate (ReportX Section 9).

100% material traceability: every claim that is *asserted* (as opposed to
one that honestly declares a gap) must show its evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .claim_model import ClaimType, EpistemicState, EvidenceGraph

# A claim in one of these states is being definitively asserted -- it must
# show its work. States NOT in this set (NOT_ASSESSED, NOT_APPLICABLE,
# UNKNOWN, HYPOTHESIS) are honest, self-declared gaps or provisional
# framing, not assertions, so the absence of evidence *is* the correct
# representation, not a defect this gate should flag.
STATUSES_REQUIRING_EVIDENCE = frozenset({
    EpistemicState.CONFIRMED,
    EpistemicState.REPORTED,
    EpistemicState.CORROBORATED,
    EpistemicState.ASSESSED,
    EpistemicState.DISPUTED,
})


@dataclass(frozen=True)
class MatrixRow:
    claim_id: str
    section: str
    claim_type: str
    evidence_refs: list[str]
    source_refs: list[str]
    corroboration: str
    confidence: str
    status: str
    has_evidence: bool

    def to_dict(self) -> dict:
        return {
            "claim": self.claim_id,
            "section": self.section,
            "type": self.claim_type,
            "evidence": self.evidence_refs,
            "source": self.source_refs,
            "corroboration": self.corroboration,
            "confidence": self.confidence,
            "status": self.status,
        }


def build_claim_support_matrix(graph: EvidenceGraph, claim_sections: dict[str, str] | None = None) -> list[MatrixRow]:
    """One row per claim, in claim_id order for a stable, diffable matrix."""
    claim_sections = claim_sections or {}
    rows = []
    for claim_id in sorted(graph.claims):
        claim = graph.claims[claim_id]
        rows.append(MatrixRow(
            claim_id=claim_id,
            section=claim_sections.get(claim_id, "UNSPECIFIED"),
            claim_type=claim.claim_type.value,
            evidence_refs=list(claim.evidence_refs),
            source_refs=list(claim.source_refs),
            corroboration=claim.corroboration_state.value,
            confidence=claim.confidence.value,
            status=claim.status.value,
            has_evidence=claim.has_evidence(),
        ))
    return rows


def render_matrix_markdown(rows: list[MatrixRow]) -> str:
    lines = [
        "| Claim | Section | Type | Evidence | Source | Corroboration | Confidence | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r.claim_id} | {r.section} | {r.claim_type} | "
            f"{', '.join(r.evidence_refs) or '—'} | {', '.join(r.source_refs) or '—'} | "
            f"{r.corroboration} | {r.confidence} | {r.status} |"
        )
    return "\n".join(lines)


@dataclass
class ClaimSupportGateResult:
    material_claims_without_evidence: list[str] = field(default_factory=list)
    quantitative_claims_without_citation: list[str] = field(default_factory=list)
    actor_attribution_without_evidence: list[str] = field(default_factory=list)
    victim_impact_without_evidence: list[str] = field(default_factory=list)
    observed_ttp_without_evidence: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any([
            self.material_claims_without_evidence,
            self.quantitative_claims_without_citation,
            self.actor_attribution_without_evidence,
            self.victim_impact_without_evidence,
            self.observed_ttp_without_evidence,
        ])

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "material_claims_without_evidence": self.material_claims_without_evidence,
            "quantitative_claims_without_citation": self.quantitative_claims_without_citation,
            "actor_attribution_without_evidence": self.actor_attribution_without_evidence,
            "victim_impact_without_evidence": self.victim_impact_without_evidence,
            "observed_ttp_without_evidence": self.observed_ttp_without_evidence,
        }


def evaluate_claim_support_gate(graph: EvidenceGraph) -> ClaimSupportGateResult:
    result = ClaimSupportGateResult()
    for claim_id in sorted(graph.claims):
        claim = graph.claims[claim_id]
        needs_evidence = claim.status in STATUSES_REQUIRING_EVIDENCE
        if not needs_evidence:
            continue
        if claim.has_evidence():
            continue

        # Every non-generic-guidance claim in an assertive state is
        # "material" for the purposes of this gate.
        if claim.claim_type != ClaimType.GENERIC_GUIDANCE:
            result.material_claims_without_evidence.append(claim_id)

        if claim.claim_type == ClaimType.STATISTIC:
            result.quantitative_claims_without_citation.append(claim_id)
        if claim.claim_type == ClaimType.ACTOR_ATTRIBUTION:
            result.actor_attribution_without_evidence.append(claim_id)
        if claim.claim_type == ClaimType.BUSINESS_IMPACT:
            result.victim_impact_without_evidence.append(claim_id)
        if claim.claim_type == ClaimType.TTP_OBSERVED:
            result.observed_ttp_without_evidence.append(claim_id)

    return result
