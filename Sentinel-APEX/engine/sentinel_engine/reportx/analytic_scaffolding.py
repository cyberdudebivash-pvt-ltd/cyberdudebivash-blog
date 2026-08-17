"""Alternative hypotheses (Section 17), intelligence gaps (Section 18), and
the report-specific bibliography/citation graph (Section 22).

Grouped in one module because all three are "scaffolding" structures a
premium report assembles from the same underlying ``EvidenceGraph`` rather
than new epistemics of their own — each is a *view* over claims/sources
that already exist, plus a small amount of its own required metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .claim_model import EvidenceGraph, SourceRole


# ============================================================
# Section 17 — Alternative hypotheses
# ============================================================

@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    label: str  # e.g. "H1"
    statement: str
    supporting_evidence_claim_ids: tuple[str, ...] = ()
    contradicting_evidence_claim_ids: tuple[str, ...] = ()
    confidence: str = ""
    collection_requirement: str = ""

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id, "label": self.label, "statement": self.statement,
            "supporting_evidence_claim_ids": list(self.supporting_evidence_claim_ids),
            "contradicting_evidence_claim_ids": list(self.contradicting_evidence_claim_ids),
            "confidence": self.confidence, "collection_requirement": self.collection_requirement,
        }


@dataclass(frozen=True)
class HypothesisSet:
    """For one ambiguous analytic question (attribution, exploitation,
    breach impact, campaign linkage, victim confirmation, causality)."""

    question: str
    hypotheses: tuple[Hypothesis, ...]

    def is_well_formed(self) -> bool:
        # Section 17: don't fabricate hypotheses when the question isn't
        # analytically meaningful -- but when a set IS presented, it must
        # have at least 2 real alternatives (a "hypothesis set" of one
        # isn't alternative reasoning, it's a restated conclusion) and each
        # must carry at least one evidence reference on either side.
        if len(self.hypotheses) < 2:
            return False
        return all(h.supporting_evidence_claim_ids or h.contradicting_evidence_claim_ids for h in self.hypotheses)


# ============================================================
# Section 18 — Intelligence gaps / collection requirements
# ============================================================

@dataclass(frozen=True)
class IntelligenceGap:
    description: str
    category: str  # "KNOWN_UNKNOWN" | "COLLECTION_GAP" | "PRIORITY_INTELLIGENCE_REQUIREMENT"
    what_would_confirm_or_refute: str = ""

    def to_dict(self) -> dict:
        return {
            "description": self.description, "category": self.category,
            "what_would_confirm_or_refute": self.what_would_confirm_or_refute,
        }


RANSOMWARE_GAP_CHECKLIST = (
    "victim acknowledgement unavailable",
    "no incident IOCs",
    "no sample",
    "no data-volume proof",
    "no initial-access evidence",
    "no encryption confirmation",
)


def derive_ransomware_gaps(victim_observation) -> list[IntelligenceGap]:
    """Section 18's explicit ransomware checklist, derived mechanically
    from a ``VictimObservation`` rather than re-typed by hand per report --
    absence in the data becomes an explicit, visible gap, never silently
    dropped."""
    from .claim_model import EpistemicState  # local import avoids a cycle at module load

    gaps: list[IntelligenceGap] = []
    unresolved = {EpistemicState.NOT_ASSESSED, EpistemicState.UNKNOWN}
    if victim_observation.victim_acknowledgement in unresolved:
        gaps.append(IntelligenceGap("Victim acknowledgement unavailable.", "KNOWN_UNKNOWN",
                                     "A public victim statement or regulator filing acknowledging the incident."))
    if not victim_observation.observed_incident_ioc_claim_ids:
        gaps.append(IntelligenceGap("No incident-specific IOCs observed.", "COLLECTION_GAP",
                                     "Network/host indicators tied specifically to this incident."))
    if victim_observation.sample_proof_status in unresolved:
        gaps.append(IntelligenceGap("No proof sample of claimed stolen data.", "COLLECTION_GAP",
                                     "A verifiable sample from the claimed leak."))
    if victim_observation.independent_confirmation in unresolved:
        gaps.append(IntelligenceGap("No independent confirmation of the leak-site claim.", "PRIORITY_INTELLIGENCE_REQUIREMENT",
                                     "A second, independent source corroborating the claim."))
    if not victim_observation.observed_incident_ttp_claim_ids:
        gaps.append(IntelligenceGap("No initial-access or incident-specific TTP evidence.", "COLLECTION_GAP",
                                     "Forensic or telemetry evidence of the actual intrusion vector."))
    return gaps


# ============================================================
# Section 22 — Report-specific bibliography / citation graph
# ============================================================

@dataclass(frozen=True)
class BibliographyEntry:
    source_id: str
    citation_reasons: tuple[SourceRole, ...]

    def to_dict(self) -> dict:
        return {"source_id": self.source_id, "citation_reasons": [r.value for r in self.citation_reasons]}


def build_bibliography(graph: EvidenceGraph) -> list[BibliographyEntry]:
    """One entry per source actually referenced by at least one claim
    (unreferenced sources -- present in the graph but never cited by any
    claim -- are excluded; they're not part of THIS report's bibliography,
    see orphan_citations below for the reverse check)."""
    used_source_ids: set[str] = set()
    for claim in graph.claims.values():
        used_source_ids.update(claim.source_refs)
        for eid in claim.evidence_refs:
            ev = graph.evidence.get(eid)
            if ev is not None:
                used_source_ids.add(ev.source_id)

    entries = []
    for sid in sorted(used_source_ids):
        src = graph.sources.get(sid)
        if src is not None:
            entries.append(BibliographyEntry(source_id=sid, citation_reasons=(src.source_role,)))
    return entries


def find_orphan_citations(graph: EvidenceGraph) -> list[str]:
    """Sources present in the graph that no claim actually cites --
    Section 22's ``orphan_citations == 0`` gate. (Named for the citation
    being orphaned FROM any claim, not the source record itself being
    invalid.)"""
    used_source_ids: set[str] = set()
    for claim in graph.claims.values():
        used_source_ids.update(claim.source_refs)
        for eid in claim.evidence_refs:
            ev = graph.evidence.get(eid)
            if ev is not None:
                used_source_ids.add(ev.source_id)
    return sorted(set(graph.sources) - used_source_ids)
