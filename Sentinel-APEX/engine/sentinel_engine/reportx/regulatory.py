"""Regulatory applicability engine (ReportX Section 14).

Never emits a regulation as generic threat-type boilerplate. Applicability
is a structured, evidence-scoped assessment — and uncertainty is
represented as ``NOT_ASSESSED``, never quietly upgraded into an implied
legal conclusion.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ApplicabilityState(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POTENTIAL = "POTENTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class RegulatoryApplicability:
    jurisdiction: str
    victim_geography: str | None
    operations_geography: str | None
    data_subject_geography: str | None
    sector: str | None
    entity_classification: str | None
    incident_facts_claim_ids: tuple[str, ...]
    regulation: str  # e.g. "GDPR", "NIS2", "HIPAA", "SEC Cyber Disclosure Rule"
    applicability_state: ApplicabilityState
    basis: str  # the reasoning, in one or two sentences -- required whenever state != NOT_ASSESSED
    confidence: str = ""  # free-text rationale, not a numeric score -- this is a legal-reasoning note, not a claim confidence

    def __post_init__(self):
        if self.applicability_state != ApplicabilityState.NOT_ASSESSED and not self.basis:
            raise ValueError(
                f"RegulatoryApplicability for {self.regulation!r} claims "
                f"{self.applicability_state.value} without a stated basis — "
                "every non-NOT_ASSESSED applicability determination must "
                "show its reasoning (Section 14)."
            )

    def to_dict(self) -> dict:
        return {
            "jurisdiction": self.jurisdiction,
            "victim_geography": self.victim_geography,
            "operations_geography": self.operations_geography,
            "data_subject_geography": self.data_subject_geography,
            "sector": self.sector,
            "entity_classification": self.entity_classification,
            "incident_facts_claim_ids": list(self.incident_facts_claim_ids),
            "regulation": self.regulation,
            "applicability_state": self.applicability_state.value,
            "basis": self.basis,
            "confidence": self.confidence,
        }


def not_assessed(regulation: str, reason: str = "") -> RegulatoryApplicability:
    """The explicit, always-safe default for insufficient evidence — never
    guess an applicability determination when the incident facts don't
    establish one (Section 14's closing instruction)."""
    return RegulatoryApplicability(
        jurisdiction="", victim_geography=None, operations_geography=None,
        data_subject_geography=None, sector=None, entity_classification=None,
        incident_facts_claim_ids=(), regulation=regulation,
        applicability_state=ApplicabilityState.NOT_ASSESSED,
        basis=reason,
    )


@dataclass
class RegulatoryGateResult:
    unsupported_determinations: list[str]  # regulation names with a positive state but no basis/facts

    @property
    def passed(self) -> bool:
        return not self.unsupported_determinations

    def to_dict(self) -> dict:
        return {"passed": self.passed, "unsupported_determinations": self.unsupported_determinations}


def evaluate_regulatory_gate(applicabilities: list[RegulatoryApplicability]) -> RegulatoryGateResult:
    """A determination above NOT_ASSESSED/NOT_APPLICABLE with zero linked
    incident facts is unsupported boilerplate, regardless of whether
    ``basis`` text was filled in — a basis sentence with no claim_ids
    behind it cannot be verified against the actual incident evidence."""
    unsupported = []
    for a in applicabilities:
        asserts_something = a.applicability_state in (
            ApplicabilityState.CONFIRMED, ApplicabilityState.LIKELY, ApplicabilityState.POTENTIAL,
        )
        if asserts_something and not a.incident_facts_claim_ids:
            unsupported.append(a.regulation)
    return RegulatoryGateResult(unsupported_determinations=unsupported)
