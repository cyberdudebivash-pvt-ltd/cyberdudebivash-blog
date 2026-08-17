"""Canonical claim / evidence / source model (ReportX Sections 3-4).

Layering (Section 3):

    SOURCE RECORDS -> EVIDENCE RECORDS -> CLAIMS -> ANALYTIC JUDGMENTS
        -> RECOMMENDATIONS -> REPORT PRODUCT

This module implements the first three layers plus the shared vocabulary
(epistemic states, temporal precision, corroboration) the later layers
build on. Analytic judgments, recommendations, and report assembly live in
sibling modules that import from here — this module has no upward
dependencies.

Every claim carries a stable ``claim_id`` (Section 3's requirement). Nothing
here computes or infers field values from ``model memory`` — every field is
either supplied by the caller (who must trace it to a real source) or left
at its explicit "not established" default (``NOT_ASSESSED`` / ``None`` /
``UNKNOWN``), never silently defaulted to something that reads as positive
evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from ..models import Confidence  # reuse, do not redefine


class EpistemicState(str, Enum):
    """How firmly established a claim is. Deliberately not a linear
    "confidence" scale — these are different *kinds* of standing, not
    degrees of the same thing (Section 3's explicit requirement)."""

    CONFIRMED = "CONFIRMED"            # verified by the analyst/engine against a primary source
    REPORTED = "REPORTED"              # stated by a source, not independently verified
    CORROBORATED = "CORROBORATED"      # REPORTED + independent second source agrees
    ASSESSED = "ASSESSED"              # an analytic judgment, not a directly observed fact
    HYPOTHESIS = "HYPOTHESIS"          # one candidate explanation among several considered
    UNKNOWN = "UNKNOWN"                # the question is meaningful but unanswered
    NOT_ASSESSED = "NOT_ASSESSED"      # not yet evaluated (distinct from UNKNOWN: nobody has looked)
    NOT_APPLICABLE = "NOT_APPLICABLE"  # the question does not apply to this claim/schema
    DISPUTED = "DISPUTED"              # sources directly conflict


# UNKNOWN and NOT_APPLICABLE are never the same field's meaning — see
# schema_isolation.py's tests, which assert this at the schema level for
# RANSOMWARE_VICTIM_CLAIM's CVE-shaped fields specifically (Section 5).


class TemporalPrecision(str, Enum):
    EXACT_TIMESTAMP = "EXACT_TIMESTAMP"
    DATE_ONLY = "DATE_ONLY"
    MONTH_ONLY = "MONTH_ONLY"
    YEAR_ONLY = "YEAR_ONLY"
    UNKNOWN = "UNKNOWN"


_TEMPORAL_PATTERNS: tuple[tuple[re.Pattern, TemporalPrecision], ...] = (
    (re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"), TemporalPrecision.EXACT_TIMESTAMP),
    (re.compile(r"^\d{4}-\d{2}-\d{2}$"), TemporalPrecision.DATE_ONLY),
    (re.compile(r"^\d{4}-\d{2}$"), TemporalPrecision.MONTH_ONLY),
    (re.compile(r"^\d{4}$"), TemporalPrecision.YEAR_ONLY),
)


def infer_temporal_precision(raw: str | None) -> TemporalPrecision:
    """Classify a date string's actual precision instead of assuming full
    timestamp precision. Section 4's explicit example: a source giving only
    ``2026-08-18`` must never be represented as ``2026-08-18T00:00:00Z`` —
    that fabricates a precision (and a specific clock time) the source never
    stated. Callers store the ORIGINAL string in ``source_date`` and this
    function's result in ``temporal_precision`` side by side; nothing here
    rewrites the string itself.
    """
    if not raw:
        return TemporalPrecision.UNKNOWN
    for pattern, precision in _TEMPORAL_PATTERNS:
        if pattern.match(raw.strip()):
            return precision
    return TemporalPrecision.UNKNOWN


class SourceRole(str, Enum):
    """Why a source is cited — Section 22's bibliography categories,
    defined here so a SourceRecord can self-declare its role at the point
    of creation rather than being reclassified later."""

    PRIMARY_EVENT_SOURCE = "PRIMARY_EVENT_SOURCE"
    CORROBORATION = "CORROBORATION"
    ACTOR_CONTEXT = "ACTOR_CONTEXT"
    VULNERABILITY_SOURCE = "VULNERABILITY_SOURCE"
    DETECTION_SOURCE = "DETECTION_SOURCE"
    STATISTICAL_SOURCE = "STATISTICAL_SOURCE"
    REGULATORY_SOURCE = "REGULATORY_SOURCE"
    METHODOLOGY_SOURCE = "METHODOLOGY_SOURCE"


class SourceType(str, Enum):
    VENDOR_CNA = "VENDOR_CNA"
    CISA = "CISA"
    NVD = "NVD"
    MITRE = "MITRE"
    PRIMARY_TECHNICAL_ADVISORY = "PRIMARY_TECHNICAL_ADVISORY"
    LEAK_SITE_AGGREGATOR = "LEAK_SITE_AGGREGATOR"  # e.g. ransomware.live — observation only, see corroboration_policy.py
    VICTIM_STATEMENT = "VICTIM_STATEMENT"
    REGULATOR_FILING = "REGULATOR_FILING"
    JOURNALISM = "JOURNALISM"
    CTI_VENDOR_RESEARCH = "CTI_VENDOR_RESEARCH"
    SECURITY_RESEARCHER = "SECURITY_RESEARCHER"
    OTHER = "OTHER"


class Reliability(str, Enum):
    """Source reliability, independent of any single claim's corroboration
    state — a reliable source can still make an uncorroborated claim."""

    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SourceRecord:
    """One retrieved source. Section 4's required field set."""

    source_id: str
    url: str
    publisher: str
    source_type: SourceType
    source_role: SourceRole
    retrieved_at: str  # ISO-8601 exact timestamp — this IS exact, it's our own retrieval clock, not the source's
    source_date: Optional[str] = None       # verbatim as the source expresses it, e.g. "2026-08-18"
    temporal_precision: TemporalPrecision = TemporalPrecision.UNKNOWN
    content_sha256: Optional[str] = None
    reliability: Reliability = Reliability.UNKNOWN
    independence_group: str = ""  # sources sharing this string are NOT independent of each other (Section 10)
    accessibility: str = "PUBLIC"
    notes: str = ""

    def __post_init__(self):
        if self.source_date and self.temporal_precision == TemporalPrecision.UNKNOWN:
            # Auto-classify only when the caller didn't already set it explicitly —
            # never silently override a caller-supplied precision.
            object.__setattr__(self, "temporal_precision", infer_temporal_precision(self.source_date))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source_type"] = self.source_type.value
        d["source_role"] = self.source_role.value
        d["temporal_precision"] = self.temporal_precision.value
        d["reliability"] = self.reliability.value
        return d


@dataclass(frozen=True)
class EvidenceRecord:
    """A specific excerpt from a source that supports (or is cited by) one
    or more claims. The evidence layer sits between raw sources and claims
    so that a single source can back multiple distinct claims without each
    claim re-quoting the whole source."""

    evidence_id: str
    source_id: str
    excerpt: str
    locator: str = ""  # section/paragraph/line reference within the source, when available

    def to_dict(self) -> dict:
        return asdict(self)


class ClaimType(str, Enum):
    VICTIM_IDENTITY = "VICTIM_IDENTITY"
    ACTOR_ATTRIBUTION = "ACTOR_ATTRIBUTION"
    EXPLOITATION = "EXPLOITATION"
    TTP_OBSERVED = "TTP_OBSERVED"
    TTP_HISTORICAL = "TTP_HISTORICAL"
    DATA_THEFT = "DATA_THEFT"
    RANSOM_PAYMENT = "RANSOM_PAYMENT"
    BUSINESS_IMPACT = "BUSINESS_IMPACT"
    VULNERABILITY_FACT = "VULNERABILITY_FACT"
    DETECTION_STATE = "DETECTION_STATE"
    REGULATORY_APPLICABILITY = "REGULATORY_APPLICABILITY"
    STATISTIC = "STATISTIC"
    FORECAST = "FORECAST"
    GENERIC_GUIDANCE = "GENERIC_GUIDANCE"  # Section 6C — never incident-specific evidence


# High-impact claim types requiring stronger corroboration before their
# epistemic state may exceed REPORTED (Section 10).
HIGH_IMPACT_CLAIM_TYPES = frozenset({
    ClaimType.EXPLOITATION,
    ClaimType.ACTOR_ATTRIBUTION,
    ClaimType.DATA_THEFT,
    ClaimType.RANSOM_PAYMENT,
    ClaimType.BUSINESS_IMPACT,
    ClaimType.TTP_OBSERVED,
    ClaimType.VICTIM_IDENTITY,
})


class CorroborationState(str, Enum):
    SINGLE_SOURCE = "SINGLE_SOURCE"
    MULTI_SOURCE_INDEPENDENT = "MULTI_SOURCE_INDEPENDENT"
    MULTI_SOURCE_DEPENDENT = "MULTI_SOURCE_DEPENDENT"  # sources exist but share an independence_group
    UNCORROBORATED = "UNCORROBORATED"  # no source_refs at all


class ObservedVsContext(str, Enum):
    """Separates "this happened in THIS incident" from "this is what we
    know about the actor/technique/topic in general" — Section 6B/19's
    core distinction, made a first-class claim field so the contradiction
    engine and renderer can enforce it structurally rather than by prose
    convention."""

    OBSERVED = "OBSERVED"    # incident-specific, this event
    CONTEXT = "CONTEXT"      # actor-historical / generic background
    NOT_SET = "NOT_SET"


@dataclass
class Claim:
    """One material, independently traceable assertion."""

    claim_id: str
    claim_type: ClaimType
    text: str
    scope: str = ""
    status: EpistemicState = EpistemicState.NOT_ASSESSED
    confidence: Confidence = Confidence.LOW
    evidence_refs: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    corroboration_state: CorroborationState = CorroborationState.UNCORROBORATED
    source_independence: bool = False
    observed_vs_context: ObservedVsContext = ObservedVsContext.NOT_SET
    temporal_scope: Optional[str] = None
    applicability: str = ""
    contradictions: list[str] = field(default_factory=list)  # other claim_ids
    analyst_notes: str = ""

    def is_high_impact(self) -> bool:
        return self.claim_type in HIGH_IMPACT_CLAIM_TYPES

    def has_evidence(self) -> bool:
        return bool(self.evidence_refs) or bool(self.source_refs)

    def requires_downgrade_without_corroboration(self) -> bool:
        """Section 10: a high-impact claim resting on a single source must
        not be represented above REPORTED, regardless of how confidently
        that one source states it."""
        return (
            self.is_high_impact()
            and self.corroboration_state in (CorroborationState.SINGLE_SOURCE, CorroborationState.UNCORROBORATED)
            and self.status not in (EpistemicState.REPORTED, EpistemicState.NOT_ASSESSED,
                                     EpistemicState.NOT_APPLICABLE, EpistemicState.HYPOTHESIS,
                                     EpistemicState.UNKNOWN, EpistemicState.DISPUTED)
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["claim_type"] = self.claim_type.value
        d["status"] = self.status.value
        d["confidence"] = self.confidence.value
        d["corroboration_state"] = self.corroboration_state.value
        d["observed_vs_context"] = self.observed_vs_context.value
        return d


@dataclass
class EvidenceGraph:
    """The full, per-report container: every source, every evidence
    excerpt, every claim, keyed for O(1) lookup by the validators."""

    sources: dict[str, SourceRecord] = field(default_factory=dict)
    evidence: dict[str, EvidenceRecord] = field(default_factory=dict)
    claims: dict[str, Claim] = field(default_factory=dict)

    def add_source(self, source: SourceRecord) -> SourceRecord:
        self.sources[source.source_id] = source
        return source

    def add_evidence(self, ev: EvidenceRecord) -> EvidenceRecord:
        if ev.source_id not in self.sources:
            raise ValueError(f"EvidenceRecord {ev.evidence_id!r} references unknown source_id {ev.source_id!r}")
        self.evidence[ev.evidence_id] = ev
        return ev

    def add_claim(self, claim: Claim) -> Claim:
        for ref in claim.evidence_refs:
            if ref not in self.evidence:
                raise ValueError(f"Claim {claim.claim_id!r} references unknown evidence_id {ref!r}")
        for ref in claim.source_refs:
            if ref not in self.sources:
                raise ValueError(f"Claim {claim.claim_id!r} references unknown source_id {ref!r}")
        self.claims[claim.claim_id] = claim
        return claim

    def source_independence_groups_for(self, claim: Claim) -> set[str]:
        groups = set()
        for sid in claim.source_refs:
            src = self.sources.get(sid)
            if src is not None:
                groups.add(src.independence_group or sid)  # ungrouped sources are their own group
        for eid in claim.evidence_refs:
            ev = self.evidence.get(eid)
            if ev is not None:
                src = self.sources.get(ev.source_id)
                if src is not None:
                    groups.add(src.independence_group or src.source_id)
        return groups

    def recompute_corroboration(self, claim_id: str) -> CorroborationState:
        """Derives corroboration_state from actual source_refs/evidence_refs
        independence groupings — never set by hand, always computed, so it
        cannot silently drift from the underlying source graph."""
        claim = self.claims[claim_id]
        groups = self.source_independence_groups_for(claim)
        if not groups:
            state = CorroborationState.UNCORROBORATED
        elif len(groups) == 1:
            # could still be >1 physical source, but they're not independent
            total_sources = len(claim.source_refs) + len({
                self.evidence[e].source_id for e in claim.evidence_refs if e in self.evidence
            })
            state = CorroborationState.SINGLE_SOURCE if total_sources <= 1 else CorroborationState.MULTI_SOURCE_DEPENDENT
        else:
            state = CorroborationState.MULTI_SOURCE_INDEPENDENT
        claim.corroboration_state = state
        claim.source_independence = state == CorroborationState.MULTI_SOURCE_INDEPENDENT
        return state

    def to_dict(self) -> dict:
        return {
            "sources": {k: v.to_dict() for k, v in self.sources.items()},
            "evidence": {k: v.to_dict() for k, v in self.evidence.items()},
            "claims": {k: v.to_dict() for k, v in self.claims.items()},
        }
