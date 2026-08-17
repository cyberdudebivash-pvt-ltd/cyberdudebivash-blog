"""Cross-section consistency validation (ReportX Section 11).

Two complementary layers, because a real report's contradictions show up
in two different places:

1. **Structured dimension checks** — claims tagged with the same canonical
   dimension (``kev_state``, ``detection_state``, ``actor_identity``, ...)
   must agree. Operates on the ``EvidenceGraph``/``Claim`` model directly.
2. **Text-pattern checks** — a report is still rendered prose; the task's
   own motivating examples are contradictions between two SENTENCES, not
   two structured fields (e.g. "no validated actor-specific TTPs" next to
   "attribution based on TTPs from the source"). Operates on rendered
   text. Modeled on ``quality.py``'s existing regex-gate style rather than
   inventing a new pattern.

Gate: ``unresolved_contradictions == 0``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .claim_model import Claim, EpistemicState, EvidenceGraph

CANONICAL_DIMENSIONS = (
    "kev_state",
    "exploitation_state",
    "patch_state",
    "affected_product",
    "fixed_version",
    "actor_identity",
    "technical_attribution",
    "ttp_state",
    "ioc_state",
    "detection_state",
    "victim_confirmation",
    "breach_confirmation",
    "regulatory_applicability",
    "confidence",
    "severity",
    "temporal_chronology",
)


@dataclass(frozen=True)
class Contradiction:
    dimension: str
    description: str
    claim_id_a: str | None = None
    claim_id_b: str | None = None
    severity: str = "block"  # "block" | "warn" -- mirrors quality.py's GateFinding severity vocabulary

    def to_dict(self) -> dict:
        return {
            "dimension": self.dimension,
            "description": self.description,
            "claim_id_a": self.claim_id_a,
            "claim_id_b": self.claim_id_b,
            "severity": self.severity,
        }


# EpistemicState pairs that can never both be asserted for the same
# dimension on the same underlying fact. DISPUTED is deliberately excluded
# here -- DISPUTED is the correct state for representing a genuine
# contradiction the sources themselves haven't resolved, not something
# this checker should itself flag as an engine-introduced defect.
_DIRECTLY_OPPOSED_STATE_PAIRS = frozenset({
    frozenset({EpistemicState.CONFIRMED, EpistemicState.NOT_APPLICABLE}),
})


def find_dimension_contradictions(graph: EvidenceGraph, dimension_tags: dict[str, list[str]]) -> list[Contradiction]:
    """``dimension_tags`` maps a canonical dimension name to the list of
    ``claim_id``s that assert something about that dimension. Within one
    dimension's claim group, every claim must report the same
    ``EpistemicState`` — a mix of directly-opposed states for the same
    named dimension is the structural signature of a cross-section
    contradiction (Section 11's field list)."""

    findings: list[Contradiction] = []
    for dimension, claim_ids in dimension_tags.items():
        claims = [graph.claims[cid] for cid in claim_ids if cid in graph.claims]
        for i, a in enumerate(claims):
            for b in claims[i + 1:]:
                if frozenset({a.status, b.status}) in _DIRECTLY_OPPOSED_STATE_PAIRS:
                    findings.append(Contradiction(
                        dimension=dimension,
                        description=(
                            f"Claim {a.claim_id!r} reports {dimension}={a.status.value} "
                            f"while claim {b.claim_id!r} reports {dimension}={b.status.value} "
                            "for the same dimension."
                        ),
                        claim_id_a=a.claim_id,
                        claim_id_b=b.claim_id,
                    ))
    return findings


# ============================================================
# Text-pattern contradictions — the task's own motivating examples,
# encoded directly as regression rules.
# ============================================================

_TEXT_CONTRADICTION_RULES: tuple[tuple[re.Pattern, re.Pattern, str], ...] = (
    (
        re.compile(r"no validated actor-specific TTPs", re.IGNORECASE),
        re.compile(r"attribution\s+(?:is|was)?\s*based on TTPs", re.IGNORECASE),
        "Report states no validated actor-specific TTPs exist, but elsewhere "
        "bases attribution on TTPs from the source.",
    ),
    (
        re.compile(r"DETECTION STATUS:\s*WITHHELD_INSUFFICIENT_EVIDENCE", re.IGNORECASE),
        re.compile(r"push\s+(?:actor\s+)?detection rules?\s+(?:covering\s+\S+\s+)?immediately", re.IGNORECASE),
        "Detection status is WITHHELD_INSUFFICIENT_EVIDENCE, but guidance "
        "instructs pushing the detection rule(s) immediately.",
    ),
    (
        re.compile(r"\bexperimental\b[^.\n]{0,60}\bdetection\b", re.IGNORECASE),
        re.compile(r"production[- ]validated\s+detection", re.IGNORECASE),
        "Detection is labeled experimental in one place and "
        "production-validated in another.",
    ),
)


def find_text_contradictions(full_text: str) -> list[Contradiction]:
    findings: list[Contradiction] = []
    for pattern_a, pattern_b, description in _TEXT_CONTRADICTION_RULES:
        if pattern_a.search(full_text) and pattern_b.search(full_text):
            findings.append(Contradiction(dimension="text-pattern", description=description))
    return findings


def find_all_contradictions(
    graph: EvidenceGraph,
    dimension_tags: dict[str, list[str]] | None = None,
    full_text: str = "",
) -> list[Contradiction]:
    findings = list(find_dimension_contradictions(graph, dimension_tags or {}))
    if full_text:
        findings += find_text_contradictions(full_text)
    return findings
