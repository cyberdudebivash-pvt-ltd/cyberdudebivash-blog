"""Fail-closed product-tier downgrade ladder (P0 Release-Certification layer,
Section 7).

Reuses ``human_review.CertificationState``'s existing
``PREMIUM_READY_PENDING_HUMAN > TACTICAL_READY > FLASH_READY >
PUBLIC_REFERENCE_DRAFT`` members as the tier vocabulary — that ladder
already existed in the schema (Sections 26/44) but nothing previously
computed a report's place on it from evidence; this module is that
computation, not a new vocabulary. The achieved tier is a pure function of
which of the real 23 ``ControlResult`` rows actually passed. Nothing here
ever manufactures a passing control, borrows evidence from a different
control, or pads content to preserve a higher tier — a report either earned
its tier or it was downgraded, with the specific failed/blocked controls
recorded as the reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .commercial_readiness import ControlResult
from .human_review import CertificationState

# Failure of any of these means the CONTENT is unreliable, not merely
# incomplete -- a report is not "less premium" when its facts don't check
# out, it is not publishable at any tier under this system's truth-telling
# guarantee. Deliberately excludes "fortune_500_commercial_deliverable"
# (the roll-up itself) and "human_analyst_certification_governance" (which
# is about review state, not content correctness, and is not this module's
# concern -- automated_certification.py handles that layer separately).
CORRECTNESS_CONTROLS = frozenset({
    "source_provenance", "evidence_hash", "source_specific_facts",
    "cross_source_corroboration", "threat_type_schema_correctness",
    "cross_section_consistency", "actor_specific_analysis",
    "victim_specific_analysis", "grammar_synthesis_qa", "evidence_ledger",
    "temporal_integrity", "detection_evidence_discipline",
    "report_specific_bibliography",
})

# BLOCKED or FAILED here means "correct, but missing a component premium
# tier requires" -- caps the tier at TACTICAL rather than treating it as a
# correctness defect.
PREMIUM_COMPLETENESS_CONTROLS = frozenset({
    "forecast_methodology", "alternative_hypotheses", "intelligence_gaps",
    "regulatory_specificity", "premium_depth", "current_statistics",
    "technical_recommendations",
})


@dataclass(frozen=True)
class DowngradeResult:
    requested_tier: CertificationState
    achieved_tier: CertificationState
    downgrade_reason: str
    failed_controls: tuple[str, ...] = field(default_factory=tuple)

    @property
    def was_downgraded(self) -> bool:
        return self.achieved_tier != self.requested_tier

    def to_dict(self) -> dict:
        return {
            "requested_tier": self.requested_tier.value,
            "achieved_tier": self.achieved_tier.value,
            "downgrade_reason": self.downgrade_reason,
            "failed_controls": list(self.failed_controls),
        }


def determine_achieved_tier(
    control_results: list[ControlResult],
    requested_tier: CertificationState = CertificationState.PREMIUM_READY_PENDING_HUMAN,
) -> DowngradeResult:
    """Fail-closed: correctness failures land at the bottom
    (``PUBLIC_REFERENCE_DRAFT``) regardless of how much else passed;
    missing premium-completeness components land at ``TACTICAL_READY``;
    correct-and-reasonably-complete-but-not-quite-23/23 lands at
    ``FLASH_READY``; a genuine 23/23 keeps the requested tier."""

    by_id = {r.control_id: r for r in control_results}

    correctness_failures = tuple(sorted(
        cid for cid in CORRECTNESS_CONTROLS if cid in by_id and by_id[cid].status == "FAIL"
    ))
    if correctness_failures:
        return DowngradeResult(
            requested_tier, CertificationState.PUBLIC_REFERENCE_DRAFT,
            "one or more correctness controls FAILED -- the content itself is unreliable, "
            "not merely incomplete; no tier above PUBLIC_REFERENCE_DRAFT is fail-closed-safe.",
            correctness_failures,
        )

    if all(r.status == "PASS" for r in control_results):
        return DowngradeResult(requested_tier, requested_tier, "all 23 controls PASS -- no downgrade required.", ())

    incomplete = tuple(sorted(
        cid for cid in PREMIUM_COMPLETENESS_CONTROLS if cid in by_id and by_id[cid].status != "PASS"
    ))
    if incomplete:
        return DowngradeResult(
            requested_tier, CertificationState.TACTICAL_READY,
            "correctness controls pass, but one or more premium-completeness controls are "
            "FAILED or BLOCKED (missing forecast, hypotheses, regulatory read, depth, statistics, "
            "or technical recommendations).",
            incomplete,
        )

    remaining = tuple(sorted(r.control_id for r in control_results if r.status != "PASS"))
    return DowngradeResult(
        requested_tier, CertificationState.FLASH_READY,
        "correct and reasonably complete, but does not clear every commercial-readiness "
        "control required for the requested tier.",
        remaining,
    )
