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

# The ladder's total ordering, lowest to highest. Single source of truth for
# "is tier A at least as high as tier B" -- used below so a computed tier can
# never outrank what was actually requested (see _capped_tier_result()).
# PREMIUM_AUTOMATED_CERTIFIED is deliberately absent: it is never produced by
# this function and never passed in as requested_tier anywhere in this
# codebase (it is reachable only through automated_certification.
# certify_report_automated(), a structurally separate path -- see
# human_review.CertificationState's own docstring), so ranking it here would
# assert an ordering this module has no real basis to claim.
TIER_RANK: dict[CertificationState, int] = {
    CertificationState.PUBLIC_REFERENCE_DRAFT: 0,
    CertificationState.FLASH_READY: 1,
    CertificationState.TACTICAL_READY: 2,
    CertificationState.PREMIUM_READY_PENDING_HUMAN: 3,
    CertificationState.PREMIUM_CERTIFIED: 4,
}


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


def _capped_tier_result(
    requested_tier: CertificationState,
    natural_tier: CertificationState,
    downgrade_reason: str,
    failed_controls: tuple[str, ...],
) -> DowngradeResult:
    """``natural_tier`` is what the control mix alone suggests (e.g.
    ``TACTICAL_READY`` for a report missing premium-only inputs). That is
    only a real downgrade when it is BELOW what was requested -- a report
    that only ever asked for ``FLASH_READY`` was never trying to clear
    forecast/hypothesis/regulatory/depth/statistics/recommendation controls
    in the first place, so being BLOCKED on them is not a shortfall against
    that request. Capping at ``requested_tier`` here is what keeps
    ``determine_achieved_tier`` fail-closed in the direction that matters
    (never invents a passing control) without also fail-*open* in the
    other direction (never invents a HIGHER tier than anyone asked for,
    which is just as much a fabricated commercial claim -- see
    ``report_integrity.build_report_context()``, which renders this exact
    value into the reader-facing certification label)."""
    if TIER_RANK[natural_tier] <= TIER_RANK[requested_tier]:
        return DowngradeResult(requested_tier, natural_tier, downgrade_reason, failed_controls)
    return DowngradeResult(
        requested_tier, requested_tier,
        f"{downgrade_reason} Capped at the requested tier ({requested_tier.value}), which does not "
        "require these controls -- no downgrade from the requested tier is warranted.",
        failed_controls,
    )


def determine_achieved_tier(
    control_results: list[ControlResult],
    requested_tier: CertificationState = CertificationState.PREMIUM_READY_PENDING_HUMAN,
) -> DowngradeResult:
    """Fail-closed: correctness failures land at the bottom
    (``PUBLIC_REFERENCE_DRAFT``) regardless of how much else passed;
    missing premium-completeness components land at ``TACTICAL_READY``;
    correct-and-reasonably-complete-but-not-quite-23/23 lands at
    ``FLASH_READY``; a genuine 23/23 keeps the requested tier. All three
    downgrade branches are additionally capped at ``requested_tier`` via
    ``_capped_tier_result`` -- fail-closed cuts both ways: a computed tier
    must never fall below what the evidence supports, but it must also
    never rise above what was actually requested."""

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
        return _capped_tier_result(
            requested_tier, CertificationState.TACTICAL_READY,
            "correctness controls pass, but one or more premium-completeness controls are "
            "FAILED or BLOCKED (missing forecast, hypotheses, regulatory read, depth, statistics, "
            "or technical recommendations).",
            incomplete,
        )

    remaining = tuple(sorted(r.control_id for r in control_results if r.status != "PASS"))
    return _capped_tier_result(
        requested_tier, CertificationState.FLASH_READY,
        "correct and reasonably complete, but does not clear every commercial-readiness "
        "control required for the requested tier.",
        remaining,
    )
