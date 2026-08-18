"""Per-report automated premium certification (P0 Release-Certification
layer, Sections 3/5/6/9).

The central invariant, enforced by construction rather than by convention:
``certify_report_automated()`` never imports ``ReviewRecord`` and never
constructs one. Automated certification and human review are two
structurally disjoint code paths that happen to write into the same
``CertificationState`` vocabulary — a ``PREMIUM_AUTOMATED_CERTIFIED`` result
coming out of this module is, by construction, incapable of being confused
with a human's ``APPROVE``.

Section 5's distinction, made concrete: this module's only certified input
is a ``release_certification.ReleaseCertificationManifest`` (the release's
own demonstrated behaviour on the four required canaries) plus THIS
report's own real 23-control result. A canary's approval never reaches an
individual future report through this code path — there is no parameter
here through which one could.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .claim_model import SourceRecord
from .commercial_readiness import ControlResult
from .detection_validation import DetectionRule, check_all_rules
from .evidence_integrity import evaluate_source_integrity_gate
from .human_review import CertificationState
from .product_depth import ReportSection, find_template_repetition
from .release_certification import ReleaseCertificationManifest, ReleaseState, detect_drift
from .tier_downgrade import determine_achieved_tier


class EscalationReason(str, Enum):
    UNUSUAL_SOURCE_DISAGREEMENT = "UNUSUAL_SOURCE_DISAGREEMENT"
    NOVEL_THREAT_TYPE = "NOVEL_THREAT_TYPE"
    NEW_SCHEMA_FIELD = "NEW_SCHEMA_FIELD"
    CRITICAL_ATTRIBUTION = "CRITICAL_ATTRIBUTION"
    CRITICAL_VICTIM_CONFIRMATION = "CRITICAL_VICTIM_CONFIRMATION"
    ACTIVE_EXPLOITATION_AMBIGUITY = "ACTIVE_EXPLOITATION_AMBIGUITY"
    EXCEPTIONAL_REGULATORY_DETERMINATION = "EXCEPTIONAL_REGULATORY_DETERMINATION"
    DETECTION_STATE_PROMOTION = "DETECTION_STATE_PROMOTION"
    NOVEL_UNSUPPORTED_TECHNICAL_RECOMMENDATION = "NOVEL_UNSUPPORTED_TECHNICAL_RECOMMENDATION"
    CONFIDENCE_ANOMALY = "CONFIDENCE_ANOMALY"
    EXTREME_SEVERITY = "EXTREME_SEVERITY"
    SOURCE_INTEGRITY_FALLBACK_THRESHOLD = "SOURCE_INTEGRITY_FALLBACK_THRESHOLD"
    CROSS_REPORT_SIMILARITY_ANOMALY = "CROSS_REPORT_SIMILARITY_ANOMALY"
    COMMERCIAL_VALIDATOR_WARNING = "COMMERCIAL_VALIDATOR_WARNING"


@dataclass(frozen=True)
class AutomatedCertificationResult:
    report_id: str
    release_id: str
    certification_state: CertificationState
    commercial_readiness_pass_count: int
    commercial_readiness_total_count: int
    escalation_reasons: tuple[EscalationReason, ...] = field(default_factory=tuple)
    refusal_reasons: tuple[str, ...] = field(default_factory=tuple)
    decided_at: str = ""

    @property
    def is_automated_certified(self) -> bool:
        return self.certification_state == CertificationState.PREMIUM_AUTOMATED_CERTIFIED

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id, "release_id": self.release_id,
            "certification_state": self.certification_state.value,
            "commercial_readiness_pass_count": self.commercial_readiness_pass_count,
            "commercial_readiness_total_count": self.commercial_readiness_total_count,
            "escalation_reasons": [r.value for r in self.escalation_reasons],
            "refusal_reasons": list(self.refusal_reasons),
            "decided_at": self.decided_at,
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def certify_report_automated(
    report_id: str,
    release_manifest: ReleaseCertificationManifest | None,
    control_results: list[ControlResult],
    escalation_reasons: list[EscalationReason] | None = None,
    repo_root: Path | None = None,
) -> AutomatedCertificationResult:
    """Section 6's pseudo-contract, literally:

    ``if not current_release.is_certified: refuse``
    ``if commercial_controls != 23_PASS: refuse`` (fail-closed downgrade, not disappearance)
    ``if drift_detected: escalate human review``
    ``if escalation_triggered: PREMIUM_READY_PENDING_HUMAN``
    ``else: PREMIUM_AUTOMATED_CERTIFIED``
    """
    escalation_reasons = escalation_reasons or []
    pass_count = sum(1 for r in control_results if r.status == "PASS")
    total_count = len(control_results)

    if release_manifest is None or not release_manifest.is_certified:
        return AutomatedCertificationResult(
            report_id, release_manifest.release_id if release_manifest else "",
            CertificationState.PREMIUM_READY_PENDING_HUMAN, pass_count, total_count,
            tuple(escalation_reasons),
            ("no currently REPORTX_RELEASE_CERTIFIED release manifest supplied -- automated "
             "certification is refused until a release is certified (Section 5: an uncertified "
             "release cannot vouch for any report).",),
            _now(),
        )

    drift = detect_drift(release_manifest, repo_root)
    if drift.drifted:
        return AutomatedCertificationResult(
            report_id, release_manifest.release_id,
            CertificationState.PREMIUM_READY_PENDING_HUMAN, pass_count, total_count,
            tuple(escalation_reasons),
            (f"release component drift detected since certification: {list(drift.changed_components)} "
             "-- escalated to human review per Section 8.",),
            _now(),
        )

    if pass_count != total_count:
        downgrade = determine_achieved_tier(control_results, requested_tier=CertificationState.PREMIUM_READY_PENDING_HUMAN)
        return AutomatedCertificationResult(
            report_id, release_manifest.release_id, downgrade.achieved_tier, pass_count, total_count,
            tuple(escalation_reasons),
            (f"commercial readiness {pass_count}/{total_count}, not 23/23 -- refused automated "
             f"premium certification and fail-closed downgraded: {downgrade.downgrade_reason}",),
            _now(),
        )

    if escalation_reasons:
        return AutomatedCertificationResult(
            report_id, release_manifest.release_id,
            CertificationState.PREMIUM_READY_PENDING_HUMAN, pass_count, total_count,
            tuple(escalation_reasons),
            (f"23/23 PASS, but {len(escalation_reasons)} escalation signal(s) present "
             "-- routed to human review rather than automated certification.",),
            _now(),
        )

    return AutomatedCertificationResult(
        report_id, release_manifest.release_id, CertificationState.PREMIUM_AUTOMATED_CERTIFIED,
        pass_count, total_count, (), (), _now(),
    )


# ============================================================
# Derivable escalation signals -- Section 9 names 14 categories; the three
# below are the ones this codebase has real, existing gates for (reused, not
# re-implemented). The other 11 (novel threat type, critical attribution,
# confidence anomaly, extreme severity, ...) are inherently analyst/product
# judgment calls with no existing signal in this data model to derive them
# from honestly; ``EscalationReason`` still names them so a human reviewer,
# an upstream classifier, or a future gate can supply them as input to
# ``certify_report_automated()`` without inventing a new vocabulary. Wiring
# fabricated detection logic for signals this system cannot actually see
# would violate the same non-fabrication discipline that governs claims and
# evidence -- so this module does not pretend to.
# ============================================================

def derive_detection_state_escalation(
    detection_rules: list[DetectionRule], rendered_text: str,
) -> list[EscalationReason]:
    if check_all_rules(detection_rules, rendered_text):
        return [EscalationReason.DETECTION_STATE_PROMOTION]
    return []


def derive_source_integrity_escalation(
    sources: list[SourceRecord], max_fallback_ratio: float = 0.34,
) -> list[EscalationReason]:
    gate = evaluate_source_integrity_gate(list(sources))
    total = gate.full_content_hash_count + gate.excerpt_fingerprint_count
    if total and (gate.excerpt_fingerprint_count / total) > max_fallback_ratio:
        return [EscalationReason.SOURCE_INTEGRITY_FALLBACK_THRESHOLD]
    return []


def derive_cross_report_similarity_escalation(
    report_id: str, this_report_sections: list[ReportSection], corpus_sections: list[ReportSection],
) -> list[EscalationReason]:
    findings = find_template_repetition(list(this_report_sections) + list(corpus_sections))
    if any(f.report_id_a == report_id or f.report_id_b == report_id for f in findings):
        return [EscalationReason.CROSS_REPORT_SIMILARITY_ANOMALY]
    return []


def render_automated_certification_block(report_id: str, release_id: str, pass_count: int, total_count: int) -> str:
    """Section 12's automated-report template, verbatim. Never contains the
    words 'HUMAN REVIEWED', 'ANALYST APPROVED', or 'PREMIUM_CERTIFIED' — see
    ``render_human_reviewed_certification_block`` below for the ONLY block
    permitted to say those things, and ``test_automated_certification.py``
    for the test that keeps the two from drifting into each other."""
    return (
        "Certification:\n"
        "CYBERDUDEBIVASH SENTINEL APEX REPORTX\n"
        "AUTOMATED PREMIUM CERTIFIED\n\n"
        f"Commercial Readiness:\n{pass_count}/{total_count} PASS\n\n"
        f"Release:\n{release_id}\n\n"
        "Human Review:\nNOT INDIVIDUALLY HUMAN REVIEWED"
    )


def render_human_reviewed_certification_block(
    pass_count: int, total_count: int, reviewer_identity: str, artifact_sha256: str,
) -> str:
    """Section 12's human-reviewed template, verbatim. Only ever call this
    with a real, artifact-bound ``ReviewRecord``'s own fields — this
    function does not itself validate the review, it only renders the
    block, so validate with ``human_review.is_review_valid_for_artifact``
    (or ``resolve_certification_state``) BEFORE calling it."""
    return (
        "Certification:\n"
        "CYBERDUDEBIVASH SENTINEL APEX REPORTX\n"
        "PREMIUM CERTIFIED\n\n"
        f"Commercial Readiness:\n{pass_count}/{total_count} PASS\n\n"
        "Human Review:\nAPPROVED\n\n"
        f"Reviewer:\n{reviewer_identity}\n\n"
        f"Artifact:\n{artifact_sha256[:16]}..."
    )


def collect_derivable_escalations(
    report_id: str,
    detection_rules: list[DetectionRule],
    rendered_text: str,
    sources: list[SourceRecord],
    this_report_sections: list[ReportSection] | None = None,
    corpus_sections: list[ReportSection] | None = None,
) -> list[EscalationReason]:
    """Convenience aggregator over the three derivable signals above.
    Cross-report similarity is only checked when a corpus was actually
    supplied -- an empty corpus is not evidence of similarity, it's absence
    of a comparison, so it is skipped rather than silently passed."""
    reasons = derive_detection_state_escalation(detection_rules, rendered_text)
    reasons += derive_source_integrity_escalation(sources)
    if this_report_sections is not None and corpus_sections:
        reasons += derive_cross_report_similarity_escalation(report_id, this_report_sections, corpus_sections)
    return reasons
