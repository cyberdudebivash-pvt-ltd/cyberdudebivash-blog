"""Release-health telemetry (P0 Release-Certification layer, Section 16).

Aggregates real ``audit_log.AuditLogRecord`` history and real
``quality_sampling.SampleOutcome`` history into the metrics Section 16
names. The four finer-grained counts (control failures, contradictions
detected, unsupported claims blocked, source-integrity failures) are
computed from the actual ``ControlResult`` lists a caller has on hand for
those reports — never string-sniffed out of a free-text reason field, which
would be a guess dressed up as a metric.

Read-only with respect to certification: this module never sets a
``CertificationState``. It only ever moves a *release* from
``REPORTX_RELEASE_CERTIFIED`` to ``REPORTX_RELEASE_REVIEW_REQUIRED`` when a
degradation threshold trips (``apply_health_degradation``) — the same
transition ``release_certification.apply_drift_check`` performs for drift,
applied here to accumulated quality signal instead of file-content change.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .audit_log import AuditLogRecord
from .commercial_readiness import ControlResult
from .quality_sampling import SampleOutcome, sample_defect_rate
from .release_certification import ReleaseCertificationManifest, ReleaseState


@dataclass(frozen=True)
class ReleaseHealthMetrics:
    reports_processed: int
    premium_automated_certified: int
    human_escalations: int
    downgrades: int
    control_failures: int
    contradictions_detected: int
    unsupported_claims_blocked: int
    source_integrity_failures: int
    human_qa_samples: int
    human_qa_defect_rate: float

    def to_dict(self) -> dict:
        return {
            "reports_processed": self.reports_processed,
            "premium_automated_certified": self.premium_automated_certified,
            "human_escalations": self.human_escalations,
            "downgrades": self.downgrades,
            "control_failures": self.control_failures,
            "contradictions_detected": self.contradictions_detected,
            "unsupported_claims_blocked": self.unsupported_claims_blocked,
            "source_integrity_failures": self.source_integrity_failures,
            "human_qa_samples": self.human_qa_samples,
            "human_qa_defect_rate": self.human_qa_defect_rate,
        }


def aggregate_health(
    audit_records: list[AuditLogRecord],
    control_results_by_report: dict[str, list[ControlResult]] | None = None,
    sample_outcomes: list[SampleOutcome] | None = None,
) -> ReleaseHealthMetrics:
    control_results_by_report = control_results_by_report or {}
    sample_outcomes = sample_outcomes or []

    premium_automated = sum(1 for r in audit_records if r.certification_state == "PREMIUM_AUTOMATED_CERTIFIED")
    escalations = sum(1 for r in audit_records if r.human_review_required and r.escalation_reason)
    downgrades = sum(1 for r in audit_records if r.downgrade_reason)

    control_failures = 0
    contradictions = 0
    unsupported_claims = 0
    source_integrity_failures = 0
    for results in control_results_by_report.values():
        by_id = {r.control_id: r for r in results}
        control_failures += sum(1 for r in results if r.status == "FAIL")
        if "cross_section_consistency" in by_id:
            contradictions += len(by_id["cross_section_consistency"].failures)
        for cid in ("source_specific_facts", "victim_specific_analysis", "evidence_ledger"):
            if cid in by_id:
                unsupported_claims += len(by_id[cid].failures)
        if "evidence_hash" in by_id:
            source_integrity_failures += len(by_id["evidence_hash"].failures)

    return ReleaseHealthMetrics(
        reports_processed=len(audit_records),
        premium_automated_certified=premium_automated,
        human_escalations=escalations,
        downgrades=downgrades,
        control_failures=control_failures,
        contradictions_detected=contradictions,
        unsupported_claims_blocked=unsupported_claims,
        source_integrity_failures=source_integrity_failures,
        human_qa_samples=len(sample_outcomes),
        human_qa_defect_rate=sample_defect_rate(sample_outcomes),
    )


@dataclass(frozen=True)
class DegradationThresholds:
    max_human_qa_defect_rate: float = 0.10
    max_escalation_rate: float = 0.25
    max_control_failure_rate: float = 0.05


def check_degradation_threshold(
    metrics: ReleaseHealthMetrics, thresholds: DegradationThresholds | None = None,
) -> tuple[bool, tuple[str, ...]]:
    thresholds = thresholds or DegradationThresholds()
    reasons: list[str] = []

    if metrics.reports_processed:
        escalation_rate = metrics.human_escalations / metrics.reports_processed
        if escalation_rate > thresholds.max_escalation_rate:
            reasons.append(
                f"escalation rate {escalation_rate:.1%} exceeds threshold {thresholds.max_escalation_rate:.1%} "
                f"({metrics.human_escalations}/{metrics.reports_processed} reports)"
            )
        control_failure_rate = metrics.control_failures / metrics.reports_processed
        if control_failure_rate > thresholds.max_control_failure_rate:
            reasons.append(
                f"control failure rate {control_failure_rate:.1%} exceeds threshold "
                f"{thresholds.max_control_failure_rate:.1%} ({metrics.control_failures} failures / "
                f"{metrics.reports_processed} reports)"
            )

    if metrics.human_qa_samples and metrics.human_qa_defect_rate > thresholds.max_human_qa_defect_rate:
        reasons.append(
            f"human QA defect rate {metrics.human_qa_defect_rate:.1%} exceeds threshold "
            f"{thresholds.max_human_qa_defect_rate:.1%} ({metrics.human_qa_samples} samples)"
        )

    return bool(reasons), tuple(reasons)


def apply_health_degradation(
    manifest: ReleaseCertificationManifest,
    metrics: ReleaseHealthMetrics,
    thresholds: DegradationThresholds | None = None,
) -> ReleaseCertificationManifest:
    """Mirrors ``release_certification.apply_drift_check``'s shape: a
    manifest that isn't currently ``REPORTX_RELEASE_CERTIFIED`` has nothing
    to degrade away from, so it passes through unchanged."""
    if manifest.release_decision != ReleaseState.REPORTX_RELEASE_CERTIFIED:
        return manifest
    degraded, reasons = check_degradation_threshold(metrics, thresholds)
    if not degraded:
        return manifest
    return replace(
        manifest,
        release_decision=ReleaseState.REPORTX_RELEASE_REVIEW_REQUIRED,
        failed_requirements=manifest.failed_requirements + tuple(f"release health degradation: {r}" for r in reasons),
    )
