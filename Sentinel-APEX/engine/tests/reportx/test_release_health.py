"""Tests for sentinel_engine.reportx.release_health."""

from __future__ import annotations

import dataclasses

from sentinel_engine.reportx.audit_log import AuditLogRecord
from sentinel_engine.reportx.commercial_readiness import ControlResult
from sentinel_engine.reportx.quality_sampling import SampleOutcome
from sentinel_engine.reportx.release_certification import ReleaseState
from sentinel_engine.reportx.release_health import (
    DegradationThresholds,
    aggregate_health,
    apply_health_degradation,
    check_degradation_threshold,
)


def _audit(report_id="r1", state="PREMIUM_AUTOMATED_CERTIFIED", escalation="", downgrade="", human_required=False):
    return AuditLogRecord(
        report_id=report_id, artifact_sha256="a" * 64, release_id="rel-1", timestamp="2026-08-18T00:00:00Z",
        automated_controls="23/23", certification_state=state, escalation_reason=escalation,
        downgrade_reason=downgrade, human_review_required=human_required,
    )


class TestAggregateHealth:
    def test_counts_premium_automated_certified(self):
        records = [_audit(state="PREMIUM_AUTOMATED_CERTIFIED"), _audit(state="PREMIUM_AUTOMATED_CERTIFIED"),
                   _audit(state="TACTICAL_READY")]
        metrics = aggregate_health(records)
        assert metrics.reports_processed == 3
        assert metrics.premium_automated_certified == 2

    def test_counts_human_escalations_only_when_flagged_and_reasoned(self):
        records = [
            _audit(escalation="CRITICAL_ATTRIBUTION", human_required=True),
            _audit(escalation="", human_required=True),  # required but no escalation reason -- not counted
            _audit(escalation="EXTREME_SEVERITY", human_required=False),  # reason but not required -- not counted
        ]
        metrics = aggregate_health(records)
        assert metrics.human_escalations == 1

    def test_counts_downgrades(self):
        records = [_audit(downgrade="fail-closed to TACTICAL"), _audit(downgrade=""), _audit(downgrade="fail-closed")]
        metrics = aggregate_health(records)
        assert metrics.downgrades == 2

    def test_derives_finer_grained_counts_from_real_control_results(self):
        results_report_1 = [
            ControlResult("cross_section_consistency", "x", "FAIL", "e", failures=["contradiction A", "contradiction B"]),
            ControlResult("source_specific_facts", "x", "FAIL", "e", failures=["unsupported claim X"]),
            ControlResult("evidence_hash", "x", "FAIL", "e", failures=["source Y missing hash"]),
            ControlResult("evidence_ledger", "x", "PASS", "e"),
        ]
        metrics = aggregate_health([_audit()], control_results_by_report={"r1": results_report_1})
        assert metrics.control_failures == 3
        assert metrics.contradictions_detected == 2
        assert metrics.unsupported_claims_blocked == 1
        assert metrics.source_integrity_failures == 1

    def test_human_qa_defect_rate_comes_from_real_sample_outcomes(self):
        outcomes = [SampleOutcome("r1", "t", "rev", defect_found=True), SampleOutcome("r2", "t", "rev", defect_found=False)]
        metrics = aggregate_health([], sample_outcomes=outcomes)
        assert metrics.human_qa_samples == 2
        assert metrics.human_qa_defect_rate == 0.5

    def test_empty_input_produces_zeroed_metrics_not_an_error(self):
        metrics = aggregate_health([])
        assert metrics.reports_processed == 0
        assert metrics.human_qa_defect_rate == 0.0


class TestDegradationThreshold:
    def test_healthy_metrics_do_not_trigger(self):
        metrics = aggregate_health([_audit() for _ in range(20)])
        degraded, reasons = check_degradation_threshold(metrics)
        assert not degraded
        assert not reasons

    def test_high_escalation_rate_triggers(self):
        records = [_audit(escalation="X", human_required=True) for _ in range(10)] + [_audit() for _ in range(10)]
        metrics = aggregate_health(records)
        degraded, reasons = check_degradation_threshold(metrics, DegradationThresholds(max_escalation_rate=0.25))
        assert degraded
        assert any("escalation rate" in r for r in reasons)

    def test_high_human_qa_defect_rate_triggers(self):
        outcomes = [SampleOutcome(f"r{i}", "t", "rev", defect_found=(i < 3)) for i in range(10)]
        metrics = aggregate_health([], sample_outcomes=outcomes)
        degraded, reasons = check_degradation_threshold(metrics, DegradationThresholds(max_human_qa_defect_rate=0.10))
        assert degraded
        assert any("defect rate" in r for r in reasons)

    def test_zero_samples_does_not_falsely_trigger_defect_rate(self):
        metrics = aggregate_health([_audit() for _ in range(5)])
        degraded, _ = check_degradation_threshold(metrics)
        assert not degraded


class TestApplyHealthDegradation:
    def _certified_manifest_stub(self):
        from sentinel_engine.reportx.release_certification import ReleaseCertificationManifest
        return ReleaseCertificationManifest(
            release_id="rel-1", reportx_engine_version="0.1.0", git_commit_sha="deadbeef",
            claim_schema_version="x", quality_gate_version="x", commercial_validator_version="x",
            threat_schema_versions="x", renderer_version="x", system5_adapter_version="x",
            component_hashes={}, dependency_lock_hash="x", certification_timestamp="2026-08-18T00:00:00Z",
            certified_canary_ids=(), certified_canary_artifact_hashes={}, certified_canary_review_record_hashes={},
            test_results=(), reviewer_identity="TEST-ONLY", release_decision=ReleaseState.REPORTX_RELEASE_CERTIFIED,
        )

    def test_degraded_health_flips_certified_release_to_review_required(self):
        manifest = self._certified_manifest_stub()
        records = [_audit(escalation="X", human_required=True) for _ in range(10)] + [_audit() for _ in range(5)]
        metrics = aggregate_health(records)
        updated = apply_health_degradation(manifest, metrics, DegradationThresholds(max_escalation_rate=0.25))
        assert updated.release_decision == ReleaseState.REPORTX_RELEASE_REVIEW_REQUIRED
        assert any("release health degradation" in f for f in updated.failed_requirements)

    def test_healthy_metrics_leave_certified_release_untouched(self):
        manifest = self._certified_manifest_stub()
        metrics = aggregate_health([_audit() for _ in range(20)])
        updated = apply_health_degradation(manifest, metrics)
        assert updated == manifest

    def test_not_certified_release_is_a_no_op_regardless_of_health(self):
        manifest = dataclasses.replace(self._certified_manifest_stub(), release_decision=ReleaseState.NOT_CERTIFIED)
        records = [_audit(escalation="X", human_required=True) for _ in range(20)]
        metrics = aggregate_health(records)
        updated = apply_health_degradation(manifest, metrics, DegradationThresholds(max_escalation_rate=0.01))
        assert updated == manifest
