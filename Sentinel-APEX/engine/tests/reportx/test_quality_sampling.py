"""Tests for sentinel_engine.reportx.quality_sampling -- Section 17 test
#14 ("sampling does not alter certification semantics") plus general
module coverage.
"""

from __future__ import annotations

import inspect

from sentinel_engine.reportx import quality_sampling as qs
from sentinel_engine.reportx.human_review import (
    CertificationState,
    ReviewDecision,
    ReviewRecord,
    compute_artifact_hash,
    resolve_certification_state,
)
from sentinel_engine.reportx.quality_sampling import RiskFactors, SamplingConfig, SampleOutcome, sample_defect_rate, should_sample


class TestSamplingModuleIsStructurallyIsolatedFromCertification:
    """Section 17 test #14, enforced structurally: this module cannot
    reach into a CertificationState decision even in principle, because it
    never imports the modules that produce one."""

    def test_module_does_not_import_human_review_or_automated_certification(self):
        # Check actual import statements, not prose -- this module's own
        # docstring legitimately NAMES these modules to explain the
        # isolation guarantee, which would false-positive a raw substring
        # scan of the whole file.
        import_lines = [
            line for line in inspect.getsource(qs).splitlines()
            if line.strip().startswith(("import ", "from "))
        ]
        imported_text = "\n".join(import_lines)
        assert "human_review" not in imported_text
        assert "automated_certification" not in imported_text
        assert "release_certification" not in imported_text


class TestSamplingDoesNotAlterCertificationOutcome:
    def test_certification_state_is_identical_before_and_after_a_sample_is_recorded(self):
        text = "some real artifact text"
        review = ReviewRecord(
            report_id="r1", artifact_sha256=compute_artifact_hash(text),
            reviewer_identity="TEST-ONLY Reviewer", review_timestamp="2026-08-18T00:00:00Z",
            decision=ReviewDecision.APPROVE, review_version=1, is_test_only_fixture=True,
        )
        before = resolve_certification_state(True, True, review, text)

        # Sample it, record a defect -- this must have zero effect on the
        # certification computation above, since nothing about resolving
        # certification state ever reads a SampleOutcome.
        config = SamplingConfig(sample_percentage=1.0)  # force-sample for this test
        assert should_sample("r1", config)
        outcome = SampleOutcome(report_id="r1", sampled_at="2026-08-18T01:00:00Z",
                                 reviewer="TEST-ONLY QA Reviewer", defect_found=True, notes="found a real defect")

        after = resolve_certification_state(True, True, review, text)
        assert before == after == CertificationState.PREMIUM_CERTIFIED
        # the recorded outcome exists purely as telemetry -- nothing above consumed it
        assert outcome.defect_found is True


class TestDeterministicSampling:
    def test_same_report_id_and_config_always_samples_the_same_way(self):
        config = SamplingConfig(sample_percentage=0.5)
        first = should_sample("report-abc", config)
        second = should_sample("report-abc", config)
        assert first == second

    def test_zero_percent_never_samples(self):
        config = SamplingConfig(sample_percentage=0.0)
        assert not any(should_sample(f"report-{i}", config) for i in range(200))

    def test_100_percent_always_samples(self):
        config = SamplingConfig(sample_percentage=1.0)
        assert all(should_sample(f"report-{i}", config) for i in range(200))

    def test_risk_weighting_increases_sampling_likelihood(self):
        config = SamplingConfig(sample_percentage=0.05, high_risk_weight=10.0)
        baseline_rate = sum(should_sample(f"r{i}", config) for i in range(2000)) / 2000
        risky_rate = sum(
            should_sample(f"r{i}", config, RiskFactors(is_high_risk=True)) for i in range(2000)
        ) / 2000
        assert risky_rate > baseline_rate

    def test_weight_is_capped_at_1(self):
        config = SamplingConfig(sample_percentage=1.0, high_risk_weight=10.0)
        assert qs.sampling_weight(config, RiskFactors(is_high_risk=True)) == 1.0


class TestSamplingConfigValidation:
    def test_out_of_range_percentage_rejected(self):
        import pytest
        with pytest.raises(ValueError):
            SamplingConfig(sample_percentage=1.5)
        with pytest.raises(ValueError):
            SamplingConfig(sample_percentage=-0.1)


class TestSampleDefectRate:
    def test_empty_outcomes_is_zero_not_a_division_error(self):
        assert sample_defect_rate([]) == 0.0

    def test_defect_rate_is_the_real_fraction(self):
        outcomes = [
            SampleOutcome("r1", "t", "rev", defect_found=True),
            SampleOutcome("r2", "t", "rev", defect_found=False),
            SampleOutcome("r3", "t", "rev", defect_found=False),
            SampleOutcome("r4", "t", "rev", defect_found=False),
        ]
        assert sample_defect_rate(outcomes) == 0.25
