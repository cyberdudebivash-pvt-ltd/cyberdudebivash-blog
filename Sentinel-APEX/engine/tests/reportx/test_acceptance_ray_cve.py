"""ReportX Section 35 acceptance test: CVE-2025-62593 (Ray).

Golden fixtures: tests/fixtures/reportx-commercial-readiness/
cve-2025-62593-ray-{BEFORE,AFTER}.json (repo root, per the task's own
specified path). BEFORE deliberately reconstructs the named defect
classes; AFTER is built from real research retrieved this session
(GitHub Security Advisory GHSA-q279-jhrf-cc6v).
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import date

import pytest

from sentinel_engine.reportx.bundle_io import bundle_from_dict
from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness
from sentinel_engine.reportx.qa_linter import lint_text

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
BEFORE_PATH = FIXTURES_DIR / "cve-2025-62593-ray-BEFORE.json"
AFTER_PATH = FIXTURES_DIR / "cve-2025-62593-ray-AFTER.json"


def _load(path: Path):
    with open(path, encoding="utf-8") as fh:
        return bundle_from_dict(json.load(fh))


@pytest.fixture(scope="module")
def before_results():
    bundle = _load(BEFORE_PATH)
    return bundle, evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))


@pytest.fixture(scope="module")
def after_results():
    bundle = _load(AFTER_PATH)
    return bundle, evaluate_commercial_readiness(bundle, as_of=date(2026, 8, 18))


class TestFixturesExist:
    def test_before_fixture_exists_at_the_specified_path(self):
        assert BEFORE_PATH.is_file(), f"expected {BEFORE_PATH}"

    def test_after_fixture_exists_at_the_specified_path(self):
        assert AFTER_PATH.is_file(), f"expected {AFTER_PATH}"


class TestBeforeIsCorrectlyCaughtDefective:
    def test_broken_sentence_fragment_caught(self, before_results):
        bundle, _ = before_results
        findings = lint_text(bundle.rendered_text)
        assert any(f.check == "dangling_sentence_fragment" for f in findings), \
            "the 'confirming active exploitation in the .' defect must be caught"

    def test_detection_withheld_vs_push_immediately_contradiction_caught(self, before_results):
        _, results = before_results
        statuses = {r.control_id: r.status for r in results}
        assert statuses["cross_section_consistency"] == "FAIL"

    def test_experimental_vs_production_validated_promotion_caught(self, before_results):
        _, results = before_results
        statuses = {r.control_id: r.status for r in results}
        assert statuses["detection_evidence_discipline"] == "FAIL"

    def test_unsupported_regulatory_claim_caught(self, before_results):
        _, results = before_results
        statuses = {r.control_id: r.status for r in results}
        assert statuses["regulatory_specificity"] == "FAIL"

    def test_fabricated_exact_timestamp_precision_label_caught(self, before_results):
        # The fixture's source_date is the real, correct date-only string
        # ("2025-11-26") but wrongly claims EXACT_TIMESTAMP precision --
        # exactly the Section 4/8 fabrication defect. Row 14 (temporal
        # integrity) must catch the mismatch between the claimed precision
        # and what re-inferring the raw date string actually produces.
        bundle, results = before_results
        from sentinel_engine.reportx.claim_model import TemporalPrecision, infer_temporal_precision
        src = bundle.graph.sources["s-ghsa"]
        assert src.temporal_precision == TemporalPrecision.EXACT_TIMESTAMP  # the wrong, caller-forced claim
        assert infer_temporal_precision(src.source_date) == TemporalPrecision.DATE_ONLY  # the truth
        statuses = {r.control_id: r.status for r in results}
        assert statuses["temporal_integrity"] == "FAIL"

    def test_unsupported_forecast_confidence_caught(self, before_results):
        _, results = before_results
        statuses = {r.control_id: r.status for r in results}
        assert statuses["forecast_methodology"] == "FAIL"

    def test_before_final_verdict_is_not_commercial_ready(self, before_results):
        _, results = before_results
        assert results[-1].status == "FAIL"  # fortune_500_commercial_deliverable
        assert any(r.status == "FAIL" for r in results)


class TestAfterIsCleanRealResearch:
    def test_no_broken_sentence_fragments(self, after_results):
        bundle, _ = after_results
        findings = lint_text(bundle.rendered_text)
        assert not any(f.check == "dangling_sentence_fragment" for f in findings)

    def test_no_cross_section_contradictions(self, after_results):
        _, results = after_results
        statuses = {r.control_id: r.status for r in results}
        assert statuses["cross_section_consistency"] == "PASS"

    def test_no_unsupported_regulatory_claims(self, after_results):
        _, results = after_results
        statuses = {r.control_id: r.status for r in results}
        assert statuses["regulatory_specificity"] == "PASS"
        bundle, _ = after_results
        # Explicitly NOT_APPLICABLE, not silently omitted.
        regs = {r.regulation: r.applicability_state.value for r in bundle.regulatory_applicabilities}
        assert regs["FDA/USDA regulatory frameworks"] == "NOT_APPLICABLE"
        assert regs["OT/ICS-specific regulatory or advisory frameworks"] == "NOT_APPLICABLE"

    def test_exploitation_state_does_not_overclaim_beyond_poc(self, after_results):
        bundle, _ = after_results
        claim = bundle.graph.claims["c-exploitation-status"]
        assert claim.status.value == "REPORTED"  # not CONFIRMED -- PoC only, per the source

    def test_kev_status_honestly_not_assessed_not_guessed(self, after_results):
        bundle, _ = after_results
        claim = bundle.graph.claims["c-kev-status"]
        assert claim.status.value == "NOT_ASSESSED"

    def test_no_detection_rules_means_no_fabricated_validation_state(self, after_results):
        bundle, _ = after_results
        assert bundle.detection_rules == []
        assert "detection" not in bundle.rendered_text.lower() or "no detection-readiness claim is made" in bundle.rendered_text.lower()

    def test_forecast_withheld_not_fabricated(self, after_results):
        bundle, _ = after_results
        from sentinel_engine.reportx.forecast import WithheldForecast
        assert len(bundle.forecasts) == 1
        assert isinstance(bundle.forecasts[0], WithheldForecast)

    def test_fixed_version_is_the_prioritized_remediation(self, after_results):
        bundle, _ = after_results
        assert "2.52.0" in bundle.rendered_text

    def test_no_ot_ics_or_food_safety_language_present(self, after_results):
        bundle, _ = after_results
        lowered = bundle.rendered_text.lower()
        for banned in ("industrial control", "food-production", "food safety", "fda", "usda"):
            assert banned not in lowered, f"unsupported context leaked: {banned!r}"
