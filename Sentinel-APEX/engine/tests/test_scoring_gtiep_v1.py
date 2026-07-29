"""GTIEP v1 scoring extension: the five new dimensions, the embedded-
detection-content credit, and the hand-authored-report scoring path this
platform never had before (platform/open-issues.md Issue 3 item 3)."""
from pathlib import Path

from sentinel_engine import pipeline
from sentinel_engine.models import SourceDocument
from sentinel_engine.report_ingest import build_pipeline_result
from sentinel_engine.report_parser import parse_report
from sentinel_engine.scoring import (
    WEIGHTS,
    _analyst_usability,
    _defensive_guidance,
    _embedded_detection_formats,
    _report_structure,
    _technical_accuracy,
    _visualizations,
    score,
)

FIXTURES = Path(__file__).parent / "fixtures"
REPORTS_ROOT = Path(__file__).parent.parent.parent / "reports"
REAL_REPORT = REPORTS_ROOT / "published" / "SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md"
REAL_REPORT_0002 = REPORTS_ROOT / "published" / "SA-2026-0002-panos-globalprotect-cve-2026-0257-auth-bypass.md"


def _real_report():
    return parse_report(REAL_REPORT.read_text())


def _real_report_0002():
    return parse_report(REAL_REPORT_0002.read_text())


def _automated_result():
    src = SourceDocument(
        raw_text=(FIXTURES / "raw-source-sample.txt").read_text(),
        source_url="https://example.org/advisory",
        source_name="Example Advisory",
    )
    return pipeline.run(src, "RPT-GTIEP-1")


# ── weights ──────────────────────────────────────────────────────────────

def test_weights_still_sum_to_one_with_five_new_dimensions():
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9
    assert len(WEIGHTS) == 14


# ── backward compatibility: automated pipeline is unaffected ───────────────

def test_automated_pipeline_result_has_empty_raw_sections_by_default():
    result = _automated_result()
    assert result.raw_sections == {}


def test_new_dimensions_degrade_to_documented_neutral_defaults_when_unpopulated():
    result = _automated_result()
    s = score(result)
    # Exact neutral defaults documented in each function's docstring —
    # regression-guards the backward-compatibility contract explicitly,
    # not just "doesn't crash."
    assert s.dimensions["report_structure"] == 50
    assert s.dimensions["defensive_guidance"] == 50
    assert s.dimensions["analyst_usability"] == 50
    assert s.dimensions["visualizations"] == 40


def test_embedded_detection_formats_is_empty_when_raw_sections_absent():
    result = _automated_result()
    assert _embedded_detection_formats(result) == set()


# ── the real gap this closes: a hand-authored report's embedded Sigma ────

def test_build_pipeline_result_credits_the_real_embedded_sigma_rule():
    # SA-2026-0001 has a real, independently-verified Sigma rule embedded
    # in its own prose. Before this change there was no PipelineResult for
    # a hand-authored report at all, so nothing could ever credit it.
    result = build_pipeline_result(_real_report())
    assert "sigma" in _embedded_detection_formats(result)
    assert result.score.dimensions["detection_value"] > 0
    assert "sigma" in result.score.rationale["detection_value"]


def test_build_pipeline_result_produces_a_real_reproducible_score():
    result = build_pipeline_result(_real_report())
    assert result.score is not None
    assert 0 <= result.score.overall <= 100
    assert result.score.gate_passed is True  # SA-2026-0001 v1.1 passes the gate cleanly
    # Deterministic: scoring the same parsed report twice must agree.
    again = build_pipeline_result(_real_report())
    assert again.score.overall == result.score.overall


def test_embedded_detection_formats_is_empty_for_a_report_with_no_sigma_rule():
    # SA-2026-0002 explicitly omits a Sigma rule (undocumented log-schema
    # fields, per its own text) -- confirms the detector isn't a
    # rubber-stamp that always finds something.
    result = build_pipeline_result(_real_report_0002())
    assert "sigma" not in _embedded_detection_formats(result)


def test_build_pipeline_result_report_structure_reflects_real_sections():
    result = build_pipeline_result(_real_report())
    assert result.raw_sections  # populated, unlike the automated path
    assert result.score.dimensions["report_structure"] > 50  # a real, structured report


# ── unit tests for each new dimension, direct and isolated ────────────────

class _Fake:
    def __init__(self, raw_sections=None, gate=None):
        self.raw_sections = raw_sections or {}
        self.gate = gate


def test_report_structure_scores_proportionally_to_sections_present():
    rich = _Fake(raw_sections={
        "Executive Summary": "x", "Verified Facts": "x", "Technical Analysis": "x",
        "MITRE ATT&CK": "x", "IOC Intelligence": "x", "Key Findings": "x",
        "CWE Analysis": "x", "CAPEC Mapping": "x",
    })
    thin = _Fake(raw_sections={"Executive Summary": "x"})
    assert _report_structure(rich)[0] > _report_structure(thin)[0]


def test_defensive_guidance_counts_the_six_labeled_sections():
    full = _Fake(raw_sections={name: "x" for name in [
        "Containment Strategy", "Eradication Strategy", "Recovery Guidance",
        "Vulnerability Management Guidance", "Patch Prioritization",
        "Security Architecture Recommendations", "Zero Trust Considerations",
    ]})
    none = _Fake(raw_sections={"Executive Summary": "x"})
    assert _defensive_guidance(full)[0] == 100
    assert _defensive_guidance(none)[0] == 0


def test_analyst_usability_rewards_references_confidence_and_tables():
    good = _Fake(raw_sections={
        "References": "https://example.com",
        "Confidence Assessment": "HIGH",
        "IOC Intelligence": "| type | value |\n|---|---|\n| ip | 1.2.3.4 |",
    })
    bare = _Fake(raw_sections={"Executive Summary": "just prose, no structure"})
    assert _analyst_usability(good)[0] > _analyst_usability(bare)[0]


def test_visualizations_counts_tables_and_images():
    with_both = _Fake(raw_sections={
        "IOC Intelligence": "| a | b |\n|---|---|\n| 1 | 2 |",
        "Attack Chain": "![diagram](https://example.com/chain.png)",
    })
    neither = _Fake(raw_sections={"Executive Summary": "plain text only"})
    assert _visualizations(with_both)[0] > _visualizations(neither)[0]


def test_technical_accuracy_penalizes_block_findings_more_than_warn():
    from sentinel_engine.models import GateFinding, GateResult
    clean = _Fake(gate=GateResult(findings=[]))
    warned = _Fake(gate=GateResult(findings=[GateFinding("x", "warn", "minor issue")]))
    blocked = _Fake(gate=GateResult(findings=[GateFinding("x", "block", "major issue")]))
    assert _technical_accuracy(clean)[0] > _technical_accuracy(warned)[0] > _technical_accuracy(blocked)[0]


def test_technical_accuracy_neutral_when_no_gate_available():
    assert _technical_accuracy(_Fake(gate=None))[0] == 70
