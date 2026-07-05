from pathlib import Path

from sentinel_engine import pipeline
from sentinel_engine.enrichment import Enricher
from sentinel_engine.models import (
    CVEEnrichment,
    GateFinding,
    GateResult,
    SourceDocument,
)
from sentinel_engine.scoring import WEIGHTS, score

FIXTURES = Path(__file__).parent / "fixtures"


def _rich_result():
    src = SourceDocument(
        raw_text=(FIXTURES / "raw-source-sample.txt").read_text(),
        source_url="https://example.org/advisory",
        source_name="Example Advisory",
    )
    return pipeline.run(src, "RPT-SCORE-1")


def _thin_result():
    src = SourceDocument(
        raw_text="A vendor announced a security conference for analysts next month. "
        "Registration is open and covers general industry topics.",
        source_url="https://example.org/news",
    )
    return pipeline.run(src, "RPT-SCORE-2")


def test_weights_sum_to_one():
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


def test_all_dimensions_present_and_in_range():
    s = _rich_result().score
    assert set(s.dimensions) == set(WEIGHTS)
    for v in s.dimensions.values():
        assert 0 <= v <= 100
    assert 0 <= s.overall <= 100
    for key in s.dimensions:
        assert s.rationale[key]  # every score has an auditable basis


def test_rich_report_scores_high_and_publishes():
    s = _rich_result().score
    assert s.dimensions["detection_value"] > 0
    assert s.dimensions["evidence_quality"] >= 50
    assert s.overall >= 60
    assert s.eligible
    assert s.tier != "BLOCKED"


def test_enriched_report_reaches_premium_tier():
    # live enrichment (KEV + high CVSS) lifts executive/commercial value, which
    # is what should push a strong report from FREE into a paid tier
    result = _rich_result()
    result.enrichments = [CVEEnrichment(
        cve_id="CVE-2024-4577", status="enriched", cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N", epss_score=0.97, kev_listed=True,
        sources=["nvd", "epss", "kev"],
    )]
    s = score(result)
    assert s.overall > _rich_result().score.overall
    assert s.tier in ("PRO", "ENTERPRISE")


def test_thin_report_scores_low_and_holds():
    s = _thin_result().score
    assert s.overall < 60
    assert not s.eligible
    assert s.tier == "BLOCKED"


def test_blocking_gate_forces_ineligible_regardless_of_score():
    result = _rich_result()
    bad_gate = GateResult(findings=[GateFinding("x", "block", "boom")])
    s = score(result, gate=bad_gate)
    assert s.overall >= 60  # content is strong
    assert not s.gate_passed
    assert not s.eligible   # correctness beats commercial value
    assert s.tier == "BLOCKED"


def test_threshold_is_respected():
    result = _rich_result()
    low = score(result, threshold=1)
    high = score(result, threshold=100)
    assert low.eligible
    assert not high.eligible
    assert low.overall == high.overall  # same content, different gate


def test_enrichment_lifts_executive_and_confidence():
    result = _rich_result()
    before = result.score
    # inject a KEV+CVSS enrichment and rescore
    result.enrichments = [CVEEnrichment(
        cve_id="CVE-2024-4577", status="enriched", cvss_score=9.8,
        kev_listed=True, sources=["nvd"],
    )]
    after = score(result)
    assert after.dimensions["executive_value"] > before.dimensions["executive_value"]
    assert after.dimensions["commercial_value"] >= before.dimensions["commercial_value"]


def test_scoring_is_deterministic():
    a = _rich_result().score
    b = _rich_result().score
    assert a.to_dict() == b.to_dict()


def test_enterprise_tier_requires_detection_value():
    # a report can score high on evidence/exec but without detections must not
    # reach ENTERPRISE tier (which gates on detection_value >= 60)
    s = _rich_result().score
    if s.tier == "ENTERPRISE":
        assert s.dimensions["detection_value"] >= 60
