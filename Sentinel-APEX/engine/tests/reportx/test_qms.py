"""Tests for sentinel_engine.reportx.qms -- the read-only re-grouping of
the 23-row commercial_readiness.py matrix under the ROLE mandate's 18
named QUALITY MANAGEMENT SYSTEM categories.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from automation.config import Config
from automation.content_discovery import DiscoveredArticle

from sentinel_engine.reportx.commercial_readiness import ControlResult
from sentinel_engine.reportx.pipeline_composer import compose_report
from sentinel_engine.reportx.qms import (
    QMS_CATEGORY_CAVEATS,
    QMS_CONTROL_MAP,
    QMS_UNGATED_CATEGORIES,
    QMSCategory,
    evaluate_quality_management_system,
    render_qms_summary,
)

CONFIG = Config()

# The 18 category names verbatim from the ROLE mandate's "Quality gates
# must evaluate:" list (see the QUALITY MANAGEMENT SYSTEM section of the
# original ROLE message) -- kept independent of qms.py's own enum so a
# rename in the enum can't silently pass this test.
_MANDATE_CATEGORY_NAMES = (
    "Evidence", "Analytical Quality", "Tradecraft", "Technical Accuracy", "Editorial Quality",
    "Consistency", "Traceability", "Confidence Discipline", "Detection Quality",
    "Operational Utility", "Executive Readability", "Role-based Guidance", "Forecast Quality",
    "No unsupported claims", "No hallucinations", "No duplicated content",
    "No boilerplate repetition", "No fabricated evidence",
)

# The real 23 control_ids evaluate_commercial_readiness() can ever emit
# (commercial_readiness.py's own control IDs, transcribed once here so a
# typo in QMS_CONTROL_MAP is caught even for control_ids that happen not
# to appear in the specific fixture bundles below).
_REAL_CONTROL_IDS = frozenset({
    "source_provenance", "evidence_hash", "automated_review_disclosure", "source_specific_facts",
    "cross_source_corroboration", "threat_type_schema_correctness", "cross_section_consistency",
    "actor_specific_analysis", "victim_specific_analysis", "current_statistics",
    "regulatory_specificity", "technical_recommendations", "detection_evidence_discipline",
    "temporal_integrity", "grammar_synthesis_qa", "forecast_methodology", "evidence_ledger",
    "alternative_hypotheses", "intelligence_gaps", "report_specific_bibliography",
    "human_analyst_certification_governance", "premium_depth", "fortune_500_commercial_deliverable",
})


def _cve_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-88888",
        title="CVE-2026-88888 test vulnerability",
        summary="A test vulnerability allows remote code execution via crafted OS command injection in a "
                "web-facing administrative endpoint.",
        published_at="2026-08-17T11:16:44Z", content_hash="beefcafe", labels=["Vulnerabilities"], source="nvd",
        cve_id="CVE-2026-88888", cvss_score=9.1, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-78"], kev_listed=False,
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


class TestCategoryFidelityToTheMandate:
    def test_every_mandate_category_name_is_represented_exactly_once(self):
        enum_values = [c.value for c in QMSCategory]
        assert sorted(enum_values) == sorted(_MANDATE_CATEGORY_NAMES)
        assert len(enum_values) == len(set(enum_values)) == 18

    def test_every_category_is_either_control_mapped_or_named_ungated(self):
        mapped = set(QMS_CONTROL_MAP.keys())
        ungated = set(QMS_UNGATED_CATEGORIES)
        assert mapped | ungated == set(QMSCategory)
        assert mapped & ungated == set()  # no category is both


class TestControlMapReferencesRealControls:
    def test_every_mapped_control_id_is_a_real_commercial_readiness_control(self):
        for category, control_ids in QMS_CONTROL_MAP.items():
            for cid in control_ids:
                assert cid in _REAL_CONTROL_IDS, f"{category.value} references unknown control_id {cid!r}"

    def test_ungated_categories_have_a_caveat_explaining_the_gap(self):
        for category in QMS_UNGATED_CATEGORIES:
            assert QMS_CATEGORY_CAVEATS.get(category), f"{category.value} has no caveat explaining its gap"


class TestEvaluateAgainstARealComposedReport:
    def test_clean_cve_evidence_passes_every_gated_category_or_is_honestly_blocked(self):
        composed = compose_report(_cve_article(), CONFIG)
        report = evaluate_quality_management_system(composed.control_results)
        for r in report.category_results:
            if r.status == "NOT_GATED":
                continue
            assert r.status in ("PASS", "BLOCKED"), f"{r.category.value}: {r.status} -- {r.failures}"

    def test_ungated_categories_are_reported_not_silently_passed(self):
        composed = compose_report(_cve_article(), CONFIG)
        report = evaluate_quality_management_system(composed.control_results)
        names = {r.category for r in report.category_results if r.status == "NOT_GATED"}
        assert QMSCategory.EXECUTIVE_READABILITY in names
        assert QMSCategory.ROLE_BASED_GUIDANCE in names
        # NOT_GATED categories must not count toward the "all clear" roll-up.
        assert QMSCategory.EXECUTIVE_READABILITY not in {
            r.category for r in report.category_results if r.status == "PASS"
        }

    def test_role_based_guidance_caveat_names_the_real_supporting_code(self):
        composed = compose_report(_cve_article(), CONFIG)
        report = evaluate_quality_management_system(composed.control_results)
        by_category = {r.category: r for r in report.category_results}
        assert "RoleAudience" in by_category[QMSCategory.ROLE_BASED_GUIDANCE].caveat


class TestFailurePropagation:
    def _bundle_with(self, control_id: str, status: str) -> list[ControlResult]:
        return [ControlResult(control_id, control_id, status, "synthetic fixture", failures=(
            [f"{control_id} synthetically failed"] if status == "FAIL" else []
        ))]

    def test_a_failed_contributing_control_fails_its_category(self):
        results = self._bundle_with("cross_section_consistency", "FAIL")
        report = evaluate_quality_management_system(results)
        by_category = {r.category: r for r in report.category_results}
        assert by_category[QMSCategory.CONSISTENCY].status == "FAIL"
        assert by_category[QMSCategory.CONSISTENCY].failures

    def test_all_blocked_contributing_controls_block_the_category_not_pass_it(self):
        results = self._bundle_with("cross_section_consistency", "BLOCKED")
        report = evaluate_quality_management_system(results)
        by_category = {r.category: r for r in report.category_results}
        assert by_category[QMSCategory.CONSISTENCY].status == "BLOCKED"

    def test_no_contributing_controls_present_at_all_blocks_the_category(self):
        report = evaluate_quality_management_system([])
        by_category = {r.category: r for r in report.category_results}
        assert by_category[QMSCategory.CONSISTENCY].status == "BLOCKED"
        assert by_category[QMSCategory.CONSISTENCY].status != "NOT_GATED"  # mapped, just unattempted

    def test_a_fail_anywhere_in_a_real_bundle_is_never_reported_as_pass(self):
        # Guard against a false-PASS bug: forcing one real control to FAIL
        # must always surface as a category FAIL, never get lost in the map.
        composed = compose_report(_cve_article(), CONFIG)
        mutated = [
            ControlResult(r.control_id, r.name, "FAIL", "mutated for test", ["forced failure"])
            if r.control_id == "evidence_hash" else r
            for r in composed.control_results
        ]
        report = evaluate_quality_management_system(mutated)
        by_category = {r.category: r for r in report.category_results}
        assert by_category[QMSCategory.EVIDENCE].status == "FAIL"
        assert by_category[QMSCategory.NO_FABRICATED_EVIDENCE].status == "FAIL"
        assert not report.gated_categories_pass


class TestRenderQmsSummary:
    def test_render_includes_every_category_name_and_verdict(self):
        composed = compose_report(_cve_article(), CONFIG)
        report = evaluate_quality_management_system(composed.control_results)
        text = render_qms_summary(report)
        for category in QMSCategory:
            assert category.value in text
        assert "VERDICT" in text

    def test_render_surfaces_caveats_for_partially_covered_categories(self):
        composed = compose_report(_cve_article(), CONFIG)
        report = evaluate_quality_management_system(composed.control_results)
        text = render_qms_summary(report)
        assert "validate_publication" in text


class TestToDictIsJsonSafe:
    def test_to_dict_round_trips_through_json(self):
        import json
        composed = compose_report(_cve_article(), CONFIG)
        report = evaluate_quality_management_system(composed.control_results)
        serialized = json.dumps(report.to_dict())
        restored = json.loads(serialized)
        assert len(restored["category_results"]) == 18
