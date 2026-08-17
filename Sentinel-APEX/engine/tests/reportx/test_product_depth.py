from sentinel_engine.reportx.product_depth import (
    DepthAssessment,
    ReportSection,
    find_template_repetition,
)

GENERIC_ACTOR_PARAGRAPH = (
    "This ransomware group operates a typical affiliate-based extortion model, "
    "leveraging double-extortion tactics that combine encryption with data theft "
    "to maximize pressure on victims across multiple industry verticals globally."
)


class TestTemplateRepetitionDetection:
    def test_identical_incident_specific_sections_across_reports_flagged(self):
        sections = [
            ReportSection(report_id="rw-1", section_name="Actor Analysis", text=GENERIC_ACTOR_PARAGRAPH),
            ReportSection(report_id="rw-2", section_name="Actor Analysis", text=GENERIC_ACTOR_PARAGRAPH),
        ]
        findings = find_template_repetition(sections)
        assert len(findings) == 1
        assert findings[0].section_name == "Actor Analysis"

    def test_same_report_never_compared_to_itself(self):
        sections = [
            ReportSection(report_id="rw-1", section_name="Actor Analysis", text=GENERIC_ACTOR_PARAGRAPH),
        ]
        assert find_template_repetition(sections) == []

    def test_allowed_shared_classification_never_flagged(self):
        sections = [
            ReportSection(report_id="rw-1", section_name="Actor Analysis", text=GENERIC_ACTOR_PARAGRAPH,
                          classification="STANDARD_DEFENSIVE_GUIDANCE"),
            ReportSection(report_id="rw-2", section_name="Actor Analysis", text=GENERIC_ACTOR_PARAGRAPH,
                          classification="STANDARD_DEFENSIVE_GUIDANCE"),
        ]
        assert find_template_repetition(sections) == []

    def test_section_name_outside_incident_specific_list_ignored(self):
        sections = [
            ReportSection(report_id="rw-1", section_name="Appendices", text=GENERIC_ACTOR_PARAGRAPH),
            ReportSection(report_id="rw-2", section_name="Appendices", text=GENERIC_ACTOR_PARAGRAPH),
        ]
        assert find_template_repetition(sections) == []

    def test_genuinely_distinct_incident_analysis_not_flagged(self):
        sections = [
            ReportSection(report_id="rw-1", section_name="Victimology",
                          text="Spoonful of Comfort is a US-based gift retailer operating primarily online."),
            ReportSection(report_id="rw-2", section_name="Victimology",
                          text="SAGASTA sro is a Slovak manufacturing firm with on-premises industrial systems."),
        ]
        assert find_template_repetition(sections) == []


class TestDepthAssessment:
    def test_padding_signal_from_repetition_fails_regardless_of_other_metrics(self):
        assessment = DepthAssessment(
            rendered_word_count=20000, material_claim_count=50,
            distinct_evidence_backed_sections=20,
            template_repetition_findings=[
                find_template_repetition([
                    ReportSection(report_id="rw-1", section_name="Actor Analysis", text=GENERIC_ACTOR_PARAGRAPH),
                    ReportSection(report_id="rw-2", section_name="Actor Analysis", text=GENERIC_ACTOR_PARAGRAPH),
                ])[0]
            ],
        )
        assert assessment.has_padding_signal
        assert not assessment.passes_premium_depth()

    def test_thin_report_below_floor_fails_even_with_no_repetition(self):
        assessment = DepthAssessment(rendered_word_count=2000, material_claim_count=2,
                                      distinct_evidence_backed_sections=2)
        assert not assessment.passes_premium_depth()

    def test_adequately_deep_unpadded_report_passes(self):
        assessment = DepthAssessment(rendered_word_count=15000, material_claim_count=30,
                                      distinct_evidence_backed_sections=12)
        assert assessment.passes_premium_depth()
