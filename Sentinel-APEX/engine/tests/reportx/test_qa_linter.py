from sentinel_engine.reportx.qa_linter import (
    check_code_fence_balance,
    check_dangling_colon,
    check_dangling_sentence_fragments,
    check_duplicate_headings,
    check_duplicate_paragraphs,
    check_markdown_table_cell_counts,
    check_unresolved_templates,
    critical_defect_count,
    lint_text,
    to_gate_result,
)


class TestRayBrokenSentenceFixtureRegression:
    """Section 8/35's exact defect example, as a permanent regression case."""

    def test_confirming_active_exploitation_in_the_dot_is_caught(self):
        text = "Multiple independent security researchers have released proof-of-concept code, confirming active exploitation in the ."
        findings = check_dangling_sentence_fragments(text)
        assert len(findings) >= 1
        assert findings[0].check == "dangling_sentence_fragment"
        assert findings[0].severity == "block"

    def test_properly_completed_sentence_not_flagged(self):
        text = "Multiple independent security researchers have released proof-of-concept code, confirming active exploitation in the wild."
        assert check_dangling_sentence_fragments(text) == []

    def test_other_dangling_determiner_patterns_also_caught(self):
        for text in [
            "This vulnerability affects a widely deployed component of the.",
            "The patch was issued by a.",
            "The exploit was documented in a.",
        ]:
            assert len(check_dangling_sentence_fragments(text)) >= 1, f"missed: {text!r}"


class TestUnresolvedTemplates:
    def test_double_brace_template_caught(self):
        findings = check_unresolved_templates("The victim is {{victim_name}}.")
        assert any(f.check == "unresolved_template_variable" for f in findings)

    def test_python_format_leftover_caught(self):
        findings = check_unresolved_templates("Severity: {severity_level}")
        assert any(f.check == "unresolved_template_variable" for f in findings)

    def test_placeholder_tokens_caught(self):
        findings = check_unresolved_templates("Impact assessment: TBD")
        assert any(f.check == "empty_placeholder" for f in findings)

    def test_none_leak_caught(self):
        findings = check_unresolved_templates("The affected product is None and the vendor is Acme.")
        assert any(f.check == "none_value_leak" for f in findings)

    def test_single_equals_none_leak_still_caught(self):
        findings = check_unresolved_templates("Debug dump: vendor = None, product = None")
        assert any(f.check == "none_value_leak" for f in findings)

    def test_equality_comparison_described_in_prose_is_not_a_false_positive(self):
        # Real regression: a live CVE-2026-75110 (NVD) record's own genuine
        # technical prose read "...the comparison None == None evaluates
        # true" -- an accurate description of the vulnerable code's
        # equality check, not a leaked unset field. Caught via
        # automation.main --dry-run against real, current discovery data,
        # not a synthetic fixture.
        text = (
            "os.getenv(\"INTERNAL_SERVICE_SECRET\") returns None and a request omitting the header "
            "also yields None, so the comparison None == None evaluates true."
        )
        findings = check_unresolved_templates(text)
        assert not any(f.check == "none_value_leak" for f in findings), findings

    def test_not_equal_and_relational_comparisons_are_not_false_positives(self):
        for text in (
            "The check requires token != None before granting access.",
            "Only entries where retries <= None are treated as unset.",
        ):
            findings = check_unresolved_templates(text)
            assert not any(f.check == "none_value_leak" for f in findings), (text, findings)

    def test_clean_text_has_no_findings(self):
        assert check_unresolved_templates("The affected product is Ray, maintained by Anyscale.") == []


class TestDuplicateHeadings:
    def test_repeated_heading_at_same_level_flagged(self):
        text = "## Actor Analysis\nSome text.\n\n## Actor Analysis\nMore text.\n"
        findings = check_duplicate_headings(text)
        assert len(findings) == 1
        assert findings[0].severity == "warn"

    def test_headings_at_different_levels_not_flagged(self):
        text = "## Actor Analysis\nSome text.\n\n### Actor Analysis\nMore text.\n"
        assert check_duplicate_headings(text) == []

    def test_unique_headings_not_flagged(self):
        text = "## Actor Analysis\nx\n\n## Victim Analysis\ny\n"
        assert check_duplicate_headings(text) == []


class TestDuplicateParagraphs:
    def test_identical_long_paragraph_repeated_flagged(self):
        para = "This is a sufficiently long paragraph that repeats itself across two unrelated sections of the report to trigger detection."
        text = f"{para}\n\nSome other content here entirely.\n\n{para}\n"
        findings = check_duplicate_paragraphs(text)
        assert len(findings) == 1

    def test_short_paragraphs_below_threshold_ignored(self):
        text = "Short.\n\nShort.\n\nShort.\n"
        assert check_duplicate_paragraphs(text) == []


class TestDanglingColon:
    def test_colon_followed_by_blank_line_flagged(self):
        text = "Key findings:\n\nNext section starts here."
        findings = check_dangling_colon(text)
        assert len(findings) == 1

    def test_colon_followed_by_list_not_flagged(self):
        text = "Key findings:\n- item one\n- item two\n"
        assert check_dangling_colon(text) == []


class TestCodeFenceBalance:
    def test_balanced_fences_pass(self):
        text = "```yaml\nkey: value\n```\n"
        assert check_code_fence_balance(text) == []

    def test_unbalanced_fence_flagged(self):
        text = "```yaml\nkey: value\n"
        findings = check_code_fence_balance(text)
        assert len(findings) == 1
        assert findings[0].severity == "block"


class TestMarkdownTableCells:
    def test_consistent_table_passes(self):
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n"
        assert check_markdown_table_cell_counts(text) == []

    def test_ragged_row_flagged(self):
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n| 3 |\n"
        findings = check_markdown_table_cell_counts(text)
        assert len(findings) == 1
        assert findings[0].severity == "block"


class TestAggregateGate:
    def test_clean_document_has_zero_critical_defects(self):
        text = (
            "## Executive Summary\n\n"
            "This report describes a confirmed vulnerability in a widely used component.\n\n"
            "## Technical Analysis\n\n"
            "```yaml\ntitle: test\n```\n\n"
            "| Field | Value |\n|---|---|\n| CVE | CVE-2099-0001 |\n"
        )
        findings = lint_text(text)
        assert critical_defect_count(findings) == 0

    def test_defective_document_has_nonzero_critical_defects(self):
        text = "This vulnerability was confirmed, resulting in active exploitation in the ."
        findings = lint_text(text)
        assert critical_defect_count(findings) > 0

    def test_to_gate_result_bridges_into_shared_gatefinding_shape(self):
        findings = [f for f in lint_text("Something in the .")]
        gate = to_gate_result(findings)
        assert gate.passed is False
        assert any(f.gate.startswith("qa.") for f in gate.blocks)
