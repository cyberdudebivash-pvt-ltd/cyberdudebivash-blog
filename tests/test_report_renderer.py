"""Tests for automation.report_renderer -- specifically the evidence-
conditioned, syntax-validated detection generators (_validated_sigma /
_validated_kql) and the vulnerability-class gate in _detection_package()
that decides when either is allowed to fire at all. No dedicated test file
covered this module before (REPORTX-LEGACY-PIPELINE-AUDIT.md /
REPORTX-QUALITY-MANAGEMENT-SYSTEM.md both flag this as a real gap); this
does not attempt full coverage of every rendering helper in the module,
only the detection-generation path, which is the part with a real
fail-closed contract worth regression-testing.
"""

from __future__ import annotations

import dataclasses
import unittest

from automation.config import Config
from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import REVIEW_STATUS, build_report_context
from automation.report_renderer import (
    _detection_package,
    _detection_section,
    _family_analysis,
    _kql_string_list,
    _technical_evidence,
    _validated_kql,
    _validated_sigma,
    render_evidence_report,
)


def _article(summary: str, **kwargs) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-77777",
        title="CVE-2026-77777 test vulnerability",
        summary=summary,
        published_at="2026-08-12T06:00:00+00:00",
        content_hash=_compute_hash("https://nvd.nist.gov/vuln/detail/CVE-2026-77777", "CVE-2026-77777"),
        labels=["Vulnerabilities"],
        source="nvd",
        cve_id="CVE-2026-77777",
    )
    defaults.update(kwargs)
    return DiscoveredArticle(**defaults)


_VALID_KQL_RULE = {
    "title": "Test rule",
    "table": "DeviceProcessEvents",
    "table_note": "",
    "where": ['FileName has_any ("cmd.exe", "powershell.exe")'],
    "project": ["Timestamp", "FileName"],
}


class TestKqlStringList(unittest.TestCase):
    def test_produces_uniform_double_quoted_literals(self):
        # Regression test: an earlier version used Python's repr(), which
        # mixes single- and double-quoted output depending on a token's
        # own content (e.g. repr("' OR ") uses double quotes while
        # repr("UNION SELECT") uses single quotes) -- not valid, uniform
        # KQL string-literal style.
        rendered = _kql_string_list(["' OR ", "UNION SELECT", "SLEEP("])
        self.assertEqual(rendered, '"\' OR ", "UNION SELECT", "SLEEP("')
        self.assertNotIn("'", rendered.replace("' OR ", ""))  # no stray single-quote wrapping

    def test_escapes_embedded_double_quotes_and_backslashes(self):
        rendered = _kql_string_list(['say "hi"', "back\\slash"])
        self.assertEqual(rendered, '"say \\"hi\\"", "back\\\\slash"')


class TestValidatedKqlContract(unittest.TestCase):
    def test_valid_rule_renders_table_then_pipe_stages(self):
        rendered = _validated_kql("CDB-TEST-1", _VALID_KQL_RULE)
        code_lines = [ln for ln in rendered.splitlines() if not ln.startswith("//")]
        self.assertEqual(code_lines[0], "DeviceProcessEvents")
        for line in code_lines[1:]:
            self.assertTrue(line.startswith("| "))

    def test_missing_mandatory_field_raises(self):
        bad = {k: v for k, v in _VALID_KQL_RULE.items() if k != "where"}
        with self.assertRaises(ValueError):
            _validated_kql("CDB-TEST-1", bad)

    def test_empty_where_list_raises(self):
        bad = dict(_VALID_KQL_RULE, where=[])
        with self.assertRaises(ValueError):
            _validated_kql("CDB-TEST-1", bad)

    def test_invalid_table_identifier_raises(self):
        bad = dict(_VALID_KQL_RULE, table="Not; A Valid Identifier")
        with self.assertRaises(ValueError):
            _validated_kql("CDB-TEST-1", bad)

    def test_a_paren_inside_a_string_literal_does_not_falsely_trip_balance_check(self):
        # "SLEEP(" is a real SQL-injection time-blind indicator token and a
        # perfectly valid KQL string literal despite its unbalanced paren
        # *as literal content* -- only structural (code-level) parens must
        # balance. This is a direct regression test for a bug caught while
        # building this generator: the first version counted every paren
        # in the whole rendered text and raised on exactly this input.
        rule = dict(_VALID_KQL_RULE, where=['RequestUri has_any ("SLEEP(", "WAITFOR DELAY")'])
        rendered = _validated_kql("CDB-TEST-1", rule)
        self.assertIn('"SLEEP("', rendered)

    def test_genuinely_unbalanced_structural_paren_still_raises(self):
        rule = dict(_VALID_KQL_RULE, where=['FileName has_any (("cmd.exe")'])  # extra literal "("
        with self.assertRaises(ValueError):
            _validated_kql("CDB-TEST-1", rule)

    def test_unterminated_string_literal_raises(self):
        rule = dict(_VALID_KQL_RULE, where=['FileName has_any ("cmd.exe)'])  # missing closing quote
        with self.assertRaises(ValueError):
            _validated_kql("CDB-TEST-1", rule)

    def test_stage_without_recognized_operator_raises(self):
        rule = dict(_VALID_KQL_RULE, where=["FileName looks_kinda_like cmd"])
        with self.assertRaises(ValueError):
            _validated_kql("CDB-TEST-1", rule)

    def test_table_note_is_rendered_as_a_comment_not_code(self):
        rule = dict(_VALID_KQL_RULE, table_note="Bind to your real table before deployment.")
        rendered = _validated_kql("CDB-TEST-1", rule)
        note_line = next(ln for ln in rendered.splitlines() if "Bind to your real table" in ln)
        self.assertTrue(note_line.startswith("//"))


class TestValidatedSigmaStillWorksUnchanged(unittest.TestCase):
    """Guard that adding the KQL generator alongside it did not disturb
    the pre-existing, already-relied-upon Sigma contract."""

    def test_valid_rule_round_trips_through_real_yaml(self):
        rule = {
            "title": "t", "description": "d", "references": ["https://example.com"], "date": "2026-01-01",
            "logsource": {"category": "webserver"},
            "detection": {"selection": {"cs-uri-query|contains": ["x"]}, "condition": "selection"},
            "falsepositives": ["fp"], "level": "medium", "tags": ["attack.t1190"],
        }
        rendered = _validated_sigma("CDB-TEST-1", rule)
        self.assertIn("condition: selection", rendered)

    def test_missing_condition_raises(self):
        rule = {
            "title": "t", "description": "d", "references": [], "date": "2026-01-01",
            "logsource": {"category": "webserver"}, "detection": {"selection": {}},
            "falsepositives": [], "level": "medium", "tags": [],
        }
        with self.assertRaises(ValueError):
            _validated_sigma("CDB-TEST-1", rule)


class TestDetectionPackageGeneratesBothFormatsForTheSameEvidenceGate(unittest.TestCase):
    """The vulnerability-class gate in _detection_package() is the single
    source of truth for whether ANY real detection content is defensible.
    Sigma and KQL must always agree with each other, because they are two
    renderings of that one decision, not two independent ones."""

    def _package_for(self, summary: str):
        article = _article(summary)
        context = build_report_context(article)
        return _detection_package(article, context), context

    def test_sql_injection_produces_both_formats(self):
        pkg, ctx = self._package_for("A SQL injection flaw in the login form allows authentication bypass.")
        self.assertEqual(ctx.vulnerability_class, "sql_injection")
        self.assertEqual(pkg.status, "syntax_validated_experimental")
        self.assertTrue(pkg.sigma_yaml)
        self.assertTrue(pkg.kql)
        self.assertIn("RequestUri", pkg.kql)

    def test_path_traversal_produces_both_formats(self):
        pkg, ctx = self._package_for("A path traversal flaw in the file download handler allows arbitrary file read.")
        self.assertEqual(ctx.vulnerability_class, "path_traversal")
        self.assertTrue(pkg.sigma_yaml)
        self.assertTrue(pkg.kql)

    def test_ssrf_produces_both_formats(self):
        pkg, ctx = self._package_for("A server-side request forgery flaw allows reaching internal metadata services.")
        self.assertEqual(ctx.vulnerability_class, "server_side_request_forgery")
        self.assertTrue(pkg.sigma_yaml)
        self.assertTrue(pkg.kql)

    def test_web_command_injection_produces_both_formats(self):
        pkg, ctx = self._package_for(
            "A command injection vulnerability in a web-facing administrative endpoint allows remote code execution."
        )
        self.assertEqual(ctx.vulnerability_class, "command_injection")
        self.assertTrue(pkg.sigma_yaml)
        self.assertTrue(pkg.kql)
        self.assertIn("DeviceProcessEvents", pkg.kql)

    def test_denial_of_service_withholds_both_formats(self):
        pkg, ctx = self._package_for("A denial of service flaw in the packet parser causes a crash.")
        self.assertEqual(ctx.vulnerability_class, "denial_of_service")
        self.assertIsNone(pkg.sigma_yaml)
        self.assertIsNone(pkg.kql)

    def test_ransomware_claim_withholds_both_formats(self):
        article = DiscoveredArticle(
            url="https://www.ransomware.live/id/test", title="Acme Test Corp",
            summary="qilin has listed Acme Test Corp as a new victim on its leak site.",
            published_at="2026-08-18T00:00:00Z", content_hash="cafef00d",
            labels=["Ransomware", "qilin"], source="ransomware_intel",
        )
        context = build_report_context(article)
        pkg = _detection_package(article, context)
        self.assertEqual(pkg.status, "withheld_insufficient_evidence")
        self.assertIsNone(pkg.sigma_yaml)
        self.assertIsNone(pkg.kql)


class TestDetectionSectionRendersKql(unittest.TestCase):
    def test_kql_block_present_when_package_has_kql(self):
        article = _article("A SQL injection flaw in the login form allows authentication bypass.")
        context = build_report_context(article)
        pkg = _detection_package(article, context)
        html = _detection_section(pkg)
        self.assertIn("SENTINEL KQL", html)
        self.assertIn("WebRequestLogs", html)

    def test_kql_block_absent_when_package_has_no_kql(self):
        article = _article("A denial of service flaw in the packet parser causes a crash.")
        context = build_report_context(article)
        pkg = _detection_package(article, context)
        html = _detection_section(pkg)
        self.assertNotIn("SENTINEL KQL", html)


_SUMMARY_TEXT = "Attackers exploited a novel technique to bypass the affected control entirely."


class TestFamilyAnalysisDoesNotRepeatTheSourceSummary(unittest.TestCase):
    """P0 fix: ``_family_analysis()`` must not re-quote ``article.summary``
    -- that exact text already appears once in the Executive Summary
    section (report_renderer's own render_evidence_report assembly) and
    once, explicitly labeled, in ``_technical_evidence()``'s "Source
    Evidence Extract". A third, unlabeled repeat here was the real,
    reproduced "hallmark of template-driven synthesis" duplication found
    live on a published report -- verified here per family branch, since
    every branch used to open with the identical raw-summary paragraph."""

    def test_ransomware_claim_family_does_not_repeat_the_summary(self):
        article = _article(_SUMMARY_TEXT, source="ransomware_intel", cve_id=None,
                            url="https://example.test/ransomware", title="Group X Claims Victim Y")
        context = build_report_context(article)
        self.assertEqual(context.family, "ransomware_claim")
        html = _family_analysis(article, context)
        self.assertNotIn(_SUMMARY_TEXT, html)
        self.assertIn("Evidence boundary", html)  # the real analytical content survives

    def test_breach_notice_family_does_not_repeat_the_summary(self):
        article = _article(_SUMMARY_TEXT, source="breach_intel", cve_id=None,
                            url="https://example.test/breach", title="Breach Record Z")
        context = build_report_context(article)
        self.assertEqual(context.family, "breach_notice")
        html = _family_analysis(article, context)
        self.assertNotIn(_SUMMARY_TEXT, html)

    def test_ai_security_family_does_not_repeat_the_summary(self):
        article = _article("A prompt injection technique against a large language model was documented.",
                            cve_id=None, labels=["AI Security"],
                            url="https://example.test/ai-sec", title="LLM Prompt Injection Study")
        context = build_report_context(article)
        self.assertEqual(context.family, "ai_security")
        html = _family_analysis(article, context)
        self.assertNotIn("A prompt injection technique against a large language model was documented.", html)

    def test_cve_advisory_family_does_not_repeat_the_summary(self):
        article = _article(_SUMMARY_TEXT)  # default helper already sets cve_id
        context = build_report_context(article)
        self.assertEqual(context.family, "cve_advisory")
        html = _family_analysis(article, context)
        self.assertNotIn(_SUMMARY_TEXT, html)
        self.assertIn("Vulnerability class", html)  # the real analytical content survives

    def test_general_intelligence_fallback_does_not_repeat_the_summary(self):
        # The exact shape of the two real, live-verified problem reports
        # (JWR PhaaS, "general_intelligence"; CISA Windows Task Host,
        # "ransomware_reporting" -- neither matches a specialized branch).
        article = _article(_SUMMARY_TEXT, source="global_rss", cve_id=None,
                            url="https://example.test/general", title="Some Unmatched Intelligence Item")
        context = build_report_context(article)
        self.assertEqual(context.family, "general_intelligence")
        html = _family_analysis(article, context)
        self.assertNotIn(_SUMMARY_TEXT, html)
        self.assertIn("Intelligence Assessment", html)

    def test_source_evidence_extract_still_carries_the_summary_exactly_once(self):
        # The de-duplication must not have deleted the summary everywhere --
        # _technical_evidence() is the one, explicitly-labeled place it
        # belongs, and must still show it.
        article = _article(_SUMMARY_TEXT, source="global_rss", cve_id=None,
                            url="https://example.test/general", title="Some Unmatched Intelligence Item")
        html = _technical_evidence(article)
        self.assertIn(_SUMMARY_TEXT, html)
        self.assertEqual(html.count(_SUMMARY_TEXT), 1)


class TestFamilyAnalysisExploitPrerequisitesClause(unittest.TestCase):
    """COMMERCIAL-QUALITY-2026-08-19: independently verified live that two
    real, published CVE reports with materially different real exploit
    prerequisites (CVE-2026-75914: AV:N/PR:N/UI:N -- no user interaction;
    CVE-2026-75912: AV:N/PR:N/UI:R -- user interaction required) rendered
    the byte-for-byte identical "Assessment" sentence, because it was a
    fixed string keyed only on confirmed-vs-not-confirmed exploitation
    status. The CVSS vector these facts come from is already shown verbatim
    in the same report's "Verified Facts" section -- this only makes the
    Assessment sentence actually reflect it."""

    def test_no_user_interaction_and_required_user_interaction_render_different_text(self):
        no_interaction = _article(_SUMMARY_TEXT, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        requires_interaction = _article(_SUMMARY_TEXT, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N")
        html_no_interaction = _family_analysis(no_interaction, build_report_context(no_interaction))
        html_requires_interaction = _family_analysis(requires_interaction, build_report_context(requires_interaction))
        self.assertIn("no user interaction", html_no_interaction)
        self.assertIn("and user interaction", html_requires_interaction)
        self.assertNotIn("and no user interaction", html_requires_interaction)
        self.assertNotEqual(html_no_interaction, html_requires_interaction)

    def test_missing_cvss_vector_falls_back_to_the_original_static_sentence(self):
        article = _article(_SUMMARY_TEXT, cvss_vector=None)
        html = _family_analysis(article, build_report_context(article))
        self.assertIn(
            "Active exploitation is not confirmed by the available evidence. "
            "Prioritization must combine technical severity, exposure, asset criticality, "
            "and compensating controls.",
            html,
        )

    def test_confirmed_exploitation_also_carries_the_prerequisites_clause(self):
        article = _article(_SUMMARY_TEXT, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        context = dataclasses.replace(build_report_context(article), exploitation_status="confirmed")
        html = _family_analysis(article, context)
        self.assertIn("exploitable over the network", html)


class TestNoFalseOrMissingHumanReviewClaims(unittest.TestCase):
    """P0-AI-NATIVE-CERTIFICATION-2026-08-19 regression coverage: this
    pipeline publishes without a per-report human reviewer, so the public
    output must neither carry the old defensive "not human reviewed"
    disclaimer nor swing the other way into a false claim that a human
    reviewed, approved, or manually verified a report that no human
    touched. Mandate 22's exact acceptance test, plus the false-claim
    checks it also specifies."""

    def _rendered_html(self) -> str:
        article = _article(_SUMMARY_TEXT)
        return render_evidence_report(article, Config()).html

    def test_rendered_public_report_does_not_contain_the_old_disclaimer(self):
        self.assertNotIn("not human reviewed", self._rendered_html().lower())

    def test_rendered_public_report_does_not_falsely_claim_human_review(self):
        lower = self._rendered_html().lower()
        for phrase in ("human reviewed", "analyst approved", "manually verified"):
            self.assertNotIn(phrase, lower)

    def test_rendered_public_report_states_the_truthful_automated_production_mode(self):
        # REVIEW_STATUS is the single source of truth for this claim --
        # asserting the live constant, not a duplicated literal, so this
        # test can't silently drift from what report_integrity.py defines.
        self.assertIn(REVIEW_STATUS, self._rendered_html())


if __name__ == "__main__":
    unittest.main()
