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

import unittest

from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import build_report_context
from automation.report_renderer import (
    _detection_package,
    _detection_section,
    _kql_string_list,
    _validated_kql,
    _validated_sigma,
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


if __name__ == "__main__":
    unittest.main()
