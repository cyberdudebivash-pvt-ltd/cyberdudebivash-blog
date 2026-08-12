"""Production evidence-integrity tests for CTI transformation and rendering."""

import base64
import html
import re
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import yaml

from automation.authority_transformer import (
    AuthorityTransformer,
    _build_dynamic_og_image_url,
    _generate_svg_thumbnail,
    _template_enhance,
)
from automation.config import Config
from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import (
    CERTIFICATION_STATUS,
    REVIEW_STATUS,
    PublicationIntegrityError,
    build_report_context,
    validate_publication,
)
from automation.report_renderer import render_evidence_report


def _make_article(**kwargs) -> DiscoveredArticle:
    defaults = {
        "url": "https://intel.cyberdudebivash.com/reports/CVE-2026-9999",
        "title": "CVE-2026-9999 Critical Windows RCE — CVSS 9.8",
        "summary": (
            "A remote code execution vulnerability in a Windows web service allows "
            "unauthenticated attackers to execute commands."
        ),
        "published_at": "2026-08-12T06:00:00+00:00",
        "content_hash": _compute_hash(
            "https://intel.cyberdudebivash.com/reports/CVE-2026-9999",
            "CVE-2026-9999",
        ),
        "labels": ["Vulnerabilities", "CYBERDUDEBIVASH", "Threat Intelligence"],
        "source": "nvd",
        "full_content": "CVE ID: CVE-2026-9999\nDescription: Remote code execution in a Windows web service.\nCVSS Score: 9.8",
        "cve_id": "CVE-2026-9999",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-78"],
        "affected_vendor": "Example",
        "affected_product": "Example Web Service",
    }
    defaults.update(kwargs)
    return DiscoveredArticle(**defaults)


class TestEvidenceFirstTemplate(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_shared_visual_contract_and_provenance(self):
        article = _make_article()
        rendered = render_evidence_report(article, self.config)
        content = rendered.html

        for section in (
            "Executive Summary",
            "Threat Classification and Evidence Status",
            "Verified Facts",
            "Technical Analysis",
            "Exposure and Remediation Decisions",
            "Source Evidence Extract",
            "Detection Engineering",
            "References",
            "Provenance and Review Status",
        ):
            self.assertIn(section, content)

        self.assertIn(rendered.context.report_id, content)
        self.assertIn(rendered.context.source_record_hash, content)
        self.assertIn(article.url, content)
        self.assertIn(REVIEW_STATUS, content)
        self.assertIn(CERTIFICATION_STATUS, content)

    def test_template_import_routes_to_production_renderer(self):
        article = _make_article()
        content = _template_enhance(article, self.config)
        self.assertIn('data-review-status="automated-unreviewed"', content)
        self.assertNotIn("Executive Decision Matrix", content)

    def test_report_identity_is_deterministic_for_same_source_record(self):
        article = _make_article()
        one = build_report_context(article)
        two = build_report_context(article)
        self.assertEqual(one.report_id, two.report_id)
        self.assertEqual(one.source_record_hash, two.source_record_hash)

    def test_report_identity_changes_when_source_record_changes(self):
        original = build_report_context(_make_article())
        changed = build_report_context(_make_article(summary="Materially changed source evidence."))
        self.assertNotEqual(original.source_record_hash, changed.source_record_hash)
        self.assertNotEqual(original.report_id, changed.report_id)

    def test_source_content_is_html_escaped(self):
        article = _make_article(
            url='https://example.org/advisory?x=1&next="bad"',
            summary='<script>alert("x")</script> source text',
            full_content='<img src=x onerror=alert(1)>',
        )
        rendered = render_evidence_report(article, self.config)
        self.assertNotIn('<script>alert("x")</script>', rendered.html)
        self.assertNotIn('<img src=x onerror=alert(1)>', rendered.html)
        self.assertIn("&lt;script&gt;", rendered.html)
        self.assertIn("&amp;", rendered.html)


class TestCveAndKevSemantics(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_confirmed_absence_from_kev_is_not_no_exploitation_claim(self):
        article = _make_article(kev_listed=False)
        content = AuthorityTransformer(self.config).transform(article)["content"]
        self.assertIn("Not Listed", content)
        self.assertIn("does not prove absence of exploitation", content)
        self.assertNotIn("No confirmed exploitation on record", content)
        self.assertNotIn("Actively exploited in the wild", content)
        self.assertNotIn("Exploitation is confirmed active", content)

    def test_kev_true_is_the_structured_confirmation(self):
        article = _make_article(
            source="cisa_kev",
            kev_listed=True,
            kev_date_added="2026-08-10",
            kev_due_date="2026-08-31",
            kev_required_action="Apply mitigations per vendor instructions.",
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["report_family"], "cisa_kev")
        self.assertIn("Confirmed — CISA KEV listed", content)
        self.assertIn("Apply mitigations per vendor instructions.", content)
        self.assertIn("CISA FEDERAL MANDATE", content)

    def test_unknown_kev_does_not_become_false_negative(self):
        article = _make_article(kev_listed=None)
        content = AuthorityTransformer(self.config).transform(article)["content"]
        self.assertIn("Unknown or unavailable; no negative claim is made", content)
        self.assertNotIn("Not Listed", content)

    def test_dos_cve_does_not_get_rce_or_webshell_material(self):
        article = _make_article(
            title="CVE-2026-48439 — CVSS 7.5 denial-of-service vulnerability",
            summary="A denial-of-service condition can crash the affected CAI service.",
            full_content="CVE ID: CVE-2026-48439\nCWE: CWE-400\nImpact: denial of service",
            cve_id="CVE-2026-48439",
            cvss_score=7.5,
            cwe_ids=["CWE-400"],
            kev_listed=False,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["detection_status"], "telemetry_specification_only")
        self.assertIn("Availability-impact evidence", content)
        self.assertNotIn("Web Service Spawning a Command Interpreter", content)
        self.assertNotIn("web shell", content.lower())
        self.assertNotIn("lateral movement", content.lower())

    def test_spoofing_cve_uses_identity_telemetry_not_web_exploitation(self):
        article = _make_article(
            title="CVE-2026-57104 Windows NAT spoofing vulnerability",
            summary="A spoofing weakness affects Windows NAT identity handling.",
            cve_id="CVE-2026-57104",
            cvss_score=8.8,
            cwe_ids=None,
            kev_listed=False,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["detection_status"], "telemetry_specification_only")
        self.assertIn("identity/control-boundary weakness", content)
        self.assertNotIn("Web Service Spawning", content)

    def test_sql_injection_rule_has_real_uuid_and_valid_yaml(self):
        article = _make_article(
            title="CVE-2026-72898 Metabase SQL injection",
            summary="A SQL injection vulnerability affects a Metabase web endpoint.",
            full_content="CVE ID: CVE-2026-72898\nCWE: CWE-89\nClass: SQL injection",
            cve_id="CVE-2026-72898",
            cwe_ids=["CWE-89"],
            kev_listed=True,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["detection_status"], "syntax_validated_experimental")
        self.assertIn("SQL Injection Probing", content)
        match = re.search(r"<code>(title:.*?)</code>", content, re.DOTALL)
        self.assertIsNotNone(match)
        rule = yaml.safe_load(html.unescape(match.group(1)))
        self.assertRegex(rule["id"], r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        self.assertIn("condition", rule["detection"])
        self.assertEqual(rule["status"], "experimental")


class TestFamilySpecificSchemas(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_ransomware_claim_has_claim_boundary_and_no_patch_schema(self):
        article = _make_article(
            source="ransomware_intel",
            title="Qilin Ransomware Claims New Victim: Example Co",
            summary="Qilin has listed Example Co as a new victim on its leak site.",
            full_content="Ransomware Group: Qilin\nVictim: Example Co\nSector: Technology",
            labels=["Ransomware", "Threat Intelligence"],
            cve_id=None,
            cvss_score=None,
            cvss_vector=None,
            cwe_ids=None,
            affected_vendor=None,
            affected_product=None,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["report_family"], "ransomware_claim")
        self.assertEqual(result["detection_status"], "withheld_insufficient_evidence")
        self.assertIn("Third-party actor claim — independently unverified", content)
        self.assertIn("no validated actor-specific IOCs or TTPs", content)
        self.assertNotIn("pre-exploitation", content.lower())
        self.assertNotIn("PATCH unconfirmed", content)
        self.assertNotIn("Sigma YAML", content)

    def test_ai_news_has_governance_schema_not_phishing_rule(self):
        article = _make_article(
            source="global_rss",
            title="OpenAI Astra model safety evaluation published",
            summary="OpenAI published evaluation results for the next Astra AI model.",
            full_content="Model evaluation and capability safety news.",
            labels=["AI Security", "Threat Intelligence"],
            cve_id=None,
            cvss_score=None,
            cvss_vector=None,
            cwe_ids=None,
            affected_vendor=None,
            affected_product=None,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["report_family"], "ai_security")
        self.assertEqual(result["detection_status"], "not_applicable")
        self.assertIn("AI Security Assessment", content)
        self.assertIn("Governance and Engineering Actions", content)
        self.assertNotIn("Sigma YAML", content)
        self.assertNotIn("Office Application Shell Spawn", content)
        self.assertNotIn("phishing detection logic", content.lower())

    def test_automated_reports_never_name_a_human_analyst(self):
        content = AuthorityTransformer(self.config).transform(_make_article())["content"]
        self.assertIn(REVIEW_STATUS, content)
        self.assertNotIn("Bivash Kumar Nayak — Chief Security Architect", content)
        self.assertIn("Automated Intelligence Engine", content)


class TestFailClosedPublicationGate(unittest.TestCase):
    def test_blocks_false_exploitation_assertion(self):
        article = _make_article(kev_listed=False)
        context = build_report_context(article)
        safe = render_evidence_report(article, Config()).html
        unsafe = safe + "<p>Exploitation is confirmed active.</p>"
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, unsafe)
        self.assertTrue(any("unverified exploitation assertion" in issue for issue in caught.exception.issues))

    def test_blocks_placeholders(self):
        article = _make_article()
        context = build_report_context(article)
        unsafe = render_evidence_report(article, Config()).html + "<p>Not Found Sector</p>"
        with self.assertRaises(PublicationIntegrityError):
            validate_publication(article, context, unsafe)

    def test_blocks_missing_provenance(self):
        article = _make_article()
        context = build_report_context(article)
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, "<p>short report</p>")
        self.assertTrue(any("missing report identifier" in issue for issue in caught.exception.issues))

    def test_blocks_human_attribution_without_review_event(self):
        article = _make_article()
        context = build_report_context(article)
        unsafe = render_evidence_report(article, Config()).html + "Bivash Kumar Nayak — Chief Security Architect"
        with self.assertRaises(PublicationIntegrityError):
            validate_publication(article, context, unsafe)


class TestAuthorityTransformerContract(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.transformer = AuthorityTransformer(self.config)

    def test_transform_returns_production_metadata(self):
        result = self.transformer.transform(_make_article())
        required = {
            "title",
            "content",
            "labels",
            "image_url",
            "meta_title",
            "meta_description",
            "keywords",
            "source_url",
            "content_hash",
            "content_source",
            "report_id",
            "source_record_hash",
            "report_family",
            "review_status",
            "certification_status",
            "detection_status",
            "generated_at",
        }
        self.assertTrue(required.issubset(result))
        self.assertEqual(result["content_source"], "evidence_safe_template")
        self.assertEqual(result["source_url"], _make_article().url)
        self.assertEqual(result["content_hash"], _make_article().content_hash)
        self.assertLessEqual(len(result["labels"]), 20)

    def test_default_publication_never_calls_llm(self):
        with patch("automation.authority_transformer.call_llm") as mocked:
            self.transformer.transform(_make_article())
        mocked.assert_not_called()

    def test_structured_data_has_automated_author_and_no_fake_counts(self):
        content = self.transformer.transform(_make_article())["content"]
        self.assertIn("SENTINEL APEX Automated Intelligence Engine", content)
        self.assertNotIn("2,400+", content)
        self.assertNotIn("production-ready Sigma", content)
        self.assertNotIn('"@type": "HowTo"', content)
        self.assertNotIn('"@type": "FAQPage"', content)

    def test_svg_thumbnail_and_dynamic_image_contract(self):
        result = self.transformer.transform(_make_article())
        self.assertIn("data:image/svg+xml;base64,", result["content"])
        params = parse_qs(urlparse(result["image_url"]).query)
        self.assertEqual(params["cve"], ["CVE-2026-9999"])
        self.assertEqual(params["severity"], ["CRITICAL"])

    def test_svg_alt_is_well_formed_and_palette_is_category_specific(self):
        tag = _generate_svg_thumbnail('Windows "RCE"', ["Ransomware"], "not-a-number")
        self.assertRegex(tag, r'alt="[^"]*"')
        svg = base64.b64decode(tag.split("base64,")[1].split('"')[0]).decode("utf-8")
        self.assertIn("#f59e0b", svg)

    def test_og_builder_omits_unknown_values(self):
        url = _build_dynamic_og_image_url(
            self.config,
            title="General intelligence",
            severity=None,
            cve_id="",
            cvss=None,
            type_label="Threat Intel",
        )
        params = parse_qs(urlparse(url).query)
        self.assertNotIn("cve", params)
        self.assertNotIn("cvss", params)


if __name__ == "__main__":
    unittest.main()
