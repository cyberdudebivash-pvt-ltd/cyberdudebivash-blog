"""
Tests for authority_transformer — content generation, HTML validity, CTA injection.
"""

import json
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from automation.authority_transformer import AuthorityTransformer, _template_enhance
from automation.config import Config
from automation.content_discovery import DiscoveredArticle, _compute_hash


def _make_article(**kwargs) -> DiscoveredArticle:
    defaults = {
        "url": "https://blog.cyberdudebivash.in/posts/test-cve",
        "title": "CVE-2026-9999 Critical Windows RCE — CVSS 9.8",
        "summary": "A critical remote code execution vulnerability in Windows IKE allows unauthenticated attackers to execute arbitrary code with SYSTEM privileges.",
        "published_at": datetime.now(timezone.utc).isoformat(),
        "content_hash": _compute_hash("https://blog.cyberdudebivash.in/posts/test-cve", "CVE-2026-9999"),
        "labels": ["Vulnerabilities", "Zero-Day", "CISA KEV", "CYBERDUDEBIVASH"],
        "source": "rss",
    }
    defaults.update(kwargs)
    return DiscoveredArticle(**defaults)


class TestTemplateEnhancement(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""  # Force template path

    def test_template_contains_all_sections(self):
        # Section names/structure below match the 2026-07-06 "trust & quality
        # retrofit" (commit ee9447e) — several sections were renamed and the
        # div-card layout replaced the old <h3>/<ul> structure.
        article = _make_article()
        html = _template_enhance(article, self.config)
        required_sections = [
            "Executive Summary",
            "Verified Facts",
            "Threat Classification & Severity",
            "Business Impact",
            "Technical Analysis",
            "MITRE ATT&CK Mapping",
            "IOC Intelligence",
            "Detection Engineering Guidance",
            "Sigma Detection Rule",
            "Threat Hunting Queries",
            "SOC Analyst Playbook",
            "Executive Decision Matrix",
            "Executive Recommendations",
            "Predictive Intelligence",
            "MSSP Partner Advisory",
            "SENTINEL APEX Intelligence Correlation",
            "Long-Term Strategic Risk",
            "References",
        ]
        for section in required_sections:
            self.assertIn(section, html, f"Missing section: {section}")

    def test_cve_analysis_section_present_when_cve_in_title(self):
        article = _make_article()  # Default fixture has CVE-2026-9999
        html = _template_enhance(article, self.config)
        self.assertIn("CVE Analysis", html)
        self.assertIn("CVE-2026-9999", html)

    def test_cve_analysis_fallback_when_no_cve(self):
        # Trust retrofit made this section CVE-conditional — no CVE means the
        # section is omitted entirely rather than padded with filler text.
        article = _make_article(title="Ransomware Campaign", summary="Generic ransomware news", labels=["Ransomware"])
        html = _template_enhance(article, self.config)
        self.assertNotIn("CVE Analysis", html)

    def test_sigma_rules_valid_yaml_structure(self):
        article = _make_article()
        html = _template_enhance(article, self.config)
        self.assertIn("Sigma Detection Rule", html)
        self.assertIn("tags:", html)
        # Each tag must be on its own properly-indented line — no broken double-indent
        self.assertNotIn("attack.impact\n        -", html)
        self.assertNotIn("attack.initial_access\n        -", html)

    def test_sigma_logsource_valid_format(self):
        # Use titles/summaries that trigger the correct branch
        for title, summary, labels, expected_field in [
            ("LockBit Ransomware Campaign", "Ransomware encrypted hospital systems", ["Ransomware"], "category: process_creation"),
            ("APT28 Nation-State Attack", "nation-state threat actor targeted government", ["APT"], "category: process_creation"),
            ("CVE-2026-9999 Remote Code Execution", "Critical RCE vulnerability CVSS 9.8", ["Vulnerabilities"], "category: webserver"),
        ]:
            with self.subTest(labels=labels):
                article = _make_article(title=title, summary=summary, labels=labels)
                html = _template_enhance(article, self.config)
                self.assertIn(expected_field, html, f"logsource field missing for {labels}")

    def test_mitre_attack_in_output(self):
        article = _make_article(labels=["Ransomware"])
        html = _template_enhance(article, self.config)
        self.assertIn("T1", html)

    def test_ai_section_when_ai_labels(self):
        article = _make_article(
            title="LLM Prompt Injection Attack",
            summary="AI systems are vulnerable to prompt injection attacks",
            labels=["AI Security"],
        )
        html = _template_enhance(article, self.config)
        self.assertIn("AI Security Impact", html)

    def test_ai_section_omitted_when_no_ai_content(self):
        article = _make_article(
            title="Windows RCE Vulnerability",
            summary="Critical Windows vulnerability patched",
            labels=["Vulnerabilities"],
        )
        html = _template_enhance(article, self.config)
        self.assertNotIn("AI Security Impact", html)

    def test_no_fabricated_content(self):
        article = _make_article()
        html = _template_enhance(article, self.config)
        # Should not contain fabricated statistics we didn't put in
        self.assertNotIn("$4.2 billion", html.lower())

    def test_output_has_list_items(self):
        # Trust retrofit replaced semantic <ul>/<li>/<h3> markup with a
        # div-card layout (styled bullet chips + a table) for the premium
        # enterprise UI — check for that structure instead.
        article = _make_article()
        html = _template_enhance(article, self.config)
        self.assertIn("<table", html)
        self.assertGreater(html.count("border-radius:0 4px 4px 0"), 5)


class TestAuthorityTransformer(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""  # Force template path
        self.transformer = AuthorityTransformer(self.config)

    def test_transform_returns_required_keys(self):
        article = _make_article()
        result = self.transformer.transform(article)
        required_keys = ["title", "content", "labels", "meta_title", "meta_description",
                         "keywords", "source_url", "content_hash", "content_source"]
        for key in required_keys:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_content_contains_cta_blocks(self):
        article = _make_article()
        result = self.transformer.transform(article)
        content = result["content"]
        self.assertIn("SENTINEL APEX", content)
        self.assertIn("cyberdudebivash.com", content)

    def test_content_contains_schema_json_ld(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertIn('application/ld+json', result["content"])

    def test_title_optimised_for_seo(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertLessEqual(len(result["title"]), 90)
        self.assertTrue(len(result["title"]) > 10)

    def test_blogger_title_includes_cve(self):
        article = _make_article(title="CVE-2026-1234 Critical Windows Flaw")
        result = self.transformer.transform(article)
        self.assertIn("CVE-2026-1234", result["title"])

    def test_labels_non_empty(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertGreater(len(result["labels"]), 0)

    def test_labels_max_20(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertLessEqual(len(result["labels"]), 20)

    def test_content_source_template_when_no_api_key(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertEqual(result["content_source"], "template")

    def test_source_url_preserved(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertEqual(result["source_url"], article.url)

    def test_content_hash_preserved(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertEqual(result["content_hash"], article.content_hash)

    def test_read_more_link_in_content(self):
        article = _make_article()
        result = self.transformer.transform(article)
        self.assertIn(article.url, result["content"])

    def test_ransomware_content_includes_backup_advice(self):
        article = _make_article(
            title="LockBit Ransomware Hits Healthcare",
            summary="LockBit ransomware encrypted hospital systems",
            labels=["Ransomware"],
        )
        result = self.transformer.transform(article)
        self.assertIn("backup", result["content"].lower())

    def test_svg_thumbnail_present_in_content(self):
        article = _make_article()
        result = self.transformer.transform(article)
        # SVG thumbnail must be the first meaningful element — Blogger uses it as firstImageUrl
        self.assertIn("data:image/svg+xml;base64,", result["content"])
        self.assertIn('<img src="data:image/svg+xml;base64,', result["content"])

    def test_svg_thumbnail_quotes_escaped_in_alt(self):
        article = _make_article(title='Windows "RCE" Vulnerability — CVE-2026-9999')
        result = self.transformer.transform(article)
        # Verify the alt attribute is well-formed (no raw unescaped double-quote breaks it)
        import re as _re
        alt_match = _re.search(r'alt="([^"]*)"', result["content"])
        self.assertIsNotNone(alt_match, "alt attribute not found or malformed by unescaped quotes")

    def test_cvss_float_conversion_resilience(self):
        from automation.authority_transformer import _generate_svg_thumbnail
        try:
            result = _generate_svg_thumbnail("Test Title", ["Ransomware"], cvss="not-a-number")
            self.assertIn("<img", result)
        except (ValueError, TypeError):
            self.fail("_generate_svg_thumbnail raised on malformed CVSS input")

    def test_svg_thumbnail_category_palette_ransomware(self):
        import base64
        from automation.authority_transformer import _generate_svg_thumbnail
        result = _generate_svg_thumbnail("Ransomware Attack", ["Ransomware"])
        svg_text = base64.b64decode(result.split("base64,")[1].split('"')[0]).decode("utf-8")
        self.assertIn("#f59e0b", svg_text)  # Ransomware amber accent

    def test_svg_thumbnail_category_palette_ai(self):
        import base64
        from automation.authority_transformer import _generate_svg_thumbnail
        result = _generate_svg_thumbnail("LLM Prompt Injection", ["AI Security"])
        svg_text = base64.b64decode(result.split("base64,")[1].split('"')[0]).decode("utf-8")
        self.assertIn("#a855f7", svg_text)  # AI Security purple accent

    def test_content_contains_all_required_sections(self):
        article = _make_article()
        result = self.transformer.transform(article)
        content = result["content"]
        required = [
            "Executive Summary", "Verified Facts", "Threat Classification & Severity",
            "Business Impact", "Technical Analysis", "CVE Analysis",
            "MITRE ATT&CK Mapping", "IOC Intelligence", "Detection Engineering Guidance",
            "Sigma Detection Rule", "Threat Hunting Queries", "SOC Analyst Playbook",
            "Executive Decision Matrix", "Executive Recommendations", "Predictive Intelligence",
            "MSSP Partner Advisory",
            "SENTINEL APEX Intelligence Correlation", "Long-Term Strategic Risk", "References",
        ]
        for section in required:
            self.assertIn(section, content, f"Section missing from assembled Blogger HTML: {section}")

    def test_cve_ids_normalised_to_uppercase(self):
        from automation.seo_optimizer import _extract_cve_ids
        ids = _extract_cve_ids("cve-2026-1234 and CVE-2025-9999 and Cve-2024-0001")
        self.assertTrue(all(c == c.upper() for c in ids), f"Non-uppercase CVE IDs: {ids}")
        self.assertIn("CVE-2026-1234", ids)
        self.assertIn("CVE-2025-9999", ids)


class TestRiskCommandCenter(unittest.TestCase):
    """Executive Risk Command Center — must show only verified data, never fabricate."""

    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.transformer = AuthorityTransformer(self.config)

    def test_omitted_entirely_when_no_verified_data(self):
        article = _make_article(
            title="Generic Ransomware Campaign", summary="A ransomware group claimed victims.",
            labels=["Ransomware"],
        )
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("Executive Risk Command Center", content)

    def test_renders_cvss_only_when_no_enrichment(self):
        """A plain CVE title (regex-extractable CVSS) still gets a dashboard,
        but must not show EPSS/KEV tile values that were never fetched.
        Note: the article's own "CISA KEV" *label* and the fixed "CISA Known
        Exploited Vulnerabilities Catalog" reference link legitimately appear
        elsewhere on the page — this checks the dashboard's own KEV tile
        values specifically, not the substring "CISA KEV" anywhere at all."""
        article = _make_article()  # default fixture: CVE-2026-9999, CVSS 9.8, no enrichment fields
        content = self.transformer.transform(article)["content"]
        self.assertIn("Executive Risk Command Center", content)
        self.assertIn("CVE-2026-9999", content)
        self.assertIn("9.8", content)
        self.assertNotIn("EPSS Score", content)
        self.assertNotIn("Not Listed", content)
        self.assertNotIn(">LISTED<", content)

    def test_full_enrichment_renders_all_verified_fields(self):
        article = _make_article(
            cve_id="CVE-2021-44228", cvss_score=10.0,
            epss_score=0.99999, epss_percentile=1.0,
            kev_listed=True, kev_due_date="2021-12-24",
            kev_required_action="Apply updates per vendor instructions.",
            affected_vendor="Apache", affected_product="Log4j",
        )
        content = self.transformer.transform(article)["content"]
        self.assertIn("Executive Risk Command Center", content)
        self.assertIn("10.0", content)
        self.assertIn("100.0%", content)
        self.assertIn("LISTED", content)
        self.assertIn("Remediation due 2021-12-24", content)
        self.assertIn("Exploitation confirmed?", content)
        self.assertIn("Apply updates per vendor instructions.", content)

    def test_kev_unknown_does_not_render_as_not_listed(self):
        """kev_listed=None (lookup failed/never ran) must not be shown as a
        false 'Not Listed' — that would misrepresent an unknown as verified."""
        article = _make_article(cve_id="CVE-2026-9999", cvss_score=9.8, kev_listed=None)
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("Not Listed", content)
        self.assertNotIn(">LISTED<", content)

    def test_kev_confirmed_absent_renders_not_listed(self):
        article = _make_article(cve_id="CVE-2026-9999", cvss_score=5.0, kev_listed=False)
        content = self.transformer.transform(article)["content"]
        self.assertIn("Not Listed", content)

    def test_low_severity_cvss_does_not_trigger_patch_now_decision(self):
        article = _make_article(cve_id="CVE-2026-1111", cvss_score=3.1, kev_listed=False)
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("Patch immediately?", content)


class TestMultiSiemDetectionQueries(unittest.TestCase):
    """Every detection branch must emit Splunk/Elastic/Sentinel/QRadar/Chronicle
    queries derived from the same logic as its Sigma rule — not just Sigma alone."""

    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.transformer = AuthorityTransformer(self.config)

    def _content_for(self, title, summary, labels):
        article = _make_article(title=title, summary=summary, labels=labels)
        return self.transformer.transform(article)["content"]

    def test_all_five_platforms_present_for_ransomware(self):
        content = self._content_for(
            "LockBit Ransomware Hits Healthcare Sector",
            "LockBit ransomware group encrypted hospital systems.",
            ["Ransomware"],
        )
        self.assertIn("Multi-SIEM Detection Queries", content)
        for label in ["Splunk SPL", "Elastic EQL", "Microsoft Sentinel KQL", "IBM QRadar AQL", "Google Chronicle YARA-L"]:
            self.assertIn(label, content, f"Missing platform: {label}")
        self.assertIn("vssadmin", content.lower())

    def test_ot_branch_has_industrial_ports_in_queries(self):
        content = self._content_for(
            "SCADA Historian Compromise at Water Treatment Facility",
            "Attackers accessed the OT network via unprotected industrial control systems.",
            ["OT Security"],
        )
        self.assertIn("Multi-SIEM Detection Queries", content)
        self.assertIn("502", content)  # Modbus port, shared across all 5 platform queries

    def test_cve_branch_present(self):
        content = self._content_for(
            "CVE-2026-9999 Critical Windows RCE", "Critical RCE vulnerability CVSS 9.8.", ["Vulnerabilities"],
        )
        self.assertIn("Multi-SIEM Detection Queries", content)

    def test_general_fallback_branch_present(self):
        content = self._content_for(
            "Phishing Campaign Targets Finance Employees", "A generic phishing email campaign was observed.", ["Phishing"],
        )
        self.assertIn("Multi-SIEM Detection Queries", content)

    def test_deployment_validation_disclaimer_present(self):
        content = self._content_for(
            "CVE-2026-9999 Critical Windows RCE", "Critical RCE vulnerability CVSS 9.8.", ["Vulnerabilities"],
        )
        self.assertIn("VALIDATE FIELD NAMES AGAINST YOUR ENVIRONMENT", content)


class TestRecommendedServicesWiring(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.transformer = AuthorityTransformer(self.config)

    def test_ransomware_report_recommends_incident_response(self):
        article = _make_article(
            title="LockBit Ransomware Hits Healthcare", summary="LockBit ransomware group encrypted hospital systems.",
            labels=["Ransomware", "CYBERDUDEBIVASH", "Threat Intelligence"],
        )
        content = self.transformer.transform(article)["content"]
        self.assertIn("Recommended For This Threat", content)
        self.assertIn("Incident Response", content)

    def test_uses_existing_service_css_classes(self):
        article = _make_article(labels=["Vulnerabilities", "CYBERDUDEBIVASH"])
        content = self.transformer.transform(article)["content"]
        self.assertIn('class="apex-services"', content)
        self.assertIn('class="apex-svc-item"', content)


class TestIndustryIntelligenceWiring(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.transformer = AuthorityTransformer(self.config)

    def test_healthcare_report_renders_industry_block(self):
        article = _make_article(
            title="Ransomware Group Hits Regional Hospital Network",
            summary="A ransomware group encrypted patient records at a healthcare system.",
            labels=["Ransomware"],
        )
        content = self.transformer.transform(article)["content"]
        self.assertIn("Industry Impact Intelligence", content)
        self.assertIn("Healthcare", content)
        self.assertIn("HIPAA", content)

    def test_generic_cve_report_omits_industry_block(self):
        article = _make_article(title="CVE-2026-9999 Critical RCE", summary="Critical remote code execution.", labels=["Vulnerabilities"])
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("Industry Impact Intelligence", content)


class TestExecutiveDecisionCenter(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.transformer = AuthorityTransformer(self.config)

    def test_all_six_audiences_present(self):
        article = _make_article(cvss_score=9.8)
        content = self.transformer.transform(article)["content"]
        for role in ["CEO Summary", "Board Summary", "CISO Summary", "SOC Summary", "DevSecOps Summary", "Cloud Summary"]:
            self.assertIn(role, content, f"{role} missing")

    def test_always_present_even_without_cvss(self):
        article = _make_article(title="Generic Ransomware News", summary="A ransomware group claimed victims.", labels=["Ransomware"])
        content = self.transformer.transform(article)["content"]
        self.assertIn("Executive Decision Center", content)

    def test_summaries_are_not_identical_text(self):
        """Each audience card must say something genuinely different."""
        article = _make_article(cvss_score=9.8)
        content = self.transformer.transform(article)["content"]
        from automation.authority_transformer import _build_executive_decision_center
        block = _build_executive_decision_center("Vulnerabilities", "CVE-2026-9999", "CRITICAL", self.config)
        import re
        texts = re.findall(r'letter-spacing:1px;\s*text-transform:uppercase;margin-bottom:8px">([^<]+)</div>\s*<div[^>]*>([^<]+)</div>', block)
        bodies = [t[1] for t in texts]
        self.assertEqual(len(bodies), len(set(bodies)), "Two or more audience summaries are identical text")


class TestTrustStatsBlock(unittest.TestCase):
    """Real numbers only, read from data/published_posts.json — never fabricated."""

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmpdir, "published_posts.json")
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.config.state_file = self.state_path
        self.transformer = AuthorityTransformer(self.config)

    def _write_state(self, data):
        with open(self.state_path, "w") as f:
            json.dump(data, f)

    def test_renders_real_published_count(self):
        self._write_state({"total_published": 2378, "posts": {}})
        article = _make_article()
        content = self.transformer.transform(article)["content"]
        self.assertIn("Threat Reports Published", content)
        self.assertIn("2,378", content)

    def test_renders_detection_rules_and_siem_platform_count(self):
        from automation.authority_transformer import SIEM_PLATFORM_LABELS
        self._write_state({"total_published": 100, "posts": {}})
        article = _make_article()
        content = self.transformer.transform(article)["content"]
        self.assertIn("Detection Rules Generated", content)
        self.assertIn("Supported SIEM Platforms", content)
        self.assertIn(str(len(SIEM_PLATFORM_LABELS)), content)

    def test_renders_unique_cve_count_when_present(self):
        self._write_state({
            "total_published": 5,
            "posts": {
                "a": {"cves": ["CVE-2021-44228"]},
                "b": {"cves": ["CVE-2021-44228", "CVE-2026-9999"]},
            },
        })
        article = _make_article()
        content = self.transformer.transform(article)["content"]
        self.assertIn("Unique CVEs Tracked", content)

    def test_omitted_when_state_file_missing(self):
        # Deliberately never write self.state_path
        article = _make_article()
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("Threat Reports Published", content)

    def test_omitted_when_total_published_zero(self):
        self._write_state({"total_published": 0, "posts": {}})
        article = _make_article()
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("Threat Reports Published", content)


class TestHowToSchemaWiring(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.transformer = AuthorityTransformer(self.config)

    def test_howto_schema_present_for_ransomware(self):
        article = _make_article(
            title="LockBit Ransomware Hits Healthcare", summary="LockBit ransomware group encrypted hospital systems.",
            labels=["Ransomware"],
        )
        content = self.transformer.transform(article)["content"]
        self.assertIn('"@type": "HowTo"', content)

    def test_no_howto_script_block_for_generic_content(self):
        article = _make_article(
            title="General Security News", summary="Nothing specific here.", labels=["Threat Intelligence"],
        )
        content = self.transformer.transform(article)["content"]
        self.assertNotIn('"@type": "HowTo"', content)


class TestAiSecurityImpactStyling(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.anthropic_api_key = ""
        self.transformer = AuthorityTransformer(self.config)

    def test_uses_shared_section_header_not_bare_h3(self):
        article = _make_article(
            title="LLM Prompt Injection Attack on Enterprise AI Agents",
            summary="AI systems vulnerable to prompt injection targeting RAG pipelines.",
            labels=["AI Security"],
        )
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("<h3>AI Security Impact</h3>", content)
        self.assertIn("AI Security Impact", content)
        self.assertIn("border-left:3px solid #a855f7", content)

    def test_omitted_when_not_ai_related(self):
        article = _make_article(title="Windows RCE Vulnerability", labels=["Vulnerabilities"])
        content = self.transformer.transform(article)["content"]
        self.assertNotIn("AI Security Impact", content)


if __name__ == "__main__":
    unittest.main()
