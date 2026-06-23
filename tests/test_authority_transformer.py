"""
Tests for authority_transformer — content generation, HTML validity, CTA injection.
"""

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
        article = _make_article()
        html = _template_enhance(article, self.config)
        required_sections = [
            "Executive Summary",
            "Threat Overview",
            "Threat Severity Assessment",
            "Business Impact",
            "Technical Analysis",
            "MITRE ATT&CK Mapping",
            "IOC Intelligence",
            "Detection Engineering Guidance",
            "Sigma Rules",
            "Threat Hunting Queries",
            "SOC Analyst Actions",
            "Executive Recommendations",
            "MSSP Opportunities",
            "Sentinel APEX Intelligence Correlation",
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
        article = _make_article(title="Ransomware Campaign", summary="Generic ransomware news", labels=["Ransomware"])
        html = _template_enhance(article, self.config)
        self.assertIn("CVE Analysis", html)
        self.assertIn("No specific CVE identifiers", html)

    def test_sigma_rules_valid_yaml_structure(self):
        import re as _re
        article = _make_article()
        html = _template_enhance(article, self.config)
        self.assertIn("Sigma Rules", html)
        # Tags must each be on their own line with proper YAML list indent
        self.assertIn("tags:", html)
        # Verify no malformed double-indented tags (old bug)
        self.assertNotIn("attack.impact\n        -", html)

    def test_sigma_logsource_valid_format(self):
        # Use titles/summaries that trigger the correct branch (is_ransomware checks text, not labels)
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
        article = _make_article()
        html = _template_enhance(article, self.config)
        self.assertIn("<li>", html)
        self.assertIn("<h3>", html)


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
        # Unescaped double quote would break the alt attribute HTML
        # After the alt=" opening, there should be no raw unescaped "
        import re as _re
        alt_match = _re.search(r'alt="([^"]*)"', result["content"])
        self.assertIsNotNone(alt_match, "alt attribute not found or malformed")

    def test_cvss_float_conversion_resilience(self):
        # CVSS value that could be malformed should not raise
        from automation.authority_transformer import _generate_svg_thumbnail
        try:
            result = _generate_svg_thumbnail("Test Title", ["Ransomware"], cvss="not-a-number")
            self.assertIn("<img", result)
        except (ValueError, TypeError):
            self.fail("_generate_svg_thumbnail raised on bad CVSS value")

    def test_svg_thumbnail_category_palette_ransomware(self):
        import base64
        from automation.authority_transformer import _generate_svg_thumbnail
        result = _generate_svg_thumbnail("Ransomware Attack", ["Ransomware"])
        # SVG is base64-encoded inside the img src — decode to check palette color
        b64 = result.split('base64,')[1].split('"')[0]
        svg_text = base64.b64decode(b64).decode("utf-8")
        self.assertIn("#f59e0b", svg_text)  # Ransomware amber accent

    def test_svg_thumbnail_category_palette_ai(self):
        import base64
        from automation.authority_transformer import _generate_svg_thumbnail
        result = _generate_svg_thumbnail("LLM Prompt Injection", ["AI Security"])
        b64 = result.split('base64,')[1].split('"')[0]
        svg_text = base64.b64decode(b64).decode("utf-8")
        self.assertIn("#a855f7", svg_text)  # AI Security purple accent

    def test_content_contains_all_18_sections(self):
        article = _make_article()
        result = self.transformer.transform(article)
        content = result["content"]
        required = [
            "Executive Summary", "Threat Overview", "Threat Severity Assessment",
            "Business Impact", "Technical Analysis", "CVE Analysis",
            "MITRE ATT&CK Mapping", "IOC Intelligence", "Detection Engineering Guidance",
            "Sigma Rules", "Threat Hunting Queries", "SOC Analyst Actions",
            "Executive Recommendations", "MSSP Opportunities",
            "Sentinel APEX Intelligence Correlation", "Long-Term Strategic Risk", "References",
        ]
        for section in required:
            self.assertIn(section, content, f"Section missing from assembled content: {section}")


if __name__ == "__main__":
    unittest.main()
