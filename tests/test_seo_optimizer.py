"""
Tests for seo_optimizer — metadata generation, schema validation, keyword extraction.
"""

import json
import unittest
from datetime import datetime, timezone

from automation.config import Config
from automation.seo_optimizer import SEOOptimizer, _extract_cve_ids, _extract_cvss, _truncate


class TestHelpers(unittest.TestCase):
    def test_extract_cve_ids(self):
        text = "CVE-2026-33824 and CVE-2025-1234 are both critical"
        cves = _extract_cve_ids(text)
        self.assertIn("CVE-2026-33824", cves)
        self.assertIn("CVE-2025-1234", cves)

    def test_extract_cve_case_insensitive(self):
        cves = _extract_cve_ids("cve-2026-9999 critical flaw")
        self.assertTrue(any("CVE-2026-9999" in c.upper() for c in cves))

    def test_extract_cvss(self):
        self.assertEqual(_extract_cvss("CVSS 9.8 critical vulnerability"), "9.8")
        self.assertEqual(_extract_cvss("CVSS: 7.5 high"), "7.5")
        self.assertIsNone(_extract_cvss("no score here"))

    def test_truncate_within_limit(self):
        text = "Short text"
        self.assertEqual(_truncate(text, 100), text)

    def test_truncate_at_word_boundary(self):
        text = "Word one two three four five six seven eight nine ten"
        result = _truncate(text, 30)
        self.assertLessEqual(len(result), 30)
        self.assertTrue(result.endswith("..."))

    def test_truncate_does_not_split_word(self):
        text = "Hello world this is a long text that needs truncation"
        result = _truncate(text, 25)
        # Should end at word boundary
        self.assertNotIn(result[-4:-3], [" "])


class TestSEOOptimizer(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.optimizer = SEOOptimizer(self.config)
        self.pub_date = datetime.now(timezone.utc).isoformat()

    def _generate(self, title="CVE-2026-1234 Critical RCE Vulnerability", summary="A critical vulnerability"):
        return self.optimizer.generate(
            title=title,
            summary=summary,
            url="https://blog.cyberdudebivash.in/posts/test",
            labels=["Vulnerabilities", "Zero-Day", "CYBERDUDEBIVASH"],
            published_at=self.pub_date,
        )

    def test_meta_title_contains_brand(self):
        result = self._generate()
        self.assertIn("CYBERDUDEBIVASH", result["meta_title"])

    def test_meta_title_max_length(self):
        result = self._generate("A very long title " * 10)
        self.assertLessEqual(len(result["meta_title"]), 65)

    def test_meta_description_max_length(self):
        result = self._generate(summary="A summary " * 100)
        self.assertLessEqual(len(result["meta_description"]), 160)

    def test_keywords_contains_base_terms(self):
        result = self._generate()
        kw_str = " ".join(result["keywords"]).lower()
        self.assertIn("cybersecurity", kw_str)

    def test_og_tags_structure(self):
        result = self._generate()
        og = result["og_tags"]
        self.assertIn("og:title", og)
        self.assertIn("og:description", og)
        self.assertIn("og:image", og)
        self.assertEqual(og["og:type"], "article")

    def test_twitter_card_structure(self):
        result = self._generate()
        tc = result["twitter_card"]
        self.assertEqual(tc["twitter:card"], "summary_large_image")
        self.assertIn("twitter:title", tc)

    def test_json_ld_valid_structure(self):
        result = self._generate()
        ld = result["json_ld"]
        self.assertIn("@context", ld)
        self.assertEqual(ld["@context"], "https://schema.org")
        self.assertIn("@graph", ld)
        types = [item.get("@type") for item in ld["@graph"]]
        self.assertIn("Article", types)
        self.assertIn("Organization", types)
        self.assertIn("BreadcrumbList", types)

    def test_json_ld_serializable(self):
        result = self._generate()
        # Should not raise
        serialized = json.dumps(result["json_ld"])
        self.assertIsInstance(serialized, str)

    def test_cve_included_in_description_prefix(self):
        result = self._generate(title="CVE-2026-9999 Windows RCE")
        # CVE should appear in description or keywords
        all_text = result["meta_description"] + " ".join(result["keywords"])
        self.assertIn("CVE-2026-9999", all_text)

    def test_faq_schema_for_vulnerability(self):
        faq = self.optimizer.build_faq_schema(
            "CVE-2026-1234 Critical Flaw",
            "A vulnerability allows RCE",
            ["Vulnerabilities"],
        )
        self.assertEqual(faq.get("@type"), "FAQPage")
        self.assertGreater(len(faq["mainEntity"]), 0)

    def test_faq_schema_empty_for_generic(self):
        faq = self.optimizer.build_faq_schema(
            "Generic Security Article",
            "Some content about security",
            ["Threat Intelligence"],
        )
        # May be empty dict if no matching signals
        self.assertIsInstance(faq, dict)


if __name__ == "__main__":
    unittest.main()
