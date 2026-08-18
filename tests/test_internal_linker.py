"""
Tests for automation.internal_linker — including the new state-file-backed
correlation block (real cross-references, never fabricated links).
"""

import json
import os
import tempfile
import unittest

from automation.config import Config
from automation.internal_linker import InternalLinker


class TestBuildCorrelationBlock(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmpdir, "published_posts.json")
        self.config = Config()
        self.config.state_file = self.state_path
        self.linker = InternalLinker(self.config)

    def _write_state(self, posts):
        with open(self.state_path, "w") as f:
            json.dump({"total_published": len(posts), "posts": posts}, f)

    def test_cve_match_ranks_above_label_only_match(self):
        self._write_state({
            "hash1": {"source_title": "Log4Shell Deep Dive", "blogger_url": "https://x/log4shell",
                      "cves": ["CVE-2021-44228"], "labels": ["Vulnerabilities"], "published_at": "2026-07-01"},
            "hash2": {"source_title": "Generic Vuln Roundup", "blogger_url": "https://x/roundup",
                      "cves": [], "labels": ["Vulnerabilities"], "published_at": "2026-07-15"},
        })
        block = self.linker.build_correlation_block(["Vulnerabilities"], ["CVE-2021-44228"])
        # CVE match must appear before the label-only match in the output
        self.assertLess(block.index("Log4Shell Deep Dive"), block.index("Generic Vuln Roundup"))

    def test_omits_unrelated_recent_posts_when_no_direct_match(self):
        self._write_state({
            "hash1": {"source_title": "Unrelated Ransomware Report", "blogger_url": "https://x/ransomware",
                      "cves": [], "labels": ["Ransomware"], "published_at": "2026-07-10"},
        })
        block = self.linker.build_correlation_block(["AI Security"], [])
        self.assertEqual(block, "")

    def test_excludes_current_article_by_hash(self):
        self._write_state({
            "hash1": {"source_title": "Should Not Appear", "blogger_url": "https://x/self",
                      "cves": [], "labels": ["Ransomware"], "published_at": "2026-07-10"},
        })
        block = self.linker.build_correlation_block(["Ransomware"], [], exclude_hash="hash1")
        self.assertEqual(block, "")

    def test_missing_state_file_returns_empty_no_crash(self):
        self.config.state_file = "/nonexistent/path.json"
        block = self.linker.build_correlation_block(["Ransomware"], [])
        self.assertEqual(block, "")

    def test_empty_posts_returns_empty(self):
        self._write_state({})
        block = self.linker.build_correlation_block(["Ransomware"], [])
        self.assertEqual(block, "")

    def test_entry_missing_blogger_url_skipped(self):
        self._write_state({
            "hash1": {"source_title": "No URL Entry", "blogger_url": None,
                      "cves": [], "labels": ["Ransomware"], "published_at": "2026-07-10"},
        })
        block = self.linker.build_correlation_block(["Ransomware"], [])
        self.assertEqual(block, "")

    def test_universal_base_labels_do_not_count_as_a_real_relationship(self):
        # COMMERCIAL-QUALITY-2026-08-18: independently verified live (and
        # separately flagged in the same terms by an external review) that
        # a ransomware victim-claim report's "Related Intelligence" showed
        # multiple unrelated critical CVEs. Root cause: content_discovery's
        # _infer_labels() puts "CYBERDUDEBIVASH"/"Threat Intelligence" (and
        # rss_aggregator.py adds "Global Intel" for RSS articles) on every
        # single article unconditionally, so the old "shared labels" match
        # always fired on these -- functionally a recency feed, not
        # correlation. An unrelated CVE report sharing only the universal
        # labels with a ransomware article must NOT be surfaced as related.
        self._write_state({
            "hash1": {
                "source_title": "Unrelated Critical CVE Advisory", "blogger_url": "https://x/unrelated-cve",
                "cves": [], "labels": ["CYBERDUDEBIVASH", "Threat Intelligence", "Vulnerabilities"],
                "published_at": "2026-08-18",
            },
        })
        block = self.linker.build_correlation_block(
            ["CYBERDUDEBIVASH", "Threat Intelligence", "Global Intel", "Ransomware"], [],
        )
        self.assertEqual(block, "")

    def test_a_genuinely_shared_discriminating_label_still_matches(self):
        # The fix must not become so strict that real relationships (e.g.
        # two ransomware reports) stop matching -- only the universal
        # labels are excluded, not every label.
        self._write_state({
            "hash1": {
                "source_title": "Another Ransomware Campaign Report", "blogger_url": "https://x/other-ransomware",
                "cves": [], "labels": ["CYBERDUDEBIVASH", "Threat Intelligence", "Ransomware"],
                "published_at": "2026-08-18",
            },
        })
        block = self.linker.build_correlation_block(
            ["CYBERDUDEBIVASH", "Threat Intelligence", "Global Intel", "Ransomware"], [],
        )
        self.assertIn("Another Ransomware Campaign Report", block)

    def test_max_results_respected(self):
        posts = {
            f"hash{i}": {"source_title": f"Report {i}", "blogger_url": f"https://x/{i}",
                         "cves": [], "labels": ["Ransomware"], "published_at": f"2026-07-{i:02d}"}
            for i in range(1, 10)
        }
        self._write_state(posts)
        block = self.linker.build_correlation_block(["Ransomware"], [], max_results=3)
        self.assertEqual(block.count("<li>"), 3)


if __name__ == "__main__":
    unittest.main()
