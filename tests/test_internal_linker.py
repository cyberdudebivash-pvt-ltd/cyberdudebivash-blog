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
