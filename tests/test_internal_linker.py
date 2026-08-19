"""
Tests for automation.internal_linker — including the new state-file-backed
correlation block (real cross-references, never fabricated links).
"""

import json
import os
import tempfile
import unittest

from automation.config import Config
from automation.internal_linker import InternalLinker, find_independent_prior_source


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
        # NOTE: uses "Zero-Day" (a genuinely discriminating label), not
        # "Vulnerabilities" -- COMMERCIAL-QUALITY-2026-08-19 correctly moved
        # "Vulnerabilities" itself into _NON_DISCRIMINATING_LABELS (see
        # test_two_unrelated_cve_reports_sharing_only_vulnerabilities_label_do_not_match
        # below), so it can no longer stand in as "some real shared label"
        # here without defeating the very fix this file also tests for.
        self._write_state({
            "hash1": {"source_title": "Log4Shell Deep Dive", "blogger_url": "https://x/log4shell",
                      "cves": ["CVE-2021-44228"], "labels": ["Zero-Day"], "published_at": "2026-07-01"},
            "hash2": {"source_title": "Generic Vuln Roundup", "blogger_url": "https://x/roundup",
                      "cves": [], "labels": ["Zero-Day"], "published_at": "2026-07-15"},
        })
        block = self.linker.build_correlation_block(["Zero-Day"], ["CVE-2021-44228"])
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

    def test_two_unrelated_cve_reports_sharing_only_vulnerabilities_label_do_not_match(self):
        # COMMERCIAL-QUALITY-2026-08-19: same defect class as the universal-
        # label test above, unaddressed within the CVE-report population
        # specifically. content_discovery._infer_labels() maps every
        # "cve"-keyword title to "Vulnerabilities" unconditionally, so two
        # CVEs from completely different vendors/products still "matched" on
        # that one shared label. Independently verified live: CVE-2026-60698
        # (Oracle WebLogic) and CVE-2026-75912 (CodeWhale) each showed five
        # "Related Intelligence Reports" that were just the five most recent
        # other CVE posts, not genuinely related vulnerabilities.
        self._write_state({
            "hash1": {
                "source_title": "CVE-2026-60698 — CVSS 9.8 CRITICAL Severity | NVD Vulnerability Record",
                "blogger_url": "https://x/cve-2026-60698",
                "cves": ["CVE-2026-60698"], "labels": ["CYBERDUDEBIVASH", "Threat Intelligence", "Vulnerabilities"],
                "published_at": "2026-08-18",
            },
        })
        block = self.linker.build_correlation_block(
            ["CYBERDUDEBIVASH", "Threat Intelligence", "Vulnerabilities"], ["CVE-2026-75912"],
        )
        self.assertEqual(block, "")

    def test_two_cve_reports_sharing_a_real_discriminating_label_still_match(self):
        # The fix must not become so strict that real relationships between
        # two different CVEs (e.g. both flagged Cloud Security) stop matching
        # -- only "Vulnerabilities" itself is excluded, not every CVE label.
        self._write_state({
            "hash1": {
                "source_title": "CVE-2026-11111 — Cloud Misconfiguration Advisory",
                "blogger_url": "https://x/cve-2026-11111",
                "cves": ["CVE-2026-11111"],
                "labels": ["CYBERDUDEBIVASH", "Threat Intelligence", "Vulnerabilities", "Cloud Security"],
                "published_at": "2026-08-18",
            },
        })
        block = self.linker.build_correlation_block(
            ["CYBERDUDEBIVASH", "Threat Intelligence", "Vulnerabilities", "Cloud Security"], ["CVE-2026-22222"],
        )
        self.assertIn("CVE-2026-11111", block)

    def test_max_results_respected(self):
        posts = {
            f"hash{i}": {"source_title": f"Report {i}", "blogger_url": f"https://x/{i}",
                         "cves": [], "labels": ["Ransomware"], "published_at": f"2026-07-{i:02d}"}
            for i in range(1, 10)
        }
        self._write_state(posts)
        block = self.linker.build_correlation_block(["Ransomware"], [], max_results=3)
        self.assertEqual(block.count("<li>"), 3)


class TestFindIndependentPriorSource(unittest.TestCase):
    """Round 7: real, already-persisted independent-source corroboration --
    never a live network fetch, never fabricated when the data doesn't
    actually establish independence."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmpdir, "published_posts.json")

    def _write_state(self, posts):
        with open(self.state_path, "w") as f:
            json.dump({"total_published": len(posts), "posts": posts}, f)

    def test_finds_a_genuinely_different_publisher_for_the_same_cve(self):
        self._write_state({
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-1234"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        match = find_independent_prior_source("CVE-2026-1234", "nvd", self.state_path)
        self.assertIsNotNone(match)
        self.assertEqual(match["source_publisher"], "BleepingComputer")

    def test_same_publisher_is_not_independent(self):
        self._write_state({
            "hash1": {
                "source_url": "https://nvd.nist.gov/x", "source_title": "x",
                "cves": ["CVE-2026-1234"], "published_at": "2026-08-01T00:00:00Z",
                "source": "nvd", "source_publisher": None,
            },
        })
        match = find_independent_prior_source("CVE-2026-1234", "nvd", self.state_path)
        self.assertIsNone(match)

    def test_unknown_publisher_is_never_assumed_independent(self):
        # A pre-Round-7 entry has neither "source" nor "source_publisher" at
        # all -- must be treated as unknown, not silently assumed different.
        self._write_state({
            "hash1": {
                "source_url": "https://example.test/x", "source_title": "x",
                "cves": ["CVE-2026-1234"], "published_at": "2026-08-01T00:00:00Z",
            },
        })
        match = find_independent_prior_source("CVE-2026-1234", "nvd", self.state_path)
        self.assertIsNone(match)

    def test_no_matching_cve_returns_none(self):
        self._write_state({
            "hash1": {
                "source_url": "https://www.bleepingcomputer.com/x", "source_title": "x",
                "cves": ["CVE-2026-9999"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "BleepingComputer",
            },
        })
        self.assertIsNone(find_independent_prior_source("CVE-2026-1234", "nvd", self.state_path))

    def test_missing_state_file_returns_none_not_a_crash(self):
        self.assertIsNone(find_independent_prior_source("CVE-2026-1234", "nvd", "/no/such/file.json"))

    def test_empty_cve_id_returns_none(self):
        self.assertIsNone(find_independent_prior_source("", "nvd", self.state_path))

    def test_candidate_with_only_a_generic_aggregator_connector_is_not_independent(self):
        # CodeRabbit review (Round 7 follow-up): a candidate whose
        # source_publisher is missing must not fall back to "global_rss"
        # (an aggregator covering ~40 distinct outlets) as if that bare
        # connector name were a specific, comparable identity -- it would
        # almost always differ from a real named publisher, making a
        # genuinely-unknown-outlet entry look "independent" by accident.
        self._write_state({
            "hash1": {
                "source_url": "https://example.test/x", "source_title": "x",
                "cves": ["CVE-2026-1234"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": None,
            },
        })
        match = find_independent_prior_source("CVE-2026-1234", "Krebs on Security", self.state_path)
        self.assertIsNone(match)

    def test_earliest_independent_match_wins_when_several_exist(self):
        self._write_state({
            "hash1": {
                "source_url": "https://a.test/x", "source_title": "later",
                "cves": ["CVE-2026-1234"], "published_at": "2026-08-10T00:00:00Z",
                "source": "global_rss", "source_publisher": "Outlet A",
            },
            "hash2": {
                "source_url": "https://b.test/x", "source_title": "earlier",
                "cves": ["CVE-2026-1234"], "published_at": "2026-08-01T00:00:00Z",
                "source": "global_rss", "source_publisher": "Outlet B",
            },
        })
        match = find_independent_prior_source("CVE-2026-1234", "nvd", self.state_path)
        self.assertEqual(match["source_publisher"], "Outlet B")


if __name__ == "__main__":
    unittest.main()
