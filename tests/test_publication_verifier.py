"""Tests for automation.publication_verifier -- ReportX Phase 1Q
post-publication fetch-back.
"""

import unittest
from unittest.mock import MagicMock, patch

from automation.blogger_publisher import BloggerPublisher
from automation.config import Config
from automation.publication_verifier import fetch_back_and_verify, verify_fetch_back

_INTENDED_CONTENT = (
    '<div data-report-id="CDB-CTI-2026-ABC123DEF456">'
    "<p>Real analytical content about a real vulnerability.</p>"
    "<!-- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-99999 -->"
    "</div>"
)


def _live_post(**overrides) -> dict:
    defaults = {
        "id": "post-123",
        "title": "CVE-2026-99999 Test Vulnerability",
        "content": _INTENDED_CONTENT,
        "labels": ["Vulnerabilities", "CVE"],
    }
    defaults.update(overrides)
    return defaults


class TestVerifyFetchBackCleanMatch(unittest.TestCase):
    def test_exact_match_is_verified_with_no_defects(self):
        result = verify_fetch_back(
            _live_post(), "post-123",
            intended_title="CVE-2026-99999 Test Vulnerability",
            intended_content=_INTENDED_CONTENT,
            intended_labels=["Vulnerabilities", "CVE"],
        )
        self.assertTrue(result.verified)
        self.assertEqual(result.defects, ())
        self.assertTrue(result.exact_content_match)
        self.assertEqual(result.fetched, True)

    def test_label_order_difference_alone_is_not_a_defect(self):
        # Labels compared as a set -- Blogger reordering them is not a
        # content-integrity defect.
        result = verify_fetch_back(
            _live_post(labels=["CVE", "Vulnerabilities"]), "post-123",
            intended_title="CVE-2026-99999 Test Vulnerability",
            intended_content=_INTENDED_CONTENT,
            intended_labels=["Vulnerabilities", "CVE"],
        )
        self.assertTrue(result.verified)

    def test_benign_content_difference_is_not_exact_match_but_no_defect_fires(self):
        # A harmless serialization difference (e.g. trailing whitespace
        # Blogger's own save path adds) that doesn't strip the provenance
        # marker, inject a placeholder, or collapse length must not itself
        # be treated as a defect -- exact_content_match is the
        # observability signal for this, not a defect.
        result = verify_fetch_back(
            _live_post(content=_INTENDED_CONTENT + " "), "post-123",
            intended_title="CVE-2026-99999 Test Vulnerability",
            intended_content=_INTENDED_CONTENT,
            intended_labels=["Vulnerabilities", "CVE"],
        )
        self.assertTrue(result.verified)
        self.assertFalse(result.exact_content_match)


class TestVerifyFetchBackRealDefects(unittest.TestCase):
    def _base_kwargs(self):
        return dict(
            intended_title="CVE-2026-99999 Test Vulnerability",
            intended_content=_INTENDED_CONTENT,
            intended_labels=["Vulnerabilities", "CVE"],
        )

    def test_title_mismatch_is_a_defect(self):
        result = verify_fetch_back(_live_post(title="Something Else Entirely"), "post-123", **self._base_kwargs())
        self.assertFalse(result.verified)
        self.assertIn("title_mismatch", result.defects)

    def test_labels_mismatch_is_a_defect(self):
        result = verify_fetch_back(_live_post(labels=["Something Else"]), "post-123", **self._base_kwargs())
        self.assertFalse(result.verified)
        self.assertIn("labels_mismatch", result.defects)

    def test_provenance_marker_stripped_is_a_defect(self):
        stripped = _INTENDED_CONTENT.replace('data-report-id="CDB-CTI-2026-ABC123DEF456"', "")
        result = verify_fetch_back(_live_post(content=stripped), "post-123", **self._base_kwargs())
        self.assertFalse(result.verified)
        self.assertIn("provenance_marker_stripped", result.defects)

    def test_source_url_comment_stripped_is_a_defect(self):
        stripped = _INTENDED_CONTENT.replace(
            "<!-- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-99999 -->", ""
        )
        result = verify_fetch_back(_live_post(content=stripped), "post-123", **self._base_kwargs())
        self.assertFalse(result.verified)
        self.assertIn("source_url_comment_stripped", result.defects)

    def test_placeholder_pattern_in_live_content_is_a_defect(self):
        result = verify_fetch_back(
            _live_post(content=_INTENDED_CONTENT + "<p>Not found sector: TODO</p>"),
            "post-123", **self._base_kwargs(),
        )
        self.assertFalse(result.verified)
        self.assertIn("placeholder_pattern_in_live_content", result.defects)

    def test_content_length_collapse_is_a_defect(self):
        result = verify_fetch_back(_live_post(content="<p>short</p>"), "post-123", **self._base_kwargs())
        self.assertFalse(result.verified)
        self.assertIn("content_length_collapsed", result.defects)

    def test_minor_length_reduction_below_threshold_is_not_a_defect(self):
        # A shorter live body that still keeps every specific marker intact
        # (well above the 50% collapse threshold) must not trip the
        # length-collapse check even though it's not an exact match.
        shorter_but_intact = (
            '<div data-report-id="CDB-CTI-2026-ABC123DEF456">'
            "<p>Real analytical content.</p>"
            "<!-- Source: https://nvd.nist.gov/vuln/detail/CVE-2026-99999 -->"
            "</div>"
        )
        self.assertGreater(len(shorter_but_intact), len(_INTENDED_CONTENT) * 0.5)
        result = verify_fetch_back(_live_post(content=shorter_but_intact), "post-123", **self._base_kwargs())
        self.assertNotIn("content_length_collapsed", result.defects)

    def test_multiple_defects_are_all_reported_together(self):
        result = verify_fetch_back(
            _live_post(title="Wrong", content="<p>x</p>", labels=["Wrong"]),
            "post-123", **self._base_kwargs(),
        )
        self.assertFalse(result.verified)
        self.assertIn("title_mismatch", result.defects)
        self.assertIn("labels_mismatch", result.defects)
        self.assertIn("provenance_marker_stripped", result.defects)
        self.assertIn("content_length_collapsed", result.defects)


class TestFetchBackAndVerifyIntegration(unittest.TestCase):
    def setUp(self):
        cfg = Config()
        cfg.blogger_client_id = "id"
        cfg.blogger_client_secret = "secret"
        cfg.blogger_refresh_token = "refresh"
        cfg.blogger_blog_id = "blog-1"
        self.publisher = BloggerPublisher(cfg)

    def test_clean_round_trip_via_real_get_post_call(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _live_post()
        with patch("requests.get", return_value=mock_resp):
            with patch.object(self.publisher, "_get_access_token", return_value="tok"):
                result = fetch_back_and_verify(
                    self.publisher, "post-123",
                    "CVE-2026-99999 Test Vulnerability", _INTENDED_CONTENT, ["Vulnerabilities", "CVE"],
                )
        self.assertTrue(result.verified)

    def test_request_failure_never_raises_and_is_distinguishable_from_a_real_defect(self):
        # A verification failure must never be confused with, or crash, an
        # already-successful publish -- see fetch_back_and_verify()'s own
        # docstring.
        import requests as req_lib
        with patch("requests.get", side_effect=req_lib.RequestException("timeout")):
            with patch.object(self.publisher, "_get_access_token", return_value="tok"):
                result = fetch_back_and_verify(
                    self.publisher, "post-123",
                    "Title", _INTENDED_CONTENT, ["Vulnerabilities"],
                )
        self.assertFalse(result.verified)
        self.assertFalse(result.fetched)
        self.assertEqual(result.defects, ("fetch_back_request_failed",))
        self.assertIn("timeout", result.error)

    def test_malformed_live_post_response_never_raises(self):
        # get_post() succeeds at the HTTP layer but returns something that
        # isn't a usable post object (e.g. an unexpected empty/None body) --
        # the comparison step must fail closed to "not evaluated", not
        # propagate an exception into the publish pipeline.
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = None
        with patch("requests.get", return_value=mock_resp):
            with patch.object(self.publisher, "_get_access_token", return_value="tok"):
                result = fetch_back_and_verify(
                    self.publisher, "post-123",
                    "Title", _INTENDED_CONTENT, ["Vulnerabilities"],
                )
        self.assertFalse(result.verified)
        self.assertTrue(result.fetched)
        self.assertEqual(result.defects, ("fetch_back_comparison_failed",))


if __name__ == "__main__":
    unittest.main()
