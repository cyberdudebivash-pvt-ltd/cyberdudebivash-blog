"""
Tests for social_preview_certifier — deterministic CERTIFIED/BLOCKED
verdicts for a report's social-preview metadata contract.
"""

import unittest

from automation.social_preview_certifier import certify_live_html, certify_metadata


class TestCertifyMetadata(unittest.TestCase):
    def _good_kwargs(self, **overrides):
        kwargs = dict(
            image_url="https://blog.cyberdudebivash.in/api/og?title=x&severity=HIGH",
            title="CVE-2026-1234 — Critical RCE in Example Product",
            description="A critical remote code execution vulnerability affecting Example Product versions before 2.1.",
        )
        kwargs.update(overrides)
        return kwargs

    def test_good_metadata_is_certified(self):
        result = certify_metadata(**self._good_kwargs())
        self.assertEqual(result.verdict, "CERTIFIED")
        self.assertEqual(result.reasons, [])

    def test_data_uri_image_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(image_url="data:image/svg+xml;base64,QUJD"))
        self.assertEqual(result.verdict, "BLOCKED")
        self.assertTrue(any("data" in r.lower() for r in result.reasons))

    def test_http_not_https_image_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(image_url="http://blog.cyberdudebivash.in/api/og?x"))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_missing_image_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(image_url=""))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_localhost_image_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(image_url="https://localhost:3000/api/og?x"))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_vercel_preview_image_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(image_url="https://my-branch-abc123.vercel.app/api/og?x"))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_empty_title_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(title=""))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_empty_description_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(description=""))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_oversized_title_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(title="A" * 500))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_wrong_og_type_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(og_type="website"))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_wrong_twitter_card_is_blocked(self):
        result = certify_metadata(**self._good_kwargs(twitter_card="summary"))
        self.assertEqual(result.verdict, "BLOCKED")

    def test_canonical_checks_skipped_when_canonical_url_not_given(self):
        # Blogger doesn't assign a real canonical URL until after publish —
        # certify_metadata must stay CERTIFIED-eligible without one, not
        # treat "unknown yet" as a failure.
        result = certify_metadata(**self._good_kwargs())
        names = [c["name"] for c in result.checks]
        self.assertNotIn("canonical_is_https", names)
        self.assertNotIn("canonical_matches_expected_domain", names)

    def test_canonical_blogspot_leak_is_blocked_when_canonical_given(self):
        result = certify_metadata(**self._good_kwargs(
            canonical_url="https://cyberbivash.blogspot.com/2026/08/x.html",
            expected_domain="cti.cyberdudebivash.in",
        ))
        self.assertEqual(result.verdict, "BLOCKED")
        self.assertTrue(any("blogspot" in r.lower() or "domain" in r.lower() for r in result.reasons))

    def test_canonical_matching_expected_domain_is_certified(self):
        result = certify_metadata(**self._good_kwargs(
            canonical_url="https://cti.cyberdudebivash.in/2026/08/x.html",
            expected_domain="cti.cyberdudebivash.in",
        ))
        self.assertEqual(result.verdict, "CERTIFIED")

    def test_passing_checks_carry_no_failure_looking_detail_text(self):
        # Regression guard: a passing check's detail must be empty, never
        # the failure-description text (caught during manual review — a
        # CERTIFIED result should never look like a wall of failures).
        result = certify_metadata(**self._good_kwargs())
        for check in result.checks:
            if check["passed"]:
                self.assertEqual(check["detail"], "")

    def test_third_party_image_host_flagged_for_dimension_uncertainty(self):
        # A URL not served by this platform's own OG endpoints can't have
        # its actual pixel dimensions certified without a live fetch — this
        # must be visible in the check list, not silently assumed fine.
        result = certify_metadata(**self._good_kwargs(image_url="https://example.com/some-banner.png"))
        names_failed = [c["name"] for c in result.checks if not c["passed"]]
        self.assertIn("image_known_good_dimensions_source", names_failed)


class TestCertifyLiveHtml(unittest.TestCase):
    GOOD_HTML = """
    <html><head>
    <link href='https://cti.cyberdudebivash.in/2026/08/x.html' rel='canonical'/>
    <meta content='CVE-2026-1234 Report' property='og:title'/>
    <meta content='A real per-article description.' property='og:description'/>
    <meta content='https://cti.cyberdudebivash.in/2026/08/x.html' property='og:url'/>
    <meta content='https://lh3.googleusercontent.com/blogger_img_proxy/abc=w1200-h630' property='og:image'/>
    <meta content='summary_large_image' name='twitter:card'/>
    <meta content='https://lh3.googleusercontent.com/blogger_img_proxy/abc=w1200-h630' name='twitter:image'/>
    </head><body>content</body></html>
    """

    def test_good_live_html_is_certified(self):
        result = certify_live_html(self.GOOD_HTML, expected_domain="cti.cyberdudebivash.in")
        self.assertEqual(result.verdict, "CERTIFIED", result.reasons)

    def test_live_data_uri_image_is_blocked(self):
        html = self.GOOD_HTML.replace(
            "https://lh3.googleusercontent.com/blogger_img_proxy/abc=w1200-h630",
            "data:image/svg+xml;base64,QUJD",
        )
        result = certify_live_html(html, expected_domain="cti.cyberdudebivash.in")
        self.assertEqual(result.verdict, "BLOCKED")

    def test_live_missing_og_image_is_blocked(self):
        html = self.GOOD_HTML.replace("<meta content='https://lh3.googleusercontent.com/blogger_img_proxy/abc=w1200-h630' property='og:image'/>", "")
        result = certify_live_html(html, expected_domain="cti.cyberdudebivash.in")
        self.assertEqual(result.verdict, "BLOCKED")

    def test_live_blogspot_leak_in_head_is_blocked(self):
        html = self.GOOD_HTML.replace(
            "</head>",
            "<script>{\"@type\":\"WebSite\",\"url\":\"https://cyberbivash.blogspot.com/\"}</script></head>",
        )
        result = certify_live_html(html, expected_domain="cti.cyberdudebivash.in")
        self.assertEqual(result.verdict, "BLOCKED")
        self.assertTrue(any("blogspot" in r.lower() for r in result.reasons))

    def test_live_wrong_canonical_domain_is_blocked(self):
        html = self.GOOD_HTML.replace(
            "https://cti.cyberdudebivash.in/2026/08/x.html", "https://some-other-site.example/x.html",
        )
        result = certify_live_html(html, expected_domain="cti.cyberdudebivash.in")
        self.assertEqual(result.verdict, "BLOCKED")

    def test_attribute_order_independence(self):
        # Real Blogger markup mixes content-before-name and name-before-content
        # ordering (verified against live-fetched pages) — the parser must
        # not depend on a fixed attribute order the way a naive regex would.
        html = """<html><head>
        <meta property='og:title' content='Reordered attrs test'/>
        <meta content='desc goes first here' property='og:description'/>
        <meta content='https://cti.cyberdudebivash.in/x.html' property='og:url'/>
        <meta content='https://blog.cyberdudebivash.in/api/og?x' property='og:image'/>
        <meta name='twitter:card' content='summary_large_image'/>
        <meta content='https://blog.cyberdudebivash.in/api/og?x' name='twitter:image'/>
        </head><body></body></html>"""
        result = certify_live_html(html, expected_domain="cti.cyberdudebivash.in")
        self.assertEqual(result.verdict, "CERTIFIED", result.reasons)


if __name__ == "__main__":
    unittest.main()
