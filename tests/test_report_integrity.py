"""RX-P1H adversarial family-classification regression tests.

``report_integrity._family()`` is the single canonical family classifier
(every other module reads ``ReportContext.family`` rather than
re-classifying) and had zero dedicated test coverage before this file,
despite being exactly the kind of boundary logic the founder mandate's
adversarial classification section (Section 24) worries about getting
wrong silently. These tests lock in behavior that already exists in the
code today -- they exist to catch a future regression, not to change
current classification.
"""

from __future__ import annotations

import unittest

from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import PublicationIntegrityError, build_report_context, validate_publication


def _article(**kwargs) -> DiscoveredArticle:
    defaults = dict(
        url="https://example.test/article", title="Untitled",
        summary="", published_at="2026-08-20T00:00:00+00:00",
        content_hash=_compute_hash("https://example.test/article", "Untitled"),
        labels=[], source="global_rss",
    )
    defaults.update(kwargs)
    if "content_hash" not in kwargs:
        defaults["content_hash"] = _compute_hash(defaults["url"], defaults["title"])
    return DiscoveredArticle(**defaults)


class TestRansomwareNewsNeverBecomesARansomwareClaim(unittest.TestCase):
    """Mandate Section 24, example 1: "CISA says ransomware gangs exploit
    Windows flaw" must not become a ransomware victim claim -- ransomware_claim
    is reserved for source=="ransomware_intel" (an actual leak-site record
    with a named victim), never for news reporting that merely mentions the
    word "ransomware"."""

    def test_cisa_advisory_about_ransomware_stays_cisa_advisory(self):
        article = _article(
            title="CISA Says Ransomware Gangs Are Exploiting a Windows Flaw",
            summary="CISA warns that multiple ransomware groups are actively exploiting a Windows vulnerability.",
            labels=["Advisory"], source="cisa_advisory",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "cisa_advisory")
        self.assertNotEqual(context.family, "ransomware_claim")

    def test_generic_news_about_ransomware_activity_becomes_ransomware_reporting_not_a_claim(self):
        article = _article(
            title="Ransomware Gangs Increasingly Target Unpatched VPN Appliances, Researchers Say",
            summary="A new report finds ransomware operators are exploiting unpatched VPN devices for initial access.",
            labels=["Ransomware", "Research"], source="global_rss",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "ransomware_reporting")
        self.assertNotEqual(context.family, "ransomware_claim")

    def test_only_the_real_leak_site_source_produces_a_ransomware_claim(self):
        article = _article(
            url="https://www.ransomware.live/id/test-victim", title="Group Claims New Victim",
            summary="Group has listed Example Corp as a new victim on its leak site.",
            labels=["Ransomware"], source="ransomware_intel",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "ransomware_claim")


class TestPhishingWithoutCVEEvidenceNeverBecomesAVulnerabilityAdvisory(unittest.TestCase):
    """Mandate Section 24, example 2: "New phishing kit abuses OAuth" must
    not become a CVE advisory unless real CVE evidence exists. There is no
    dedicated phishing family in this pipeline yet (RX-P1H scope note --
    see report_contract.py), so the correct, honest classification today is
    the general fallback, not a fabricated vulnerability advisory."""

    def test_phishing_kit_report_with_no_cve_falls_to_general_intelligence(self):
        article = _article(
            title="New Phishing Kit Abuses OAuth Device Code Flow",
            summary="Researchers detail a phishing-as-a-service kit that abuses OAuth device authorization.",
            labels=["Phishing"], source="global_rss",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "general_intelligence")
        self.assertNotEqual(context.family, "cve_advisory")

    def test_phishing_kit_report_that_does_cite_a_real_cve_becomes_cve_advisory(self):
        article = _article(
            title="Phishing Kit Chains CVE-2026-12345 for OAuth Token Theft",
            summary="The kit exploits CVE-2026-12345 in a popular OAuth library to steal session tokens.",
            labels=["Phishing"], source="global_rss", cve_id="CVE-2026-12345",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "cve_advisory")


class TestLeakSiteClaimNeverAssertsAConfirmedIncident(unittest.TestCase):
    """Mandate Section 24, example 3: "Actor claims company on leak site"
    must not become a confirmed incident -- the family is real
    (ransomware_claim), but the exploitation/evidence status must stay
    honestly third-party-claim, never confirmed, regardless of how the
    claim is worded."""

    def test_leak_site_claim_exploitation_status_is_third_party_claim_not_confirmed(self):
        article = _article(
            url="https://www.ransomware.live/id/another-victim", title="Group Claims Example Corp",
            summary="Group has listed Example Corp as a new victim on its leak site.",
            labels=["Ransomware"], source="ransomware_intel",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "ransomware_claim")
        self.assertEqual(context.exploitation_status, "third_party_claim")
        self.assertNotEqual(context.exploitation_status, "confirmed")


class TestZeroDayRoutesAcrossCVEKEVSemanticsCorrectly(unittest.TestCase):
    """Mandate Section 24, example 4: "Vendor patches actively exploited
    zero-day" must route correctly across CVE/KEV semantics -- KEV listing
    is the authoritative, higher-precedence signal (checked first in
    _family()) when present; a plain CVE with no KEV listing stays
    cve_advisory, never silently promoted to KEV."""

    def test_kev_listed_zero_day_becomes_cisa_kev(self):
        article = _article(
            title="Vendor Patches Actively Exploited Zero-Day",
            summary="The vendor released a patch for a vulnerability CISA confirms is actively exploited.",
            labels=["Zero-Day"], source="nvd", cve_id="CVE-2026-99999", kev_listed=True,
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "cisa_kev")

    def test_cve_without_kev_listing_stays_cve_advisory_not_promoted_to_kev(self):
        article = _article(
            title="Vendor Patches a Newly Disclosed Vulnerability",
            summary="The vendor released a patch for a newly disclosed vulnerability with no confirmed exploitation.",
            labels=["Vulnerabilities"], source="nvd", cve_id="CVE-2026-88888", kev_listed=False,
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "cve_advisory")
        self.assertNotEqual(context.family, "cisa_kev")


def _valid_base_html(article: DiscoveredArticle, context, extra: str = "") -> str:
    """Every field validate_publication() requires unconditionally,
    plus enough padding to clear the 3000-char minimum-length gate --
    isolates a test to only the specific check it's exercising."""
    padding = "<p>Padding sentence to satisfy the minimum production length gate.</p>" * 40
    return (
        f"<div>{context.report_id} {context.source_record_hash} {article.url} "
        f"{context.generated_at} {context.review_status} {context.certification_status}</div>"
        f"{padding}{extra}"
    )


class TestExploitationAssertionConsistency(unittest.TestCase):
    """RX-P1M: report_integrity.py's own _CONFIRMED_EXPLOITATION_PATTERNS
    (used to classify the source article) had drifted from the separate,
    narrower exact-phrase list validate_publication() used to reject an
    unverified rendered assertion -- a plausible LLM paraphrase
    ("exploitation has been observed") of the exact same fabricated claim
    would have passed the render-side gate while the classifier's own
    patterns would have caught it instantly. Fixed by reusing the same
    pattern list on the render side, additively, with a negation-lookback
    guard for this pipeline's own genuinely honest, hedged non-assertions
    of the same words (found as a real false positive against the legacy
    template's own "No confirmed exploitation evidence is available" text
    while building this exact check)."""

    def _unconfirmed_cve_context(self):
        article = _article(
            title="CVE-2026-77777 test vulnerability", summary="test",
            labels=["Vulnerabilities"], source="nvd", cve_id="CVE-2026-77777", kev_listed=False,
        )
        context = build_report_context(article)
        self.assertNotEqual(context.exploitation_status, "confirmed")
        return article, context

    def test_paraphrased_observed_exploitation_is_blocked_not_only_the_exact_legacy_phrases(self):
        # The exact gap this round found: "exploitation has been observed"
        # is a real _CONFIRMED_EXPLOITATION_PATTERNS match, but was never
        # one of the 4 hand-typed exact phrases the render-side gate
        # checked before this fix.
        article, context = self._unconfirmed_cve_context()
        html = _valid_base_html(article, context, "<p>Exploitation has been observed in limited campaigns.</p>")
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, html)
        self.assertTrue(any("unverified exploitation assertion" in issue for issue in caught.exception.issues))

    def test_original_exact_phrases_still_blocked(self):
        # Backward-compatibility regression guard: the original 4-phrase
        # list must keep working exactly as before -- additive fix, never
        # a replacement.
        article, context = self._unconfirmed_cve_context()
        html = _valid_base_html(article, context, "<p>Analysts assess actively exploited in the wild currently.</p>")
        with self.assertRaises(PublicationIntegrityError):
            validate_publication(article, context, html)

    def test_honest_negated_non_assertion_is_never_blocked(self):
        # The real false positive found building this check: a genuinely
        # honest, hedged sentence explicitly denying exploitation must
        # never be treated as the assertion it denies.
        article, context = self._unconfirmed_cve_context()
        html = _valid_base_html(
            article, context,
            "<p>No confirmed exploitation evidence is available at time of publication.</p>",
        )
        validate_publication(article, context, html)  # must not raise

    def test_confirmed_exploitation_status_permits_the_same_language(self):
        # The gate is about consistency with THIS article's own classified
        # status, not a blanket ban on the phrase -- a genuinely
        # KEV-listed/confirmed article may honestly use this language.
        article = _article(
            title="CVE-2026-77778 confirmed", summary="test", labels=["Vulnerabilities"],
            source="cisa_kev", cve_id="CVE-2026-77778", kev_listed=True,
        )
        context = build_report_context(article)
        self.assertEqual(context.exploitation_status, "confirmed")
        html = _valid_base_html(article, context, "<p>Confirmed exploitation has been observed in the wild.</p>")
        validate_publication(article, context, html)  # must not raise


class TestRansomwareClaimConfirmedBreachGate(unittest.TestCase):
    """RX-P1M, mandate's own named cross-section example: a ransomware
    leak-site listing is an unverified, third-party claim in this
    pipeline's evidence model -- rendered content must never assert the
    breach/compromise/data theft as confirmed."""

    def _ransomware_claim_context(self):
        article = _article(
            url="https://www.ransomware.live/id/gate-test", title="Group Claims Victim",
            summary="test", labels=["Ransomware"], source="ransomware_intel",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "ransomware_claim")
        return article, context

    def test_declarative_confirmed_breach_assertion_is_blocked(self):
        article, context = self._ransomware_claim_context()
        html = _valid_base_html(article, context, "<p>This report confirms the breach affecting the organization.</p>")
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, html)
        self.assertTrue(any("unverified confirmed-breach assertion" in issue for issue in caught.exception.issues))

    def test_data_theft_confirmed_language_is_blocked(self):
        article, context = self._ransomware_claim_context()
        html = _valid_base_html(article, context, "<p>Data was confirmed stolen from the victim's network.</p>")
        with self.assertRaises(PublicationIntegrityError):
            validate_publication(article, context, html)

    def test_universal_decision_boilerplate_is_never_a_false_positive(self):
        # The exact false positive found while building this check: the
        # universal Executive Summary "Decision:" line already contains
        # "...confirmed compromise..." as cautionary, nominal framing
        # (one of several hypothetical outcomes to validate, not an
        # assertion) -- must never trigger this gate.
        article, context = self._ransomware_claim_context()
        html = _valid_base_html(
            article, context,
            "<p>Validate relevance and exposure using the cited source and internal evidence before "
            "treating this record as an incident, confirmed compromise, or customer-specific finding.</p>",
        )
        validate_publication(article, context, html)  # must not raise

    def test_hedged_non_assertion_is_never_a_false_positive(self):
        article, context = self._ransomware_claim_context()
        html = _valid_base_html(
            article, context,
            "<p>The breach has not been confirmed by any independent source at this time.</p>",
        )
        validate_publication(article, context, html)  # must not raise

    def test_gate_is_scoped_to_ransomware_claim_only(self):
        # A CVE report asserting a confirmed breach in some unrelated
        # context is a different family's concern (or simply not
        # applicable) -- this gate must not fire outside ransomware_claim.
        article = _article(
            title="CVE-2026-77779 test", summary="test", labels=["Vulnerabilities"],
            source="nvd", cve_id="CVE-2026-77779", kev_listed=True,
        )
        context = build_report_context(article)
        self.assertNotEqual(context.family, "ransomware_claim")
        html = _valid_base_html(article, context, "<p>This report confirms the breach affecting the organization.</p>")
        validate_publication(article, context, html)  # must not raise -- this gate is ransomware_claim-only


class TestQuantitativeClaimGroundingGate(unittest.TestCase):
    """RX-P1M, generalizes the run #8459 incident fix (the reactive 4-item
    _UNSUPPORTED_COMMERCIAL_PATTERNS denylist, docs/audits/blogger-
    syndication-run-8459-incident-review-2026-08-20.md) into a systemic
    mechanism: a specific number in a high-impact quantitative context
    must be traceable to the source article's own text, not only the
    small set of exact strings already caught by hand. Scoped to
    body_content (the report's own narrative), never the full assembled
    html -- the real false positive found building this check was
    internal_linker.py's "Related Intelligence Reports" widget, which
    legitimately embeds OTHER real articles' headlines carrying THEIR
    OWN real numbers, appended to html outside body_content."""

    def _cve_context(self, summary="test"):
        article = _article(
            title="CVE-2026-88888 disclosure", summary=summary,
            labels=["Vulnerabilities"], source="nvd", cve_id="CVE-2026-88888", kev_listed=False,
        )
        context = build_report_context(article)
        return article, context

    def test_fabricated_number_not_in_source_text_is_blocked(self):
        article, context = self._cve_context(summary="A vulnerability disclosure with no victim counts.")
        body = "<p>Approximately 2,847 victims were affected according to internal analysis.</p>"
        html = _valid_base_html(article, context, body)
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, html, body_content=body)
        self.assertTrue(any("unsupported quantitative claim" in issue for issue in caught.exception.issues))

    def test_number_grounded_in_source_text_is_never_blocked(self):
        article, context = self._cve_context(
            summary="The disclosure affects approximately 1,200 organizations across multiple sectors.",
        )
        body = "<p>Impact analysis indicates 1,200 organizations were affected based on the source disclosure.</p>"
        html = _valid_base_html(article, context, body)
        validate_publication(article, context, html, body_content=body)  # must not raise

    def test_comma_formatting_does_not_defeat_grounding(self):
        # _grounded_numbers() strips commas specifically so a genuinely
        # source-grounded number is never flagged merely because it was
        # reformatted at render time ("2400" in the source vs. "2,400"
        # rendered).
        article, context = self._cve_context(
            summary="A dataset of 2400 records was referenced in the disclosure.",
        )
        body = "<p>The disclosure references 2,400 records in total.</p>"
        html = _valid_base_html(article, context, body)
        validate_publication(article, context, html, body_content=body)  # must not raise

    def test_number_only_in_related_content_widget_outside_body_content_is_never_blocked(self):
        # The real false positive found building this check:
        # internal_linker.py's "Related Intelligence Reports" widget is
        # appended to the final html OUTSIDE body_content and legitimately
        # carries other real articles' own numbers -- must never be
        # scanned by this gate.
        article, context = self._cve_context(summary="A vulnerability disclosure with no victim counts.")
        body = "<p>This report contains no victim-count claims of its own.</p>"
        related_widget = (
            '<div><h4>Related Intelligence Reports</h4><ul>'
            '<li><a href="https://example.test/other">144,520 Accounts Exposed in Unrelated Breach</a></li>'
            '</ul></div>'
        )
        html = _valid_base_html(article, context, body) + related_widget
        validate_publication(article, context, html, body_content=body)  # must not raise

    def test_body_content_not_provided_skips_the_check(self):
        # Safe-default precedent already established for product_tier/
        # contradictions in this same function: a caller that hasn't
        # computed body_content keeps its current behavior exactly,
        # rather than being newly gated by a check it never opted into.
        article, context = self._cve_context(summary="A vulnerability disclosure with no victim counts.")
        body = "<p>Approximately 9,999 victims were affected according to internal analysis.</p>"
        html = _valid_base_html(article, context, body)
        validate_publication(article, context, html)  # must not raise -- body_content omitted


if __name__ == "__main__":
    unittest.main()
