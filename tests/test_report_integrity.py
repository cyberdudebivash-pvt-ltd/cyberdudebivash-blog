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
from automation.report_integrity import build_report_context


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


if __name__ == "__main__":
    unittest.main()
