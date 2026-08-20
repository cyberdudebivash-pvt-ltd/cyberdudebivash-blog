"""Tests for automation.analytical_depth_gate -- the Phase D/G product-tier
verdict. The central claim under test: a report whose narrative wasn't
LLM-authored (or whose LLM-authored narrative produced zero validated Key
Judgements) cannot honestly reach PREMIUM_LONG_FORM, while the mechanism
itself is proven capable of reaching PREMIUM_LONG_FORM once Key Judgements
(RX-P1F) and every other mandatory section genuinely resolve."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import build_report_context
from automation.report_contract import Applicability, SectionResolution, SectionState
from automation.analytical_depth_gate import (
    FLASH,
    PREMIUM_LONG_FORM,
    TACTICAL,
    evaluate_product_tier,
)


def _cve_article(**kwargs) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-75912",
        title="CVE-2026-75912", summary="test",
        published_at="2026-08-18T16:18:23+00:00",
        content_hash=_compute_hash("https://nvd.nist.gov/vuln/detail/CVE-2026-75912", "CVE-2026-75912"),
        labels=["Vulnerabilities"], source="nvd", cve_id="CVE-2026-75912",
        cvss_score=7.4, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", cwe_ids=["CWE-88"],
    )
    defaults.update(kwargs)
    return DiscoveredArticle(**defaults)


class TestCurrentRealityCannotReachPremium(unittest.TestCase):
    """The load-bearing claim of this whole gate: today's real content,
    from either fallback path, cannot honestly earn PREMIUM_LONG_FORM."""

    def test_reportx_composer_output_is_capped_at_tactical(self):
        article = _cve_article()
        context = build_report_context(article)
        verdict = evaluate_product_tier(article, context, content_source="reportx_composer",
                                         detection_status="syntax_validated_experimental")
        self.assertNotEqual(verdict.tier, PREMIUM_LONG_FORM)
        self.assertFalse(verdict.llm_authored)

    def test_legacy_template_output_is_capped_at_tactical(self):
        article = _cve_article()
        context = build_report_context(article)
        verdict = evaluate_product_tier(article, context, content_source="template")
        self.assertNotEqual(verdict.tier, PREMIUM_LONG_FORM)

    def test_llm_authored_cve_report_still_capped_because_key_judgements_are_withheld(self):
        # A real LLM success (content_source in LLM_AUTHORED_SOURCES)
        # alone cannot reach premium: Key Judgements (Section 3) is
        # resolved dynamically from key_judgement_count (RX-P1F), which
        # this call doesn't pass -- defaults to 0, so it resolves WITHHELD
        # regardless of which path authored the prose body. (Intelligence
        # Gaps/Section 21 no longer withheld as of RX-P1F -- see
        # test_report_contract.py -- so Key Judgements alone is what keeps
        # this capped now.)
        article = _cve_article()
        context = build_report_context(article)
        verdict = evaluate_product_tier(article, context, content_source="groq",
                                         detection_status="syntax_validated_experimental")
        self.assertNotEqual(verdict.tier, PREMIUM_LONG_FORM)
        self.assertTrue(verdict.llm_authored)
        self.assertIn("key_judgements", verdict.mandatory_withheld)

    def test_llm_authored_ransomware_report_still_capped_for_the_same_reason(self):
        article = DiscoveredArticle(
            url="https://www.ransomware.live/id/test", title="Group Claims Victim",
            summary="test", published_at="2026-08-18T22:51:57+00:00",
            content_hash=_compute_hash("https://www.ransomware.live/id/test", "Group Claims Victim"),
            labels=["Ransomware"], source="ransomware_intel",
            ransomware_group="SilentRansomGroup", ransomware_sector="Professional Services", ransomware_country="US",
        )
        context = build_report_context(article)
        verdict = evaluate_product_tier(article, context, content_source="anthropic")
        self.assertNotEqual(verdict.tier, PREMIUM_LONG_FORM)
        self.assertIn("key_judgements", verdict.mandatory_withheld)


class TestMechanismCanReachPremiumWhenConditionsAreGenuinelyMet(unittest.TestCase):
    """Proves this isn't permanently stuck closed by construction -- once
    every mandatory section genuinely resolves and corroboration exists,
    the gate opens. Uses a mocked section-state set (not real families,
    since no real family clears every mandatory section today) to isolate
    exactly what evaluate_product_tier() itself does with a clean input."""

    def _all_complete_resolutions(self, context):
        from automation.report_contract import ALL_SECTIONS
        return [
            SectionResolution(section=s, applicability=Applicability.MANDATORY, state=SectionState.COMPLETE)
            for s in ALL_SECTIONS
        ]

    def test_llm_authored_plus_complete_sections_plus_corroboration_reaches_premium(self):
        tmpdir = tempfile.mkdtemp()
        state_path = os.path.join(tmpdir, "published_posts.json")
        with open(state_path, "w") as f:
            json.dump({"total_published": 1, "posts": {
                "hash1": {
                    "source_title": "Independent outlet covered this CVE",
                    "blogger_url": "https://x/independent",
                    "cves": ["CVE-2026-75912"], "labels": ["Vulnerabilities"],
                    "source": "global_rss", "source_publisher": "BleepingComputer",
                    "published_at": "2026-08-17",
                },
            }}, f)

        article = _cve_article(source="nvd", source_publisher=None)
        context = build_report_context(article)
        with patch("automation.analytical_depth_gate.evaluate_section_states",
                   return_value=self._all_complete_resolutions(context)):
            verdict = evaluate_product_tier(article, context, content_source="groq", state_file=state_path)

        self.assertEqual(verdict.tier, PREMIUM_LONG_FORM)
        self.assertTrue(verdict.llm_authored)
        self.assertTrue(verdict.has_independent_corroboration)

    def test_llm_authored_plus_complete_sections_but_no_corroboration_stays_tactical(self):
        tmpdir = tempfile.mkdtemp()
        state_path = os.path.join(tmpdir, "published_posts.json")
        with open(state_path, "w") as f:
            json.dump({"total_published": 0, "posts": {}}, f)

        article = _cve_article()
        context = build_report_context(article)
        with patch("automation.analytical_depth_gate.evaluate_section_states",
                   return_value=self._all_complete_resolutions(context)):
            verdict = evaluate_product_tier(article, context, content_source="groq", state_file=state_path)

        self.assertEqual(verdict.tier, TACTICAL)
        self.assertFalse(verdict.has_independent_corroboration)

    def test_omitting_state_file_never_fabricates_corroboration(self):
        # Conservative degradation: without a state_file, the gate must
        # not assume corroboration exists just because sections are complete.
        article = _cve_article()
        context = build_report_context(article)
        with patch("automation.analytical_depth_gate.evaluate_section_states",
                   return_value=self._all_complete_resolutions(context)):
            verdict = evaluate_product_tier(article, context, content_source="groq", state_file=None)

        self.assertEqual(verdict.tier, PREMIUM_LONG_FORM)
        self.assertIsNone(verdict.has_independent_corroboration)


class TestUnknownFamilyNeverGuessesEligibility(unittest.TestCase):
    def test_family_with_no_matrix_is_capped_at_tactical_even_with_llm_content(self):
        # RX-P1H: breach_notice (this test's original fixture) now has a
        # real, reconciled matrix -- see
        # TestBreachNoticeCanNowReachPremiumLongForm below for its new,
        # correct behavior. general_intelligence is the family that remains
        # deliberately unmapped (report_contract.py's own comment on why),
        # so it is the one that still proves this gate's "no matrix -> never
        # guess eligibility" discipline.
        article = DiscoveredArticle(
            url="https://example.test/roundup", title="Weekly Security News Roundup",
            summary="test", published_at="2026-08-18T00:00:00+00:00",
            content_hash=_compute_hash("https://example.test/roundup", "Weekly Security News Roundup"),
            labels=["News"], source="global_rss",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "general_intelligence")
        verdict = evaluate_product_tier(article, context, content_source="groq")
        self.assertEqual(verdict.tier, TACTICAL)


class TestBreachNoticeCanNowReachPremiumLongForm(unittest.TestCase):
    def test_breach_notice_with_llm_content_and_all_mandatory_sections_resolved_reaches_premium(self):
        # Before RX-P1H, breach_notice had no matrix at all -- this exact
        # article shape (LLM-authored, no CVE) was hard-capped at TACTICAL
        # unconditionally (see the renamed test above). This is the real
        # before/after proof that the new matrix, role routing, and
        # detection-status fix together let the gate honestly yield a higher
        # tier once the evidence supports it, without hardcoding the tier
        # or manipulating section states.
        article = DiscoveredArticle(
            url="https://example.test/breach", title="Breach Record",
            summary="test", published_at="2026-08-18T00:00:00+00:00",
            content_hash=_compute_hash("https://example.test/breach", "Breach Record"),
            labels=["Data Breach"], source="breach_intel",
        )
        context = build_report_context(article)
        self.assertEqual(context.family, "breach_notice")
        verdict = evaluate_product_tier(
            article, context, content_source="groq", detection_status="not_applicable", key_judgement_count=3,
        )
        self.assertEqual(verdict.tier, PREMIUM_LONG_FORM)
        self.assertEqual(verdict.mandatory_withheld, ())


if __name__ == "__main__":
    unittest.main()
