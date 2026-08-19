"""Tests for automation.report_contract -- the Phase A/C 24-section
applicability matrix and per-article section-state resolution."""

from __future__ import annotations

import unittest

from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import build_report_context
from automation.report_contract import (
    Applicability,
    SECTION_2_EXECUTIVE_SUMMARY,
    SECTION_3_KEY_JUDGEMENTS,
    SECTION_5_VERIFIED_FACTS,
    SECTION_9_EXPOSURE_ASSET_RELEVANCE,
    SECTION_10_ATTACK_PATH,
    SECTION_11_ATTACK_MAPPING,
    SECTION_12_ACTOR_CAMPAIGN_CONTEXT,
    SECTION_13_HISTORICAL_CORRELATION,
    SECTION_15_DETECTION_ENGINEERING,
    SECTION_18_SECTOR_GEOGRAPHIC_IMPACT,
    SECTION_21_INTELLIGENCE_GAPS,
    SectionState,
    evaluate_section_states,
    get_applicability,
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


def _ransomware_article(**kwargs) -> DiscoveredArticle:
    defaults = dict(
        url="https://www.ransomware.live/id/test", title="Group Claims Victim",
        summary="test", published_at="2026-08-18T22:51:57+00:00",
        content_hash=_compute_hash("https://www.ransomware.live/id/test", "Group Claims Victim"),
        labels=["Ransomware"], source="ransomware_intel",
    )
    defaults.update(kwargs)
    return DiscoveredArticle(**defaults)


def _state_of(resolutions, section) -> SectionState:
    return next(r.state for r in resolutions if r.section == section)


class TestApplicabilityDefaults(unittest.TestCase):
    def test_unknown_family_defaults_to_optional_never_mandatory_or_na(self):
        # A family with no reconciled matrix (breach_notice, ai_security,
        # general_intelligence today) must not silently gate on sections
        # never actually analyzed for it, nor silently hide them either.
        result = get_applicability("breach_notice", SECTION_2_EXECUTIVE_SUMMARY)
        self.assertEqual(result, Applicability.OPTIONAL)


class TestCveArticleSectionStates(unittest.TestCase):
    def test_key_judgements_always_withheld_today(self):
        # No structured analyst-judgement extraction exists anywhere in
        # this pipeline -- must never claim otherwise.
        article = _cve_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_3_KEY_JUDGEMENTS), SectionState.WITHHELD_INSUFFICIENT_EVIDENCE)

    def test_verified_facts_complete_when_cwe_present(self):
        # Real CVE-2026-75912 data (this session's uploaded report 6): has
        # a full CVSS vector AND a CWE -- Verified Facts should be COMPLETE.
        article = _cve_article(cwe_ids=["CWE-88"])
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_5_VERIFIED_FACTS), SectionState.COMPLETE)

    def test_verified_facts_partial_when_cwe_missing(self):
        # Real CVE-2026-60698 data (this session's uploaded report 3): a
        # full CVSS vector but NO CWE at all in the source record.
        article = _cve_article(cve_id="CVE-2026-60698", cwe_ids=None,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_5_VERIFIED_FACTS), SectionState.PARTIAL_EVIDENCE)

    def test_actor_campaign_context_not_applicable_for_cve(self):
        article = _cve_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_12_ACTOR_CAMPAIGN_CONTEXT), SectionState.NOT_APPLICABLE)

    def test_detection_engineering_reflects_real_status_not_capability(self):
        # Detection Engineering is IMPLEMENTED as a capability, but this
        # specific article's evidence didn't clear the gate -- must resolve
        # to withheld, not COMPLETE merely because the section exists.
        article = _cve_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context, detection_status="withheld_insufficient_evidence")
        self.assertEqual(_state_of(resolutions, SECTION_15_DETECTION_ENGINEERING), SectionState.WITHHELD_INSUFFICIENT_EVIDENCE)

    def test_detection_engineering_complete_when_real_rule_generated(self):
        article = _cve_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context, detection_status="syntax_validated_experimental")
        self.assertEqual(_state_of(resolutions, SECTION_15_DETECTION_ENGINEERING), SectionState.COMPLETE)

    def test_attack_mapping_tracks_the_same_detection_gate(self):
        article = _cve_article()
        context = build_report_context(article)
        withheld = evaluate_section_states(article, context, detection_status="withheld_insufficient_evidence")
        real = evaluate_section_states(article, context, detection_status="syntax_validated_experimental")
        self.assertEqual(_state_of(withheld, SECTION_11_ATTACK_MAPPING), SectionState.WITHHELD_INSUFFICIENT_EVIDENCE)
        self.assertEqual(_state_of(real, SECTION_11_ATTACK_MAPPING), SectionState.PARTIAL_EVIDENCE)

    def test_historical_correlation_is_always_partial_never_complete_or_withheld(self):
        # The classification mechanism is real and unconditional, but this
        # function cannot confirm a specific match without the state file.
        article = _cve_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_13_HISTORICAL_CORRELATION), SectionState.PARTIAL_EVIDENCE)


class TestRansomwareArticleSectionStates(unittest.TestCase):
    def test_attack_path_and_technical_analysis_are_not_applicable(self):
        # Founder mandate, verbatim: "Do not invent an intrusion chain" for
        # a ransomware claim.
        article = _ransomware_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_10_ATTACK_PATH), SectionState.NOT_APPLICABLE)
        self.assertEqual(_state_of(resolutions, SECTION_9_EXPOSURE_ASSET_RELEVANCE), SectionState.NOT_APPLICABLE)

    def test_actor_context_partial_when_real_group_present(self):
        article = _ransomware_article(ransomware_group="SilentRansomGroup")
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_12_ACTOR_CAMPAIGN_CONTEXT), SectionState.PARTIAL_EVIDENCE)

    def test_actor_context_withheld_for_unknown_group_placeholder(self):
        # PHASE-1-DATA-MODEL-2026-08-19's adversarial finding applies here
        # too: "Unknown Group" must not earn partial credit as if it were
        # a real, named actor.
        article = _ransomware_article(ransomware_group="Unknown Group")
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_12_ACTOR_CAMPAIGN_CONTEXT), SectionState.WITHHELD_INSUFFICIENT_EVIDENCE)

    def test_sector_impact_partial_when_sector_or_country_present(self):
        article = _ransomware_article(ransomware_sector="Professional Services")
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_18_SECTOR_GEOGRAPHIC_IMPACT), SectionState.PARTIAL_EVIDENCE)

    def test_sector_impact_withheld_when_neither_present(self):
        article = _ransomware_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_18_SECTOR_GEOGRAPHIC_IMPACT), SectionState.WITHHELD_INSUFFICIENT_EVIDENCE)

    def test_intelligence_gaps_is_partial_evidence_not_withheld(self):
        # RX-P1F: pipeline_composer.compose_report() now computes a real
        # (if minimal) intelligence_gaps list unconditionally for every
        # article (Round 2) -- the same "mechanism is real, article-
        # independent, not yet a rich per-article analysis" treatment
        # already established for Section 13 (Historical Correlation).
        # No longer honestly WITHHELD_INSUFFICIENT_EVIDENCE, which would
        # now be UNDERSTATING a real, if minimal, capability.
        article = _ransomware_article()
        context = build_report_context(article)
        resolutions = evaluate_section_states(article, context)
        self.assertEqual(_state_of(resolutions, SECTION_21_INTELLIGENCE_GAPS), SectionState.PARTIAL_EVIDENCE)


if __name__ == "__main__":
    unittest.main()
