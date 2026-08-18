"""Tests for sentinel_engine.reportx.pipeline_composer -- the live-pipeline
composer that replaces automation.authority_transformer's
_legacy_template_enhance() boilerplate with a real, evidence-graph-backed,
commercial-readiness-gated report.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from automation.config import Config
from automation.content_discovery import DiscoveredArticle

from sentinel_engine.reportx.human_review import CertificationState
from sentinel_engine.reportx.pipeline_composer import compose_report
from sentinel_engine.reportx.tier_downgrade import CORRECTNESS_CONTROLS

CONFIG = Config()


def _cve_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
        title="CVE-2026-99999 test vulnerability",
        summary="A test vulnerability allows remote code execution via crafted OS command injection in a "
                "web-facing administrative endpoint.",
        published_at="2026-08-17T11:16:44Z", content_hash="deadbeef", labels=["Vulnerabilities"], source="nvd",
        cve_id="CVE-2026-99999", cvss_score=9.1, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-78"], kev_listed=False,
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _ransomware_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://www.ransomware.live/id/test", title="Acme Test Corp",
        summary="qilin has listed Acme Test Corp as a new victim on its leak site.",
        published_at="2026-08-18T00:00:00Z", content_hash="cafef00d",
        labels=["Ransomware", "qilin"], source="ransomware_intel",
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _general_intelligence_article(**overrides) -> DiscoveredArticle:
    """Shape of the real, live-published JWR PhaaS report (family=
    general_intelligence -- no CVE, no ransomware/AI-security keyword, not
    KEV/breach/CISA-sourced): a phishing/PhaaS write-up ingested via RSS."""
    defaults = dict(
        url="https://example.test/phaas-platform-discovered", title="New Phishing-as-a-Service Platform Discovered",
        summary="A phishing-as-a-service kit streams stolen credentials to operators over WebSockets in real time.",
        published_at="2026-08-18T09:00:00Z", content_hash="phaas1234",
        labels=["Phishing", "Threat Intelligence"], source="global_rss",
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


class TestComposeReportProducesAGateCheckedResult:
    def test_cve_article_composes_and_gates_cleanly(self):
        result = compose_report(_cve_article(), CONFIG)
        assert result.total_count == 23
        assert result.pass_count >= 15  # every correctness/traceability row, at minimum
        assert result.downgrade.achieved_tier != CertificationState.PUBLIC_REFERENCE_DRAFT

    def test_all_correctness_controls_pass_for_clean_evidence(self):
        result = compose_report(_cve_article(), CONFIG)
        by_id = {r.control_id: r for r in result.control_results}
        for control_id in CORRECTNESS_CONTROLS:
            if by_id[control_id].status == "BLOCKED":
                continue  # genuinely-absent optional input (e.g. no actor-context research attempted)
            assert by_id[control_id].status == "PASS", f"{control_id}: {by_id[control_id].failures}"

    def test_ransomware_article_also_composes_and_gates_cleanly(self):
        result = compose_report(_ransomware_article(), CONFIG)
        by_id = {r.control_id: r for r in result.control_results}
        assert by_id["source_provenance"].status == "PASS"
        assert by_id["evidence_hash"].status == "PASS"
        assert by_id["cross_section_consistency"].status == "PASS"

    def test_kev_listed_article_never_asserts_confirmed_exploitation_beyond_evidence(self):
        result = compose_report(_cve_article(source="cisa_kev", kev_listed=True), CONFIG)
        by_id = {r.control_id: r for r in result.control_results}
        assert by_id["cross_source_corroboration"].status == "PASS"


class TestNoRepeatedBoilerplate:
    """The direct fix for REPORTX-LEGACY-PIPELINE-AUDIT.md's Finding 1/2:
    two DIFFERENT articles must not compose to identical analytical
    prose."""

    def test_two_different_cves_produce_different_technical_prose(self):
        article_a = _cve_article(cve_id="CVE-2026-11111", summary="A SQL injection flaw in the login form.")
        article_b = _cve_article(cve_id="CVE-2026-22222", summary="A path traversal flaw in the file download handler.")
        result_a = compose_report(article_a, CONFIG)
        result_b = compose_report(article_b, CONFIG)
        assert result_a.html != result_b.html
        assert "SQL injection" in result_a.html
        assert "path traversal" in result_b.html.lower()

    def test_role_decisions_reflect_this_articles_own_evidence_not_a_fixed_sentence(self):
        cve_result = compose_report(_cve_article(), CONFIG)
        ransomware_result = compose_report(_ransomware_article(), CONFIG)
        assert "Role-Based Decisions" in cve_result.html
        assert "Role-Based Decisions" in ransomware_result.html
        # CVE gets Vulnerability Manager + SOC Manager; ransomware gets
        # IR Manager only (no CVE/patch dimension) -- the role SETS differ.
        # Correct capitalization only (COMMERCIAL-QUALITY-2026-08-18) -- the
        # mangled "Ir Manager" str.title() produced must never appear again.
        assert "IR Manager" in ransomware_result.html
        assert "Ir Manager" not in ransomware_result.html and "Ir Manager" not in cve_result.html
        assert "IR Manager" not in cve_result.html
        assert "Vulnerability Manager" not in ransomware_result.html


class TestGovernedWithholding:
    def test_no_sigma_producing_class_withholds_rather_than_invents(self):
        # A ransomware victim-claim article has no product-specific
        # telemetry -- the detection package must withhold, not fabricate.
        result = compose_report(_ransomware_article(), CONFIG)
        by_id = {r.control_id: r for r in result.control_results}
        assert by_id["detection_evidence_discipline"].status == "PASS"
        assert not result.bundle.detection_rules[0].body
        assert len(result.bundle.detection_rules) == 1


class TestMultiFormatDetectionRules:
    """report_renderer.py's _detection_package() now generates Sentinel
    KQL alongside Sigma for the same evidence-gated vulnerability classes
    (RX-PR2 follow-through). compose_report() must surface both as
    separate, independently-labeled DetectionRule entries, not silently
    drop one -- and the detection_evidence_discipline control must still
    gate them both against the exact same evidence basis."""

    def test_command_injection_article_yields_one_rule_per_real_format(self):
        result = compose_report(_cve_article(), CONFIG)  # default summary is a web-facing command-injection CVE
        formats = {r.format for r in result.bundle.detection_rules}
        assert formats == {"sigma", "kql"}
        assert len(result.bundle.detection_rules) == 2

    def test_technique_id_is_a_bare_id_not_the_full_mapping_sentence(self):
        # COMMERCIAL-QUALITY-2026-08-18: DetectionRule.technique_id used to
        # hold the entire descriptive mapping sentence ("Execution ->
        # Command and Scripting Interpreter (T1059), conditional on
        # observed child-process execution."), not the bare ID it's typed
        # and named for -- bundle_io.py serializes it as a structured field,
        # and intelligence_validation.py's scorer already had to work
        # around this exact shape.
        result = compose_report(_cve_article(), CONFIG)
        technique_ids = {r.technique_id for r in result.bundle.detection_rules}
        assert technique_ids == {"T1059"}

    def test_both_format_rules_share_the_same_validation_state(self):
        result = compose_report(_cve_article(), CONFIG)
        states = {r.validation_state for r in result.bundle.detection_rules}
        assert len(states) == 1  # one evidence basis, one state, regardless of format count

    def test_detection_evidence_discipline_still_passes_with_two_rules(self):
        result = compose_report(_cve_article(), CONFIG)
        by_id = {r.control_id: r for r in result.control_results}
        assert by_id["detection_evidence_discipline"].status == "PASS"

    def test_kql_body_is_present_in_the_rendered_html(self):
        result = compose_report(_cve_article(), CONFIG)
        assert "SENTINEL KQL" in result.html


class TestFailClosedDowngrade:
    def test_routine_alert_never_reaches_premium_tier_it_did_not_earn(self):
        result = compose_report(_cve_article(), CONFIG, requested_tier=CertificationState.PREMIUM_READY_PENDING_HUMAN)
        assert result.downgrade.achieved_tier != CertificationState.PREMIUM_READY_PENDING_HUMAN
        assert result.downgrade.was_downgraded


class TestRoleRoutingDoesNotMisapplyVulnerabilityManagement:
    """P0 fix: Vulnerability Manager guidance requires a
    real patch/exploitation dimension. Before this fix every family --
    including phishing/PhaaS reporting and ransomware victim-claims, both
    with no CVE anywhere in their evidence -- got this decision
    unconditionally. Verified live against two real published reports: JWR
    PhaaS (family=general_intelligence) and CVE-2026-75105 (whose live
    ransomware-adjacent role text read as mechanically-generated boilerplate
    with nothing real to track against, COMMERCIAL-QUALITY-2026-08-18)."""

    def test_cve_article_still_gets_vulnerability_manager(self):
        result = compose_report(_cve_article(), CONFIG)
        assert "Vulnerability Manager" in result.html

    def test_ransomware_claim_no_longer_gets_vulnerability_manager(self):
        # A leak-site victim claim has no CVE, no patch, and no
        # exploitation-status dimension -- it is not a vulnerability-
        # management concern. IR Manager (below) already covers this
        # family with real, evidence-scoped guidance.
        result = compose_report(_ransomware_article(), CONFIG)
        assert result.context.family == "ransomware_claim"
        assert "Vulnerability Manager" not in result.html
        assert "IR Manager" in result.html

    def test_vulnerability_manager_decision_is_grammatical_for_every_exploitation_status(self):
        # Reproduces the exact live defect on CVE-2026-75105
        # (kev_listed=False): the old "...severity commensurate with
        # {exploitation_label.lower()}." template produced broken English
        # ("severity commensurate with not confirmed by available evidence;
        # not in verified kev snapshot.") because exploitation_label is a
        # standalone display phrase, not something written to complete that
        # clause grammatically.
        result = compose_report(_cve_article(kev_listed=False), CONFIG)
        assert "severity commensurate with" not in result.html
        assert "Exploitation status: Not confirmed by available evidence; not in verified KEV snapshot." in result.html
        assert "Patch status:" in result.html

    def test_general_intelligence_article_does_not_get_vulnerability_manager(self):
        result = compose_report(_general_intelligence_article(), CONFIG)
        assert result.context.family == "general_intelligence"
        assert "Vulnerability Manager" not in result.html

    def test_general_intelligence_article_omits_the_role_section_entirely_rather_than_leaving_it_empty(self):
        # A heading with nothing under it reads as broken, not honest --
        # the whole "Role-Based Decisions" section must be absent, not
        # merely empty, when this family has no grounded role guidance.
        result = compose_report(_general_intelligence_article(), CONFIG)
        assert "Role-Based Decisions" not in result.html


class TestTwoAxisReliabilityInTheRenderedReport:
    """COMMERCIAL-QUALITY-2026-08-18: end-to-end proof that the real,
    independent 2-axis Admiralty model (not the old blended "A/B —
    Reliable" line) and the real, known RSS publisher (not the generic
    "global_rss" connector name) actually reach the rendered HTML -- not
    just the underlying helper functions in isolation."""

    def test_rendered_report_shows_the_real_publisher_not_the_connector_name(self):
        # "global_rss" legitimately still appears elsewhere in the page (the
        # provenance table's separate, correct "Source system" / connector
        # row) -- what must NOT happen is the Source Reliability &
        # Corroboration section itself falling back to the connector name
        # instead of the real, known publisher.
        import re
        article = _general_intelligence_article(source="global_rss", source_publisher="Dark Reading")
        result = compose_report(article, CONFIG)
        reliability_section = re.search(
            r"Source Reliability &amp; Corroboration.*?</section>", result.html, re.DOTALL,
        ).group(0)
        assert "Dark Reading" in reliability_section
        assert "global_rss" not in reliability_section

    def test_rendered_report_shows_three_separate_labeled_reliability_lines(self):
        result = compose_report(_cve_article(), CONFIG)
        assert "Source Reliability:" in result.html
        assert "Information Credibility:" in result.html
        assert "Overall Analytical Confidence:" in result.html
        assert "A/B" not in result.html

    def test_known_rss_publisher_grades_as_moderate_not_unknown(self):
        article = _general_intelligence_article(source="global_rss", source_publisher="BleepingComputer")
        result = compose_report(article, CONFIG)
        assert "Source Reliability: C" in result.html
        assert "Source Reliability: F" not in result.html
