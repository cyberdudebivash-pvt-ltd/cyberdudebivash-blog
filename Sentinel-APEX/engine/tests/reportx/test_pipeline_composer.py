"""Tests for sentinel_engine.reportx.pipeline_composer -- the live-pipeline
composer that replaces automation.authority_transformer's
_legacy_template_enhance() boilerplate with a real, evidence-graph-backed,
commercial-readiness-gated report.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from automation.config import Config
from automation.content_discovery import DiscoveredArticle

from sentinel_engine.reportx.contradiction_engine import Contradiction
from sentinel_engine.reportx.human_review import CertificationState
from sentinel_engine.reportx.pipeline_composer import _dimension_tags_for, compose_report
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


def _ai_security_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://example.test/llm-prompt-injection-study", title="LLM Prompt Injection Study",
        summary="Researchers documented a prompt injection technique against a large language model deployment.",
        published_at="2026-08-18T09:00:00Z", content_hash="aisec1234",
        labels=["AI Security"], source="global_rss",
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _breach_notice_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://example.test/breach-record", title="Breach Record Z",
        summary="A public breach-record entry lists Example Corp among affected organizations.",
        published_at="2026-08-18T09:00:00Z", content_hash="breach1234",
        labels=["Data Breach"], source="breach_intel",
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _threat_actor_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://example.test/actor-pulse", title="Tracked Actor Infrastructure Update",
        summary="A subscribed OTX pulse updates infrastructure associated with a tracked threat actor.",
        published_at="2026-08-18T09:00:00Z", content_hash="actor1234",
        labels=["Threat Actor"], source="threat_actor_intel",
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _ransomware_reporting_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://example.test/ransomware-vpn-targeting", title="Ransomware Gangs Target VPN Appliances",
        summary="A new report finds ransomware operators increasingly exploit unpatched VPN devices for access.",
        published_at="2026-08-18T09:00:00Z", content_hash="ransnews1234",
        labels=["Ransomware", "Research"], source="global_rss",
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

    def test_commercial_readiness_scorecard_is_computed_from_the_same_bundle(self):
        # COMMERCIAL-QUALITY-2026-08-18: the 20-dimension Intelligence
        # Validation Framework scorecard (PR #90) is now computed for
        # every composed report, not just available as a standalone CLI
        # tool nothing in the live pipeline ever called.
        result = compose_report(_cve_article(), CONFIG)
        assert result.scorecard.report_id == result.report_id
        assert 0 <= result.scorecard.overall_score <= 100
        assert isinstance(result.scorecard.publication_eligible, bool)

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


class TestRXP1HRoleRoutingForPreviouslyUnroutedFamilies:
    """RX-P1H: ai_security/breach_notice/threat_actor/ransomware_reporting
    used to have zero role decisions -- same "Role-Based Decisions section
    entirely omitted" behavior as general_intelligence above. Each now gets
    exactly one, real, unconditional decision using an existing RoleAudience
    value (no new role invented), which is also what makes
    report_contract.py's new MANDATORY Section 19 for these families honest
    rather than a trap: the section is always genuinely populated."""

    def test_ai_security_gets_ciso_cio_not_vulnerability_manager(self):
        result = compose_report(_ai_security_article(), CONFIG)
        assert result.context.family == "ai_security"
        assert "Role-Based Decisions" in result.html
        assert "CISO / CIO" in result.html
        assert "Vulnerability Manager" not in result.html

    def test_breach_notice_gets_legal_compliance_privacy(self):
        result = compose_report(_breach_notice_article(), CONFIG)
        assert result.context.family == "breach_notice"
        assert "Role-Based Decisions" in result.html
        assert "Legal" in result.html

    def test_threat_actor_gets_threat_hunter(self):
        result = compose_report(_threat_actor_article(), CONFIG)
        assert result.context.family == "threat_actor"
        assert "Role-Based Decisions" in result.html
        assert "Threat Hunter" in result.html

    def test_ransomware_reporting_gets_soc_manager_not_ir_manager(self):
        # SOC Manager (situational-awareness framing), not IR Manager --
        # there is no specific claimed victim here to validate, unlike
        # ransomware_claim.
        result = compose_report(_ransomware_reporting_article(), CONFIG)
        assert result.context.family == "ransomware_reporting"
        assert "Role-Based Decisions" in result.html
        assert "SOC Manager" in result.html
        assert "IR Manager" not in result.html


class TestRXP1HFamilySpecificIntelligenceGaps:
    """RX-P1H: pipeline_composer's intelligence_gaps list was identical for
    every family regardless of evidence shape. Each of these four families
    now gets one additional, real, family-conditioned gap on top of the
    existing universal corroboration gap -- additive only, no existing
    family's gap list changes."""

    def test_universal_corroboration_gap_still_present_for_every_family(self):
        result = compose_report(_ai_security_article(), CONFIG)
        descriptions = [g.description for g in result.bundle.intelligence_gaps]
        assert any("independent second source corroborates" in d for d in descriptions)

    def test_ai_security_gets_an_additional_model_usage_gap(self):
        result = compose_report(_ai_security_article(), CONFIG)
        descriptions = [g.description for g in result.bundle.intelligence_gaps]
        assert len(descriptions) == 2
        assert any("AI system, model, or capability" in d for d in descriptions)

    def test_breach_notice_gets_an_additional_scope_gap(self):
        result = compose_report(_breach_notice_article(), CONFIG)
        descriptions = [g.description for g in result.bundle.intelligence_gaps]
        assert len(descriptions) == 2
        assert any("scope of data exposure" in d for d in descriptions)

    def test_threat_actor_gets_an_additional_activity_relevance_gap(self):
        result = compose_report(_threat_actor_article(), CONFIG)
        descriptions = [g.description for g in result.bundle.intelligence_gaps]
        assert len(descriptions) == 2
        assert any("currently active against the reader's own sector" in d for d in descriptions)

    def test_ransomware_reporting_gets_an_additional_no_named_victim_gap(self):
        result = compose_report(_ransomware_reporting_article(), CONFIG)
        descriptions = [g.description for g in result.bundle.intelligence_gaps]
        assert len(descriptions) == 2
        assert any("no specific victim organization" in d for d in descriptions)

    def test_cve_family_is_unaffected_still_gets_exactly_one_gap(self):
        # Regression guard: this addition must not have touched families
        # outside the four named above.
        result = compose_report(_cve_article(), CONFIG)
        assert len(result.bundle.intelligence_gaps) == 1


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

    def test_analytical_confidence_is_the_same_3_axes_as_structured_data(self):
        # RX-P1E-WIRE: the same 3 real axes the rendered prose lines above
        # assert on, now also available as structured data -- not a
        # separately re-derived or re-worded value.
        article = _general_intelligence_article(source="global_rss", source_publisher="BleepingComputer")
        result = compose_report(article, CONFIG)
        conf = result.analytical_confidence
        assert conf["source_reliability_grade"] == "C"
        assert isinstance(conf["information_credibility_number"], int)
        assert isinstance(conf["information_credibility_label"], str)
        assert conf["overall_confidence"] in ("HIGH", "MEDIUM", "LOW")
        assert conf["corroboration_state"] in (
            "SINGLE_SOURCE", "MULTI_SOURCE_INDEPENDENT", "MULTI_SOURCE_DEPENDENT", "UNCORROBORATED",
        )
        # Cross-check against the rendered prose line, which independently
        # embeds the same grade/label -- both must agree.
        assert f"Source Reliability: {conf['source_reliability_grade']}" in result.html


class TestDimensionTagsFor:
    """_dimension_tags_for() -- discovery_bridge.py's claim_id naming
    convention mapped to contradiction_engine.py's dimension vocabulary."""

    def test_cve_article_tags_its_own_dimensions(self):
        result = compose_report(_cve_article(), CONFIG)
        tags = _dimension_tags_for(result.bundle.graph)
        assert tags.get("exploitation_state") == ["c-exploitation-status"]
        assert tags.get("patch_state") == ["c-patch-status"]
        # kev_listed is False for the default fixture -- no c-kev-listed
        # claim is ever built for a not-listed CVE, so no kev_state tag.
        assert "kev_state" not in tags

    def test_kev_listed_cve_also_tags_kev_state(self):
        result = compose_report(_cve_article(source="cisa_kev", kev_listed=True), CONFIG)
        tags = _dimension_tags_for(result.bundle.graph)
        assert tags.get("kev_state") == ["c-kev-listed"]

    def test_ransomware_article_tags_actor_and_victim_dimensions(self):
        result = compose_report(_ransomware_article(ransomware_group="qilin"), CONFIG)
        tags = _dimension_tags_for(result.bundle.graph)
        assert tags.get("actor_identity") == ["c-actor-attribution"]
        assert tags.get("victim_confirmation") == ["c-victim-claim"]

    def test_a_claim_id_not_present_in_the_graph_is_never_a_keyerror(self):
        # Regression guard: _DIMENSION_BY_CLAIM_ID names 5 claim_ids: no
        # single real article family builds all 5 (e.g. a non-KEV CVE never
        # gets c-kev-listed, a ransomware claim never gets c-exploitation-status).
        result = compose_report(_cve_article(kev_listed=False), CONFIG)
        tags = _dimension_tags_for(result.bundle.graph)  # must not raise
        assert isinstance(tags, dict)


class TestContradictionWiring:
    """RX-P1D-WIRE: contradiction_engine.py's two checkers were real and
    tested but never invoked by compose_report() -- the identical
    certified-but-dormant pattern this session already closed for
    report_contract.py/analytical_depth_gate.py and for the evidence graph
    itself."""

    def test_real_cve_article_has_zero_contradictions(self):
        # Honest no-op proof: discovery_bridge.py's single-source claim
        # construction cannot yet produce two competing same-dimension
        # claims (see _dimension_tags_for()'s own docstring), and
        # report_renderer.py's deterministic, single-evidence-state prose
        # does not naturally trip contradiction_engine.py's 3 specific
        # text-pattern rules either.
        result = compose_report(_cve_article(), CONFIG)
        assert result.contradictions == []

    def test_real_ransomware_article_has_zero_contradictions(self):
        result = compose_report(_ransomware_article(ransomware_group="qilin"), CONFIG)
        assert result.contradictions == []

    def test_compose_report_threads_a_real_dimension_contradiction_through(self):
        # Proves the wiring's plumbing, not contradiction_engine.py's own
        # internal logic (already covered by test_contradiction_engine.py's
        # 10 tests): forces find_all_contradictions() to return a real
        # Contradiction and confirms compose_report()'s own result reflects
        # it verbatim, rather than silently dropping it anywhere between
        # the checker and ComposedReport.
        fake_finding = Contradiction(
            dimension="kev_state", description="test-forced contradiction",
            claim_id_a="c-kev-listed", claim_id_b="c-kev-listed-2",
        )
        with patch(
            "sentinel_engine.reportx.pipeline_composer.find_all_contradictions",
            return_value=[fake_finding],
        ):
            result = compose_report(_cve_article(source="cisa_kev", kev_listed=True), CONFIG)
        assert result.contradictions == [fake_finding]

    def test_compose_report_passes_its_own_real_graph_and_html_to_the_checker(self):
        # A second plumbing proof, from the other direction: confirms
        # compose_report() calls find_all_contradictions() with THIS
        # report's own real graph/dimension_tags/html, not empty or stale
        # arguments -- so a future article whose evidence genuinely does
        # produce a same-dimension conflict will actually be seen.
        with patch(
            "sentinel_engine.reportx.pipeline_composer.find_all_contradictions",
            return_value=[],
        ) as mocked:
            result = compose_report(_cve_article(source="cisa_kev", kev_listed=True), CONFIG)
        mocked.assert_called_once()
        _, kwargs = mocked.call_args
        called_graph = mocked.call_args[0][0]
        assert called_graph is result.bundle.graph
        assert kwargs["dimension_tags"] == _dimension_tags_for(result.bundle.graph)
        assert kwargs["full_text"] == result.html


class TestRXP1HHuntHypothesisWiring:
    """RX-P1I: executive_products.HuntHypothesis existed, was tested, but
    was never called from this live pipeline before -- Section 14 (Threat
    Hunting) was permanently WITHHELD_INSUFFICIENT_EVIDENCE for every
    article regardless of family. Scoped to cve_advisory only this round."""

    def test_cve_advisory_gets_a_real_hunt_hypothesis(self):
        result = compose_report(_cve_article(), CONFIG)
        assert result.context.family == "cve_advisory"
        assert len(result.hunt_hypotheses) == 1
        assert "Threat Hunting" in result.html

    def test_hunt_hypothesis_is_scoped_to_cve_advisory_only(self):
        # Mandate Section 15's own discipline: "no evidence = withhold" --
        # ransomware_claim has no real telemetry basis for this pipeline's
        # exposure+exploitation hypothesis shape, so it must get none
        # rather than a generic, evidence-free hunt bolted on regardless.
        result = compose_report(_ransomware_article(), CONFIG)
        assert result.hunt_hypotheses == []
        assert "Threat Hunting" not in result.html

    def test_general_intelligence_gets_no_hunt_hypothesis(self):
        result = compose_report(_general_intelligence_article(), CONFIG)
        assert result.hunt_hypotheses == []

    def test_hunt_hypothesis_reuses_the_real_vulnerability_class_telemetry_not_generic_advice(self):
        # Mandate Section 13: reject hunting content that is only generic
        # security advice -- required_telemetry must be the same real,
        # vulnerability-class-specific guidance _detection_package() itself
        # already computes (Reuse Before Build), not a vague restatement.
        result = compose_report(_cve_article(), CONFIG)
        hypothesis = result.hunt_hypotheses[0]
        generic_phrases = ("monitor suspicious activity", "review logs", "check for unusual behavior")
        assert not any(g in t.lower() for t in hypothesis.required_telemetry for g in generic_phrases)
        assert len(hypothesis.required_telemetry) >= 1
        # Every required field mandate Section 12/13 names is genuinely
        # populated, not left blank to satisfy a completeness check only.
        for field_name in (
            "hypothesis_id", "statement", "required_telemetry", "pivot_opportunities",
            "expected_observations", "negative_indicators", "false_positive_considerations",
            "validation_steps", "success_criteria", "escalation_criteria", "limitations",
        ):
            value = getattr(hypothesis, field_name)
            assert value, f"{field_name} must not be empty"
        assert hypothesis.maturity == "PROPOSED"

    def test_hunt_hypothesis_never_asserts_compromise_occurred(self):
        # The statement must stay a conditional ("if X, then look for Y"),
        # never a claim that exploitation actually happened.
        result = compose_report(_cve_article(), CONFIG)
        statement = result.hunt_hypotheses[0].statement.lower()
        assert "if " in statement
        assert "was exploited" not in statement
        assert "has been compromised" not in statement

    def test_hunt_hypothesis_reaches_the_intelligence_validation_scorecard(self):
        from sentinel_engine.reportx.intelligence_validation import ValidationDimension
        result = compose_report(_cve_article(), CONFIG)
        dim = result.scorecard.dimension(ValidationDimension.THREAT_HUNTING_GUIDANCE)
        assert dim.status == "PASS"

    def test_section_14_resolves_complete_for_cve_advisory_not_withheld(self):
        from automation.report_contract import SECTION_14_THREAT_HUNTING, evaluate_section_states
        result = compose_report(_cve_article(), CONFIG)
        resolutions = evaluate_section_states(
            _cve_article(), result.context, hunt_hypothesis_count=len(result.hunt_hypotheses),
        )
        state = next(r.state for r in resolutions if r.section == SECTION_14_THREAT_HUNTING)
        assert state.value == "COMPLETE"


class TestRXP1JRoleDecisionWiring:
    """RX-P1J: pipeline_composer._lean_role_decisions() built real,
    family-conditioned RoleDecision objects (RX-P1H) that were used to
    render role_html inline, but were never counted or exposed on
    ComposedReport at all -- the identical certified-but-dormant pattern
    already found and fixed for hunt_hypotheses/attack_mappings. Section 19
    (Role Decision Matrix) could therefore resolve COMPLETE without any
    proof that a structured decision list was non-empty."""

    def test_cve_article_exposes_real_role_decisions_on_the_result(self):
        result = compose_report(_cve_article(), CONFIG)
        assert len(result.role_decisions) == 2  # Vulnerability Manager + SOC Manager
        roles = {d.role.value for d in result.role_decisions}
        assert roles == {"VULNERABILITY_MANAGER", "SOC_MANAGER"}

    def test_general_intelligence_article_exposes_zero_role_decisions(self):
        result = compose_report(_general_intelligence_article(), CONFIG)
        assert result.role_decisions == []

    def test_every_real_role_decision_carries_a_real_evidence_basis(self):
        # Mandate Section 7 hard-fail: "role advice with no evidence basis
        # where evidence is required" -- proven against every family this
        # pipeline currently routes a role decision for, not just one.
        for article in (
            _cve_article(), _ransomware_article(), _ai_security_article(),
            _breach_notice_article(), _threat_actor_article(), _ransomware_reporting_article(),
        ):
            result = compose_report(article, CONFIG)
            assert result.role_decisions, f"{result.context.family} produced no role decisions"
            for d in result.role_decisions:
                assert d.evidence_claim_ids, f"{d.role.value} decision has no evidence basis"
                assert d.limitations, f"{d.role.value} decision has no stated limitations"

    def test_ransomware_claim_role_decision_states_its_escalation_condition(self):
        # The one decision whose existing rationale already states an
        # explicit conditional trigger in prose ("absent independent
        # corroboration") -- structured here, not a new claim.
        result = compose_report(_ransomware_article(), CONFIG)
        decision = next(d for d in result.role_decisions if d.role.value == "IR_MANAGER")
        assert "corroboration" in decision.escalation_condition.lower()

    def test_section_19_resolves_complete_for_cve_advisory_when_real_decisions_exist(self):
        from automation.report_contract import SECTION_19_ROLE_DECISION_MATRIX, evaluate_section_states
        result = compose_report(_cve_article(), CONFIG)
        resolutions = evaluate_section_states(
            _cve_article(), result.context, role_decision_count=len(result.role_decisions),
        )
        state = next(r.state for r in resolutions if r.section == SECTION_19_ROLE_DECISION_MATRIX)
        assert state.value == "COMPLETE"

    def test_section_19_resolves_withheld_when_a_real_caller_measures_zero(self):
        # The mandate's own named hard-fail: "role decision state marked
        # COMPLETE with zero actual role decisions" -- proven against
        # general_intelligence, the one real family with a reconciled
        # matrix (report_contract._FAMILY_APPLICABILITY has no entry for
        # general_intelligence, so this instead uses a family that DOES
        # have Section 19 as MANDATORY to prove the gate actually bites).
        from automation.report_contract import SECTION_19_ROLE_DECISION_MATRIX, Applicability, evaluate_section_states
        result = compose_report(_cve_article(), CONFIG)
        resolutions = evaluate_section_states(_cve_article(), result.context, role_decision_count=0)
        resolution = next(r for r in resolutions if r.section == SECTION_19_ROLE_DECISION_MATRIX)
        assert resolution.applicability == Applicability.MANDATORY
        assert resolution.state.value == "WITHHELD_INSUFFICIENT_EVIDENCE"


class TestRXP1JRoleDecisionSemanticGate:
    """Direct adversarial proof of _validate_role_decisions() -- mirrors
    test_attack_mapping.py's own semantic-gate adversarial coverage.
    A hand-built candidate that fails any check must never reach
    ComposedReport.role_decisions, regardless of how it was constructed."""

    def _decision(self, **overrides):
        from sentinel_engine.reportx.executive_products import RoleAudience, RoleDecision
        defaults = dict(
            role=RoleAudience.SOC_MANAGER, decision="Review the detection guidance for this record.",
            rationale="Real, evidence-scoped guidance.", evidence_claim_ids=("c-summary",),
        )
        defaults.update(overrides)
        return RoleDecision(**defaults)

    def test_a_well_formed_decision_survives_the_gate(self):
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        out = _validate_role_decisions([self._decision()])
        assert len(out) == 1

    def test_malformed_role_is_dropped(self):
        # RoleDecision.role is type-hinted RoleAudience but not runtime-
        # enforced by the frozen dataclass itself (no __post_init__) -- a
        # raw string reaching this gate (e.g. a hypothetical future caller
        # that skips the enum) must still be rejected, not silently
        # rendered with str(role) as a fabricated-looking role name.
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        assert _validate_role_decisions([self._decision(role="NOT_A_REAL_ROLE")]) == []

    def test_empty_decision_text_is_dropped(self):
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        assert _validate_role_decisions([self._decision(decision="")]) == []
        assert _validate_role_decisions([self._decision(decision="   ")]) == []

    def test_decision_with_no_evidence_basis_is_dropped(self):
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        assert _validate_role_decisions([self._decision(evidence_claim_ids=())]) == []

    def test_exact_regression_of_the_known_bare_generic_defect_is_dropped(self):
        # COMMERCIAL-QUALITY-2026-08-18's own fixed defect, permanently
        # guarded: a bare "Track against X intake." / "Monitor this
        # threat." with nothing evidence-specific appended.
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        assert _validate_role_decisions([self._decision(decision="Track against intake.")]) == []
        assert _validate_role_decisions([self._decision(decision="Monitor this threat.")]) == []
        assert _validate_role_decisions([self._decision(decision="Monitor This Threat")]) == []

    def test_duplicate_role_and_decision_pair_keeps_only_the_first(self):
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        d = self._decision()
        out = _validate_role_decisions([d, d])
        assert len(out) == 1

    def test_unsupported_numeric_deadline_is_dropped(self):
        # This pipeline has no jurisdiction/regulation evidence model in
        # the role-decision path -- any specific numeric deadline reaching
        # a RoleDecision today can only be fabricated.
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        out = _validate_role_decisions([self._decision(deadline_or_trigger="Notify within 24 hours.")])
        assert out == []

    def test_unsupported_regulatory_claim_is_dropped(self):
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        out = _validate_role_decisions(
            [self._decision(rationale="This is legally required under GDPR notification rules.")]
        )
        assert out == []

    def test_real_breach_notice_decision_does_not_false_positive_on_the_regulatory_pattern(self):
        # The real production breach_notice decision deliberately DEFERS a
        # regulatory determination rather than asserting one -- must not be
        # caught by the same gate that rejects an asserted claim above.
        from sentinel_engine.reportx.pipeline_composer import _validate_role_decisions
        from sentinel_engine.reportx.executive_products import RoleAudience
        d = self._decision(
            role=RoleAudience.LEGAL_COMPLIANCE_PRIVACY,
            decision="Assess whether this public breach record involves the organization's own data, customers, "
                     "or vendors before any notification or regulatory determination.",
            rationale="A public breach record is a disclosure to review, not a confirmed organizational incident.",
        )
        assert _validate_role_decisions([d]) == [d]
