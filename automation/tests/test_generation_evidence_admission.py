from __future__ import annotations

import unittest

from automation.content_discovery import DiscoveredArticle
from automation.generation_evidence_admission import evaluate_generation_evidence


def _article(**overrides):
    values = dict(
        url="https://example.test/source",
        title="Malware campaign report",
        summary="A source reports a malware campaign affecting freelancers.",
        published_at="2026-09-05T00:00:00+00:00",
        content_hash="abc123",
        labels=["Malware Research"],
        source="global_rss",
        source_publisher="Example Security",
        full_content="The source confirms the campaign but provides no ATT&CK IDs, IOCs, patch instructions, or forecast.",
    )
    values.update(overrides)
    return DiscoveredArticle(**values)


class GenerationEvidenceAdmissionTests(unittest.TestCase):
    def test_safe_evidence_bounded_analysis_is_admitted(self):
        article = _article()
        html = """
        <h3>Technical Analysis</h3>
        <p>The cited record establishes the existence of the reported campaign. Specific malware capabilities are not established in cited evidence.</p>
        <h3>MITRE ATT&amp;CK Assessment</h3>
        <p>Not established in cited evidence.</p>
        <h3>Forecast &amp; Outlook</h3>
        <p>No new future event is predicted by the compiler.</p>
        """
        self.assertEqual(evaluate_generation_evidence(article, html), ())

    def test_production_prompt_planning_leakage_is_rejected_upstream(self):
        article = _article()
        html = """
        <h3>Technical Analysis</h3>
        <p>The user wants me to produce a comprehensive HTML intelligence report.</p>
        <p>Let me analyze the source carefully. I need to ensure all mandatory sections are present.</p>
        <p>HTML only, no markdown. CDB_EXPLOITATION_STATUS: not_applicable.</p>
        """
        self.assertIn("PROMPT_LEAKAGE", evaluate_generation_evidence(article, html))

    def test_single_source_quote_does_not_false_positive_as_prompt_leakage(self):
        article = _article(full_content='The article quotes an agent saying "let me analyze this" during testing.')
        html = '<p>The source quotes the agent saying “let me analyze this” during the controlled test.</p>'
        self.assertNotIn("PROMPT_LEAKAGE", evaluate_generation_evidence(article, html))

    def test_internal_cdb_control_token_is_sufficient_to_reject_generation(self):
        article = _article()
        html = "<p>CDB_SOURCE_CLAIM_ONLY: false</p>"
        self.assertIn("PROMPT_LEAKAGE", evaluate_generation_evidence(article, html))

    def test_inferred_attack_ids_are_rejected_when_source_has_no_ids(self):
        article = _article()
        html = """
        <h3>MITRE ATT&amp;CK Assessment</h3>
        <ul><li>T1566 Phishing — inferred from victimology.</li><li>T1078 Valid Accounts — inferred from credential risk.</li></ul>
        """
        issues = evaluate_generation_evidence(article, html)
        self.assertTrue(any(x.startswith("ATTACK_ID_UNSUPPORTED:") for x in issues))
        joined = " ".join(issues)
        self.assertIn("T1566", joined)
        self.assertIn("T1078", joined)

    def test_exact_source_backed_attack_id_is_not_rejected(self):
        article = _article(full_content="The source explicitly maps the observed behavior to T1566.002.")
        html = "<h3>MITRE ATT&amp;CK Assessment</h3><p>T1566.002 is reported by the cited source.</p>"
        self.assertFalse(any(x.startswith("ATTACK_ID_UNSUPPORTED") for x in evaluate_generation_evidence(article, html)))

    def test_unknown_kev_cannot_be_promoted_to_negative_claim(self):
        article = _article(kev_listed=None)
        html = "<h3>Verified Facts</h3><p>The vulnerability is not listed in the CISA KEV catalog.</p>"
        self.assertIn("KEV_UNKNOWN_PROMOTED", evaluate_generation_evidence(article, html))

    def test_unknown_kev_cannot_be_promoted_to_positive_claim(self):
        article = _article(kev_listed=None)
        html = "<h3>Verified Facts</h3><p>The vulnerability is listed in the CISA KEV catalog.</p>"
        self.assertIn("KEV_UNKNOWN_PROMOTED", evaluate_generation_evidence(article, html))

    def test_verified_kev_true_allows_positive_catalog_statement(self):
        article = _article(
            source="cisa_kev",
            kev_listed=True,
            kev_required_action="Apply mitigations per vendor instructions.",
            full_content="CISA added this vulnerability to the Known Exploited Vulnerabilities catalog. It is actively exploited.",
        )
        html = "<p>This vulnerability is listed in the CISA KEV catalog and is actively exploited.</p>"
        issues = evaluate_generation_evidence(article, html)
        self.assertNotIn("KEV_UNKNOWN_PROMOTED", issues)
        self.assertNotIn("EXPLOITATION_UNSUPPORTED", issues)

    def test_unknown_exploitation_rejects_positive_assertion_but_not_negation(self):
        article = _article(cve_id="CVE-2026-99999")
        unsafe = "<p>This vulnerability is actively exploited in the wild.</p>"
        safe = "<p>No confirmed exploitation evidence is available in the cited source.</p>"
        self.assertIn("EXPLOITATION_UNSUPPORTED", evaluate_generation_evidence(article, unsafe))
        self.assertNotIn("EXPLOITATION_UNSUPPORTED", evaluate_generation_evidence(article, safe))

    def test_unconfirmed_remediation_rejects_invented_specific_patch_version(self):
        article = _article(
            cve_id="CVE-2026-84813",
            title="CVE-2026-84813 WordPress GeoDirectory SQL Injection",
            summary="GeoDirectory <= 2.8.174 is affected. CVSS 9.3.",
            full_content="The cited record does not establish a patched release.",
            cvss_score=9.3,
        )
        html = "<h3>Remediation &amp; Validation Plan</h3><p>Upgrade GeoDirectory to version 2.8.175 or later immediately.</p>"
        self.assertIn("REMEDIATION_UNSUPPORTED", evaluate_generation_evidence(article, html))

    def test_source_backed_patch_language_is_admitted(self):
        article = _article(
            cve_id="CVE-2026-12345",
            full_content="The vendor has released a patch. Upgrade to version 4.2.1.",
        )
        html = "<p>The vendor has released a patch. Upgrade to version 4.2.1 as stated in the cited advisory.</p>"
        self.assertNotIn("REMEDIATION_UNSUPPORTED", evaluate_generation_evidence(article, html))

    def test_ransomware_actor_claim_cannot_become_confirmed_breach(self):
        article = _article(
            source="ransomware_intel",
            ransomware_group="ExampleLocker",
            title="ExampleLocker claims Example Corp",
            summary="ExampleLocker listed Example Corp on its leak site.",
            full_content="This is a third-party leak-site claim and is independently unverified.",
        )
        html = "<p>The breach has been confirmed and data was stolen from the victim.</p>"
        self.assertIn("RANSOMWARE_CLAIM_PROMOTED", evaluate_generation_evidence(article, html))

    def test_model_created_future_window_is_rejected(self):
        article = _article()
        html = """
        <h3>Forecast / Outlook</h3>
        <p>It is likely that threat actors will develop exploit tooling within the next 3 months.</p>
        """
        self.assertIn("FORECAST_UNSUPPORTED", evaluate_generation_evidence(article, html))

    def test_source_backed_forecast_is_not_reclassified_as_invented(self):
        article = _article(full_content="The source states that attackers are expected to increase scanning within the next 30 days.")
        html = "<h3>Forecast &amp; Outlook</h3><p>Attackers are expected to increase scanning within the next 30 days, as stated by the source.</p>"
        self.assertNotIn("FORECAST_UNSUPPORTED", evaluate_generation_evidence(article, html))


if __name__ == "__main__":
    unittest.main()
