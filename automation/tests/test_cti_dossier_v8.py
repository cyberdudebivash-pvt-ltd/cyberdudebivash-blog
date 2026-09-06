from types import SimpleNamespace

import pytest

from automation.cti_dossier_presentation import decorate_cti_dossier
from automation.cti_dossier_v8 import MARKER, enhance_cti_dossier_v8
from automation.report_integrity import PublicationIntegrityError


BASE_HTML = """
<h3>Executive Summary</h3>
<p>Researchers observed evidence-backed behavior requiring enterprise validation.</p>
<h3>Key Judgements</h3>
<p>The public record supports scoped collection and validation, not a customer incident claim.</p>
<h3>Verified Facts</h3>
<ul>
  <li>Source publisher: Example Security Research</li>
  <li>Researchers observed a controlled callback during testing.</li>
  <li>Customer-specific compromise was not established by the public record.</li>
</ul>
<h3>Evidence &amp; Source Assessment</h3>
<p>Primary provenance is the cited public source and the report remains evidence bounded.</p>
<h3>Enterprise Exposure Assessment</h3>
<p>Exposure requires internal inventory and telemetry validation.</p>
<h3>Technical Analysis</h3>
<p>The cited behavior defines a trust-boundary validation requirement.</p>
<h3>MITRE ATT&amp;CK Assessment</h3>
<p>Not established in cited evidence.</p>
<h3>Indicators &amp; Observables</h3>
<p>Not established in cited evidence.</p>
<h3>Detection Engineering Guidance</h3>
<p>Collect process, network, agent audit, and package-manager telemetry before promoting a rule.</p>
<h3>Threat Hunting Queries</h3>
<p>Begin with confirmed technology exposure and pivot only on evidence-supported behavior.</p>
<h3>SOC Analyst Playbook</h3>
<ul><li>Validate whether the affected technology exists internally before incident escalation.</li></ul>
<h3>Analytic Confidence &amp; Limitations</h3>
<p>Public-source evidence does not establish customer-specific exposure or compromise.</p>
<h3>References</h3>
<p><a href="https://example.test/research">Example Security Research</a></p>
<h3>Provenance and Certification</h3>
<p>Generated UTC 2026-09-07T00:00:00Z</p>
"""


def _article(**overrides):
    values = dict(
        title="AI Agent Trust Boundary Research",
        labels=["AI Security", "Threat Intelligence"],
        source="global_rss",
        source_publisher="Example Security Research",
        cvss_score=None,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def _context(**overrides):
    values = dict(
        report_id="CDB-CTI-2026-ABCDEF123456",
        certification_status="Public Intelligence Certification: FLASH_READY",
        family="ai_security",
        family_label="AI Security Intelligence",
        exploitation_status="not_applicable",
        exploitation_label="Not applicable to this intelligence format",
        patch_status="not_applicable",
        patch_label="Not applicable to this intelligence format",
        achieved_tier="FLASH_READY",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def _rendered():
    v5 = decorate_cti_dossier(BASE_HTML, _article(), _context())
    return enhance_cti_dossier_v8(v5, _article(), _context())


def test_v8_renders_premium_soc_cti_command_modules_from_existing_evidence():
    rendered = _rendered()
    assert MARKER in rendered
    assert "SOC OPERATIONS CONTROL PLANE // CTI EVIDENCE GRAPH" in rendered
    assert "SOC ANALYST 60-SECOND BRIEF" in rendered
    assert "EVIDENCE LEDGER SNAPSHOT" in rendered
    assert "PROMPT LEAKAGE" in rendered
    assert "CANONICAL UNIQUENESS" in rendered
    assert "AI TRUST BOUNDARY" in rendered
    assert "AGENT AUTONOMY" in rendered
    assert "SUPPLY CHAIN" in rendered
    assert "Researchers observed a controlled callback during testing." in rendered


def test_v8_hard_blocks_customer_visible_model_planning_leakage():
    leaked = """
    <h3>Technical Analysis</h3>
    <p>The user wants me to produce a comprehensive HTML intelligence report.</p>
    <p>Let me analyze the source carefully. I need to ensure all mandatory sections are present.</p>
    """
    with pytest.raises(PublicationIntegrityError) as caught:
        enhance_cti_dossier_v8(leaked, _article(), _context())
    assert any("customer-visible" in issue for issue in caught.value.issues)


def test_v8_hard_blocks_residual_duplicate_canonical_sections():
    duplicated = """
    <h3>Executive Summary</h3><p>First.</p>
    <h3>Executive Summary</h3><p>Second.</p>
    """
    with pytest.raises(PublicationIntegrityError) as caught:
        enhance_cti_dossier_v8(duplicated, _article(), _context())
    assert any("duplicate canonical report sections" in issue for issue in caught.value.issues)


def test_v8_does_not_invent_attack_ioc_or_compliance_state():
    rendered = _rendered()
    assert "ATT&amp;CK</span><strong>NOT ESTABLISHED" in rendered
    assert "OBSERVABLES</span><strong>NOT ESTABLISHED" in rendered
    assert "SOC 2 CERTIFIED" not in rendered.upper()
    assert "SOC 2 COMPLIANT" not in rendered.upper()
    assert "TLP:CLEAR" not in rendered  # v8 must not silently assign a distribution marking.


def test_v8_groups_navigation_and_adds_semantic_section_treatments():
    rendered = _rendered()
    assert "cdbv8-nav-group" in rendered
    assert ">OVERVIEW<" in rendered
    assert ">INTELLIGENCE<" in rendered
    assert ">SOC<" in rendered
    assert 'data-intel-group="soc"' in rendered
    assert 'data-intel-group="analysis"' in rendered


def test_v8_animation_is_blogger_safe_and_respects_reduced_motion():
    rendered = _rendered()
    assert "@keyframes cdbv8-scan" in rendered
    assert "@keyframes cdbv8-flow" in rendered
    assert "@media(prefers-reduced-motion:reduce)" in rendered
    assert "<script" not in rendered.lower()


def test_v8_is_idempotent():
    once = _rendered()
    twice = enhance_cti_dossier_v8(once, _article(), _context())
    assert once == twice
    assert twice.count(f"<!-- {MARKER} -->") == 1


def test_v8_retains_existing_evidence_boundaries_and_source_links():
    rendered = _rendered()
    assert "Customer-specific compromise was not established by the public record." in rendered
    assert "https://example.test/research" in rendered
    assert "Example Security Research" in rendered
    assert "Not applicable to this intelligence format" in rendered
