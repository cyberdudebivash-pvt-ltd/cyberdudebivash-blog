from types import SimpleNamespace

from automation.cti_dossier_presentation import decorate_cti_dossier
from automation.cti_dossier_v8 import enhance_cti_dossier_v8
from automation.cti_dossier_v9 import MARKER, enhance_cti_dossier_v9


BASE_HTML = """
<h3>Executive Summary</h3>
<p>Researchers observed evidence-backed AI agent behavior requiring enterprise validation.</p>
<h3>Key Judgements</h3>
<p>The public record supports scoped collection and validation, not a customer incident claim.</p>
<h3>Verified Facts</h3>
<ul>
  <li>Source publisher: Example Security Research</li>
  <li>Researchers observed a controlled callback during testing.</li>
  <li>Customer-specific compromise was not established by the public record.</li>
</ul>
<h3>Evidence &amp; Source Assessment</h3>
<p>Primary provenance is a single identified source; an independent second source has not been found.</p>
<h3>Timeline &amp; Chronology</h3>
<p>Researchers first identified unresolved references during scanning. They then registered a controlled test name. A callback was later observed during the research exercise.</p>
<h3>Enterprise Exposure Assessment</h3>
<p>Exposure requires internal inventory and telemetry validation.</p>
<h3>Technical Analysis</h3>
<p>The cited behavior defines an AI agent trust-boundary validation requirement.</p>
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


def _article():
    return SimpleNamespace(
        title="AI Agent Trust Boundary Research",
        labels=["AI Security", "Threat Intelligence"],
        source="global_rss",
        source_publisher="Example Security Research",
        cvss_score=None,
    )


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
    v8 = enhance_cti_dossier_v8(v5, _article(), _context())
    return enhance_cti_dossier_v9(v8, _article(), _context())


def test_v9_renders_next_level_intelligence_command_modules():
    rendered = _rendered()
    assert MARKER in rendered
    assert "INTELLIGENCE CONFIDENCE // EVIDENCE MATRIX" in rendered
    assert "ENTERPRISE EXPOSURE DECISION ENGINE" in rendered
    assert "ATTACK SURFACE // CONTROL PATH" in rendered
    assert "INTELLIGENCE TIMELINE // CHRONOLOGY" in rendered
    assert "SOC / IR DECISION LIFECYCLE" in rendered
    assert "PUBLICATION AND ANALYTICAL QUALITY" not in rendered  # aria label only, not decorative heading spam


def test_v9_ai_family_uses_agent_trust_boundary_control_path_without_claiming_exploitation():
    rendered = _rendered()
    assert "EXTERNAL / MACHINE-READABLE INPUT" in rendered
    assert "AI / AGENT TRUST BOUNDARY" in rendered
    assert "TOOL / PACKAGE / SHELL ACTION" in rendered
    assert "ANALYTICAL MODEL" in rendered
    assert "It is not a claim that every stage occurred" in rendered
    assert "Not applicable to this intelligence format" in rendered


def test_v9_customer_exposure_and_compromise_remain_telemetry_conditioned():
    rendered = _rendered()
    assert "CUSTOMER EXPOSURE" in rendered
    assert "REQUIRES INTERNAL VALIDATION" in rendered
    assert "CUSTOMER COMPROMISE" in rendered
    assert "NOT ESTABLISHED BY PUBLIC INTELLIGENCE" in rendered
    assert "INTERNAL OBSERVABILITY" in rendered
    assert "REQUIRES CUSTOMER TELEMETRY" in rendered


def test_v9_does_not_invent_numeric_confidence_tlp_or_soc2_attestation():
    rendered = _rendered()
    assert "NON-PROBABILISTIC" in rendered
    assert "They are not statistical probabilities" in rendered
    assert "TLP:CLEAR" not in rendered
    assert "SOC 2 CERTIFIED" not in rendered.upper()
    assert "SOC 2 COMPLIANT" not in rendered.upper()
    assert "Framework-oriented navigation only; not a compliance or attestation statement." in rendered


def test_v9_preserves_not_established_attack_and_observable_states():
    rendered = _rendered()
    assert "ATT&amp;CK" in rendered
    assert "NOT ESTABLISHED" in rendered
    assert "OBSERVABLES" in rendered
    assert "CORROBORATION" in rendered
    assert "NOT ESTABLISHED" in rendered


def test_v9_timeline_is_derived_from_existing_chronology_text():
    rendered = _rendered()
    assert "Researchers first identified unresolved references during scanning." in rendered
    assert "They then registered a controlled test name." in rendered
    assert "A callback was later observed during the research exercise." in rendered


def test_v9_animation_is_css_only_and_respects_reduced_motion():
    rendered = _rendered()
    assert "@keyframes cdbv9-flow" in rendered
    assert "@media(prefers-reduced-motion:reduce)" in rendered
    assert "<script" not in rendered.lower()


def test_v9_is_idempotent():
    once = _rendered()
    twice = enhance_cti_dossier_v9(once, _article(), _context())
    assert once == twice
    assert twice.count(f"<!-- {MARKER} -->") == 1
