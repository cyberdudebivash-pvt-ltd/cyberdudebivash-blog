from types import SimpleNamespace

from automation.cti_dossier_v10 import MARKER, enhance_cti_dossier_v10


BASE = """
<div class="cdbd-command">COMMAND</div>
<div class="cdbv8-ledger">LEDGER</div>
<div class="cdbv9-framework">FRAMEWORK</div>
<div style="margin:0 0 24px;padding:16px 18px;background:#00080f;border:1px solid #1e3a5f55;border-radius:8px">
  <div style="color:#00d4ff;font-size:11px;font-weight:700;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px">■ Executive Risk Command Center</div>
  <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px">
    <div style="flex:1;min-width:150px;background:#050d1a;border:1px solid #64748b33;border-radius:6px;padding:14px 16px">
      <div style="color:#64748b;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1.3px;margin-bottom:6px;text-transform:uppercase">CISA KEV</div>
      <div style="color:#e2e8f0;font-size:20px;font-weight:900">Unknown</div>
      <div style="color:#64748b;font-size:10px;margin-top:4px;line-height:1.4">Unknown or unavailable; no negative claim is made</div>
    </div>
  </div>
</div>
<div style="margin:32px 0 14px;padding:10px 18px">► Executive Decision Center</div>
<div style="display:flex;flex-wrap:wrap;gap:10px"><div><strong>Board Summary</strong> No board notification is warranted at this stage.</div></div>
<h3>Executive Summary</h3><p>Evidence-bounded security intelligence requiring validation.</p>
<h3>Verified Facts</h3>
<ul>
 <li>Source publisher: Example Research</li>
 <li>Researchers observed controlled callback behavior.</li>
 <li>Customer-specific compromise is not established.</li>
</ul>
<h3>Evidence &amp; Source Assessment</h3>
<p>Primary provenance is Example Research. Reported by a single identified source.</p>
<h3>Executive Decision Matrix</h3>
<ul>
 <li>No internal exposure evidence: retain as intelligence and continue collection.</li>
 <li>Exposure confirmed but compromise unconfirmed: prioritize telemetry and supported remediation.</li>
</ul>
<h3>Executive Recommendations</h3><ul><li>Validate enterprise relevance before incident escalation.</li></ul>
<h3>Intelligence Gaps &amp; Collection Requirements</h3>
<ul><li>Customer-specific exposure is not established by the public source record.</li><li>Independent second source remains an open collection requirement.</li></ul>
<h3>Analytic Confidence &amp; Limitations</h3>
<p>Overall Analytical Confidence: MEDIUM</p>
<p>Source Reliability: C</p><p>Information Credibility: 3 (Possibly True)</p>
<a href="data:application/json;base64,AAAA" download="mitre-navigator-layer.json">Download MITRE ATT&amp;CK Navigator Layer</a>
"""


def _article(**overrides):
    values = dict(
        cve_id=None,
        source_publisher="Example Research",
        published_at="2026-09-04T10:35:17+00:00",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def _context(**overrides):
    values = dict(
        family="ai_security",
        report_id="CDB-CTI-2026-ABCDEF123456",
        source_record_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        generated_at="2026-09-06T16:15:01Z",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_v10_adds_unique_evidence_first_modules_without_replacing_v9():
    rendered = enhance_cti_dossier_v10(BASE, _article(), _context())
    assert MARKER in rendered
    assert "SOURCE CONFIDENCE &amp; CORROBORATION" in rendered
    assert "EVIDENCE GRAPH // CLAIM TRACEABILITY" in rendered
    assert "ENTERPRISE EXPOSURE VALIDATION CHECKLIST" in rendered
    assert "INTELLIGENCE CHRONOLOGY &amp; PROVENANCE RAIL" in rendered
    assert "INTELLIGENCE GAP &amp; COLLECTION TRACKER" in rendered
    assert "EXECUTIVE DECISION SUPPORT" in rendered
    assert "STIX 2.1 · ENTERPRISE IOC API" in rendered
    assert "FRAMEWORK" in rendered


def test_v10_uses_existing_qualitative_confidence_without_fake_probability():
    rendered = enhance_cti_dossier_v10(BASE, _article(), _context())
    assert "QUALITATIVE · NOT PROBABILITY" in rendered
    assert "Possibly True" in rendered
    assert "MEDIUM" in rendered
    assert "92%" not in rendered


def test_v10_ai_report_removes_inapplicable_kev_unknown_tile():
    rendered = enhance_cti_dossier_v10(BASE, _article(cve_id=None), _context(family="ai_security"))
    assert "Unknown or unavailable; no negative claim is made" not in rendered
    assert ">CISA KEV<" not in rendered


def test_v10_cve_report_preserves_unknown_kev_state():
    rendered = enhance_cti_dossier_v10(
        BASE,
        _article(cve_id="CVE-2026-12345"),
        _context(family="cve_advisory"),
    )
    assert "Unknown or unavailable; no negative claim is made" in rendered
    assert ">CISA KEV<" in rendered


def test_v10_removes_only_legacy_role_decision_center_and_keeps_canonical_decisions():
    rendered = enhance_cti_dossier_v10(BASE, _article(), _context())
    assert "No board notification is warranted at this stage." not in rendered
    assert "Executive Decision Center" not in rendered
    assert "No internal exposure evidence: retain as intelligence and continue collection." in rendered
    assert "Exposure confirmed but compromise unconfirmed" in rendered


def test_v10_exposure_validation_is_family_adaptive_and_non_assertive():
    ai = enhance_cti_dossier_v10(BASE, _article(), _context(family="ai_security"))
    assert "Can the relevant agent execute shell, package-manager" in ai
    assert "Does the agent have outbound network access" in ai
    assert "Exposure is confirmed only by internal inventory/telemetry" in ai

    cve = enhance_cti_dossier_v10(BASE, _article(cve_id="CVE-2026-12345"), _context(family="cve_advisory"))
    assert "Is the affected product or dependency present" in cve
    assert "Does the deployed version or configuration intersect" in cve


def test_v10_evidence_graph_reuses_verified_facts_and_provenance():
    rendered = enhance_cti_dossier_v10(BASE, _article(), _context())
    assert "Example Research" in rendered
    assert "Researchers observed controlled callback behavior." in rendered
    assert "CDB-CTI-2026-ABCDEF123456" in rendered
    assert "abcdef1234567890…" in rendered


def test_v10_preserves_existing_navigator_capability():
    rendered = enhance_cti_dossier_v10(BASE, _article(), _context())
    assert "ATT&amp;CK NAVIGATOR LAYER" in rendered
    assert "data:application/json;base64,AAAA" in rendered


def test_v10_does_not_assign_tlp_or_make_soc2_attestation():
    rendered = enhance_cti_dossier_v10(BASE, _article(), _context())
    upper = rendered.upper()
    assert "TLP:CLEAR" not in upper
    assert "SOC 2 CERTIFIED" not in upper
    assert "SOC 2 COMPLIANT" not in upper


def test_v10_is_blogger_safe_reduced_motion_aware_and_idempotent():
    once = enhance_cti_dossier_v10(BASE, _article(), _context())
    twice = enhance_cti_dossier_v10(once, _article(), _context())
    assert "@media(prefers-reduced-motion:reduce)" in once
    assert "@media print" in once
    assert "@keyframes cdbv10-flow" in once
    assert "<script" not in once.lower()
    assert once == twice
    assert twice.count(f"<!-- {MARKER} -->") == 1
