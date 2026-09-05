from types import SimpleNamespace

from automation.cti_evidence_convergence import MARKER, converge_cti_dossier


LIVE_SHAPE = """
<article class="cdb-cti-dossier">
<section class="cdbd-command cdbd-sev-unspecified">
  <div class="cdbd-kpi cdbd-kpi-severity"><span>SEVERITY</span><strong>UNSPECIFIED</strong></div>
</section>
<div class="cdbd-body">
<h3>Executive Summary</h3><p>canonical executive summary</p>
<div><b>Executive Risk Command Center</b><div>CVSS Score</div><div>7.0</div></div>
<h3>Technical Analysis</h3>
<p><strong>1. Executive Summary</strong></p><p>duplicate executive summary</p>
<p><strong>2. Key Judgements</strong></p><ul><li>duplicate judgement</li></ul>
<p><strong>10. Technical Analysis</strong></p><p>deep technical body that must survive</p>
<p><strong>12. MITRE ATT&amp;CK Assessment</strong></p><ul><li>speculative T1543.003 mapping</li></ul>
<p><strong>14. Detection Engineering Guidance</strong></p><p>legacy speculative detection</p>
<p><strong>24. Forecast / Outlook</strong></p><p>unsupported future prediction</p>
<h3>MITRE ATT&amp;CK Assessment</h3><p>Not established in cited evidence.</p>
<h3>Detection Engineering Guidance</h3><p>Evidence-conditioned telemetry specification.</p>
<h3>Forecast &amp; Outlook</h3><p>No new future event is predicted by the compiler.</p>
</div>
</article>
"""


def _article(**overrides):
    values = dict(cvss_score=None, cvss=None)
    values.update(overrides)
    return SimpleNamespace(**values)


def test_v6_repairs_unspecified_severity_from_rendered_structured_cvss():
    rendered = converge_cti_dossier(LIVE_SHAPE, _article())
    assert MARKER in rendered
    assert '<strong>HIGH</strong>' in rendered
    assert 'cdbd-sev-high' in rendered
    assert 'cdbd-sev-unspecified' not in rendered


def test_v6_prefers_article_structured_cvss_over_rendered_value():
    rendered = converge_cti_dossier(LIVE_SHAPE, _article(cvss_score=9.8))
    assert '<strong>CRITICAL</strong>' in rendered
    assert 'cdbd-sev-critical' in rendered


def test_nested_legacy_canonical_sections_are_removed_but_deep_technical_body_survives():
    rendered = converge_cti_dossier(LIVE_SHAPE, _article())
    assert 'duplicate executive summary' not in rendered
    assert 'duplicate judgement' not in rendered
    assert 'speculative T1543.003 mapping' not in rendered
    assert 'legacy speculative detection' not in rendered
    assert 'unsupported future prediction' not in rendered
    assert 'deep technical body that must survive' in rendered
    assert 'Not established in cited evidence.' in rendered
    assert 'Evidence-conditioned telemetry specification.' in rendered
    assert 'No new future event is predicted by the compiler.' in rendered


def test_v6_does_not_change_an_explicit_existing_severity():
    html = LIVE_SHAPE.replace('UNSPECIFIED', 'MEDIUM').replace('cdbd-sev-unspecified', 'cdbd-sev-medium')
    rendered = converge_cti_dossier(html, _article(cvss_score=9.8))
    assert '<strong>MEDIUM</strong>' in rendered
    assert '<strong>CRITICAL</strong>' not in rendered


def test_v6_is_idempotent_and_script_free():
    once = converge_cti_dossier(LIVE_SHAPE, _article())
    twice = converge_cti_dossier(once, _article())
    assert once == twice
    assert once.count(f'<!-- {MARKER} -->') == 1
    assert '<script' not in once.lower()


def test_noncanonical_numbered_subsection_is_preserved():
    html = LIVE_SHAPE.replace(
        '<p><strong>10. Technical Analysis</strong></p><p>deep technical body that must survive</p>',
        '<p><strong>10. Technical Analysis</strong></p><p>deep technical body that must survive</p>'
        '<p><strong>11. Exploit Preconditions</strong></p><p>unique precondition detail</p>',
    )
    rendered = converge_cti_dossier(html, _article())
    assert 'unique precondition detail' in rendered
