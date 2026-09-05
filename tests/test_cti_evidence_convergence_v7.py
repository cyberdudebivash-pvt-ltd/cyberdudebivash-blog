from types import SimpleNamespace

from automation import cti_evidence_convergence_v7 as v7


def test_live_shape_repairs_severity_and_removes_legacy_canonical_sections():
    html = """
    <section class="cdbd-command cdbd-sev-unspecified">
      <div class="cdbd-kpi cdbd-kpi-severity"><span>SEVERITY</span><strong>UNSPECIFIED</strong></div>
    </section>
    <section><strong>CVSS Score</strong><div>9.3</div><div>CRITICAL</div></section>
    <h3>Technical Analysis</h3>
    <p><strong>Executive Summary</strong></p>
    <p>legacy summary that must not coexist with deterministic output</p>
    <p><strong>Technical Analysis</strong></p>
    <p>unique deep technical body that must survive convergence</p>
    <p><strong>MITRE ATT&amp;CK Assessment</strong></p>
    <p>T1190 speculative legacy mapping</p>
    <p><strong>Forecast / Outlook</strong></p>
    <p>threat actors will exploit this in 3-6 months</p>
    <h3>MITRE ATT&amp;CK Assessment</h3>
    <p>Not established in cited evidence.</p>
    <h3>Forecast &amp; Outlook</h3>
    <p>No new future event is predicted by the compiler.</p>
    <h3>Executive Summary</h3>
    <p>Evidence-bounded deterministic summary.</p>
    """

    rendered = v7.converge_cti_dossier(html, SimpleNamespace())

    assert v7.MARKER in rendered
    assert ">CRITICAL<" in rendered
    assert "cdbd-sev-critical" in rendered
    assert "legacy summary that must not coexist" not in rendered
    assert "T1190 speculative legacy mapping" not in rendered
    assert "threat actors will exploit this in 3-6 months" not in rendered
    assert "unique deep technical body that must survive convergence" in rendered
    assert "Not established in cited evidence." in rendered
    assert "No new future event is predicted by the compiler." in rendered
    assert "Evidence-bounded deterministic summary." in rendered


def test_v7_installs_even_when_existing_v5_wrapper_has_same_function_name(monkeypatch):
    class FakeTransformer:
        pass

    def base(self, article, body_content, seo_data, context, image_url=None):
        return '<div class="cdbd-kpi-severity"><strong>UNSPECIFIED</strong></div><p>CVSS Score 7.0</p>'

    def _patched_assemble_html(self, article, body_content, seo_data, context, image_url=None):
        return base(self, article, body_content, seo_data, context, image_url)

    # This exactly reproduces the production collision: Dossier v5 and v6 both
    # used the generic function name `_patched_assemble_html`.
    FakeTransformer._assemble_html = _patched_assemble_html
    module = SimpleNamespace(AuthorityTransformer=FakeTransformer)

    monkeypatch.setattr(v7, "_ORIGINAL_ASSEMBLE_HTML", None)
    before = FakeTransformer._assemble_html
    assert before.__name__ == "_patched_assemble_html"

    v7.install_cti_evidence_convergence_v7(module)

    after = FakeTransformer._assemble_html
    assert after is not before
    assert getattr(after, v7._INSTALL_ATTR, False) is True

    instance = FakeTransformer()
    rendered = instance._assemble_html(None, "", {}, None)
    assert v7.MARKER in rendered
    assert ">HIGH<" in rendered

    # Explicit marker provides real idempotency without relying on function name.
    v7.install_cti_evidence_convergence_v7(module)
    assert FakeTransformer._assemble_html is after


def test_explicit_existing_severity_is_never_overwritten():
    html = """
    <section class="cdbd-command cdbd-sev-medium">
      <div class="cdbd-kpi cdbd-kpi-severity"><strong>MEDIUM</strong></div>
    </section>
    <p>CVSS Score 9.8</p>
    """
    rendered = v7.converge_cti_dossier(html, SimpleNamespace())
    assert ">MEDIUM<" in rendered
    assert "cdbd-sev-medium" in rendered
    assert "cdbd-sev-critical" not in rendered
