from automation.cti_ioc_state_reconciliation import MARKER, reconcile_ioc_state

NOT_ESTABLISHED_ONLY = """
<article>
<section data-cdb-section="indicators_observables">
<h3>Indicators &amp; Observables</h3>
<p>Not established in cited evidence. The factory does not infer the missing fact from absence of evidence.</p>
</section>
</article>
"""

WITH_REAL_INDICATORS = """
<article>
<section data-cdb-section="indicators_observables">
<h3>Indicators &amp; Observables</h3>
<p>Not established in cited evidence. The factory does not infer the missing fact from absence of evidence.</p>
</section>
<section data-section="indicators-/-observables">
<div>INDICATORS / OBSERVABLES</div>
<ul><li><strong>MD5:</strong> 581e2e2265d0c1509b3799c5a9039374</li></ul>
<div>Indicators are defanged for safe display.</div>
</section>
</article>
"""


def test_leaves_genuinely_evidence_free_report_untouched():
    rendered = reconcile_ioc_state(NOT_ESTABLISHED_ONLY)
    assert MARKER not in rendered
    assert "Not established in cited evidence" in rendered


def test_reconciles_stale_label_when_real_indicator_exists():
    rendered = reconcile_ioc_state(WITH_REAL_INDICATORS)
    assert MARKER in rendered
    assert "VERIFIED ARTIFACTS AVAILABLE" in rendered
    assert "Not established in cited evidence" not in rendered
    # The real indicator section itself is never modified.
    assert "581e2e2265d0c1509b3799c5a9039374" in rendered


def test_is_idempotent():
    once = reconcile_ioc_state(WITH_REAL_INDICATORS)
    twice = reconcile_ioc_state(once)
    assert once == twice
    assert once.count(f"<!-- {MARKER} -->") == 1


def test_ignores_indicator_looking_text_outside_the_real_section():
    html = NOT_ESTABLISHED_ONLY.replace(
        "</article>", "<p>See vendor advisory for MD5: details.</p></article>"
    )
    rendered = reconcile_ioc_state(html)
    assert MARKER not in rendered
    assert "Not established in cited evidence" in rendered
