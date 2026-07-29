import re
from pathlib import Path

from sentinel_engine import certification
from sentinel_engine.certification import (
    FAIL,
    NEEDS_REVIEW,
    NOT_APPLICABLE,
    PASS,
    RenderingResult,
    certify,
    check_publication,
    render_release_governance_markdown,
    verdict_for,
)
from sentinel_engine.models import GateFinding

REPORTS_ROOT = Path(__file__).parent.parent.parent / "reports"
REAL_REPORT = REPORTS_ROOT / "published" / "SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md"


def _stub_rendering_ok(report_path, node_bin="node", script_path=None):
    return RenderingResult(ran=True, ok=True, issues=[], warnings=[])


def _stub_rendering_fail(report_path, node_bin="node", script_path=None):
    return RenderingResult(ran=True, ok=False, issues=["table count mismatch: 6 vs 0"], warnings=[])


def _stub_rendering_not_run(report_path, node_bin="node", script_path=None):
    return RenderingResult(ran=False, issues=["node not found"])


# ── domain-mapping completeness (static, catches future un-mapped gates) ────

def test_domain_mapping_covers_every_gate_tag_quality_py_can_emit():
    quality_src = (Path(__file__).parent.parent / "sentinel_engine" / "quality.py").read_text()
    tags = set(re.findall(r'GateFinding\(\s*"([a-z-]+)"', quality_src))
    assert tags, "sanity check: the static scan must find at least one GateFinding(...) call"
    unmapped = tags - set(certification.DOMAIN_FOR_GATE)
    assert not unmapped, f"gate tags with no certification domain mapping: {unmapped}"


def test_every_mapped_domain_is_a_real_certification_domain():
    assert set(certification.DOMAIN_FOR_GATE.values()) <= set(certification.GATE_DOMAINS)


# ── verdict_for ──────────────────────────────────────────────────────────

def test_verdict_for_blocks_is_fail_regardless_of_warnings():
    assert verdict_for(["a block"], []) == FAIL
    assert verdict_for(["a block"], ["a warning"]) == FAIL


def test_verdict_for_warnings_only_is_needs_review():
    assert verdict_for([], ["a warning"]) == NEEDS_REVIEW


def test_verdict_for_nothing_is_pass():
    assert verdict_for([], []) == PASS


# ── bucketing real GateFinding objects into domains ─────────────────────

def test_bucketing_groups_findings_into_correct_domains():
    findings = [
        GateFinding("structure", "block", "missing section"),
        GateFinding("sigma", "block", "bad sigma"),
        GateFinding("hype-language", "warn", "hype word"),
    ]
    buckets = certification._bucket_gate_findings(findings)
    assert buckets["Intelligence Quality"].verdict == FAIL
    assert buckets["Detection Quality"].verdict == FAIL
    # hype-language moved to its own Editorial Quality domain (GCIEP v1) -
    # it's a tone/style concern, not an evidence-integrity one.
    assert buckets["Editorial Quality"].verdict == NEEDS_REVIEW
    assert buckets["Evidence Quality"].verdict == PASS


def test_editorial_quality_is_a_real_certification_domain():
    # GCIEP v1: the 9-stage editorial workflow this program reviews had no
    # certification domain for Editorial Review at all before this.
    assert "Editorial Quality" in certification.ALL_DOMAINS
    assert certification.DOMAIN_FOR_GATE["hype-language"] == "Editorial Quality"


def test_release_governance_markdown_includes_editorial_findings():
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_ok)
    md = render_release_governance_markdown(cert)
    assert "## Editorial Findings" in md


def test_unmapped_gate_tag_fails_open_into_intelligence_quality():
    buckets = certification._bucket_gate_findings([GateFinding("some-future-gate", "block", "x")])
    assert buckets["Intelligence Quality"].verdict == FAIL


# ── check_publication ────────────────────────────────────────────────────

def test_check_publication_not_applicable_without_html_path():
    result = check_publication(None, "some-slug")
    assert result.checked is False


def test_check_publication_fails_on_missing_file():
    result = check_publication("/nonexistent/path.html", "slug")
    assert result.checked is True
    assert result.ok is False


def test_check_publication_passes_on_a_complete_synthetic_page(tmp_path):
    html = (tmp_path / "page.html")
    html.write_text(
        '<html><head>'
        '<link rel="canonical" href="https://example.com/x">'
        '<meta property="og:title" content="t">'
        '<meta property="og:image" content="i">'
        '<meta property="og:type" content="article">'
        '<meta name="robots" content="index, follow">'
        '<script type="application/ld+json">{"@type":"Article"}</script>'
        '</head><body></body></html>'
    )
    result = check_publication(str(html), "page")
    assert result.checked is True
    assert result.ok is True
    assert result.issues == []


def test_check_publication_flags_missing_facts():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        html = Path(d) / "page.html"
        html.write_text("<html><body>no metadata at all</body></html>")
        result = check_publication(str(html), "page")
        assert result.ok is False
        assert len(result.issues) == len(certification._REQUIRED_HTML_FACTS)


def test_check_publication_warns_when_not_in_sitemap_or_nav(tmp_path):
    html = tmp_path / "page.html"
    html.write_text(
        '<link rel="canonical" href="x"><meta property="og:title" content="t">'
        '<meta property="og:image" content="i"><meta property="og:type" content="article">'
        '<meta name="robots" content="index"><script>{"@type":"Article"}</script>'
    )
    sitemap = tmp_path / "sitemap.xml"
    sitemap.write_text("<urlset></urlset>")
    index = tmp_path / "index.html"
    index.write_text("<html>no links here</html>")
    result = check_publication(str(html), "page", str(sitemap), str(index))
    assert result.ok is True  # warnings, not blocking issues
    assert any("sitemap" in w for w in result.warnings)
    assert any("navigation" in w for w in result.warnings)


# ── certify() orchestration against the real report, rendering stubbed ────

def test_certify_real_report_with_stubbed_clean_rendering_and_no_publication():
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_ok)
    assert cert.report_id == "SA-2026-0001"
    assert cert.severity == "CRITICAL"
    # Verified via `cli.py gate`: 0 blocks, exactly 2 [attack] warns.
    assert cert.domains["Intelligence Quality"].verdict == NEEDS_REVIEW
    assert len(cert.domains["Intelligence Quality"].warnings) == 2
    # GIAAP v1's reference-completeness gate (Evidence Quality domain) found
    # and this report fixed a real gap: the live NVD REST API endpoint was
    # declared as a front-matter source but never surfaced in the rendered
    # References section (report version 1.1 added reference 7 to close it).
    assert cert.domains["Evidence Quality"].verdict == PASS
    assert cert.domains["Detection Quality"].verdict == PASS
    assert cert.domains["Rendering Quality"].verdict == PASS
    assert cert.domains["Publication Quality"].verdict == NOT_APPLICABLE
    assert cert.decision == "CERTIFIED WITH CONDITIONS"


def test_certify_fails_overall_when_rendering_fails():
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_fail)
    assert cert.domains["Rendering Quality"].verdict == FAIL
    assert cert.decision == "NOT CERTIFIED"


def test_certify_rendering_not_run_is_not_applicable_not_a_false_pass_or_fail():
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_not_run)
    assert cert.domains["Rendering Quality"].verdict == NOT_APPLICABLE
    # Not-applicable must not itself block certification.
    assert cert.decision == "CERTIFIED WITH CONDITIONS"


def test_certify_real_end_to_end_with_the_actual_node_rendering_check():
    # No stub — this really shells out to certify-rendering.js, proving the
    # full Python-to-Node composition works, not just the injected path.
    cert = certify(str(REAL_REPORT))
    assert cert.domains["Rendering Quality"].verdict == PASS
    assert cert.domains["Rendering Quality"].blocks == []


# ── Release Governance document ─────────────────────────────────────────

def test_release_governance_markdown_contains_all_required_sections():
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_ok)
    doc = render_release_governance_markdown(cert)
    for heading in (
        "Executive Summary", "Certification Summary", "Quality Findings",
        "Evidence Findings", "Detection Findings", "Rendering Findings",
        "Publication Findings", "Commercial Assessment", "Known Limitations",
        "Certification Decision",
    ):
        assert f"## {heading}" in doc, f"missing section: {heading}"
    assert "SA-2026-0001" in doc
    assert "CERTIFIED WITH CONDITIONS" in doc


def test_certify_real_report_now_produces_a_real_quantitative_score():
    # GTIEP v1 / platform/open-issues.md Issue 3 item 3: certify() previously
    # had no way to score a hand-authored report at all.
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_ok)
    assert cert.score is not None
    assert 0 <= cert.score.overall <= 100
    assert cert.score.tier in ("BLOCKED", "FREE", "PRO", "ENTERPRISE")


def test_release_governance_markdown_reports_the_real_score_not_the_old_refusal():
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_ok)
    md = render_release_governance_markdown(cert)
    assert "Quantitative score (GTIEP v1 quality framework)" in md
    assert f"{cert.score.overall}/100" in md
    # The old, pre-GTIEP-v1 blanket refusal must not still be produced
    # when a real score is available.
    assert "No quantitative commercial/tier score is presented here" not in md


def test_release_governance_markdown_never_throws_on_a_failing_report():
    cert = certify(str(REAL_REPORT), _rendering_check=_stub_rendering_fail)
    doc = render_release_governance_markdown(cert)
    assert "NOT CERTIFIED" in doc
