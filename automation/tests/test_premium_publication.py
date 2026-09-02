from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from automation.blogger_publisher import BloggerPublisher
from automation.config import Config
from automation.content_discovery import DiscoveredArticle
from automation.premium_publication import (
    MIN_VISIBLE_WORDS,
    PremiumAuthorityTransformer,
    VerifiedBloggerPublisher,
    assess_enterprise_report,
    assess_live_artifact,
    build_premium_analyst_prompt,
    infer_report_type,
    install_runtime_overrides,
)


def _article(**overrides):
    values = dict(
        url="https://example.test/advisory/CVE-2026-99999",
        title="CVE-2026-99999 Example Product remote security advisory",
        summary="Example Vendor reports a security issue affecting Example Product. The source describes the issue and remediation guidance.",
        published_at="2026-09-02T00:00:00Z",
        content_hash="abc123",
        labels=["Threat Intelligence", "Vulnerabilities", "CVE Analysis"],
        source="nvd",
        full_content=("Example Vendor Example Product CVE-2026-99999 evidence and remediation details. " * 80),
        source_publisher="Example Vendor",
        cve_id="CVE-2026-99999",
        cvss_score=8.1,
        cwe_ids=["CWE-20"],
        affected_vendor="Example Vendor",
        affected_product="Example Product",
        kev_listed=False,
    )
    values.update(overrides)
    return DiscoveredArticle(**values)


def _generic_article(title: str, *, source: str = "rss", labels=None, summary=None, full_content=None, **overrides):
    """Return a non-CVE fixture whose metadata is internally consistent.

    The base fixture intentionally represents a CVE advisory and therefore
    carries CVE-specific title/content/labels and structured vulnerability
    fields. Reusing it for malware/incident classifier cases while clearing
    only ``cve_id`` creates contradictory evidence: the classifier correctly
    sees the remaining CVE content and labels and returns a vulnerability
    report. Family-classification tests must isolate the signal they intend
    to exercise rather than smuggling CVE evidence in through fixture defaults.
    """
    values = dict(
        url="https://example.test/intel/report",
        title=title,
        summary=summary or title,
        source=source,
        full_content=full_content or (title + ". Enterprise threat intelligence source material."),
        labels=labels if labels is not None else ["Threat Intelligence"],
        source_publisher="Example Publisher",
        cve_id=None,
        cvss_score=None,
        cvss_vector=None,
        cwe_ids=None,
        affected_vendor=None,
        affected_product=None,
        epss_score=None,
        epss_percentile=None,
        kev_listed=None,
        kev_date_added=None,
        kev_due_date=None,
        kev_required_action=None,
        ransomware_group=None,
        ransomware_sector=None,
        ransomware_country=None,
    )
    values.update(overrides)
    return _article(**values)


_CORE = [
    "Executive Summary", "Verified Facts", "Threat Classification", "Threat Severity Assessment",
    "Business Impact", "Technical Analysis", "CVE Analysis", "MITRE ATT&CK Mapping", "IOC Intelligence",
    "Detection Engineering Guidance", "Threat Hunting Queries", "SOC Analyst Playbook", "Executive Decision Matrix",
    "Executive Recommendations", "Sentinel APEX Intelligence Correlation", "Predictive Intelligence",
    "Long-Term Strategic Risk", "Evidence & Source Assessment", "Timeline & Chronology", "Enterprise Exposure Assessment",
    "Detection Validation & Required Telemetry", "Incident Response & Containment Decision Plan",
    "Remediation & Validation Plan", "Intelligence Gaps & Collection Requirements", "Analytic Confidence & Limitations",
    "References",
]


def _rich_html(article=None, words=None):
    article = article or _article()
    words = words or (MIN_VISIBLE_WORDS + 250)
    headings = "".join(
        f"<h3>{h}</h3><p>{'analysis evidence decision telemetry ' * 12}</p>"
        f"<ul><li>{'action evidence ' * 6}</li></ul>" for h in _CORE
    )
    filler = " ".join(["evidence"] * words)
    return (
        f'<article data-report-id="CDB-CTI-2026-ABCDEF123456">'
        f'<!-- CDB_SOURCE_URL:{article.url} -->'
        f'<p>{article.cve_id} {article.affected_vendor} {article.affected_product}</p>'
        f'{headings}<p>{filler}</p><p>Source: {article.url}</p></article>'
    )


def _transformed(article=None, **overrides):
    article = article or _article()
    values = dict(
        content=_rich_html(article), content_source="groq", quality_score=93,
        achieved_tier="FLASH_READY", product_tier="TACTICAL",
        evidence_graph={"claims": {"c1": {}}, "sources": {"s1": {}}},
        report_id="CDB-CTI-2026-ABCDEF123456", source_url=article.url,
    )
    values.update(overrides)
    return values


def test_report_type_classifier_covers_requested_commercial_families():
    assert infer_report_type(_article()) == "CVE_VULNERABILITY_REPORT"
    assert infer_report_type(_generic_article("Akira ransomware claim", source="ransomware_intel", ransomware_group="Akira")) == "RANSOMWARE_REPORT"
    assert infer_report_type(_generic_article("Data breach disclosed", source="breach_intel")) == "DATA_BREACH_REPORT"
    assert infer_report_type(_generic_article("New malware campaign uses credential stealer")) == "MALWARE_CAMPAIGN"
    assert infer_report_type(_generic_article("Deep malware analysis of a new backdoor")) == "MALWARE_ANALYSIS"
    assert infer_report_type(_generic_article("Security incident disrupts enterprise services")) == "CYBER_INCIDENT_REPORT"


def test_structured_vulnerability_signal_remains_authoritative_over_generic_incident_words():
    article = _article(title="Security incident involving CVE-2026-99999", labels=["Threat Intelligence", "Incident Response"])
    assert infer_report_type(article) == "CVE_VULNERABILITY_REPORT"


def test_premium_prompt_expands_source_window_and_preserves_evidence_boundary():
    article = _article(full_content="X" * 12000)
    prompt = build_premium_analyst_prompt(article)
    assert "PRODUCTION PREMIUM LONG-FORM CONTRACT" in prompt
    assert "UNTRUSTED SOURCE DATA START" in prompt
    assert "Detection Validation & Required Telemetry" in prompt
    assert "Intelligence Gaps & Collection Requirements" in prompt
    assert "Not established in cited evidence." in prompt
    assert "CVE_VULNERABILITY_REPORT" in prompt
    assert "X" * 6000 in prompt


def test_enterprise_gate_accepts_long_form_llm_report_with_evidence_graph():
    article = _article()
    result = assess_enterprise_report(article, _transformed(article))
    assert result.ready is True
    assert result.visible_words >= MIN_VISIBLE_WORDS
    assert result.distinct_headings >= 18


def test_enterprise_gate_blocks_safe_but_thin_fallback_renderer():
    article = _article()
    result = assess_enterprise_report(article, _transformed(article, content_source="reportx_composer"))
    assert result.ready is False
    assert any("not LLM-authored" in reason for reason in result.reasons)


def test_enterprise_gate_never_confuses_public_quality_band_with_certification():
    article = _article()
    transformed = _transformed(article)
    result = assess_enterprise_report(article, transformed)
    assert result.quality_band == "PREMIUM_PUBLIC_LONG_FORM"
    assert "CERTIFIED" not in result.quality_band
    assert transformed["achieved_tier"] == "FLASH_READY"


def test_live_artifact_exact_copy_passes_strict_fetch_back():
    article = _article()
    content = _rich_html(article)
    live = {"title": article.title, "content": content, "labels": article.labels}
    result = assess_live_artifact(live, article.title, content, article.labels)
    assert result.verified is True
    assert result.exact_content_match is True
    assert result.word_retention == pytest.approx(1.0)
    assert result.heading_retention == pytest.approx(1.0)


def test_live_artifact_detects_customer_visible_content_collapse():
    article = _article()
    intended = _rich_html(article)
    live = {"title": article.title, "content": "<h3>Executive Summary</h3><p>short</p>", "labels": article.labels}
    result = assess_live_artifact(live, article.title, intended, article.labels)
    assert result.verified is False
    assert "live_copy_below_premium_word_floor" in result.defects
    assert any(d.startswith("word_retention_below_") for d in result.defects)
    assert any(d.startswith("heading_retention_below_") for d in result.defects)


def test_verified_publisher_repairs_same_post_id_before_returning_success():
    article = _article()
    content = _rich_html(article)
    bad = {"title": article.title, "content": "<h3>Executive Summary</h3><p>short</p>", "labels": article.labels}
    good = {"title": article.title, "content": content, "labels": article.labels}
    publisher = VerifiedBloggerPublisher(Config(blogger_blog_id="blog-1"))
    publisher.get_post = Mock(side_effect=[bad, good])
    publisher.patch_post_preview = Mock(return_value={})
    publisher.update_post = Mock(return_value={})
    publisher._revert_to_draft = Mock()

    with patch.object(BloggerPublisher, "publish_post", return_value={"id": "post-123", "status": "LIVE"}), \
         patch("automation.premium_publication.time.sleep", return_value=None):
        result = publisher.publish_post(article.title, content, article.labels, image_url="https://example.test/card.png")

    assert result["id"] == "post-123"
    publisher.patch_post_preview.assert_called_once()
    publisher._revert_to_draft.assert_not_called()
    assert publisher.get_post.call_count == 2


def test_verified_publisher_reverts_unrecoverable_defective_live_copy():
    article = _article()
    content = _rich_html(article)
    bad = {"title": article.title, "content": "<h3>Executive Summary</h3><p>short</p>", "labels": article.labels}
    publisher = VerifiedBloggerPublisher(Config(blogger_blog_id="blog-1"))
    publisher.get_post = Mock(return_value=bad)
    publisher.patch_post_preview = Mock(return_value={})
    publisher.update_post = Mock(return_value={})
    publisher._revert_to_draft = Mock()

    with patch.object(BloggerPublisher, "publish_post", return_value={"id": "post-456", "status": "LIVE"}), \
         patch("automation.premium_publication.time.sleep", return_value=None), \
         pytest.raises(Exception) as exc:
        publisher.publish_post(article.title, content, article.labels)

    assert "reverted to draft" in str(exc.value)
    publisher._revert_to_draft.assert_called_once_with("post-456")


def test_runtime_override_reuses_existing_pipeline_orchestration():
    fake_main = SimpleNamespace(AuthorityTransformer=None, BloggerPublisher=None)
    install_runtime_overrides(fake_main)
    assert fake_main.AuthorityTransformer is PremiumAuthorityTransformer
    assert fake_main.BloggerPublisher is VerifiedBloggerPublisher
