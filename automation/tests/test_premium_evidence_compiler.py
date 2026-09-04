from types import SimpleNamespace

from bs4 import BeautifulSoup

from automation import premium_evidence_compiler as compiler
from automation import premium_publication as premium
from automation.content_discovery import DiscoveredArticle
from automation.report_integrity import build_report_context


def _article(**overrides):
    values = dict(
        url="https://example.test/advisory/CVE-2026-9999",
        title="CVE-2026-9999 Example Product remote code execution vulnerability",
        summary="Example Vendor disclosed a vulnerability affecting Example Product. Customer exposure is not established by this public record.",
        published_at="2026-09-03T12:00:00Z",
        content_hash="stage2-test",
        labels=["Threat Intelligence", "CVE Analysis"],
        source="nvd",
        source_publisher="Example Vendor",
        full_content="Example Vendor disclosed CVE-2026-9999 affecting Example Product. Remediation details are supplied by the authoritative advisory.",
        cve_id="CVE-2026-9999",
        cvss_score=9.8,
        affected_vendor="Example Vendor",
        affected_product="Example Product",
        kev_listed=False,
    )
    values.update(overrides)
    return DiscoveredArticle(**values)


def _dense_body(words_per_paragraph=130, paragraphs=18, list_items=18):
    body = []
    for i in range(paragraphs):
        body.append("<p>" + " ".join(f"evidence{i}_{j}" for j in range(words_per_paragraph)) + "</p>")
    body.append("<ul>")
    for i in range(list_items):
        body.append(f"<li>source specific validation action item {i}</li>")
    body.append("</ul>")
    return "".join(body)


def _passing_assessment():
    return premium.EnterpriseQualityAssessment(
        ready=True,
        report_type="CVE_VULNERABILITY_REPORT",
        quality_band=premium.PUBLIC_QUALITY_BAND,
        visible_words=4300,
        distinct_headings=25,
        substantive_paragraphs=25,
        substantive_list_items=25,
        reasons=(),
    )


def test_contract_has_exact_25_stable_sections():
    assert len(compiler.CANONICAL_SECTION_CONTRACT) == 25
    ids = [item[0] for item in compiler.CANONICAL_SECTION_CONTRACT]
    assert len(ids) == len(set(ids))
    assert ids[0] == "executive_summary"
    assert ids[-1] == "references"


def test_compiler_owns_all_public_h3_headings_in_exact_order():
    article = _article()
    context = build_report_context(article)
    raw = '<h2>Wrong heading</h2><p>source specific analytical content remains intact here</p>'
    rendered = compiler.compile_premium_body(article, context, raw)
    soup = BeautifulSoup(rendered, "html.parser")
    headings = [" ".join(h.stripped_strings) for h in soup.find_all("h3")]
    assert headings == [title for _, title in compiler.CANONICAL_SECTION_CONTRACT]
    assert "Wrong heading" in rendered
    assert soup.find("h2") is None


def test_model_supplied_references_are_removed_and_rebuilt_from_provenance():
    article = _article()
    context = build_report_context(article)
    raw = (
        '<h3>Technical Analysis</h3><p>Evidence-specific content.</p>'
        '<h3>References</h3><ul><li><a href="https://evil.example/fabricated">fabricated</a></li></ul>'
    )
    rendered = compiler.compile_premium_body(article, context, raw)
    assert "evil.example" not in rendered
    assert article.url in rendered
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-9999" in rendered
    assert [" ".join(h.stripped_strings) for h in BeautifulSoup(rendered, "html.parser").find_all("h3")].count("References") == 1


def test_reference_builder_rejects_non_http_private_and_credentialed_targets():
    assert compiler._safe_reference_url("javascript:alert(1)") is None
    assert compiler._safe_reference_url("file:///etc/passwd") is None
    assert compiler._safe_reference_url("http://127.0.0.1/private") is None
    assert compiler._safe_reference_url("http://10.0.0.7/private") is None
    assert compiler._safe_reference_url("https://user:secret@example.test/advisory") is None
    assert compiler._safe_reference_url("https://nvd.nist.gov/vuln/detail/CVE-2026-9999") is not None


def test_reference_builder_adds_kev_and_epss_only_when_structured_evidence_exists():
    plain = compiler.deterministic_references(_article())
    plain_urls = {url for _, url in plain}
    assert "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" not in plain_urls
    assert "https://www.first.org/epss/" not in plain_urls

    enriched = compiler.deterministic_references(_article(kev_listed=True, epss_score=0.91))
    urls = {url for _, url in enriched}
    assert "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" in urls
    assert "https://www.first.org/epss/" in urls


def test_semantic_preflight_refuses_short_1715_word_report_even_with_dense_structure():
    body = _dense_body(words_per_paragraph=90, paragraphs=18, list_items=18)
    assert premium._word_count(body) < premium.MIN_VISIBLE_WORDS
    assert compiler.compiler_semantic_preflight_complete(body) is False


def test_semantic_preflight_refuses_4000_words_in_only_eight_paragraphs():
    body = _dense_body(words_per_paragraph=500, paragraphs=8, list_items=18)
    assert premium._word_count(body) > 4000
    assert compiler.compiler_semantic_preflight_complete(body) is False


def test_semantic_preflight_accepts_real_depth_without_requiring_model_headings():
    body = _dense_body(words_per_paragraph=130, paragraphs=18, list_items=18)
    assert premium._word_count(body) >= premium.MIN_VISIBLE_WORDS
    assert BeautifulSoup(body, "html.parser").find("h3") is None
    assert compiler.compiler_semantic_preflight_complete(body) is True


def test_deterministic_key_judgement_never_calls_external_llm():
    article = _article()
    context = build_report_context(article)
    graph = {
        "claims": {
            "c-cve-id": {"claim_id": "c-cve-id", "claim_type": "VULNERABILITY_FACT", "text": "CVE-2026-9999 assigned", "status": "CONFIRMED"}
        }
    }

    def forbidden(*args, **kwargs):
        raise AssertionError("external LLM must not be called")

    judgements, rejections = compiler.derive_key_judgements(
        article,
        object(),
        graph,
        (),
        {"overall_confidence": "MEDIUM"},
        context,
        call_llm_fn=forbidden,
    )
    assert rejections == ()
    assert len(judgements) == 1
    assert judgements[0].claim_refs == ("c-cve-id",)
    assert judgements[0].verification_status == "SUPPORTED"


def test_ransomware_judgement_preserves_leak_claim_boundary():
    article = _article(
        source="ransomware_intel",
        cve_id=None,
        affected_vendor=None,
        affected_product=None,
        ransomware_group="ExampleGroup",
        title="ExampleGroup ransomware claim",
        full_content="ExampleGroup listed Example Victim on its leak site.",
    )
    context = SimpleNamespace(family="ransomware_claim")
    graph = {"claims": {"c-victim-claim": {"claim_id": "c-victim-claim", "status": "REPORTED"}}}
    judgements, _ = compiler.derive_key_judgements(article, object(), graph, (), {}, context)
    text = judgements[0].judgement.lower()
    assert "validation trigger" in text
    assert "not confirmation" in text
    assert "breach" in text


def test_blocking_contradiction_prevents_deterministic_judgement():
    article = _article()
    context = build_report_context(article)
    graph = {"claims": {"c-summary": {"claim_id": "c-summary", "status": "REPORTED"}}}
    judgements, reasons = compiler.derive_key_judgements(
        article, object(), graph, ({"severity": "block", "description": "sources disagree"},), {}, context
    )
    assert judgements == ()
    assert reasons == ("BLOCKING_CONTRADICTION",)


def test_compiler_assessment_preserves_precompiler_word_floor(monkeypatch):
    monkeypatch.setattr(compiler, "_ORIGINAL_ASSESSMENT", lambda article, transformed: _passing_assessment())
    transformed = {
        "compiler_input_visible_words": 1715,
        "compiler_input_substantive_paragraphs": 20,
        "compiler_input_substantive_list_items": 20,
    }
    assessment = compiler._assessment_with_input_floor(_article(), transformed)
    assert assessment.ready is False
    assert any("pre-compiler analytical depth 1715" in reason for reason in assessment.reasons)


def test_compiler_assessment_preserves_precompiler_paragraph_and_list_floors(monkeypatch):
    monkeypatch.setattr(compiler, "_ORIGINAL_ASSESSMENT", lambda article, transformed: _passing_assessment())
    transformed = {
        "compiler_input_visible_words": 4100,
        "compiler_input_substantive_paragraphs": 8,
        "compiler_input_substantive_list_items": 15,
    }
    assessment = compiler._assessment_with_input_floor(_article(), transformed)
    assert assessment.ready is False
    assert any("paragraph density 8" in reason for reason in assessment.reasons)
    assert any("list density 15" in reason for reason in assessment.reasons)


def test_measured_zero_precompiler_metrics_fail_closed(monkeypatch):
    monkeypatch.setattr(compiler, "_ORIGINAL_ASSESSMENT", lambda article, transformed: _passing_assessment())
    transformed = {
        "compiler_input_visible_words": 0,
        "compiler_input_substantive_paragraphs": 0,
        "compiler_input_substantive_list_items": 0,
    }
    assessment = compiler._assessment_with_input_floor(_article(), transformed)
    assert assessment.ready is False
    assert any("analytical depth 0" in reason for reason in assessment.reasons)
    assert any("paragraph density 0" in reason for reason in assessment.reasons)
    assert any("list density 0" in reason for reason in assessment.reasons)


def test_absent_precompiler_metrics_remain_unmeasured_not_fake_zero(monkeypatch):
    monkeypatch.setattr(compiler, "_ORIGINAL_ASSESSMENT", lambda article, transformed: _passing_assessment())
    assessment = compiler._assessment_with_input_floor(_article(), {})
    assert assessment.ready is True
    assert not any("pre-compiler" in reason for reason in assessment.reasons)


def test_patched_base_transform_does_not_materialize_missing_metrics(monkeypatch):
    monkeypatch.setattr(
        compiler,
        "_ORIGINAL_BASE_TRANSFORM",
        lambda self, article: {"content_source": "groq", "llm_attempts": []},
    )
    transformer = SimpleNamespace()
    result = compiler._patched_base_transform(transformer, _article())
    assert "compiler_input_visible_words" not in result
    assert "compiler_input_substantive_paragraphs" not in result
    assert "compiler_input_substantive_list_items" not in result


def test_compiler_does_not_insert_source_specific_iocs_or_attack_techniques():
    article = _article(full_content="No IOC or ATT&CK technique is supplied by this test source.")
    context = build_report_context(article)
    rendered = compiler.compile_premium_body(article, context, "<p>Evidence analysis only.</p>")
    assert "T1190" not in rendered
    assert "192.0.2." not in rendered
    assert "malicious.example" not in rendered
