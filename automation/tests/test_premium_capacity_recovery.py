from __future__ import annotations

from automation import generation_evidence_admission as admission
from automation import premium_capacity_recovery as capacity
from automation import premium_publication as premium
from automation.config import Config
from automation.content_discovery import DiscoveredArticle


def _dense_fragment(paragraphs: int = 10, items: int = 10, words_per_paragraph: int = 80) -> str:
    p = " ".join(["analysis"] * words_per_paragraph)
    return (
        "".join(f"<p>{p}</p>" for _ in range(paragraphs))
        + "<ul>"
        + "".join(f"<li>evidence specific validation action {i}</li>" for i in range(items))
        + "</ul>"
    )


def _article(**overrides) -> DiscoveredArticle:
    values = dict(
        url="https://example.test/source",
        title="Source-backed malware campaign",
        summary="The source reports malicious activity without an ATT&CK technique mapping.",
        published_at="2026-09-05T10:00:00Z",
        content_hash="abc123",
        labels=["Threat Intelligence"],
        source="global_rss",
        full_content="The source describes malicious activity but provides no ATT&CK technique identifier.",
    )
    values.update(overrides)
    return DiscoveredArticle(**values)


def test_continuation_rescue_uses_bounded_qwen_calls_and_reaches_existing_contract(monkeypatch):
    config = Config(
        groq_api_key="test-key",
        llm_model_groq="qwen/qwen3.8-27b",
        llm_model_groq_fallbacks=("openai/gpt-oss-120b", "qwen/qwen3.6-27b"),
    )
    base = _dense_fragment(paragraphs=10, items=10, words_per_paragraph=100)
    fragment = _dense_fragment(paragraphs=8, items=8, words_per_paragraph=160)

    monkeypatch.setattr(capacity, "_ORIGINAL_PREMIUM_LLM_CALL", lambda *args, **kwargs: (base, "groq"))
    calls = []

    def try_provider(**kwargs):
        calls.append(kwargs)
        return fragment

    monkeypatch.setattr(capacity._llm, "_try_provider", try_provider)

    result = capacity.capacity_aware_premium_llm(
        config, "source-grounded prompt", attempts=[], sleep_fn=lambda _: None
    )

    assert result is not None
    assert capacity._active_contract_complete(result[0]) is True
    assert len(calls) == 1
    assert calls[0]["max_tokens"] == capacity.CONTINUATION_MAX_TOKENS
    assert calls[0]["max_tokens"] <= 900
    assert "qwen" in calls[0]["model"].lower()


def test_complete_candidate_never_spends_continuation_quota(monkeypatch):
    config = Config(groq_api_key="test-key", llm_model_groq="qwen/qwen3.8-27b")
    complete = _dense_fragment(paragraphs=18, items=18, words_per_paragraph=125)
    monkeypatch.setattr(capacity, "_ORIGINAL_PREMIUM_LLM_CALL", lambda *args, **kwargs: (complete, "groq"))

    def unexpected(**kwargs):
        raise AssertionError("continuation quota must not be spent for a complete candidate")

    monkeypatch.setattr(capacity._llm, "_try_provider", unexpected)
    assert capacity.capacity_aware_premium_llm(config, "prompt", attempts=[], sleep_fn=lambda _: None) == (complete, "groq")


def test_tiny_candidate_is_not_padded_into_premium_report(monkeypatch):
    config = Config(groq_api_key="test-key", llm_model_groq="qwen/qwen3.8-27b")
    tiny = "<p>insufficient evidence for premium depth</p>"
    monkeypatch.setattr(capacity, "_ORIGINAL_PREMIUM_LLM_CALL", lambda *args, **kwargs: (tiny, "groq"))

    def unexpected(**kwargs):
        raise AssertionError("thin source material must remain below the premium gate")

    monkeypatch.setattr(capacity._llm, "_try_provider", unexpected)
    result = capacity.capacity_aware_premium_llm(config, "prompt", attempts=[], sleep_fn=lambda _: None)
    assert result == (tiny, "groq")
    assert capacity._active_contract_complete(result[0]) is False


def test_active_contract_rejects_stage4_unsupported_attack_id():
    article = _article()
    dense = _dense_fragment(paragraphs=18, items=18, words_per_paragraph=125)
    unsafe = dense + "<p>ATT&CK technique T1566 applies to this campaign.</p>"
    token = admission._CURRENT_ARTICLE.set(article)
    try:
        assert capacity._semantic_floor_complete(unsafe) is True
        assert capacity._active_contract_complete(unsafe) is False
    finally:
        admission._CURRENT_ARTICLE.reset(token)


def test_fragment_sanitizer_removes_headings_references_and_active_content():
    raw = (
        '<script>alert(1)</script><h3>Technical Analysis</h3>'
        '<p>evidence specific analytical paragraph with enough useful words for semantic counting</p>'
        '<h3>References</h3><p>invented reference should not become model-owned structure</p>'
    )
    safe = capacity._safe_fragment_html(raw)
    assert "<script" not in safe
    assert "<h3" not in safe
    assert "Technical Analysis" in safe
    assert premium._word_count(safe) > 0


def test_fragment_sanitizer_handles_nested_reference_heading_detachment():
    """Regression for production #8630: parent decompose detaches child snapshot node."""
    raw = (
        '<h2>References <h3>Nested model heading</h3></h2>'
        '<p class="model-output" onclick="alert(1)">source bounded analytical body</p>'
        '<h4>Technical Analysis <h5>Nested subsection</h5></h4>'
        '<script>alert(1)</script>'
    )

    safe = capacity._safe_fragment_html(raw)

    # The exact production failure was a ValueError before this point. The
    # resulting fragment must also retain the original sanitizer boundaries.
    assert "References" not in safe
    assert "<h2" not in safe
    assert "<h3" not in safe
    assert "<h4" not in safe
    assert "<h5" not in safe
    assert "<script" not in safe
    assert "onclick" not in safe
    assert 'class="model-output"' not in safe
    assert "source bounded analytical body" in safe
    assert "Technical Analysis" in safe


def test_fragment_sanitizer_is_idempotent_for_already_safe_body_html():
    raw = '<p><strong>Evidence</strong> bounded analysis</p><ul><li>validate telemetry</li></ul>'
    once = capacity._safe_fragment_html(raw)
    twice = capacity._safe_fragment_html(once)
    assert twice == once


def test_continuation_prompt_preserves_no_fabrication_contract():
    base = _dense_fragment(paragraphs=10, items=10, words_per_paragraph=50)
    prompt = capacity._continuation_prompt("SOURCE EVIDENCE", base, 1)
    assert "Never invent a fact" in prompt
    assert "do not repeat" in prompt.lower()
    assert "Current deficit" in prompt
