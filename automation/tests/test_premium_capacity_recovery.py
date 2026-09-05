from __future__ import annotations

from automation import premium_capacity_recovery as capacity
from automation import premium_incident_recovery as recovery
from automation import premium_publication as premium
from automation.config import Config


def _dense_fragment(paragraphs: int = 10, items: int = 10, words_per_paragraph: int = 80) -> str:
    p = " ".join(["analysis"] * words_per_paragraph)
    return (
        "".join(f"<p>{p}</p>" for _ in range(paragraphs))
        + "<ul>"
        + "".join(f"<li>evidence specific validation action {i}</li>" for i in range(items))
        + "</ul>"
    )


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
    assert recovery._raw_contract_complete(result[0]) is True
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
    assert recovery._raw_contract_complete(result[0]) is False


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


def test_continuation_prompt_preserves_no_fabrication_contract():
    base = _dense_fragment(paragraphs=10, items=10, words_per_paragraph=50)
    prompt = capacity._continuation_prompt("SOURCE EVIDENCE", base, 1)
    assert "Never invent a fact" in prompt
    assert "do not repeat" in prompt.lower()
    assert "Current deficit" in prompt
