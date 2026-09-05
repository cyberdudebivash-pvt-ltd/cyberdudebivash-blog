"""Regression tests for the production #8623 Stage-5 runtime-alias defect."""
from __future__ import annotations

from automation import authority_transformer as authority
from automation import premium_capacity_recovery as capacity
from automation import premium_capacity_runtime_binding as binding
from automation.config import Config


def _dense_fragment(paragraphs: int, items: int, words_per_paragraph: int) -> str:
    paragraph = " ".join(["analysis"] * words_per_paragraph)
    return (
        "".join(f"<p>{paragraph}</p>" for _ in range(paragraphs))
        + "<ul>"
        + "".join(f"<li>evidence specific validation action {i}</li>" for i in range(items))
        + "</ul>"
    )


def test_runtime_binding_wraps_actual_authority_consumer(monkeypatch):
    """Replacing premium module aliases is insufficient; live consumer must be rebound."""
    calls = []

    def stage4_live_call(config, prompt, max_tokens=3000, attempts=None, sleep_fn=None):
        calls.append("stage4")
        return _dense_fragment(10, 10, 100), "groq"

    monkeypatch.setattr(authority, "call_llm", stage4_live_call)
    monkeypatch.setattr(binding, "_INSTALLED", False)
    monkeypatch.setattr(capacity, "_ORIGINAL_PREMIUM_LLM_CALL", None)

    fragment = _dense_fragment(8, 8, 160)
    provider_calls = []

    def short_provider(**kwargs):
        provider_calls.append(kwargs)
        return fragment

    monkeypatch.setattr(capacity._llm, "_try_provider", short_provider)

    binding.install_capacity_runtime_binding_fix()

    assert authority.call_llm is capacity.capacity_aware_premium_llm
    assert capacity._ORIGINAL_PREMIUM_LLM_CALL is stage4_live_call

    result = authority.call_llm(
        Config(groq_api_key="test-key", llm_model_groq="qwen/qwen3.8-27b"),
        "source-grounded prompt",
        attempts=[],
        sleep_fn=lambda _: None,
    )

    assert calls == ["stage4"]
    assert result is not None
    assert capacity._active_contract_complete(result[0]) is True
    assert len(provider_calls) == 1
    assert provider_calls[0]["max_tokens"] <= 900


def test_runtime_binding_is_idempotent(monkeypatch):
    """Repeated startup hooks must never wrap capacity recovery around itself."""
    def stage4_live_call(config, prompt, max_tokens=3000, attempts=None, sleep_fn=None):
        return None

    monkeypatch.setattr(authority, "call_llm", stage4_live_call)
    monkeypatch.setattr(binding, "_INSTALLED", False)
    monkeypatch.setattr(capacity, "_ORIGINAL_PREMIUM_LLM_CALL", None)

    binding.install_capacity_runtime_binding_fix()
    original = capacity._ORIGINAL_PREMIUM_LLM_CALL
    binding.install_capacity_runtime_binding_fix()

    assert authority.call_llm is capacity.capacity_aware_premium_llm
    assert capacity._ORIGINAL_PREMIUM_LLM_CALL is original
    assert original is stage4_live_call
