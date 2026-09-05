from __future__ import annotations

from automation import authority_transformer as authority
from automation import premium_capacity_recovery as capacity
from automation import premium_quota_scheduler_v11 as v11
from automation.config import Config


def test_oversized_qwen_is_reserved_before_transport(monkeypatch):
    calls = []

    def inner(**kwargs):
        calls.append(kwargs)
        return "unexpected"

    monkeypatch.setattr(v11, "_ORIGINAL_TRY_PROVIDER", inner)
    attempts = []
    result = v11.quota_aware_try_provider(
        name="groq",
        url="https://example.test",
        api_key="k",
        model="qwen/qwen3.6-27b",
        prompt="p",
        max_tokens=4400,
        extra_headers={},
        sleep_fn=lambda _: None,
        attempts=attempts,
    )
    assert result is None
    assert calls == []
    assert attempts[-1]["error"] == "V11_RESERVED_FOR_CHUNKS"


def test_short_qwen_forces_real_pacing_function(monkeypatch):
    captured = {}

    def inner(**kwargs):
        captured.update(kwargs)
        return "<p>fragment</p>"

    monkeypatch.setattr(v11, "_ORIGINAL_TRY_PROVIDER", inner)
    fake_noop = lambda _: None
    result = v11.quota_aware_try_provider(
        name="groq",
        url="https://example.test",
        api_key="k",
        model="qwen/qwen3.6-27b",
        prompt="p",
        max_tokens=900,
        extra_headers={},
        sleep_fn=fake_noop,
        attempts=[],
    )
    assert result
    assert captured["sleep_fn"] is v11.time.sleep


def test_non_qwen_preserves_caller_sleep(monkeypatch):
    captured = {}

    def inner(**kwargs):
        captured.update(kwargs)
        return "ok"

    monkeypatch.setattr(v11, "_ORIGINAL_TRY_PROVIDER", inner)
    sleeper = lambda _: None
    v11.quota_aware_try_provider(
        name="groq",
        url="https://example.test",
        api_key="k",
        model="openai/gpt-oss-120b",
        prompt="p",
        max_tokens=4400,
        extra_headers={},
        sleep_fn=sleeper,
        attempts=[],
    )
    assert captured["sleep_fn"] is sleeper


def test_live_v11_binding_uses_stage4_inner_not_v9(monkeypatch):
    previous_live = authority.call_llm
    previous_inner = capacity._ORIGINAL_PREMIUM_LLM_CALL
    previous_installed = v11._INSTALLED
    previous_try = v11._ORIGINAL_TRY_PROVIDER
    try:
        stage4 = lambda *args, **kwargs: ("<p>safe</p>", "groq")
        capacity._ORIGINAL_PREMIUM_LLM_CALL = stage4
        monkeypatch.setattr(v11._llm, "_try_provider", lambda **kwargs: None)
        v11._INSTALLED = False
        v11._ORIGINAL_TRY_PROVIDER = None
        authority.call_llm = capacity.capacity_aware_premium_llm
        v11.install_quota_aware_scheduler_v11(None)
        assert authority.call_llm is v11.quota_aware_capacity_llm
        assert v11._INNER_LLM_CALL is stage4
    finally:
        authority.call_llm = previous_live
        capacity._ORIGINAL_PREMIUM_LLM_CALL = previous_inner
        v11._INSTALLED = previous_installed
        v11._ORIGINAL_TRY_PROVIDER = previous_try


def test_seed_path_can_build_when_long_form_chain_returns_none(monkeypatch):
    config = Config(
        groq_api_key="test-key",
        llm_model_groq="qwen/qwen3.6-27b",
        llm_model_groq_fallbacks=("qwen/qwen3.8-27b",),
    )
    monkeypatch.setattr(v11, "_INNER_LLM_CALL", lambda *args, **kwargs: None)

    paragraph = " ".join(["analysis"] * 130)
    fragment = "".join(f"<p>{paragraph}</p>" for _ in range(5)) + "<ul>" + "".join(
        f"<li>evidence specific validation action number {i}</li>" for i in range(6)
    ) + "</ul>"
    calls = []

    def short_call(config, prompt, model, ledger):
        calls.append((model, prompt))
        return fragment

    monkeypatch.setattr(v11, "_call_short_qwen", short_call)
    result = v11.quota_aware_capacity_llm(config, "SOURCE EVIDENCE", attempts=[])
    assert result is not None
    assert len(calls) >= 1
    assert capacity._semantic_metrics(result[0])[0] >= 2200
    assert capacity._semantic_metrics(result[0])[1] >= 18
    assert capacity._semantic_metrics(result[0])[2] >= 18


def test_v11_never_marks_incomplete_chunk_body_complete(monkeypatch):
    config = Config(
        groq_api_key="test-key",
        llm_model_groq="qwen/qwen3.6-27b",
        llm_model_groq_fallbacks=("qwen/qwen3.8-27b",),
    )
    monkeypatch.setattr(v11, "_INNER_LLM_CALL", lambda *args, **kwargs: ("<p>" + "analysis " * 400 + "</p>", "groq"))
    monkeypatch.setattr(v11, "_call_short_qwen", lambda *args, **kwargs: "<p>short evidence bounded fragment</p>")
    result = v11.quota_aware_capacity_llm(config, "SOURCE EVIDENCE", attempts=[])
    assert result is not None
    assert capacity._active_contract_complete(result[0]) is False
