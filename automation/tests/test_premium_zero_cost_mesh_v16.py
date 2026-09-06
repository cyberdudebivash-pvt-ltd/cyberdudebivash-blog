from types import SimpleNamespace
from unittest.mock import Mock

import requests

from automation.config import Config
from automation import premium_zero_cost_mesh_v16 as mesh
from automation import premium_zero_cost_mesh_v16_hardening as hardening


def _cfg(**overrides):
    values = dict(
        groq_api_key="groq-key",
        gemini_api_key="gemini-key",
        nvidia_nim_api_key="nvapi-key",
        openrouter_api_key="openrouter-key",
        deepseek_api_key="deepseek-key",
        anthropic_api_key="anthropic-key",
        allow_paid_llm=False,
        gemini_public_data_only=True,
        nvidia_nim_public_data_only=True,
        llm_model_gemini="gemini-test-primary",
        llm_model_gemini_fallbacks=("gemini-test-fallback",),
        llm_model_nvidia_nim="nvidia/test-primary",
        llm_model_nvidia_nim_fallbacks=("nvidia/test-fallback",),
    )
    values.update(overrides)
    return Config(**values)


def test_config_loads_zero_cost_provider_secrets_and_policy(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret")
    monkeypatch.setenv("NVIDIA_NIM_API_KEY", "nvidia-secret")
    monkeypatch.setenv("ALLOW_PAID_LLM", "false")
    monkeypatch.setenv("GEMINI_PUBLIC_DATA_ONLY", "true")
    monkeypatch.setenv("NVIDIA_NIM_PUBLIC_DATA_ONLY", "true")
    monkeypatch.setenv("NVIDIA_NIM_MODEL", "nvidia/custom")
    monkeypatch.setenv("NVIDIA_NIM_FALLBACK_MODELS", "nvidia/a,nvidia/b")

    config = Config.from_env()

    assert config.gemini_api_key == "gemini-secret"
    assert config.nvidia_nim_api_key == "nvidia-secret"
    assert config.allow_paid_llm is False
    assert config.gemini_public_data_only is True
    assert config.nvidia_nim_public_data_only is True
    assert config.llm_model_nvidia_nim == "nvidia/custom"
    assert config.llm_model_nvidia_nim_fallbacks == ("nvidia/a", "nvidia/b")


def test_groq_success_short_circuits_all_alternate_providers(monkeypatch):
    inner = Mock(return_value=("groq report", "groq"))
    gemini = Mock(side_effect=AssertionError("Gemini must not run after Groq success"))
    nvidia = Mock(side_effect=AssertionError("NVIDIA must not run after Groq success"))
    openrouter = Mock(side_effect=AssertionError("OpenRouter must not run after Groq success"))
    monkeypatch.setattr(mesh, "_try_gemini", gemini)
    monkeypatch.setattr(mesh, "_try_nvidia", nvidia)
    monkeypatch.setattr(mesh, "_try_openrouter_free", openrouter)

    result = mesh._run_mesh(inner, _cfg(), "prompt", 4400, [], lambda _s: None)

    assert result == ("groq report", "groq")
    assert inner.call_count == 1
    called_config = inner.call_args.args[0]
    assert called_config.groq_api_key == "groq-key"
    assert called_config.deepseek_api_key == ""
    assert called_config.openrouter_api_key == ""
    assert called_config.anthropic_api_key == ""
    gemini.assert_not_called()
    nvidia.assert_not_called()
    openrouter.assert_not_called()


def test_fallback_order_is_strictly_gemini_then_nvidia_then_openrouter(monkeypatch):
    order = []
    inner = Mock(return_value=None)

    def gemini(*_args, **_kwargs):
        order.append("gemini")
        return None

    def nvidia(*_args, **_kwargs):
        order.append("nvidia_nim")
        return ("nvidia report", "nvidia_nim")

    def openrouter(*_args, **_kwargs):
        order.append("openrouter")
        return ("should-not-run", "openrouter")

    monkeypatch.setattr(mesh, "_try_gemini", gemini)
    monkeypatch.setattr(mesh, "_try_nvidia", nvidia)
    monkeypatch.setattr(mesh, "_try_openrouter_free", openrouter)

    result = mesh._run_mesh(inner, _cfg(), "prompt", 4400, [], lambda _s: None)

    assert result == ("nvidia report", "nvidia_nim")
    assert order == ["gemini", "nvidia_nim"]


def test_gemini_success_does_not_spend_nvidia_or_openrouter_quota(monkeypatch):
    inner = Mock(return_value=None)
    monkeypatch.setattr(mesh, "_try_gemini", Mock(return_value=("gemini report", "gemini")))
    nvidia = Mock(side_effect=AssertionError("NVIDIA must not be eagerly evaluated"))
    openrouter = Mock(side_effect=AssertionError("OpenRouter must not be eagerly evaluated"))
    monkeypatch.setattr(mesh, "_try_nvidia", nvidia)
    monkeypatch.setattr(mesh, "_try_openrouter_free", openrouter)

    result = mesh._run_mesh(inner, _cfg(), "prompt", 4400, [], lambda _s: None)

    assert result == ("gemini report", "gemini")
    nvidia.assert_not_called()
    openrouter.assert_not_called()


def test_paid_providers_are_never_reached_when_policy_is_false(monkeypatch):
    inner = Mock(return_value=None)
    monkeypatch.setattr(mesh, "_try_gemini", Mock(return_value=None))
    monkeypatch.setattr(mesh, "_try_nvidia", Mock(return_value=None))
    monkeypatch.setattr(mesh, "_try_openrouter_free", Mock(return_value=None))
    attempts = []

    result = mesh._run_mesh(inner, _cfg(allow_paid_llm=False), "prompt", 4400, attempts, lambda _s: None)

    assert result is None
    # Exactly one legacy-inner call: the Groq-only stage. There is no paid pass.
    assert inner.call_count == 1
    called_config = inner.call_args.args[0]
    assert called_config.deepseek_api_key == ""
    assert called_config.anthropic_api_key == ""
    assert {a["provider"] for a in attempts if a["error"] == "paid_provider_disabled_by_policy"} == {
        "deepseek",
        "anthropic",
    }


def test_gemini_requires_explicit_public_data_only_policy(monkeypatch):
    monkeypatch.setattr(mesh.requests, "post", Mock(side_effect=AssertionError("network call forbidden")))
    attempts = []

    result = mesh._try_gemini(
        _cfg(gemini_public_data_only=False), "public-ish prompt", 4400, attempts, lambda _s: None
    )

    assert result is None
    assert attempts[-1]["error"] == "public_data_only_policy_not_enabled"
    mesh.requests.post.assert_not_called()


def test_nvidia_requires_explicit_public_data_only_policy(monkeypatch):
    transport = Mock(side_effect=AssertionError("network call forbidden"))
    monkeypatch.setattr(mesh._llm, "_try_provider", transport)
    attempts = []

    result = mesh._try_nvidia(
        _cfg(nvidia_nim_public_data_only=False), "public-ish prompt", 4400, attempts, lambda _s: None
    )

    assert result is None
    assert attempts[-1]["error"] == "public_data_only_policy_not_enabled"
    transport.assert_not_called()


def test_gemini_discards_thought_parts_and_returns_only_answer_text():
    before = mesh._RUNTIME["gemini_thought_parts_discarded"]
    payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"thought": True, "text": "private reasoning must never publish"},
                        {"text": "Evidence-bounded answer"},
                    ]
                }
            }
        ]
    }

    result = mesh._gemini_text(payload)

    assert result == "Evidence-bounded answer"
    assert "private reasoning" not in result
    assert mesh._RUNTIME["gemini_thought_parts_discarded"] == before + 1


def test_gemini_long_retry_after_is_recorded_but_not_retried_early(monkeypatch):
    response = Mock()
    response.status_code = 429
    response.headers = {"Retry-After": "200"}
    response.text = '{"error":"requests per day (RPD) exhausted"}'
    error = requests.exceptions.HTTPError("429")
    error.response = response
    response.raise_for_status = Mock(side_effect=error)
    monkeypatch.setattr(mesh.requests, "post", Mock(return_value=response))
    monkeypatch.setattr(mesh._quota, "cooldown_remaining", Mock(return_value=0.0))
    record = Mock()
    monkeypatch.setattr(mesh._quota, "record_429", record)
    sleep = Mock()
    attempts = []

    result = mesh._call_gemini_model(
        _cfg(), "prompt", "gemini-test-primary", 4400, attempts, sleep
    )

    assert result is None
    assert mesh.requests.post.call_count == 1
    record.assert_called_once_with("gemini", "gemini-test-primary", response)
    sleep.assert_not_called()
    assert attempts[-1]["ok"] is False


def test_nvidia_uses_existing_openai_compatible_quota_aware_transport(monkeypatch):
    transport = Mock(return_value="NVIDIA report")
    monkeypatch.setattr(mesh._llm, "_try_provider", transport)
    attempts = []

    result = mesh._try_nvidia(_cfg(), "prompt", 4400, attempts, lambda _s: None)

    assert result == ("NVIDIA report", "nvidia_nim")
    kwargs = transport.call_args.kwargs
    assert kwargs["name"] == "nvidia_nim"
    assert kwargs["url"] == mesh.NVIDIA_NIM_URL
    assert kwargs["model"] == "nvidia/test-primary"
    assert kwargs["api_key"] == "nvapi-key"
    assert kwargs["max_tokens"] == 4400


def test_mesh_capacity_bypasses_groq_only_saturation_when_alt_free_capacity_exists(monkeypatch):
    signals = [
        {"provider": "groq", "model": "a", "limit_type": "TPD"},
        {"provider": "groq", "model": "b", "limit_type": "TPD"},
    ]
    monkeypatch.setattr(mesh, "_ORIGINAL_CAPACITY_CONSTRAINED", lambda: (True, signals))
    monkeypatch.setattr(mesh, "_alternate_free_capacity_available", lambda: True)

    constrained, returned = mesh.mesh_capacity_constrained()

    assert constrained is False
    assert returned is signals


def test_mesh_capacity_restores_v13_deferral_when_all_alt_free_capacity_is_exhausted(monkeypatch):
    signals = [
        {"provider": "groq", "model": "a", "limit_type": "TPD"},
        {"provider": "groq", "model": "b", "limit_type": "TPD"},
    ]
    monkeypatch.setattr(mesh, "_ORIGINAL_CAPACITY_CONSTRAINED", lambda: (True, signals))
    monkeypatch.setattr(mesh, "_alternate_free_capacity_available", lambda: False)

    constrained, returned = mesh.mesh_capacity_constrained()

    assert constrained is True
    assert returned is signals


def test_alternate_capacity_requires_key_policy_and_noncooled_model(monkeypatch):
    config = _cfg(openrouter_api_key="")

    def remaining(provider, model):
        if provider == "gemini":
            return 60.0
        if provider == "nvidia_nim" and model == "nvidia/test-primary":
            return 0.0
        return 60.0

    monkeypatch.setattr(mesh._quota, "cooldown_remaining", remaining)

    assert mesh._alternate_free_capacity_available(config) is True
    assert mesh._alternate_free_capacity_available(
        _cfg(gemini_public_data_only=False, nvidia_nim_public_data_only=False)
    ) is False


def test_installer_registers_provider_identity_and_final_live_bindings(monkeypatch):
    original_authority = lambda *_a, **_k: None
    original_judgements = lambda *_a, **_k: None
    original_capacity = lambda: (False, [])
    monkeypatch.setattr(mesh, "_INSTALLED", False)
    monkeypatch.setattr(mesh, "_INNER_AUTHORITY_CALL", None)
    monkeypatch.setattr(mesh, "_INNER_KEY_JUDGEMENTS_CALL", None)
    monkeypatch.setattr(mesh, "_ORIGINAL_CAPACITY_CONSTRAINED", None)
    monkeypatch.setattr(mesh._authority, "call_llm", original_authority)
    monkeypatch.setattr(mesh._key_judgements, "call_llm", original_judgements)
    monkeypatch.setattr(mesh._allocator, "_capacity_constrained", original_capacity)
    monkeypatch.setattr(mesh._compiler, "_LLM_PROVIDER_SOURCES", frozenset({"groq"}))
    monkeypatch.setattr(mesh._publication, "_LLM_SOURCES", frozenset({"groq"}))
    monkeypatch.setattr(mesh._depth, "LLM_AUTHORED_SOURCES", frozenset({"groq"}))
    hosts = dict(mesh._quota._PROVIDER_BY_HOST)
    monkeypatch.setattr(mesh._quota, "_PROVIDER_BY_HOST", hosts)

    mesh.install_zero_cost_mesh_v16(SimpleNamespace())

    assert mesh._authority.call_llm is mesh.zero_cost_authority_llm
    assert mesh._key_judgements.call_llm is mesh.zero_cost_key_judgements_llm
    assert mesh._allocator._capacity_constrained is mesh.mesh_capacity_constrained
    assert mesh._quota._PROVIDER_BY_HOST["integrate.api.nvidia.com"] == "nvidia_nim"
    assert {"gemini", "nvidia_nim"}.issubset(mesh._compiler._LLM_PROVIDER_SOURCES)
    assert {"gemini", "nvidia_nim"}.issubset(mesh._publication._LLM_SOURCES)
    assert {"gemini", "nvidia_nim"}.issubset(mesh._depth.LLM_AUTHORED_SOURCES)


def test_hardening_gives_authority_fallbacks_the_existing_premium_completion_budget(monkeypatch):
    captured = {}

    def inner(_config, _prompt, **kwargs):
        captured.update(kwargs)
        return ("report", "gemini")

    monkeypatch.setattr(hardening, "_INNER_AUTHORITY_CALL", inner)
    result = hardening.premium_budget_zero_cost_authority_llm(
        _cfg(), "prompt", max_tokens=3000, attempts=[], sleep_fn=lambda _s: None
    )

    assert result == ("report", "gemini")
    assert captured["max_tokens"] == hardening.PREMIUM_COMPLETION_TOKENS == 4400


def test_run_report_telemetry_contains_provider_counts_not_secrets(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        hardening,
        "_INNER_WRITE_RUN_REPORT",
        lambda report, logs_dir: captured.update(report=report, logs_dir=logs_dir),
    )
    hardening._TELEMETRY["attempts"].clear()
    hardening._TELEMETRY["successes"].clear()
    hardening._TELEMETRY["failures"].clear()
    hardening._record_rows(
        [
            {"provider": "gemini", "model": "m", "ok": False, "error": "429"},
            {"provider": "nvidia_nim", "model": "n", "ok": True, "error": None},
        ]
    )
    report = {"run_status": "SUCCESS"}

    hardening.write_run_report_with_v16_telemetry(report, "logs")

    telemetry = report["zero_cost_mesh_v16"]
    assert telemetry["attempt_ledger"]["gemini"] == 1
    assert telemetry["success_ledger"]["nvidia_nim"] == 1
    serialized = repr(telemetry)
    assert "gemini-key" not in serialized
    assert "nvapi-key" not in serialized
    assert captured["report"] is report


def test_production_workflow_injects_only_zero_cost_llm_secrets():
    from pathlib import Path

    workflow = Path(".github/workflows/blogger-syndication.yml").read_text(encoding="utf-8")

    assert "GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}" in workflow
    assert "NVIDIA_NIM_API_KEY: ${{ secrets.NVIDIA_NIM_API_KEY }}" in workflow
    assert 'ALLOW_PAID_LLM: "false"' in workflow
    assert 'GEMINI_PUBLIC_DATA_ONLY: "true"' in workflow
    assert 'NVIDIA_NIM_PUBLIC_DATA_ONLY: "true"' in workflow
    assert "DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}" not in workflow
    assert "ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}" not in workflow
