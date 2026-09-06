import json
from types import SimpleNamespace
from unittest.mock import Mock

from automation import premium_puter_user_pays_v17 as puter_v17


def _reset_runtime():
    puter_v17._RUNTIME["attempts"] = 0
    puter_v17._RUNTIME["successes"] = 0
    puter_v17._RUNTIME["failures"] = 0
    puter_v17._RUNTIME["actual_calls"] = 0
    puter_v17._RUNTIME["policy_blocks"].clear()
    puter_v17._RUNTIME["bridge_failures"].clear()


def _enable(monkeypatch, *, token="puter-secret", max_calls="1"):
    monkeypatch.setenv("PUTER_AUTOMATION_ENABLED", "true")
    monkeypatch.setenv("PUTER_PUBLIC_DATA_ONLY", "true")
    monkeypatch.setenv("PUTER_AUTH_TOKEN", token)
    monkeypatch.setenv("PUTER_MODEL", "gpt-5.6-luna")
    monkeypatch.setenv("PUTER_MAX_CALLS_PER_RUN", max_calls)
    monkeypatch.setenv("PUTER_MIN_REMAINING_MICROCENTS", "25000000")


def test_puter_is_disabled_by_default_and_never_spawns_node(monkeypatch):
    _reset_runtime()
    monkeypatch.delenv("PUTER_AUTOMATION_ENABLED", raising=False)
    monkeypatch.setenv("PUTER_AUTH_TOKEN", "puter-secret")
    monkeypatch.setenv("PUTER_PUBLIC_DATA_ONLY", "true")
    runner = Mock(side_effect=AssertionError("Node must not run without explicit opt-in"))
    monkeypatch.setattr(puter_v17.subprocess, "run", runner)
    attempts = []

    result = puter_v17._try_puter("public CTI prompt", 4400, attempts)

    assert result is None
    assert attempts[-1]["error"] == "operator_opt_in_disabled"
    runner.assert_not_called()


def test_puter_requires_auth_token(monkeypatch):
    _reset_runtime()
    _enable(monkeypatch, token="")
    runner = Mock(side_effect=AssertionError("Node must not run without auth token"))
    monkeypatch.setattr(puter_v17.subprocess, "run", runner)
    attempts = []

    result = puter_v17._try_puter("public CTI prompt", 4400, attempts)

    assert result is None
    assert attempts[-1]["error"] == "missing_auth_token"
    runner.assert_not_called()


def test_puter_requires_explicit_public_data_only_policy(monkeypatch):
    _reset_runtime()
    _enable(monkeypatch)
    monkeypatch.setenv("PUTER_PUBLIC_DATA_ONLY", "false")
    runner = Mock(side_effect=AssertionError("Node must not run outside public-data-only policy"))
    monkeypatch.setattr(puter_v17.subprocess, "run", runner)
    attempts = []

    result = puter_v17._try_puter("prompt", 4400, attempts)

    assert result is None
    assert attempts[-1]["error"] == "public_data_only_policy_not_enabled"
    runner.assert_not_called()


def test_existing_v16_success_short_circuits_puter(monkeypatch):
    _reset_runtime()
    _enable(monkeypatch)
    inner = Mock(return_value=("Gemini report", "gemini"))
    monkeypatch.setattr(puter_v17, "_INNER_AUTHORITY_CALL", inner)
    runner = Mock(side_effect=AssertionError("Puter must not run after v16 success"))
    monkeypatch.setattr(puter_v17.subprocess, "run", runner)

    result = puter_v17.puter_fallback_authority_llm(
        SimpleNamespace(), "prompt", max_tokens=3000, attempts=[], sleep_fn=lambda _s: None
    )

    assert result == ("Gemini report", "gemini")
    runner.assert_not_called()


def test_puter_success_runs_only_after_v16_exhaustion_and_uses_premium_budget(monkeypatch):
    _reset_runtime()
    _enable(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "must-not-reach-bridge")
    inner = Mock(return_value=None)
    monkeypatch.setattr(puter_v17, "_INNER_AUTHORITY_CALL", inner)
    completed = SimpleNamespace(
        stdout=json.dumps({
            "ok": True,
            "text": "Evidence-bounded Puter report",
            "model": "gpt-5.6-luna",
            "usage": {
                "remaining_before_microcents": 90000000,
                "remaining_after_microcents": 80000000,
            },
        }) + "\n",
        returncode=0,
    )
    runner = Mock(return_value=completed)
    monkeypatch.setattr(puter_v17.subprocess, "run", runner)
    attempts = []

    result = puter_v17.puter_fallback_authority_llm(
        SimpleNamespace(), "public CTI prompt", max_tokens=3000, attempts=attempts, sleep_fn=lambda _s: None
    )

    assert result == ("Evidence-bounded Puter report", "puter")
    call = runner.call_args
    payload = json.loads(call.kwargs["input"])
    assert payload["max_tokens"] == puter_v17.PREMIUM_COMPLETION_TOKENS == 4400
    assert payload["min_remaining_microcents"] == 25000000
    assert call.kwargs["env"]["PUTER_AUTH_TOKEN"] == "puter-secret"
    assert "GROQ_API_KEY" not in call.kwargs["env"]
    assert attempts[-1]["ok"] is True
    assert attempts[-1]["allowance_guard"] == "passed"


def test_allowance_guard_failure_never_persists_allowance_amount(monkeypatch):
    _reset_runtime()
    _enable(monkeypatch)
    completed = SimpleNamespace(
        stdout=json.dumps({
            "ok": False,
            "error": "allowance_reserve_guard",
            "remaining_microcents": 1234567,
            "min_remaining_microcents": 25000000,
        }) + "\n",
        returncode=3,
    )
    monkeypatch.setattr(puter_v17.subprocess, "run", Mock(return_value=completed))
    attempts = []

    result = puter_v17._try_puter("prompt", 4400, attempts)

    assert result is None
    assert attempts[-1]["error"] == "allowance_reserve_guard"
    serialized = repr(attempts[-1]) + repr(puter_v17.telemetry_snapshot())
    assert "1234567" not in serialized
    assert "25000000" not in serialized
    assert puter_v17.telemetry_snapshot()["telemetry_contains_allowance_amounts"] is False


def test_per_run_call_cap_prevents_second_outbound_request(monkeypatch):
    _reset_runtime()
    _enable(monkeypatch, max_calls="1")
    completed = SimpleNamespace(
        stdout=json.dumps({"ok": False, "error": "puter_call_failed:temporary"}) + "\n",
        returncode=5,
    )
    runner = Mock(return_value=completed)
    monkeypatch.setattr(puter_v17.subprocess, "run", runner)

    assert puter_v17._try_puter("prompt one", 4400, []) is None
    attempts = []
    assert puter_v17._try_puter("prompt two", 4400, attempts) is None

    assert runner.call_count == 1
    assert attempts[-1]["error"] == "per_run_call_cap_reached"


def test_telemetry_never_contains_token(monkeypatch):
    _reset_runtime()
    _enable(monkeypatch, token="super-sensitive-puter-token")

    telemetry = puter_v17.telemetry_snapshot()

    assert telemetry["token_configured"] is True
    assert telemetry["telemetry_contains_token"] is False
    assert "super-sensitive-puter-token" not in repr(telemetry)


def test_installer_registers_puter_as_llm_source_and_owns_final_bindings(monkeypatch):
    _reset_runtime()
    original_authority = lambda *_a, **_k: None
    original_judgements = lambda *_a, **_k: None
    main_module = SimpleNamespace(_write_run_report=lambda *_a, **_k: None)

    monkeypatch.setattr(puter_v17, "_INSTALLED", False)
    monkeypatch.setattr(puter_v17, "_INNER_AUTHORITY_CALL", None)
    monkeypatch.setattr(puter_v17, "_INNER_KEY_JUDGEMENTS_CALL", None)
    monkeypatch.setattr(puter_v17, "_INNER_WRITE_RUN_REPORT", None)
    monkeypatch.setattr(puter_v17._authority, "call_llm", original_authority)
    monkeypatch.setattr(puter_v17._key_judgements, "call_llm", original_judgements)
    monkeypatch.setattr(puter_v17._compiler, "_LLM_PROVIDER_SOURCES", frozenset({"groq", "gemini"}))
    monkeypatch.setattr(puter_v17._publication, "_LLM_SOURCES", frozenset({"groq", "gemini"}))
    monkeypatch.setattr(puter_v17._depth, "LLM_AUTHORED_SOURCES", frozenset({"groq", "gemini"}))

    puter_v17.install_puter_user_pays_v17(main_module)

    assert puter_v17._authority.call_llm is puter_v17.puter_fallback_authority_llm
    assert puter_v17._key_judgements.call_llm is puter_v17.puter_fallback_key_judgements_llm
    assert main_module._write_run_report is puter_v17.write_run_report_with_v17_telemetry
    assert "puter" in puter_v17._compiler._LLM_PROVIDER_SOURCES
    assert "puter" in puter_v17._publication._LLM_SOURCES
    assert "puter" in puter_v17._depth.LLM_AUTHORED_SOURCES


def test_workflow_keeps_puter_opt_in_and_pins_node24_runtime():
    from pathlib import Path

    workflow = Path(".github/workflows/blogger-syndication.yml").read_text(encoding="utf-8")
    runtime = Path("automation/puter_runtime/package.json").read_text(encoding="utf-8")

    assert 'node-version: "24"' in workflow
    assert "PUTER_AUTH_TOKEN: ${{ secrets.PUTER_AUTH_TOKEN }}" in workflow
    assert "PUTER_AUTOMATION_ENABLED: ${{ vars.PUTER_AUTOMATION_ENABLED }}" in workflow
    assert 'PUTER_PUBLIC_DATA_ONLY: "true"' in workflow
    assert '"@heyputer/puter.js": "2.2.8"' in runtime
