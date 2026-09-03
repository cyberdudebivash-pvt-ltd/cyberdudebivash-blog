from datetime import datetime, timedelta, timezone

import requests

from automation import provider_quota_ledger as ledger


def _response(*, retry_after="120", body="Rate limit reached on tokens per day (TPD)"):
    response = requests.Response()
    response.status_code = 429
    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)
    response._content = body.encode("utf-8")
    response.url = "https://api.groq.com/openai/v1/chat/completions"
    return response


def _configure_tmp(monkeypatch, tmp_path):
    path = tmp_path / "provider_quota_state.json"
    monkeypatch.setenv("CDB_PROVIDER_QUOTA_STATE", str(path))
    for key in ledger._TELEMETRY:
        ledger._TELEMETRY[key] = 0
    return path


def test_tpd_429_persists_nonsecret_model_cooldown(monkeypatch, tmp_path):
    path = _configure_tmp(monkeypatch, tmp_path)
    entry = ledger.record_429("groq", "model-a", _response(retry_after="120"))
    assert entry["limit_type"] == "TPD"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "model-a" in text
    assert "api_key" not in text.lower()
    assert "authorization" not in text.lower()
    assert "prompt" not in text.lower()


def test_tpm_is_classified_independently(monkeypatch, tmp_path):
    _configure_tmp(monkeypatch, tmp_path)
    entry = ledger.record_429(
        "groq",
        "model-a",
        _response(body="Rate limit reached on tokens per minute (TPM)"),
    )
    assert entry["limit_type"] == "TPM"
    assert ledger.telemetry_snapshot()["tpm_events"] == 1


def test_cooldown_survives_new_load_from_disk(monkeypatch, tmp_path):
    _configure_tmp(monkeypatch, tmp_path)
    ledger.record_429("groq", "model-a", _response(retry_after="180"))
    assert ledger.cooldown_remaining("groq", "model-a") > 0
    # The second lookup reloads state from disk; there is no process-only
    # dictionary involved in the decision.
    assert ledger.cooldown_remaining("groq", "model-a") > 0


def test_expired_state_is_removed(monkeypatch, tmp_path):
    path = _configure_tmp(monkeypatch, tmp_path)
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    state = {
        "version": 1,
        "updated_at": past.isoformat(),
        "models": {
            "groq::model-a": {
                "provider": "groq",
                "model": "model-a",
                "limit_type": "TPD",
                "unavailable_until": past.isoformat(),
                "last_429": past.isoformat(),
                "retry_after_seconds": 1,
            }
        },
    }
    ledger._atomic_save(state)
    assert ledger.cooldown_remaining("groq", "model-a") == 0
    assert "groq::model-a" not in ledger._load_state()["models"]
    assert path.is_file()


def test_durable_skip_does_not_call_inner_provider(monkeypatch, tmp_path):
    _configure_tmp(monkeypatch, tmp_path)
    ledger.record_429("groq", "model-a", _response(retry_after="120"))
    called = []
    monkeypatch.setattr(ledger, "_ORIGINAL_TRY_PROVIDER", lambda **kwargs: called.append(kwargs) or "unexpected")
    attempts = []
    result = ledger.durable_try_provider(
        name="groq",
        url="https://api.groq.com/openai/v1/chat/completions",
        api_key="secret",
        model="model-a",
        prompt="x",
        max_tokens=100,
        extra_headers={},
        sleep_fn=lambda _seconds: None,
        attempts=attempts,
    )
    assert result is None
    assert called == []
    assert attempts[0]["error"] == "durable_provider_cooldown_active"
    assert ledger.telemetry_snapshot()["durable_provider_skips"] == 1


def test_unavailable_model_does_not_block_other_model(monkeypatch, tmp_path):
    _configure_tmp(monkeypatch, tmp_path)
    ledger.record_429("groq", "model-a", _response(retry_after="120"))
    called = []

    def inner(**kwargs):
        called.append(kwargs["model"])
        return "ok"

    monkeypatch.setattr(ledger, "_ORIGINAL_TRY_PROVIDER", inner)
    result = ledger.durable_try_provider(
        name="groq",
        url="https://api.groq.com/openai/v1/chat/completions",
        api_key="secret",
        model="model-b",
        prompt="x",
        max_tokens=100,
        extra_headers={},
        sleep_fn=lambda _seconds: None,
        attempts=[],
    )
    assert result == "ok"
    assert called == ["model-b"]


def test_success_clears_stale_persisted_cooldown(monkeypatch, tmp_path):
    _configure_tmp(monkeypatch, tmp_path)
    ledger.record_429("groq", "model-a", _response(retry_after="120"))
    monkeypatch.setattr(ledger, "_ORIGINAL_OPENAI_CALL", lambda **kwargs: "content")
    result = ledger.durable_openai_call(
        url="https://api.groq.com/openai/v1/chat/completions",
        api_key="secret",
        model="model-a",
        prompt="x",
        max_tokens=100,
        extra_headers={},
        sleep_fn=lambda _seconds: None,
    )
    assert result == "content"
    assert ledger.cooldown_remaining("groq", "model-a") == 0


def test_http_429_from_inner_call_is_persisted_and_reraised(monkeypatch, tmp_path):
    _configure_tmp(monkeypatch, tmp_path)
    response = _response(retry_after="90")
    error = requests.exceptions.HTTPError("429")
    error.response = response

    def fail(**kwargs):
        raise error

    monkeypatch.setattr(ledger, "_ORIGINAL_OPENAI_CALL", fail)
    try:
        ledger.durable_openai_call(
            url="https://api.groq.com/openai/v1/chat/completions",
            api_key="secret",
            model="model-a",
            prompt="x",
            max_tokens=100,
            extra_headers={},
            sleep_fn=lambda _seconds: None,
        )
    except requests.exceptions.HTTPError:
        pass
    else:
        raise AssertionError("HTTPError should be re-raised")
    assert ledger.cooldown_remaining("groq", "model-a") > 0


def test_429_without_usable_retry_after_is_not_persisted(monkeypatch, tmp_path):
    path = _configure_tmp(monkeypatch, tmp_path)
    result = ledger.record_429("groq", "model-a", _response(retry_after=None))
    assert result is None
    assert not path.exists()
    assert ledger.telemetry_snapshot()["transient_429_events"] == 1


def test_retry_after_is_bounded(monkeypatch, tmp_path):
    _configure_tmp(monkeypatch, tmp_path)
    entry = ledger.record_429("groq", "model-a", _response(retry_after="999999999"))
    assert entry["retry_after_seconds"] == ledger._MAX_RETRY_AFTER_SECONDS


def test_provider_mapping_is_host_scoped():
    assert ledger._provider_for_url("https://api.groq.com/openai/v1/chat/completions") == "groq"
    assert ledger._provider_for_url("https://openrouter.ai/api/v1/chat/completions") == "openrouter"
    assert ledger._provider_for_url("https://api.deepseek.com/chat/completions") == "deepseek"
