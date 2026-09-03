"""Tests for llm_client.call_llm's provider-attempt instrumentation.

There was no test coverage for automation/ before this file. These tests
target only the new `attempts` tracking, added to answer a real operational
question raised by analysis of logs/run-*.json (4019 historical run
reports): ~98% of all published content used the template fallback rather
than any LLM provider, and the run report had no way to show *why* (no
API key configured vs. rate limit vs. some other failure) — only *that*
it fell back.
"""
from unittest.mock import Mock, patch

from automation.config import Config
from automation import llm_client
from automation.llm_client import _call_openai_compat, _raw_retry_after_seconds, call_llm


def test_no_providers_configured_records_no_api_key_for_all_four():
    attempts = []
    result = call_llm(Config(), "prompt", attempts=attempts)
    assert result is None
    assert [a["provider"] for a in attempts] == ["groq", "deepseek", "openrouter", "anthropic"]
    assert all(a["ok"] is False and a["error"] == "no_api_key" for a in attempts)


def test_first_provider_success_records_single_ok_attempt():
    attempts = []
    with patch("automation.llm_client._call_openai_compat", return_value="generated content"):
        result = call_llm(Config(groq_api_key="k"), "prompt", attempts=attempts)
    assert result == ("generated content", "groq")
    assert attempts == [{"provider": "groq", "model": "openai/gpt-oss-120b", "ok": True, "error": None}]


def test_groq_primary_model_failure_falls_through_to_groq_fallback_model_first():
    # Production incident 2026-09-03 (continued): Groq's free/on_demand
    # tier enforces its daily token quota per model, not account-wide, so
    # a real per-model outage must be answered by trying the *next Groq
    # model* (an independent daily budget on the same key) before ever
    # falling through to a paid provider we know is unfunded.
    attempts = []
    with patch(
        "automation.llm_client._call_openai_compat",
        side_effect=[RuntimeError("HTTP 429 rate limited"), "content from fallback model"],
    ):
        result = call_llm(
            Config(groq_api_key="k1", deepseek_api_key="k2"), "prompt", attempts=attempts
        )
    assert result == ("content from fallback model", "groq")
    assert attempts == [
        {"provider": "groq", "model": "openai/gpt-oss-120b", "ok": False, "error": "HTTP 429 rate limited"},
        {"provider": "groq", "model": "openai/gpt-oss-20b", "ok": True, "error": None},
    ]


def test_all_groq_models_exhausted_falls_through_to_deepseek():
    attempts = []
    config = Config(groq_api_key="k1", deepseek_api_key="k2")
    groq_model_count = 1 + len(config.llm_model_groq_fallbacks)
    with patch(
        "automation.llm_client._call_openai_compat",
        side_effect=[RuntimeError("429") for _ in range(groq_model_count)] + ["content from deepseek"],
    ):
        result = call_llm(config, "prompt", attempts=attempts)
    assert result == ("content from deepseek", "deepseek")
    assert [a["provider"] for a in attempts] == ["groq"] * groq_model_count + ["deepseek"]
    assert attempts[-1] == {"provider": "deepseek", "model": "deepseek-chat", "ok": True, "error": None}


def test_empty_response_is_recorded_as_a_failed_attempt_and_does_not_return():
    # Only groq has a key, but an empty response must not be mistaken for
    # success — the loop should still record every Groq model attempt as
    # failed and continue to the (keyless) remaining providers, same as
    # any other per-provider failure.
    attempts = []
    config = Config(groq_api_key="k")
    groq_model_count = 1 + len(config.llm_model_groq_fallbacks)
    with patch("automation.llm_client._call_openai_compat", return_value=""):
        result = call_llm(config, "prompt", attempts=attempts)
    assert result is None
    assert [a["provider"] for a in attempts[:groq_model_count]] == ["groq"] * groq_model_count
    assert all(a["error"] == "empty_response" for a in attempts[:groq_model_count])
    assert [a["provider"] for a in attempts[groq_model_count:]] == ["deepseek", "openrouter", "anthropic"]
    assert all(a["error"] == "no_api_key" for a in attempts[groq_model_count:])


def test_attempts_parameter_is_optional_and_backward_compatible():
    with patch("automation.llm_client._call_openai_compat", return_value="x"):
        result = call_llm(Config(groq_api_key="k"), "prompt")
    assert result == ("x", "groq")


def test_groq_fallback_models_deduplicate_against_the_primary_model():
    # If an operator's GROQ_FALLBACK_MODELS override happens to repeat the
    # primary model, it must not be tried twice.
    attempts = []
    config = Config(groq_api_key="k", llm_model_groq_fallbacks=("openai/gpt-oss-120b", "qwen/qwen3.6-27b"))
    with patch("automation.llm_client._call_openai_compat", return_value="ok"):
        call_llm(config, "prompt", attempts=attempts)
    assert [a["model"] for a in attempts] == ["openai/gpt-oss-120b"]


# Production incident 2026-09-03 (continued): OpenRouter's own paid model
# (deepseek/deepseek-chat) was hardcoded here and unfunded (402 on every
# call). Its free ($0-priced, ":free"-suffixed) catalog is reported to
# churn weekly, so a hardcoded free model ID would just recreate the same
# incident the next time OpenRouter retires it. These tests cover live
# discovery against OpenRouter's own /models endpoint instead.


def _reset_openrouter_cache():
    llm_client._openrouter_free_model_cache = None
    llm_client._openrouter_discovery_attempted = False


def _models_response(models):
    resp = Mock()
    resp.raise_for_status = Mock()
    resp.json = Mock(return_value={"data": models})
    return resp


def test_openrouter_discovery_picks_the_largest_context_free_model():
    _reset_openrouter_cache()
    try:
        models = [
            {"id": "some/paid-model", "pricing": {"prompt": "0.002", "completion": "0.004"}, "context_length": 128000},
            {"id": "some/small-free-model:free", "pricing": {"prompt": "0", "completion": "0"}, "context_length": 8000},
            {"id": "some/large-free-model:free", "pricing": {"prompt": "0", "completion": "0"}, "context_length": 131072},
        ]
        with patch("automation.llm_client.requests.get", return_value=_models_response(models)):
            model = llm_client._discover_openrouter_free_model("k")
        assert model == "some/large-free-model:free"
    finally:
        _reset_openrouter_cache()


def test_openrouter_discovery_returns_none_when_no_free_model_is_listed():
    _reset_openrouter_cache()
    try:
        models = [{"id": "some/paid-model", "pricing": {"prompt": "0.002", "completion": "0.004"}, "context_length": 128000}]
        with patch("automation.llm_client.requests.get", return_value=_models_response(models)):
            assert llm_client._discover_openrouter_free_model("k") is None
    finally:
        _reset_openrouter_cache()


def test_openrouter_discovery_failure_is_never_fatal():
    _reset_openrouter_cache()
    try:
        with patch("automation.llm_client.requests.get", side_effect=RuntimeError("network down")):
            assert llm_client._discover_openrouter_free_model("k") is None
    finally:
        _reset_openrouter_cache()


def test_openrouter_discovery_is_cached_per_process():
    _reset_openrouter_cache()
    try:
        models = [{"id": "some/free-model:free", "pricing": {"prompt": "0", "completion": "0"}, "context_length": 100}]
        with patch("automation.llm_client.requests.get", return_value=_models_response(models)) as mock_get:
            first = llm_client._discover_openrouter_free_model("k")
            second = llm_client._discover_openrouter_free_model("k")
        assert first == second == "some/free-model:free"
        mock_get.assert_called_once()
    finally:
        _reset_openrouter_cache()


def test_call_llm_uses_the_discovered_openrouter_free_model():
    _reset_openrouter_cache()
    try:
        attempts = []
        models = [{"id": "some/free-model:free", "pricing": {"prompt": "0", "completion": "0"}, "context_length": 100}]
        config = Config(groq_api_key="", openrouter_api_key="ork")
        with patch("automation.llm_client.requests.get", return_value=_models_response(models)), \
             patch("automation.llm_client._call_openai_compat", return_value="ok") as mock_call:
            result = call_llm(config, "prompt", attempts=attempts)
        assert result == ("ok", "openrouter")
        assert mock_call.call_args.kwargs["model"] == "some/free-model:free"
    finally:
        _reset_openrouter_cache()


def test_call_llm_skips_openrouter_gracefully_when_no_free_model_is_available():
    _reset_openrouter_cache()
    try:
        attempts = []
        config = Config(groq_api_key="", openrouter_api_key="ork")
        with patch("automation.llm_client.requests.get", return_value=_models_response([])):
            result = call_llm(config, "prompt", attempts=attempts)
        assert result is None
        openrouter_attempts = [a for a in attempts if a["provider"] == "openrouter"]
        assert openrouter_attempts == [{"provider": "openrouter", "model": None, "ok": False, "error": "no_free_model_available"}]
    finally:
        _reset_openrouter_cache()


# Production incident 2026-09-03 (continued): #158 and #159 fixed proactive
# pacing, but every real production run still published zero posts, and the
# 429-retry log showed delay_seconds pinned at exactly the _MAX_BACKOFF_
# SECONDS cap (65.0) with zero variance across 12 samples in one run --
# consistent with the provider's real Retry-After exceeding what we honor,
# but previously unconfirmable because only the capped value was ever
# logged, never what the provider actually asked for. These tests cover
# the new diagnostic instrumentation that makes that visible on the next
# real run, without changing any retry/pacing behavior.


def _rate_limited_response(retry_after: str, body: str = '{"error": "rate limited"}'):
    resp = Mock()
    resp.status_code = 429
    resp.headers = {"Retry-After": retry_after}
    resp.text = body
    return resp


def _success_response(content: str = "ok"):
    resp = Mock()
    resp.status_code = 200
    resp.headers = {}
    resp.raise_for_status = Mock()
    resp.json = Mock(return_value={"choices": [{"message": {"content": content}}]})
    return resp


def test_raw_retry_after_seconds_is_never_capped():
    # The provider's honest value (200s here) is far above _MAX_BACKOFF_
    # SECONDS -- the raw parser must return it unmodified; only the capped
    # _retry_after_seconds() is allowed to clamp it.
    assert _raw_retry_after_seconds(_rate_limited_response("200")) == 200.0


def test_rate_limit_log_captures_the_uncapped_provider_value_and_body():
    old_backoff = llm_client._MAX_BACKOFF_SECONDS
    llm_client._MAX_BACKOFF_SECONDS = 65.0
    try:
        responses = [
            _rate_limited_response("200", body='{"error": "please retry in 200s"}'),
            _success_response("generated"),
        ]
        fake_sleep = Mock()
        with patch("automation.llm_client.requests.post", side_effect=responses), \
             patch.object(llm_client, "logger") as fake_logger:
            result = _call_openai_compat(
                url="https://api.groq.com/openai/v1/chat/completions",
                api_key="k", model="m", prompt="p", max_tokens=100,
                extra_headers={}, sleep_fn=fake_sleep,
            )
        assert result == "generated"

        # We only ever waited the capped 65s ...
        fake_sleep.assert_called_once_with(65.0)

        # ... but the log records what the provider actually asked for,
        # proving the two are different rather than silently discarding it.
        rate_limit_calls = [
            c for c in fake_logger.info.call_args_list
            if c.args and c.args[0] == "LLM provider rate-limited, retrying"
        ]
        assert len(rate_limit_calls) == 1
        logged = rate_limit_calls[0].kwargs["extra"]
        assert logged["delay_seconds"] == 65.0
        assert logged["raw_retry_after_seconds"] == 200.0
        assert "200s" in logged["response_body"]
    finally:
        llm_client._MAX_BACKOFF_SECONDS = old_backoff


def test_rate_limit_log_handles_a_missing_retry_after_header_gracefully():
    old_backoff = llm_client._MAX_BACKOFF_SECONDS
    llm_client._MAX_BACKOFF_SECONDS = 65.0
    try:
        no_header_response = Mock()
        no_header_response.status_code = 429
        no_header_response.headers = {}
        no_header_response.text = ""
        responses = [no_header_response, _success_response("generated")]
        fake_sleep = Mock()
        with patch("automation.llm_client.requests.post", side_effect=responses), \
             patch.object(llm_client, "logger") as fake_logger:
            _call_openai_compat(
                url="https://api.groq.com/openai/v1/chat/completions",
                api_key="k", model="m", prompt="p", max_tokens=100,
                extra_headers={}, sleep_fn=fake_sleep,
            )
        rate_limit_calls = [
            c for c in fake_logger.info.call_args_list
            if c.args and c.args[0] == "LLM provider rate-limited, retrying"
        ]
        logged = rate_limit_calls[0].kwargs["extra"]
        assert logged["raw_retry_after_seconds"] is None
        assert logged["response_body"] is None
    finally:
        llm_client._MAX_BACKOFF_SECONDS = old_backoff
