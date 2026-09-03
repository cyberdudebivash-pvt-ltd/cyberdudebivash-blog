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
    assert attempts == [{"provider": "groq", "ok": True, "error": None}]


def test_first_provider_exception_falls_through_with_both_attempts_recorded():
    attempts = []
    with patch(
        "automation.llm_client._call_openai_compat",
        side_effect=[RuntimeError("HTTP 429 rate limited"), "content from deepseek"],
    ):
        result = call_llm(
            Config(groq_api_key="k1", deepseek_api_key="k2"), "prompt", attempts=attempts
        )
    assert result == ("content from deepseek", "deepseek")
    assert attempts == [
        {"provider": "groq", "ok": False, "error": "HTTP 429 rate limited"},
        {"provider": "deepseek", "ok": True, "error": None},
    ]


def test_empty_response_is_recorded_as_a_failed_attempt_and_does_not_return():
    # Only groq has a key, but an empty response must not be mistaken for
    # success — the loop should still record it as a failed attempt and
    # continue on to the (keyless) remaining providers, same as any other
    # per-provider failure.
    attempts = []
    with patch("automation.llm_client._call_openai_compat", return_value=""):
        result = call_llm(Config(groq_api_key="k"), "prompt", attempts=attempts)
    assert result is None
    assert attempts[0] == {"provider": "groq", "ok": False, "error": "empty_response"}
    assert [a["provider"] for a in attempts[1:]] == ["deepseek", "openrouter", "anthropic"]
    assert all(a["error"] == "no_api_key" for a in attempts[1:])


def test_attempts_parameter_is_optional_and_backward_compatible():
    with patch("automation.llm_client._call_openai_compat", return_value="x"):
        result = call_llm(Config(groq_api_key="k"), "prompt")
    assert result == ("x", "groq")


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
