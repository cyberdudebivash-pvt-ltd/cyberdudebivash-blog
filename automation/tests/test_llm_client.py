"""Tests for llm_client.call_llm's provider-attempt instrumentation.

There was no test coverage for automation/ before this file. These tests
target only the new `attempts` tracking, added to answer a real operational
question raised by analysis of logs/run-*.json (4019 historical run
reports): ~98% of all published content used the template fallback rather
than any LLM provider, and the run report had no way to show *why* (no
API key configured vs. rate limit vs. some other failure) — only *that*
it fell back.
"""
from unittest.mock import patch

from automation.config import Config
from automation.llm_client import call_llm


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
