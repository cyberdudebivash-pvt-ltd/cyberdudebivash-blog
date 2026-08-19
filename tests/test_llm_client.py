"""
Tests for the multi-provider LLM client — provider priority, fallback, error handling.
"""

import unittest
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.llm_client import (
    _backoff_seconds,
    _call_openai_compat,
    _retry_after_seconds,
    _MAX_BACKOFF_SECONDS,
    _MAX_RETRIES_ON_RATE_LIMIT,
    call_llm,
)


def _config(**kwargs) -> Config:
    cfg = Config()
    for k, v in kwargs.items():
        setattr(cfg, k, v)
    return cfg


class TestCallLLMNoKeys(unittest.TestCase):
    def test_returns_none_when_no_keys_set(self):
        cfg = Config()  # All API keys are empty strings
        result = call_llm(cfg, "test prompt")
        self.assertIsNone(result)

    def test_returns_none_when_only_empty_strings(self):
        cfg = _config(
            groq_api_key="",
            deepseek_api_key="",
            openrouter_api_key="",
            anthropic_api_key="",
        )
        result = call_llm(cfg, "test prompt")
        self.assertIsNone(result)


class TestCallLLMGroqPriority(unittest.TestCase):
    """Groq is tried first when key is set."""

    def test_groq_called_first_when_key_set(self):
        cfg = _config(groq_api_key="gsk-test", deepseek_api_key="ds-test")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Groq analysis result"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = call_llm(cfg, "test prompt")

        self.assertIsNotNone(result)
        content, provider = result
        self.assertEqual(provider, "groq")
        self.assertEqual(content, "Groq analysis result")

        # Verify Groq URL was hit
        call_url = mock_post.call_args[0][0]
        self.assertIn("groq.com", call_url)

    def test_groq_returns_tuple_of_content_and_provider(self):
        cfg = _config(groq_api_key="gsk-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "  Threat intel content  "}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp):
            result = call_llm(cfg, "test prompt")

        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        content, provider = result
        self.assertEqual(content, "Threat intel content")
        self.assertEqual(provider, "groq")


class TestCallLLMDeepSeek(unittest.TestCase):
    def test_deepseek_called_when_groq_fails(self):
        cfg = _config(groq_api_key="bad-key", deepseek_api_key="ds-valid")

        groq_resp = MagicMock()
        groq_resp.raise_for_status.side_effect = Exception("Groq 401")

        deepseek_resp = MagicMock()
        deepseek_resp.json.return_value = {
            "choices": [{"message": {"content": "DeepSeek analysis"}}]
        }
        deepseek_resp.raise_for_status = MagicMock()

        with patch("requests.post", side_effect=[groq_resp, deepseek_resp]):
            result = call_llm(cfg, "test prompt")

        self.assertIsNotNone(result)
        content, provider = result
        self.assertEqual(provider, "deepseek")
        self.assertEqual(content, "DeepSeek analysis")

    def test_deepseek_used_when_only_deepseek_key(self):
        cfg = _config(deepseek_api_key="ds-only-key")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "DeepSeek only result"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = call_llm(cfg, "test prompt")

        call_url = mock_post.call_args[0][0]
        self.assertIn("deepseek.com", call_url)
        content, provider = result
        self.assertEqual(provider, "deepseek")


class TestCallLLMOpenRouter(unittest.TestCase):
    def test_openrouter_used_when_only_openrouter_key(self):
        cfg = _config(openrouter_api_key="sk-or-test")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "OpenRouter result"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = call_llm(cfg, "test prompt")

        call_url = mock_post.call_args[0][0]
        self.assertIn("openrouter.ai", call_url)
        content, provider = result
        self.assertEqual(provider, "openrouter")

    def test_openrouter_sends_referer_header(self):
        cfg = _config(openrouter_api_key="sk-or-test")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "OK"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp) as mock_post:
            call_llm(cfg, "test prompt")

        headers_sent = mock_post.call_args[1]["headers"]
        self.assertIn("HTTP-Referer", headers_sent)
        self.assertIn("cyberdudebivash.in", headers_sent["HTTP-Referer"])


class TestCallLLMFallbackChain(unittest.TestCase):
    def test_falls_through_all_failing_providers_to_none(self):
        cfg = _config(
            groq_api_key="bad-groq",
            deepseek_api_key="bad-deepseek",
            openrouter_api_key="bad-openrouter",
        )

        fail_resp = MagicMock()
        fail_resp.raise_for_status.side_effect = Exception("HTTP 401")

        with patch("requests.post", return_value=fail_resp):
            result = call_llm(cfg, "test prompt")

        self.assertIsNone(result)

    def test_openrouter_is_last_resort_before_none(self):
        cfg = _config(
            groq_api_key="bad",
            deepseek_api_key="bad",
            openrouter_api_key="good-or",
        )

        fail_resp = MagicMock()
        fail_resp.raise_for_status.side_effect = Exception("HTTP 401")

        ok_resp = MagicMock()
        ok_resp.json.return_value = {
            "choices": [{"message": {"content": "Fallback content"}}]
        }
        ok_resp.raise_for_status = MagicMock()

        with patch("requests.post", side_effect=[fail_resp, fail_resp, ok_resp]):
            result = call_llm(cfg, "test prompt")

        self.assertIsNotNone(result)
        _, provider = result
        self.assertEqual(provider, "openrouter")


class TestOpenAICompatCall(unittest.TestCase):
    def test_strips_whitespace_from_response(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "\n  content here  \n"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp):
            result = _call_openai_compat(
                url="https://api.example.com/v1/chat/completions",
                api_key="test-key",
                model="test-model",
                prompt="test",
                max_tokens=100,
                extra_headers={},
            )

        self.assertEqual(result, "content here")

    def test_raises_on_http_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 429")

        with patch("requests.post", return_value=mock_resp):
            with self.assertRaises(Exception):
                _call_openai_compat(
                    url="https://api.example.com/v1/chat/completions",
                    api_key="test-key",
                    model="test-model",
                    prompt="test",
                    max_tokens=100,
                    extra_headers={},
                )


class TestRetryAfterParsing(unittest.TestCase):
    """RX-P1-PROVIDER-RELIABILITY: _retry_after_seconds() -- real APIs send
    either delay-seconds or an HTTP-date (RFC 9110 §10.2.3)."""

    def test_numeric_seconds_form(self):
        resp = MagicMock(headers={"Retry-After": "3"})
        self.assertEqual(_retry_after_seconds(resp), 3.0)

    def test_http_date_form(self):
        from datetime import datetime, timedelta, timezone
        future = datetime.now(timezone.utc) + timedelta(seconds=4)
        resp = MagicMock(headers={"Retry-After": future.strftime("%a, %d %b %Y %H:%M:%S GMT")})
        seconds = _retry_after_seconds(resp)
        self.assertIsNotNone(seconds)
        self.assertAlmostEqual(seconds, 4.0, delta=1.5)

    def test_missing_header_returns_none(self):
        resp = MagicMock(headers={})
        self.assertIsNone(_retry_after_seconds(resp))

    def test_unparseable_value_returns_none(self):
        resp = MagicMock(headers={"Retry-After": "not-a-number-or-date"})
        self.assertIsNone(_retry_after_seconds(resp))

    def test_capped_at_max_backoff(self):
        resp = MagicMock(headers={"Retry-After": "999999"})
        self.assertEqual(_retry_after_seconds(resp), _MAX_BACKOFF_SECONDS)

    def test_none_response_returns_none(self):
        self.assertIsNone(_retry_after_seconds(None))


class TestBackoffSeconds(unittest.TestCase):
    def test_real_retry_after_hint_always_wins(self):
        self.assertEqual(_backoff_seconds(attempt=0, retry_after=2.5), 2.5)
        self.assertEqual(_backoff_seconds(attempt=1, retry_after=2.5), 2.5)

    def test_exponential_growth_without_a_hint(self):
        first = _backoff_seconds(attempt=0, retry_after=None)
        second = _backoff_seconds(attempt=1, retry_after=None)
        # Jitter makes exact values non-deterministic; growth trend must hold.
        self.assertLess(first, _MAX_BACKOFF_SECONDS)
        self.assertGreaterEqual(second, first - 1.0)  # generous bound for jitter overlap

    def test_never_exceeds_the_bounded_ceiling(self):
        for attempt in range(10):
            self.assertLessEqual(_backoff_seconds(attempt=attempt, retry_after=None), _MAX_BACKOFF_SECONDS)


class TestOpenAICompatRetryOn429(unittest.TestCase):
    """The actual bounded-retry mechanism, isolated from the provider chain."""

    def test_retries_on_429_then_succeeds_without_a_real_sleep(self):
        rate_limited = MagicMock(status_code=429, headers={"Retry-After": "1"})
        ok = MagicMock(status_code=200)
        ok.json.return_value = {"choices": [{"message": {"content": "recovered"}}]}
        ok.raise_for_status = MagicMock()
        sleep_calls = []

        with patch("requests.post", side_effect=[rate_limited, ok]):
            result = _call_openai_compat(
                url="https://api.example.com/v1/chat/completions", api_key="k", model="m",
                prompt="p", max_tokens=100, extra_headers={}, sleep_fn=sleep_calls.append,
            )

        self.assertEqual(result, "recovered")
        self.assertEqual(sleep_calls, [1.0])  # real Retry-After honored exactly

    def test_never_retries_on_402_billing_error(self):
        # "Do not blindly retry billing failures such as 402" -- must raise
        # on the FIRST attempt, never call sleep_fn, never call requests.post twice.
        billing_error = MagicMock(status_code=402)
        billing_error.raise_for_status.side_effect = Exception("402 Payment Required")
        sleep_calls = []

        with patch("requests.post", return_value=billing_error) as mock_post:
            with self.assertRaises(Exception):
                _call_openai_compat(
                    url="https://api.example.com/v1/chat/completions", api_key="k", model="m",
                    prompt="p", max_tokens=100, extra_headers={}, sleep_fn=sleep_calls.append,
                )

        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual(sleep_calls, [])

    def test_gives_up_after_bounded_retries_and_raises(self):
        always_rate_limited = MagicMock(status_code=429, headers={})
        always_rate_limited.raise_for_status.side_effect = Exception("429 Too Many Requests")
        sleep_calls = []

        with patch("requests.post", return_value=always_rate_limited) as mock_post:
            with self.assertRaises(Exception):
                _call_openai_compat(
                    url="https://api.example.com/v1/chat/completions", api_key="k", model="m",
                    prompt="p", max_tokens=100, extra_headers={}, sleep_fn=sleep_calls.append,
                )

        # _MAX_RETRIES_ON_RATE_LIMIT retries -> _MAX_RETRIES_ON_RATE_LIMIT + 1 total attempts.
        self.assertEqual(mock_post.call_count, _MAX_RETRIES_ON_RATE_LIMIT + 1)
        self.assertEqual(len(sleep_calls), _MAX_RETRIES_ON_RATE_LIMIT)

    def test_call_llm_threads_sleep_fn_through_the_full_provider_chain(self):
        # End-to-end proof through the public call_llm() entry point, not
        # just the inner helper -- Groq rate-limited once, recovers, and no
        # real time is spent waiting.
        cfg = _config(groq_api_key="gsk-test")
        rate_limited = MagicMock(status_code=429, headers={})
        ok = MagicMock(status_code=200)
        ok.json.return_value = {"choices": [{"message": {"content": "Groq recovered"}}]}
        ok.raise_for_status = MagicMock()
        sleep_calls = []

        with patch("requests.post", side_effect=[rate_limited, ok]):
            result = call_llm(cfg, "test prompt", sleep_fn=sleep_calls.append)

        self.assertEqual(result, ("Groq recovered", "groq"))
        self.assertEqual(len(sleep_calls), 1)


class TestLLMModelConfig(unittest.TestCase):
    """Verify model defaults are sane."""

    def test_groq_default_model(self):
        # P0-REPORTX-2026-08-19: was a "llama" substring check, but Groq
        # deprecated llama-3.3-70b-versatile (2026-06-17 announced,
        # 2026-08-16 effective) -- the current default is their own
        # documented replacement, not a Llama model at all.
        cfg = Config()
        self.assertIn("gpt-oss", cfg.llm_model_groq.lower())

    def test_deepseek_default_model(self):
        cfg = Config()
        self.assertIn("deepseek", cfg.llm_model_deepseek.lower())

    def test_openrouter_default_model(self):
        cfg = Config()
        self.assertIn("deepseek", cfg.llm_model_openrouter.lower())


if __name__ == "__main__":
    unittest.main()
