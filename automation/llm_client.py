"""
CYBERDUDEBIVASH® SENTINEL APEX — Multi-Provider LLM Client
Priority chain: Groq → DeepSeek → OpenRouter → Anthropic (future) → None
All current providers use the OpenAI-compatible chat completions API.
"""

import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import requests
from .config import Config
from .logger import setup_logger

logger = setup_logger("llm_client")

# RX-P1-PROVIDER-RELIABILITY: live-canary evidence (PHASE-0-RELEASE-CERTIFICATION.md)
# showed Groq succeeding then immediately 429-ing on the very next call within
# the same run, while DeepSeek/OpenRouter fail on account-level 402 (not
# retryable, not fixable from this repository) -- so retrying is only ever
# worth attempting on 429. Bounded deliberately: the triggering workflow has
# a real, non-fatal-but-real 5-minute ceiling and processes up to 5 posts per
# run (PRODUCTION-PIPELINE-AS-IS.md §2.5), so one provider's rate limit must
# never be able to consume more than a small, fixed slice of that budget.
_MAX_RETRIES_ON_RATE_LIMIT = 2  # up to 3 total attempts per provider
_MAX_BACKOFF_SECONDS = 10.0
_BASE_BACKOFF_SECONDS = 1.0


def _retry_after_seconds(response) -> Optional[float]:
    """Parses a real ``Retry-After`` header -- either delay-seconds or an
    HTTP-date (RFC 9110 §10.2.3, both forms seen across real APIs) -- capped
    at ``_MAX_BACKOFF_SECONDS`` so a provider's own hint can't itself blow
    the bounded budget above. Returns ``None`` (never 0) when absent or
    unparseable, so the caller falls back to its own backoff schedule
    instead of silently retrying with no delay at all."""
    if response is None:
        return None
    value = response.headers.get("Retry-After")
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            seconds = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            return None
    return max(0.0, min(seconds, _MAX_BACKOFF_SECONDS))


def _backoff_seconds(attempt: int, retry_after: Optional[float]) -> float:
    """A real ``Retry-After`` hint always wins (the provider knows its own
    limit better than a guess); otherwise bounded exponential backoff with
    jitter (avoids every concurrent workflow run retrying in lockstep)."""
    if retry_after is not None:
        return retry_after
    return min(_BASE_BACKOFF_SECONDS * (2 ** attempt) + random.uniform(0, _BASE_BACKOFF_SECONDS), _MAX_BACKOFF_SECONDS)

# Provider definitions — tried in order listed
_PROVIDERS = [
    {
        "name": "groq",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "model_attr": "llm_model_groq",
        "key_attr": "groq_api_key",
        "headers": {},
    },
    {
        "name": "deepseek",
        "url": "https://api.deepseek.com/v1/chat/completions",
        "model_attr": "llm_model_deepseek",
        "key_attr": "deepseek_api_key",
        "headers": {},
    },
    {
        "name": "openrouter",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "model_attr": "llm_model_openrouter",
        "key_attr": "openrouter_api_key",
        "headers": {
            "HTTP-Referer": "https://blog.cyberdudebivash.in",
            "X-Title": "CYBERDUDEBIVASH SENTINEL APEX",
        },
    },
    {
        "name": "anthropic",
        "url": "https://api.anthropic.com/v1/messages",
        "model_attr": "claude_model",
        "key_attr": "anthropic_api_key",
        "headers": {},
        "is_anthropic": True,
    },
]


def call_llm(
    config: Config,
    prompt: str,
    max_tokens: int = 3000,
    attempts: Optional[list] = None,
    sleep_fn=time.sleep,
) -> Optional[tuple[str, str]]:
    """
    Try each configured LLM provider in priority order.
    Returns (content, provider_name) on first success, or None if all fail.

    If `attempts` is provided, every provider considered is appended to it as
    {"provider": name, "ok": bool, "error": str | None} — including providers
    skipped for having no API key configured. This lets a caller persist
    *why* a run fell back to the template (no key vs. rate limit vs. other
    API failure) instead of only recording *that* it did, which the run
    report previously had no way to distinguish.

    `sleep_fn` (default `time.sleep`) governs the bounded 429 retry-with-
    backoff in `_call_openai_compat()` -- exposed here, not just on that
    inner function, so a caller/test can control it without reaching past
    this module's own public entry point.
    """
    for provider in _PROVIDERS:
        name = provider["name"]
        api_key = getattr(config, provider["key_attr"], "")
        if not api_key:
            if attempts is not None:
                attempts.append({"provider": name, "ok": False, "error": "no_api_key"})
            continue

        model = getattr(config, provider["model_attr"], "")

        try:
            if provider.get("is_anthropic"):
                content = _call_anthropic(api_key, model, prompt, max_tokens)
            else:
                content = _call_openai_compat(
                    url=provider["url"],
                    api_key=api_key,
                    model=model,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    extra_headers=provider.get("headers", {}),
                    sleep_fn=sleep_fn,
                )

            if content:
                logger.info(
                    "LLM call succeeded",
                    extra={"provider": name, "model": model, "chars": len(content)},
                )
                if attempts is not None:
                    attempts.append({"provider": name, "ok": True, "error": None})
                return content, name

            if attempts is not None:
                attempts.append({"provider": name, "ok": False, "error": "empty_response"})

        except Exception as e:
            logger.warning(
                "LLM provider failed, trying next",
                extra={"provider": name, "error": str(e)},
            )
            if attempts is not None:
                attempts.append({"provider": name, "ok": False, "error": str(e)[:200]})
            continue

    logger.info("No LLM provider available — using template fallback")
    return None


def _call_openai_compat(
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
    sleep_fn=time.sleep,
) -> Optional[str]:
    """Call any OpenAI-compatible chat completions endpoint.

    Retries only on HTTP 429 (bounded, backoff+jitter or a real
    ``Retry-After`` hint -- see module docstring above), up to
    ``_MAX_RETRIES_ON_RATE_LIMIT`` times. Every other failure (a 402
    billing error in particular) is never retried -- it raises immediately,
    exactly as before this change, so ``call_llm()``'s own provider-chain
    fallback still moves on without delay. ``sleep_fn`` defaults to
    ``time.sleep``; tests inject a no-op to assert on backoff timing
    without a real test suite actually waiting on it.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **extra_headers,
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    for attempt in range(_MAX_RETRIES_ON_RATE_LIMIT + 1):
        resp = requests.post(url, json=payload, headers=headers, timeout=60)
        if resp.status_code == 429 and attempt < _MAX_RETRIES_ON_RATE_LIMIT:
            delay = _backoff_seconds(attempt, _retry_after_seconds(resp))
            logger.info(
                "LLM provider rate-limited, retrying",
                extra={"url": url, "attempt": attempt + 1, "delay_seconds": round(delay, 2)},
            )
            sleep_fn(delay)
            continue
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()


def _call_anthropic(api_key: str, model: str, prompt: str, max_tokens: int) -> Optional[str]:
    """Call Anthropic Messages API (non-OpenAI format)."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text.strip()
    except ImportError:
        # anthropic package not installed — use raw HTTP
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            json=payload,
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"].strip()
