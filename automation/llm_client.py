"""
CYBERDUDEBIVASH® SENTINEL APEX — Multi-Provider LLM Client

Production zero-spend priority chain:
  Groq free model pool -> Gemini Free Tier -> OpenRouter zero-priced model
  -> optional paid providers (only when ALLOW_PAID_LLM=true) -> None.

Gemini is additionally fail-closed behind GEMINI_PUBLIC_DATA_ONLY=true because
this free-tier route is intended only for already-public CTI/OSINT evidence.
DeepSeek and Anthropic remain supported for future commercial operation, but
production cannot call them while the zero-spend circuit is closed.
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

_MAX_RETRIES_ON_RATE_LIMIT = 2  # up to 3 total attempts per provider
_MAX_BACKOFF_SECONDS = 10.0
_BASE_BACKOFF_SECONDS = 1.0


def _raw_retry_after_seconds(response) -> Optional[float]:
    """Parse Retry-After without applying the pipeline's bounded wait cap."""
    if response is None:
        return None
    value = response.headers.get("Retry-After")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        try:
            return (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            return None


def _retry_after_seconds(response) -> Optional[float]:
    """Parse Retry-After and clamp it to the bounded pipeline wait ceiling."""
    raw = _raw_retry_after_seconds(response)
    if raw is None:
        return None
    return max(0.0, min(raw, _MAX_BACKOFF_SECONDS))


def _backoff_seconds(attempt: int, retry_after: Optional[float]) -> float:
    """Use provider Retry-After when present; otherwise bounded jittered backoff."""
    if retry_after is not None:
        return retry_after
    return min(
        _BASE_BACKOFF_SECONDS * (2 ** attempt) + random.uniform(0, _BASE_BACKOFF_SECONDS),
        _MAX_BACKOFF_SECONDS,
    )


_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
_DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions"
_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# OpenRouter's zero-priced catalog changes independently of this repository.
# Discover a current :free model once per Actions process instead of pinning a
# stale model ID.
_OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
_openrouter_free_model_cache: Optional[str] = None
_openrouter_discovery_attempted = False


def _discover_openrouter_free_model(api_key: str, sleep_fn=time.sleep) -> Optional[str]:
    """Return a currently zero-priced OpenRouter :free model, never raising."""
    del sleep_fn  # compatibility with existing callers; discovery itself is one GET.
    global _openrouter_free_model_cache, _openrouter_discovery_attempted
    if _openrouter_discovery_attempted:
        return _openrouter_free_model_cache
    _openrouter_discovery_attempted = True
    try:
        resp = requests.get(
            _OPENROUTER_MODELS_URL,
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=20,
        )
        resp.raise_for_status()
        models = resp.json().get("data", [])
        free = [
            m for m in models
            if str(m.get("pricing", {}).get("prompt", "-1")) in ("0", "0.0")
            and str(m.get("pricing", {}).get("completion", "-1")) in ("0", "0.0")
            and str(m.get("id", "")).endswith(":free")
        ]
        if not free:
            return None
        free.sort(key=lambda m: m.get("context_length") or 0, reverse=True)
        _openrouter_free_model_cache = free[0]["id"]
        return _openrouter_free_model_cache
    except Exception as exc:
        logger.warning("OpenRouter free-model discovery failed", extra={"error": str(exc)[:200]})
        return None


def _attempt_groq(config: Config, prompt: str, max_tokens: int, attempts, sleep_fn):
    key = config.groq_api_key
    if not key:
        if attempts is not None:
            attempts.append({"provider": "groq", "model": None, "ok": False, "error": "no_api_key"})
        return None

    seen_models: set[str] = set()
    for model in [config.llm_model_groq, *config.llm_model_groq_fallbacks]:
        if not model or model in seen_models:
            continue
        seen_models.add(model)
        result = _try_provider(
            name="groq", url=_GROQ_URL, api_key=key, model=model,
            prompt=prompt, max_tokens=max_tokens, extra_headers={},
            sleep_fn=sleep_fn, attempts=attempts,
        )
        if result is not None:
            return result, "groq"
    return None


def _attempt_gemini(config: Config, prompt: str, max_tokens: int, attempts, sleep_fn):
    key = config.gemini_api_key
    if not key:
        if attempts is not None:
            attempts.append({"provider": "gemini", "model": None, "ok": False, "error": "no_api_key"})
        return None

    # Free-tier Gemini may receive only public CTI/OSINT in this factory. This
    # is an operator assertion, not a content classifier: if the production
    # workflow does not explicitly assert the public-data boundary, no Gemini
    # transport call is permitted.
    if not config.gemini_public_data_only:
        if attempts is not None:
            attempts.append({
                "provider": "gemini", "model": None, "ok": False,
                "error": "public_data_only_not_enabled",
            })
        logger.warning("Gemini skipped because public-data-only boundary is not enabled")
        return None

    seen_models: set[str] = set()
    for model in [config.llm_model_gemini, *config.llm_model_gemini_fallbacks]:
        if not model or model in seen_models:
            continue
        seen_models.add(model)
        result = _try_provider(
            name="gemini", url=_GEMINI_URL, api_key=key, model=model,
            prompt=prompt, max_tokens=max_tokens, extra_headers={},
            sleep_fn=sleep_fn, attempts=attempts,
        )
        if result is not None:
            return result, "gemini"
    return None


def _attempt_openrouter(config: Config, prompt: str, max_tokens: int, attempts, sleep_fn):
    key = config.openrouter_api_key
    if not key:
        if attempts is not None:
            attempts.append({"provider": "openrouter", "model": None, "ok": False, "error": "no_api_key"})
        return None

    free_model = _discover_openrouter_free_model(key, sleep_fn=sleep_fn)
    if not free_model:
        if attempts is not None:
            attempts.append({
                "provider": "openrouter", "model": None, "ok": False,
                "error": "no_free_model_available",
            })
        return None

    result = _try_provider(
        name="openrouter", url=_OPENROUTER_URL,
        api_key=key, model=free_model, prompt=prompt, max_tokens=max_tokens,
        extra_headers={
            "HTTP-Referer": "https://blog.cyberdudebivash.in",
            "X-Title": "CYBERDUDEBIVASH SENTINEL APEX",
        },
        sleep_fn=sleep_fn, attempts=attempts,
    )
    return (result, "openrouter") if result is not None else None


def _record_paid_disabled(attempts, provider: str, model: Optional[str]) -> None:
    if attempts is not None:
        attempts.append({
            "provider": provider,
            "model": model,
            "ok": False,
            "error": "paid_provider_disabled",
        })


def _attempt_paid_providers(config: Config, prompt: str, max_tokens: int, attempts, sleep_fn):
    """Future commercial path; unreachable while ALLOW_PAID_LLM is false."""
    if not config.allow_paid_llm:
        if config.deepseek_api_key:
            _record_paid_disabled(attempts, "deepseek", config.llm_model_deepseek)
        elif attempts is not None:
            attempts.append({"provider": "deepseek", "model": None, "ok": False, "error": "no_api_key"})
        if config.anthropic_api_key:
            _record_paid_disabled(attempts, "anthropic", config.claude_model)
        elif attempts is not None:
            attempts.append({"provider": "anthropic", "model": None, "ok": False, "error": "no_api_key"})
        return None

    if config.deepseek_api_key:
        result = _try_provider(
            name="deepseek", url=_DEEPSEEK_URL,
            api_key=config.deepseek_api_key, model=config.llm_model_deepseek,
            prompt=prompt, max_tokens=max_tokens, extra_headers={},
            sleep_fn=sleep_fn, attempts=attempts,
        )
        if result is not None:
            return result, "deepseek"
    elif attempts is not None:
        attempts.append({"provider": "deepseek", "model": None, "ok": False, "error": "no_api_key"})

    if config.anthropic_api_key:
        try:
            content = _call_anthropic(config.anthropic_api_key, config.claude_model, prompt, max_tokens)
            if content:
                logger.info(
                    "LLM call succeeded",
                    extra={"provider": "anthropic", "model": config.claude_model, "chars": len(content)},
                )
                if attempts is not None:
                    attempts.append({"provider": "anthropic", "model": config.claude_model, "ok": True, "error": None})
                return content, "anthropic"
            if attempts is not None:
                attempts.append({"provider": "anthropic", "model": config.claude_model, "ok": False, "error": "empty_response"})
        except Exception as exc:
            logger.warning("LLM provider failed", extra={"provider": "anthropic", "error": str(exc)})
            if attempts is not None:
                attempts.append({"provider": "anthropic", "model": config.claude_model, "ok": False, "error": str(exc)[:200]})
    elif attempts is not None:
        attempts.append({"provider": "anthropic", "model": None, "ok": False, "error": "no_api_key"})
    return None


def call_llm(
    config: Config,
    prompt: str,
    max_tokens: int = 3000,
    attempts: Optional[list] = None,
    sleep_fn=time.sleep,
) -> Optional[tuple[str, str]]:
    """Run the zero-spend provider mesh and return the first successful output.

    Production order is Groq -> Gemini -> OpenRouter. DeepSeek/Anthropic are
    attempted only when ``config.allow_paid_llm`` is explicitly true. Every
    provider/model considered can be recorded in ``attempts`` for run telemetry.
    """
    for runner in (_attempt_groq, _attempt_gemini, _attempt_openrouter):
        result = runner(config, prompt, max_tokens, attempts, sleep_fn)
        if result is not None:
            return result

    paid = _attempt_paid_providers(config, prompt, max_tokens, attempts, sleep_fn)
    if paid is not None:
        return paid

    logger.info("No zero-cost LLM provider available — using deterministic fallback")
    return None


def _try_provider(
    name: str, url: str, api_key: str, model: str, prompt: str, max_tokens: int,
    extra_headers: dict, sleep_fn, attempts: Optional[list],
) -> Optional[str]:
    """Attempt one OpenAI-compatible provider/model and record the disposition."""
    try:
        content = _call_openai_compat(
            url=url, api_key=api_key, model=model, prompt=prompt,
            max_tokens=max_tokens, extra_headers=extra_headers, sleep_fn=sleep_fn,
        )
        if content:
            logger.info("LLM call succeeded", extra={"provider": name, "model": model, "chars": len(content)})
            if attempts is not None:
                attempts.append({"provider": name, "model": model, "ok": True, "error": None})
            return content
        if attempts is not None:
            attempts.append({"provider": name, "model": model, "ok": False, "error": "empty_response"})
        return None
    except Exception as exc:
        logger.warning(
            "LLM provider failed, trying next",
            extra={"provider": name, "model": model, "error": str(exc)},
        )
        if attempts is not None:
            attempts.append({"provider": name, "model": model, "ok": False, "error": str(exc)[:200]})
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
    """Call an OpenAI-compatible chat endpoint with bounded 429 recovery."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **extra_headers,
    }
    # Google recommends the default temperature for Gemini 3-class models;
    # keep legacy deterministic temperature for the other provider families.
    temperature = 1.0 if str(model).lower().startswith("gemini-3") else 0.3
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    for attempt in range(_MAX_RETRIES_ON_RATE_LIMIT + 1):
        resp = requests.post(url, json=payload, headers=headers, timeout=60)
        if resp.status_code == 429 and attempt < _MAX_RETRIES_ON_RATE_LIMIT:
            raw_retry_after = _raw_retry_after_seconds(resp)
            if raw_retry_after is not None and raw_retry_after > _MAX_BACKOFF_SECONDS:
                logger.info(
                    "LLM provider rate-limited beyond the retry ceiling, skipping remaining retries",
                    extra={
                        "url": url,
                        "attempt": attempt + 1,
                        "raw_retry_after_seconds": raw_retry_after,
                        "backoff_ceiling_seconds": _MAX_BACKOFF_SECONDS,
                        "response_body": resp.text[:500] if resp.text else None,
                    },
                )
                resp.raise_for_status()
            delay = _backoff_seconds(attempt, _retry_after_seconds(resp))
            logger.info(
                "LLM provider rate-limited, retrying",
                extra={
                    "url": url,
                    "attempt": attempt + 1,
                    "delay_seconds": round(delay, 2),
                    "raw_retry_after_seconds": raw_retry_after,
                    "response_body": resp.text[:500] if resp.text else None,
                },
            )
            sleep_fn(delay)
            continue
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
    return None


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
