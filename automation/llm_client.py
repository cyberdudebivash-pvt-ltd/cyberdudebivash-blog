"""
CYBERDUDEBIVASH® SENTINEL APEX — Multi-Provider LLM Client

Priority chain: Groq (primary free-tier model, then each fallback
free-tier model -- see Config.llm_model_groq_fallbacks -- each an
independent daily quota on the same key) -> DeepSeek -> OpenRouter (a
free model discovered live from its own catalog) -> Anthropic -> None.

Free-tier-only by design (2026-09-03 operator decision): DeepSeek's and
OpenRouter's paid tiers are unfunded until the platform earns real
revenue, so this chain is built to extract maximum free daily capacity
from Groq (see call_llm's docstring) before ever reaching a provider
known to fail on billing.

All current providers use the OpenAI-compatible chat completions API
except Anthropic, which uses its own Messages API format.
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


def _raw_retry_after_seconds(response) -> Optional[float]:
    """Parses a real ``Retry-After`` header -- either delay-seconds or an
    HTTP-date (RFC 9110 §10.2.3, both forms seen across real APIs) -- with
    NO cap applied. This is the provider's own, honest statement of how
    long it wants us to wait; ``_retry_after_seconds()`` below is the
    version actually used to schedule a retry (capped at
    ``_MAX_BACKOFF_SECONDS`` for the pipeline's own bounded-budget reasons).
    Kept separate and logged (see ``_call_openai_compat`` below) so a real
    429 always leaves evidence of what the provider actually asked for,
    not just what we chose to honor -- production incident 2026-09-03:
    every single observed retry delay was logged as exactly the capped
    value with zero variance across 12 samples, strong evidence the real
    ask consistently exceeds the cap and every retry was therefore
    scheduled before the provider was actually ready, guaranteeing the
    second 429. Without the raw value on record, that could only ever be
    inferred, never confirmed."""
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
    """Parses a real ``Retry-After`` header, capped at
    ``_MAX_BACKOFF_SECONDS`` so a provider's own hint can't itself blow the
    bounded budget above. Returns ``None`` (never 0) when absent or
    unparseable, so the caller falls back to its own backoff schedule
    instead of silently retrying with no delay at all."""
    raw = _raw_retry_after_seconds(response)
    if raw is None:
        return None
    return max(0.0, min(raw, _MAX_BACKOFF_SECONDS))


def _backoff_seconds(attempt: int, retry_after: Optional[float]) -> float:
    """A real ``Retry-After`` hint always wins (the provider knows its own
    limit better than a guess); otherwise bounded exponential backoff with
    jitter (avoids every concurrent workflow run retrying in lockstep)."""
    if retry_after is not None:
        return retry_after
    return min(_BASE_BACKOFF_SECONDS * (2 ** attempt) + random.uniform(0, _BASE_BACKOFF_SECONDS), _MAX_BACKOFF_SECONDS)

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# Production incident 2026-09-03: the account has no funded paid provider
# and none is coming until the platform earns real revenue (operator
# decision) -- so DeepSeek and OpenRouter's paid tiers being unfunded (402
# on every call, confirmed via production logs) is not "fixable" in the
# sense of adding money. What *is* fixable: Groq's free/on_demand tier
# enforces its "tokens per day" (TPD) ceiling PER MODEL, not account-wide
# (confirmed directly from a real 429 response body: "Rate limit reached
# for model `openai/gpt-oss-120b` ... on tokens per day (TPD): Limit
# 200000, Used 198641" -- a model-scoped message, and Groq's own free-tier
# rate-limit table lists separate 200K TPD allowances per model). The same
# GROQ_API_KEY already configured gets independent daily budgets on each
# of these models -- trying them in sequence before ever falling through
# to a dead paid provider multiplies real, free, zero-signup daily
# capacity roughly 4x with no new secret required. Verified against Groq's
# own free-tier rate-limit documentation on 2026-09-03. The actual default
# list lives on Config.llm_model_groq_fallbacks (overridable via the
# GROQ_FALLBACK_MODELS env var) so an operator can react to a Groq catalog
# change without a code deploy.

# OpenRouter's free (":free"-suffixed, $0 pricing) model catalog is
# reported to churn weekly -- entire free tiers have been added and
# discontinued within the same month (verified via web research
# 2026-09-03). Hardcoding one free model ID here would just recreate this
# exact incident the next time OpenRouter retires it. Instead, ask
# OpenRouter's own public /models endpoint which models are currently
# priced at zero and use one of those -- self-healing against catalog
# churn instead of another guess. Cached per-process (one GitHub Actions
# job = one process = at most one real discovery call per run).
_OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
_openrouter_free_model_cache: Optional[str] = None
_openrouter_discovery_attempted = False


def _discover_openrouter_free_model(api_key: str, sleep_fn=time.sleep) -> Optional[str]:
    """Returns a currently-free (`$0` prompt and completion pricing) model
    ID from OpenRouter's live catalog, or None if discovery fails or no
    free model is currently listed. Never raises -- a discovery failure
    just means OpenRouter is skipped this run, same as `no_api_key`."""
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
        # Prefer the model with the largest context window -- premium
        # report prompts are long; a free model too small to fit the
        # prompt would just fail differently, not more usefully.
        free.sort(key=lambda m: m.get("context_length") or 0, reverse=True)
        _openrouter_free_model_cache = free[0]["id"]
        return _openrouter_free_model_cache
    except Exception as e:
        logger.warning("OpenRouter free-model discovery failed", extra={"error": str(e)[:200]})
        return None


def call_llm(
    config: Config,
    prompt: str,
    max_tokens: int = 3000,
    attempts: Optional[list] = None,
    sleep_fn=time.sleep,
) -> Optional[tuple[str, str]]:
    """
    Try each configured LLM provider in priority order -- Groq (its own
    free-tier model, then each configured fallback free-tier model, each
    with an independent daily quota) -> DeepSeek -> OpenRouter (a live-
    discovered free model) -> Anthropic. Returns (content, provider_name)
    on first success, or None if all fail. `provider_name` is always the
    bare provider family ("groq", "deepseek", "openrouter", "anthropic")
    regardless of which specific model within that family succeeded, so
    callers checking membership in a fixed provider-name set (e.g. "was
    this LLM-authored") keep working unchanged.

    If `attempts` is provided, every provider/model considered is appended
    to it as {"provider": name, "model": str | None, "ok": bool,
    "error": str | None} -- including providers skipped for having no API
    key configured (one entry per family in that case, not one per model:
    there is nothing more to say about a missing key than that it is
    missing). This lets a caller persist *why* a run fell back to the
    template (no key vs. rate limit vs. other API failure) instead of only
    recording *that* it did.

    `sleep_fn` (default `time.sleep`) governs the bounded 429 retry-with-
    backoff in `_call_openai_compat()` -- exposed here, not just on that
    inner function, so a caller/test can control it without reaching past
    this module's own public entry point.
    """
    groq_key = config.groq_api_key
    if groq_key:
        seen_models: set = set()
        groq_models = [config.llm_model_groq, *config.llm_model_groq_fallbacks]
        for model in groq_models:
            if not model or model in seen_models:
                continue
            seen_models.add(model)
            result = _try_provider(
                name="groq", url=_GROQ_URL, api_key=groq_key, model=model,
                prompt=prompt, max_tokens=max_tokens, extra_headers={},
                sleep_fn=sleep_fn, attempts=attempts,
            )
            if result is not None:
                return result, "groq"
    elif attempts is not None:
        attempts.append({"provider": "groq", "model": None, "ok": False, "error": "no_api_key"})

    deepseek_key = config.deepseek_api_key
    if deepseek_key:
        result = _try_provider(
            name="deepseek", url="https://api.deepseek.com/v1/chat/completions",
            api_key=deepseek_key, model=config.llm_model_deepseek,
            prompt=prompt, max_tokens=max_tokens, extra_headers={},
            sleep_fn=sleep_fn, attempts=attempts,
        )
        if result is not None:
            return result, "deepseek"
    elif attempts is not None:
        attempts.append({"provider": "deepseek", "model": None, "ok": False, "error": "no_api_key"})

    openrouter_key = config.openrouter_api_key
    if openrouter_key:
        free_model = _discover_openrouter_free_model(openrouter_key, sleep_fn=sleep_fn)
        if free_model:
            result = _try_provider(
                name="openrouter", url="https://openrouter.ai/api/v1/chat/completions",
                api_key=openrouter_key, model=free_model,
                prompt=prompt, max_tokens=max_tokens,
                extra_headers={
                    "HTTP-Referer": "https://blog.cyberdudebivash.in",
                    "X-Title": "CYBERDUDEBIVASH SENTINEL APEX",
                },
                sleep_fn=sleep_fn, attempts=attempts,
            )
            if result is not None:
                return result, "openrouter"
        elif attempts is not None:
            attempts.append({"provider": "openrouter", "model": None, "ok": False, "error": "no_free_model_available"})
    elif attempts is not None:
        attempts.append({"provider": "openrouter", "model": None, "ok": False, "error": "no_api_key"})

    anthropic_key = config.anthropic_api_key
    if anthropic_key:
        try:
            content = _call_anthropic(anthropic_key, config.claude_model, prompt, max_tokens)
            if content:
                logger.info("LLM call succeeded", extra={"provider": "anthropic", "model": config.claude_model, "chars": len(content)})
                if attempts is not None:
                    attempts.append({"provider": "anthropic", "model": config.claude_model, "ok": True, "error": None})
                return content, "anthropic"
            if attempts is not None:
                attempts.append({"provider": "anthropic", "model": config.claude_model, "ok": False, "error": "empty_response"})
        except Exception as e:
            logger.warning("LLM provider failed, trying next", extra={"provider": "anthropic", "error": str(e)})
            if attempts is not None:
                attempts.append({"provider": "anthropic", "model": config.claude_model, "ok": False, "error": str(e)[:200]})
    elif attempts is not None:
        attempts.append({"provider": "anthropic", "model": None, "ok": False, "error": "no_api_key"})

    logger.info("No LLM provider available — using template fallback")
    return None


def _try_provider(
    name: str, url: str, api_key: str, model: str, prompt: str, max_tokens: int,
    extra_headers: dict, sleep_fn, attempts: Optional[list],
) -> Optional[str]:
    """Single (provider, model) attempt against the OpenAI-compatible chat
    completions API. Returns the content string on success, None on any
    failure (recorded into `attempts` either way) -- callers loop to the
    next model/provider on None, exactly as the previous single-attempt
    inline logic did per provider."""
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
    except Exception as e:
        logger.warning("LLM provider failed, trying next", extra={"provider": name, "model": model, "error": str(e)})
        if attempts is not None:
            attempts.append({"provider": name, "model": model, "ok": False, "error": str(e)[:200]})
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
            raw_retry_after = _raw_retry_after_seconds(resp)
            # Production incident 2026-09-03 (see _raw_retry_after_seconds's
            # docstring): every retry scheduled against a raw ask this far
            # past our own ceiling was observed to hit a second 429 anyway,
            # 12/12 samples, zero variance -- a wait-then-retry on THIS
            # model is a guaranteed failure, not a real second chance, when
            # the provider has explicitly told us its own reset is minutes
            # to tens of minutes away (a tokens-per-day quota, not a
            # transient tokens-per-minute one). Paying the capped wait
            # anyway just delays call_llm's own model/provider fallback
            # chain from reaching a model that can actually answer now --
            # so skip the remaining retries and let that fallback run
            # immediately instead.
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
            # raw_retry_after (uncapped) vs delay_seconds (what we actually
            # waited) -- see _raw_retry_after_seconds's docstring. If these
            # two diverge, the provider asked for longer than we honored
            # and this retry is scheduled before the provider says it will
            # be ready. response_body is truncated (rate-limit error bodies
            # are typically short JSON) purely so a real reason/reset-time
            # string a provider includes is visible in logs, never silently
            # discarded as it was before this instrumentation existed.
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
