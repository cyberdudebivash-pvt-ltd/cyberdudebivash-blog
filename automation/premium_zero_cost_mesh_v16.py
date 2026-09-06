"""P0 v16 zero-cost multi-provider inference mesh for SENTINEL APEX.

The production factory is pre-revenue and must not make automatic paid LLM
calls.  Existing provider-resilience layers already make Groq model capacity
quota-aware and preserve OpenRouter's zero-priced catalog path.  v16 adds two
independent free-capacity domains without weakening any evidence or publication
gate:

    Groq free pool -> Gemini Free Tier -> NVIDIA NIM free API endpoint
    -> OpenRouter zero-priced model -> safe defer

DeepSeek and Anthropic remain configurable for a future commercial phase, but
are never called unless ``ALLOW_PAID_LLM=true``.  The production workflow keeps
that flag false and does not inject paid-provider credentials into the job.

Privacy/trust boundary:
- Gemini and hosted NVIDIA NIM are enabled only when their explicit
  ``*_PUBLIC_DATA_ONLY`` controls are true.
- This pipeline is for public CTI/OSINT.  Customer telemetry, credentials,
  unpublished VDP material, private incidents, or proprietary data must never
  be sent through these free endpoints.
- Model output remains untrusted analytical enrichment.  ReportX evidence,
  contradiction, prompt-leak, duplicate-section, provenance, and publication
  gates remain authoritative.

NVIDIA's Build API Catalog describes hosted NIM as a free *prototype* endpoint;
v16 therefore treats it as opportunistic fallback capacity, not an enterprise
availability SLA.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import replace
from typing import Callable, Optional

import requests

from . import analytical_depth_gate as _depth
from . import authority_transformer as _authority
from . import key_judgements as _key_judgements
from . import llm_client as _llm
from . import premium_evidence_compiler as _compiler
from . import premium_publication as _publication
from . import provider_quota_ledger as _quota
from .logger import setup_logger

logger = setup_logger("premium_zero_cost_mesh_v16")

MARKER = "CDB-ZERO-COST-INFERENCE-MESH-V16"
GEMINI_URL_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
NVIDIA_NIM_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

# One bounded retry is enough for a genuinely transient free-tier 429.  Durable
# reset windows are persisted by provider_quota_ledger and skipped on later
# calls/runs rather than repeatedly burning quota.
_MAX_TRANSIENT_RETRIES = 1

_INNER_AUTHORITY_CALL: Optional[Callable] = None
_INNER_KEY_JUDGEMENTS_CALL: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "provider_attempts": Counter(),
    "provider_successes": Counter(),
    "policy_blocks": Counter(),
    "gemini_thought_parts_discarded": 0,
}


def _append_attempt(attempts, *, provider: str, model, ok: bool, error=None, **extra) -> None:
    if attempts is None:
        return
    row = {
        "provider": provider,
        "model": model,
        "ok": bool(ok),
        "error": error,
    }
    row.update(extra)
    attempts.append(row)


def _dedupe_models(primary: str, fallbacks) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for model in [primary, *(fallbacks or ())]:
        value = str(model or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _public_only_enabled(config, provider: str) -> bool:
    attr = {
        "gemini": "gemini_public_data_only",
        "nvidia_nim": "nvidia_nim_public_data_only",
    }[provider]
    return bool(getattr(config, attr, False))


def _gemini_text(payload: dict) -> str:
    """Extract only answer text, never provider reasoning/thought parts."""
    chunks: list[str] = []
    for candidate in payload.get("candidates") or []:
        content = candidate.get("content") or {}
        for part in content.get("parts") or []:
            if part.get("thought") is True:
                _RUNTIME["gemini_thought_parts_discarded"] += 1
                continue
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                chunks.append(text.strip())
        if chunks:
            break
    return "\n".join(chunks).strip()


def _gemini_retry_delay(response) -> Optional[float]:
    try:
        raw = _llm._raw_retry_after_seconds(response)
    except Exception:
        raw = None
    if raw is None:
        return None
    try:
        raw = float(raw)
    except (TypeError, ValueError):
        return None
    if raw < 0:
        return 0.0
    # Never let one free endpoint monopolize the factory run.
    return min(raw, float(getattr(_llm, "_MAX_BACKOFF_SECONDS", 65.0)))


def _call_gemini_model(config, prompt: str, model: str, max_tokens: int, attempts, sleep_fn) -> Optional[str]:
    provider = "gemini"
    if not getattr(config, "gemini_api_key", ""):
        _append_attempt(attempts, provider=provider, model=model, ok=False, error="no_api_key")
        return None
    if not _public_only_enabled(config, provider):
        _RUNTIME["policy_blocks"][provider] += 1
        _append_attempt(
            attempts,
            provider=provider,
            model=model,
            ok=False,
            error="public_data_only_policy_not_enabled",
        )
        return None

    remaining = _quota.cooldown_remaining(provider, model)
    if remaining > 0:
        _append_attempt(
            attempts,
            provider=provider,
            model=model,
            ok=False,
            error="durable_provider_cooldown_active",
            retry_after_seconds=round(remaining, 2),
        )
        return None

    url = GEMINI_URL_TEMPLATE.format(model=model)
    headers = {
        "x-goog-api-key": config.gemini_api_key,
        "Content-Type": "application/json",
    }
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": int(max_tokens),
        },
    }

    for retry_index in range(_MAX_TRANSIENT_RETRIES + 1):
        _RUNTIME["provider_attempts"][provider] += 1
        try:
            response = requests.post(url, headers=headers, json=body, timeout=60)
        except Exception as exc:
            _append_attempt(
                attempts,
                provider=provider,
                model=model,
                ok=False,
                error=str(exc)[:200],
            )
            return None

        if response.status_code == 429:
            _quota.record_429(provider, model, response)
            delay = _gemini_retry_delay(response)
            if retry_index < _MAX_TRANSIENT_RETRIES and delay is not None and delay <= float(
                getattr(_llm, "_MAX_BACKOFF_SECONDS", 65.0)
            ):
                sleep_fn(delay)
                continue

        try:
            response.raise_for_status()
        except Exception as exc:
            _append_attempt(
                attempts,
                provider=provider,
                model=model,
                ok=False,
                error=str(exc)[:200],
            )
            return None

        try:
            content = _gemini_text(response.json())
        except Exception as exc:
            _append_attempt(
                attempts,
                provider=provider,
                model=model,
                ok=False,
                error=f"invalid_response:{str(exc)[:160]}",
            )
            return None

        if not content:
            _append_attempt(attempts, provider=provider, model=model, ok=False, error="empty_response")
            return None

        _quota.clear_model(provider, model)
        _RUNTIME["provider_successes"][provider] += 1
        _append_attempt(attempts, provider=provider, model=model, ok=True, error=None)
        logger.info("Gemini free-tier call succeeded", extra={"model": model, "chars": len(content)})
        return content

    return None


def _try_gemini(config, prompt: str, max_tokens: int, attempts, sleep_fn) -> Optional[tuple[str, str]]:
    if not getattr(config, "gemini_api_key", ""):
        _append_attempt(attempts, provider="gemini", model=None, ok=False, error="no_api_key")
        return None
    if not _public_only_enabled(config, "gemini"):
        _RUNTIME["policy_blocks"]["gemini"] += 1
        _append_attempt(
            attempts,
            provider="gemini",
            model=None,
            ok=False,
            error="public_data_only_policy_not_enabled",
        )
        return None

    models = _dedupe_models(
        getattr(config, "llm_model_gemini", ""),
        getattr(config, "llm_model_gemini_fallbacks", ()),
    )
    for model in models:
        content = _call_gemini_model(config, prompt, model, max_tokens, attempts, sleep_fn)
        if content:
            return content, "gemini"
    return None


def _try_nvidia(config, prompt: str, max_tokens: int, attempts, sleep_fn) -> Optional[tuple[str, str]]:
    provider = "nvidia_nim"
    key = getattr(config, "nvidia_nim_api_key", "")
    if not key:
        _append_attempt(attempts, provider=provider, model=None, ok=False, error="no_api_key")
        return None
    if not _public_only_enabled(config, provider):
        _RUNTIME["policy_blocks"][provider] += 1
        _append_attempt(
            attempts,
            provider=provider,
            model=None,
            ok=False,
            error="public_data_only_policy_not_enabled",
        )
        return None

    models = _dedupe_models(
        getattr(config, "llm_model_nvidia_nim", ""),
        getattr(config, "llm_model_nvidia_nim_fallbacks", ()),
    )
    for model in models:
        _RUNTIME["provider_attempts"][provider] += 1
        content = _llm._try_provider(
            name=provider,
            url=NVIDIA_NIM_URL,
            api_key=key,
            model=model,
            prompt=prompt,
            max_tokens=max_tokens,
            extra_headers={},
            sleep_fn=sleep_fn,
            attempts=attempts,
        )
        if content:
            _RUNTIME["provider_successes"][provider] += 1
            return content, provider
    return None


def _try_openrouter_free(config, prompt: str, max_tokens: int, attempts, sleep_fn) -> Optional[tuple[str, str]]:
    provider = "openrouter"
    key = getattr(config, "openrouter_api_key", "")
    if not key:
        _append_attempt(attempts, provider=provider, model=None, ok=False, error="no_api_key")
        return None
    model = _llm._discover_openrouter_free_model(key, sleep_fn=sleep_fn)
    if not model:
        _append_attempt(
            attempts,
            provider=provider,
            model=None,
            ok=False,
            error="no_free_model_available",
        )
        return None
    content = _llm._try_provider(
        name=provider,
        url="https://openrouter.ai/api/v1/chat/completions",
        api_key=key,
        model=model,
        prompt=prompt,
        max_tokens=max_tokens,
        extra_headers={
            "HTTP-Referer": "https://blog.cyberdudebivash.in",
            "X-Title": "CYBERDUDEBIVASH SENTINEL APEX",
        },
        sleep_fn=sleep_fn,
        attempts=attempts,
    )
    return (content, provider) if content else None


def _groq_only_config(config):
    """Hide every non-Groq legacy key from the already-proven inner runtime."""
    return replace(
        config,
        deepseek_api_key="",
        openrouter_api_key="",
        anthropic_api_key="",
    )


def _paid_only_config(config):
    return replace(
        config,
        groq_api_key="",
        openrouter_api_key="",
    )


def _copy_provider_attempts(target, source, allowed: set[str]) -> None:
    if target is None:
        return
    for row in source:
        if str(row.get("provider")) in allowed:
            target.append(row)


def _run_mesh(inner_call: Callable, config, prompt: str, max_tokens: int, attempts, sleep_fn):
    # Preserve all existing Groq model pacing, durable TPD recovery, bounded Qwen
    # chunking and evidence-admission behavior by calling the proven inner stack
    # with paid/OpenRouter keys hidden for this first stage.
    groq_attempts: list[dict] = []
    kwargs = {"max_tokens": max_tokens, "attempts": groq_attempts}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = inner_call(_groq_only_config(config), prompt, **kwargs)
    _copy_provider_attempts(attempts, groq_attempts, {"groq"})
    if result:
        return result

    for candidate in (
        _try_gemini(config, prompt, max_tokens, attempts, sleep_fn or time.sleep),
        _try_nvidia(config, prompt, max_tokens, attempts, sleep_fn or time.sleep),
        _try_openrouter_free(config, prompt, max_tokens, attempts, sleep_fn or time.sleep),
    ):
        if candidate:
            return candidate

    # Future commercial escape hatch.  This is deliberately opt-in and the
    # production workflow sets ALLOW_PAID_LLM=false and withholds these secrets.
    if bool(getattr(config, "allow_paid_llm", False)):
        paid_attempts: list[dict] = []
        kwargs = {"max_tokens": max_tokens, "attempts": paid_attempts}
        if sleep_fn is not None:
            kwargs["sleep_fn"] = sleep_fn
        result = inner_call(_paid_only_config(config), prompt, **kwargs)
        _copy_provider_attempts(attempts, paid_attempts, {"deepseek", "anthropic"})
        if result:
            return result
    else:
        for provider, attr in (
            ("deepseek", "deepseek_api_key"),
            ("anthropic", "anthropic_api_key"),
        ):
            if getattr(config, attr, ""):
                _RUNTIME["policy_blocks"][provider] += 1
                _append_attempt(
                    attempts,
                    provider=provider,
                    model=None,
                    ok=False,
                    error="paid_provider_disabled_by_policy",
                )

    logger.info("v16 zero-cost provider mesh exhausted; preserving safe defer behavior")
    return None


def zero_cost_authority_llm(config, prompt: str, max_tokens: int = 3000, attempts=None, sleep_fn=time.sleep):
    if _INNER_AUTHORITY_CALL is None:
        raise RuntimeError("v16 authority mesh is not installed")
    return _run_mesh(_INNER_AUTHORITY_CALL, config, prompt, max_tokens, attempts, sleep_fn)


def zero_cost_key_judgements_llm(config, prompt: str, max_tokens: int = 2000, attempts=None, sleep_fn=time.sleep):
    if _INNER_KEY_JUDGEMENTS_CALL is None:
        raise RuntimeError("v16 key-judgements mesh is not installed")
    return _run_mesh(_INNER_KEY_JUDGEMENTS_CALL, config, prompt, max_tokens, attempts, sleep_fn)


def telemetry_snapshot() -> dict:
    return {
        "version": "v16",
        "provider_attempts": dict(_RUNTIME["provider_attempts"]),
        "provider_successes": dict(_RUNTIME["provider_successes"]),
        "policy_blocks": dict(_RUNTIME["policy_blocks"]),
        "gemini_thought_parts_discarded": int(_RUNTIME["gemini_thought_parts_discarded"]),
        "paid_default": False,
        "public_data_only_providers": ["gemini", "nvidia_nim"],
    }


def install_zero_cost_mesh_v16(main_module) -> None:
    """Install after quota/capacity layers so v16 owns the final live consumer."""
    del main_module
    global _INNER_AUTHORITY_CALL, _INNER_KEY_JUDGEMENTS_CALL, _INSTALLED
    if _INSTALLED:
        return

    # Give NVIDIA's exact hosted API hostname a stable durable-ledger identity.
    _quota._PROVIDER_BY_HOST[NVIDIA_NIM_URL.split("//", 1)[1].split("/", 1)[0]] = "nvidia_nim"

    # Provider identity is part of the analytical-depth contract.  Gemini/NIM
    # must be recognized as genuine LLM-authored enrichment rather than silently
    # mislabeled as deterministic/template fallback.
    new_sources = {"gemini", "nvidia_nim"}
    _compiler._LLM_PROVIDER_SOURCES = frozenset(set(_compiler._LLM_PROVIDER_SOURCES) | new_sources)
    _publication._LLM_SOURCES = frozenset(set(_publication._LLM_SOURCES) | new_sources)
    _depth.LLM_AUTHORED_SOURCES = frozenset(set(_depth.LLM_AUTHORED_SOURCES) | new_sources)

    _INNER_AUTHORITY_CALL = _authority.call_llm
    _authority.call_llm = zero_cost_authority_llm

    # key_judgements imported call_llm by value and therefore needs an explicit
    # final binding.  Stage-2 normally derives judgements deterministically, but
    # this closes the paid-provider escape route if that legacy path is invoked.
    _INNER_KEY_JUDGEMENTS_CALL = _key_judgements.call_llm
    _key_judgements.call_llm = zero_cost_key_judgements_llm

    if _authority.call_llm is not zero_cost_authority_llm:
        raise RuntimeError("v16 failed to bind authority_transformer.call_llm")
    if _key_judgements.call_llm is not zero_cost_key_judgements_llm:
        raise RuntimeError("v16 failed to bind key_judgements.call_llm")

    _INSTALLED = True
    logger.info(
        "P0 v16 zero-cost inference mesh installed",
        extra={
            "marker": MARKER,
            "order": ["groq", "gemini", "nvidia_nim", "openrouter_free", "safe_defer"],
            "paid_default": False,
            "public_data_only": True,
        },
    )
