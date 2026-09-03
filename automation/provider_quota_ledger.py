"""Durable, non-secret provider/model quota circuit breaker for the CTI factory.

GitHub Actions starts a new Python process for every scheduled factory run.  The
existing premium-yield cooldown is deliberately process-local, which means a
provider-declared TPD/TPM reset learned by one run is forgotten by the next.
For a 96-runs/day factory that turns a useful 429 into repeated quota-burning
requests.

This module is an additive runtime layer installed *after* the existing provider
budget, yield-hardening and model-aware pacing layers.  It persists only quota
metadata (provider/model/reset timestamps); credentials, prompts, completions,
headers and response bodies are never written.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

import requests

from . import llm_client as _llm
from .logger import setup_logger

logger = setup_logger("provider_quota_ledger")

_LEDGER_VERSION = 1
_DEFAULT_STATE_FILE = "data/provider_quota_state.json"
_MAX_MODELS = 64
_MAX_RETRY_AFTER_SECONDS = 172800.0  # two days; protects against corrupt hints

_ORIGINAL_OPENAI_CALL: Optional[Callable] = None
_ORIGINAL_TRY_PROVIDER: Optional[Callable] = None
_INSTALLED = False

_TELEMETRY = {
    "durable_provider_skips": 0,
    "quota_events": 0,
    "tpd_events": 0,
    "tpm_events": 0,
    "transient_429_events": 0,
    "expired_entries_cleaned": 0,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _state_path() -> Path:
    return Path(os.environ.get("CDB_PROVIDER_QUOTA_STATE", _DEFAULT_STATE_FILE))


def _empty_state() -> dict:
    return {"version": _LEDGER_VERSION, "updated_at": None, "models": {}}


def _parse_utc(value: object) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_state() -> dict:
    path = _state_path()
    if not path.is_file():
        return _empty_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        logger.warning("Provider quota ledger unreadable; starting from an empty bounded state")
        return _empty_state()
    if not isinstance(raw, dict) or not isinstance(raw.get("models"), dict):
        return _empty_state()
    raw["version"] = _LEDGER_VERSION
    return raw


def _atomic_save(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    state["version"] = _LEDGER_VERSION
    state["updated_at"] = _utcnow().isoformat()

    # Bound the persisted surface by most-recent event.  This is quota
    # metadata, not a historical event store.
    models = state.setdefault("models", {})
    if len(models) > _MAX_MODELS:
        ordered = sorted(
            models.items(),
            key=lambda item: str(item[1].get("last_429") or item[1].get("updated_at") or ""),
            reverse=True,
        )[:_MAX_MODELS]
        state["models"] = dict(ordered)

    payload = json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


def _provider_for_url(url: str) -> str:
    host = (urlsplit(str(url)).hostname or "").lower()
    if "groq.com" in host:
        return "groq"
    if "openrouter.ai" in host:
        return "openrouter"
    if "deepseek.com" in host:
        return "deepseek"
    return host or "unknown"


def _model_key(provider: str, model: str) -> str:
    return f"{str(provider).strip().lower()}::{str(model).strip()}"


def _clean_expired(state: dict, now: Optional[datetime] = None) -> int:
    now = now or _utcnow()
    models = state.setdefault("models", {})
    expired = []
    for key, entry in models.items():
        until = _parse_utc(entry.get("unavailable_until")) if isinstance(entry, dict) else None
        if until is None or until <= now:
            expired.append(key)
    for key in expired:
        models.pop(key, None)
    if expired:
        _TELEMETRY["expired_entries_cleaned"] += len(expired)
    return len(expired)


def _classify_limit(response: requests.Response) -> str:
    text = ""
    try:
        text = (response.text or "").lower()
    except Exception:
        pass
    if "tokens per day" in text or "(tpd)" in text or " tpd:" in text:
        return "TPD"
    if "tokens per minute" in text or "(tpm)" in text or " tpm:" in text:
        return "TPM"
    if "requests per day" in text or "(rpd)" in text:
        return "RPD"
    if "requests per minute" in text or "(rpm)" in text:
        return "RPM"
    return "TRANSIENT_429"


def _bounded_retry_after(response: requests.Response) -> Optional[float]:
    try:
        value = _llm._raw_retry_after_seconds(response)
    except Exception:
        value = None
    if value is None:
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return min(value, _MAX_RETRY_AFTER_SECONDS)


def record_429(provider: str, model: str, response: requests.Response) -> Optional[dict]:
    """Persist a provider-declared cooldown.  Returns the stored entry."""
    retry_after = _bounded_retry_after(response)
    if retry_after is None:
        # A 429 without a usable reset hint is important telemetry but unsafe to
        # persist as a long outage.  Existing bounded retry/backoff remains the
        # authority for that request.
        _TELEMETRY["transient_429_events"] += 1
        return None

    now = _utcnow()
    state = _load_state()
    _clean_expired(state, now)
    limit_type = _classify_limit(response)
    key = _model_key(provider, model)
    until = now + timedelta(seconds=retry_after)
    existing = state.setdefault("models", {}).get(key, {})
    existing_until = _parse_utc(existing.get("unavailable_until")) if isinstance(existing, dict) else None
    if existing_until and existing_until > until:
        until = existing_until

    entry = {
        "provider": str(provider),
        "model": str(model),
        "limit_type": limit_type,
        "unavailable_until": until.isoformat(),
        "last_429": now.isoformat(),
        "retry_after_seconds": round(retry_after, 3),
    }
    state["models"][key] = entry
    _atomic_save(state)

    _TELEMETRY["quota_events"] += 1
    if limit_type == "TPD":
        _TELEMETRY["tpd_events"] += 1
    elif limit_type == "TPM":
        _TELEMETRY["tpm_events"] += 1
    else:
        _TELEMETRY["transient_429_events"] += 1

    logger.info(
        "Durable provider quota cooldown persisted",
        extra={
            "provider": provider,
            "model": model,
            "limit_type": limit_type,
            "retry_after_seconds": round(retry_after, 2),
            "unavailable_until": until.isoformat(),
        },
    )
    return entry


def cooldown_remaining(provider: str, model: str, now: Optional[datetime] = None) -> float:
    now = now or _utcnow()
    state = _load_state()
    cleaned = _clean_expired(state, now)
    if cleaned:
        _atomic_save(state)
    entry = state.get("models", {}).get(_model_key(provider, model))
    if not isinstance(entry, dict):
        return 0.0
    until = _parse_utc(entry.get("unavailable_until"))
    if until is None or until <= now:
        return 0.0
    return max(0.0, (until - now).total_seconds())


def clear_model(provider: str, model: str) -> None:
    state = _load_state()
    key = _model_key(provider, model)
    if key in state.get("models", {}):
        state["models"].pop(key, None)
        _atomic_save(state)


def telemetry_snapshot() -> dict:
    state = _load_state()
    _clean_expired(state)
    active = []
    for entry in state.get("models", {}).values():
        if not isinstance(entry, dict):
            continue
        active.append({
            "provider": entry.get("provider"),
            "model": entry.get("model"),
            "limit_type": entry.get("limit_type"),
            "unavailable_until": entry.get("unavailable_until"),
        })
    return {**_TELEMETRY, "active_cooldowns": active, "active_cooldown_count": len(active)}


def durable_openai_call(
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
    sleep_fn,
):
    if _ORIGINAL_OPENAI_CALL is None:
        raise RuntimeError("provider quota ledger runtime is not installed")
    provider = _provider_for_url(url)
    try:
        content = _ORIGINAL_OPENAI_CALL(
            url=url,
            api_key=api_key,
            model=model,
            prompt=prompt,
            max_tokens=max_tokens,
            extra_headers=extra_headers,
            sleep_fn=sleep_fn,
        )
    except requests.exceptions.HTTPError as exc:
        response = getattr(exc, "response", None)
        if response is not None and getattr(response, "status_code", None) == 429:
            record_429(provider, model, response)
        raise
    else:
        if content:
            clear_model(provider, model)
        return content


def durable_try_provider(
    name: str,
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
    sleep_fn,
    attempts: Optional[list],
):
    if _ORIGINAL_TRY_PROVIDER is None:
        raise RuntimeError("provider quota ledger runtime is not installed")

    provider = str(name or _provider_for_url(url))
    remaining = cooldown_remaining(provider, model)
    if remaining > 0:
        _TELEMETRY["durable_provider_skips"] += 1
        logger.info(
            "Skipping provider model from durable quota ledger",
            extra={"provider": provider, "model": model, "retry_after_seconds": round(remaining, 2)},
        )
        if attempts is not None:
            attempts.append({
                "provider": provider,
                "model": model,
                "ok": False,
                "error": "durable_provider_cooldown_active",
                "retry_after_seconds": round(remaining, 2),
            })
        return None

    return _ORIGINAL_TRY_PROVIDER(
        name=name,
        url=url,
        api_key=api_key,
        model=model,
        prompt=prompt,
        max_tokens=max_tokens,
        extra_headers=extra_headers,
        sleep_fn=sleep_fn,
        attempts=attempts,
    )


def install_provider_quota_ledger() -> None:
    """Install after all existing model pacing/cooldown wrappers."""
    global _ORIGINAL_OPENAI_CALL, _ORIGINAL_TRY_PROVIDER, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_OPENAI_CALL = _llm._call_openai_compat
    _ORIGINAL_TRY_PROVIDER = _llm._try_provider
    _llm._call_openai_compat = durable_openai_call
    _llm._try_provider = durable_try_provider
    _INSTALLED = True
    logger.info("Durable provider quota ledger installed", extra={"state_file": str(_state_path())})
