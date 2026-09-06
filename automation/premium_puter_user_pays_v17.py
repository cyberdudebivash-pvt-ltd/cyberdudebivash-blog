"""P0-safe Puter User-Pays fallback for SENTINEL APEX.

Puter.js is not treated as another anonymous/free backend quota pool. In browser
applications Puter's User-Pays model meters AI usage to the signed-in end user.
For GitHub Actions / backend automation the official Node.js integration uses a
Puter auth token, which makes the token owner the metered user. This layer is
therefore deliberately *outside* the v16 zero-cost mesh and is disabled by
default.

Effective production order:

    v16 free mesh (Groq -> Gemini -> NVIDIA NIM -> OpenRouter free)
    -> Puter User-Pays (explicit operator opt-in + allowance guard)
    -> safe defer

Safety invariants:
- PUTER_AUTOMATION_ENABLED must be explicitly true.
- PUTER_PUBLIC_DATA_ONLY must be explicitly true.
- PUTER_AUTH_TOKEN is passed only to a least-privilege Node subprocess and is
  never written to logs, attempts, telemetry, prompts, reports, or state files.
- Before every request the Node bridge calls puter.auth.getMonthlyUsage() and
  refuses the request when allowance telemetry is unavailable or the configured
  remaining-allowance reserve would be crossed.
- Calls are capped per workflow run. The default is one call.
- Existing ReportX evidence, analytical-depth, prompt-leak, contradiction,
  provenance, and Blogger fetch-back gates remain authoritative and unchanged.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import analytical_depth_gate as _depth
from . import authority_transformer as _authority
from . import key_judgements as _key_judgements
from . import premium_evidence_compiler as _compiler
from . import premium_publication as _publication
from .logger import setup_logger
from .premium_provider_budget import PREMIUM_COMPLETION_TOKENS

logger = setup_logger("premium_puter_user_pays_v17")

MARKER = "CDB-PUTER-USER-PAYS-V17"
PROVIDER = "puter"
BRIDGE_PATH = Path(__file__).resolve().parent / "puter_runtime" / "bridge.mjs"

_INNER_AUTHORITY_CALL: Optional[Callable] = None
_INNER_KEY_JUDGEMENTS_CALL: Optional[Callable] = None
_INNER_WRITE_RUN_REPORT: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "attempts": 0,
    "successes": 0,
    "failures": 0,
    "actual_calls": 0,
    "policy_blocks": Counter(),
    "bridge_failures": Counter(),
}


def _parse_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _parse_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class PuterPolicy:
    auth_token: str
    enabled: bool
    public_data_only: bool
    model: str
    max_calls_per_run: int
    min_remaining_microcents: int
    max_prompt_chars: int
    timeout_seconds: float

    @classmethod
    def from_env(cls) -> "PuterPolicy":
        return cls(
            auth_token=os.environ.get("PUTER_AUTH_TOKEN", "").strip(),
            enabled=_parse_bool("PUTER_AUTOMATION_ENABLED", False),
            public_data_only=_parse_bool("PUTER_PUBLIC_DATA_ONLY", False),
            model=os.environ.get("PUTER_MODEL", "gpt-5.6-luna").strip() or "gpt-5.6-luna",
            max_calls_per_run=_parse_int("PUTER_MAX_CALLS_PER_RUN", 1, 0, 5),
            # Puter documents resource accounting in microcents. Keep a default
            # $0.25-equivalent reserve (25,000,000 microcents) before any call.
            min_remaining_microcents=_parse_int(
                "PUTER_MIN_REMAINING_MICROCENTS", 25_000_000, 0, 10_000_000_000
            ),
            max_prompt_chars=_parse_int("PUTER_MAX_PROMPT_CHARS", 120_000, 1_000, 500_000),
            timeout_seconds=_parse_float("PUTER_TIMEOUT_SECONDS", 90.0, 10.0, 180.0),
        )


def _append_attempt(attempts, *, model: Optional[str], ok: bool, error: Optional[str], **extra) -> None:
    if attempts is None:
        return
    row = {
        "provider": PROVIDER,
        "model": model,
        "ok": bool(ok),
        "error": error,
    }
    row.update(extra)
    attempts.append(row)


def _safe_bridge_env(token: str) -> dict[str, str]:
    """Pass only process essentials plus the Puter token to the Node bridge."""
    env: dict[str, str] = {"PUTER_AUTH_TOKEN": token}
    for key in ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def _decode_bridge_payload(stdout: str) -> Optional[dict]:
    # The SDK should not log to stdout, but parse from the end so an incidental
    # informational line cannot make the caller treat a valid JSON result as a
    # transport failure.
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _try_puter(prompt: str, max_tokens: int, attempts=None) -> Optional[tuple[str, str]]:
    policy = PuterPolicy.from_env()

    if not policy.enabled:
        _RUNTIME["policy_blocks"]["operator_opt_in_disabled"] += 1
        _append_attempt(
            attempts,
            model=policy.model,
            ok=False,
            error="operator_opt_in_disabled",
        )
        return None
    if not policy.auth_token:
        _RUNTIME["policy_blocks"]["missing_auth_token"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="missing_auth_token")
        return None
    if not policy.public_data_only:
        _RUNTIME["policy_blocks"]["public_data_only_policy_not_enabled"] += 1
        _append_attempt(
            attempts,
            model=policy.model,
            ok=False,
            error="public_data_only_policy_not_enabled",
        )
        return None
    if policy.max_calls_per_run <= 0 or _RUNTIME["actual_calls"] >= policy.max_calls_per_run:
        _RUNTIME["policy_blocks"]["per_run_call_cap_reached"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="per_run_call_cap_reached")
        return None
    if not BRIDGE_PATH.is_file():
        _RUNTIME["bridge_failures"]["bridge_missing"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="bridge_missing")
        return None

    payload = {
        "prompt": prompt,
        "model": policy.model,
        "max_tokens": int(max_tokens),
        "temperature": 0.2,
        "min_remaining_microcents": policy.min_remaining_microcents,
        "max_prompt_chars": policy.max_prompt_chars,
    }

    _RUNTIME["attempts"] += 1
    _RUNTIME["actual_calls"] += 1
    try:
        completed = subprocess.run(
            ["node", str(BRIDGE_PATH)],
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=policy.timeout_seconds,
            check=False,
            env=_safe_bridge_env(policy.auth_token),
        )
    except FileNotFoundError:
        _RUNTIME["failures"] += 1
        _RUNTIME["bridge_failures"]["node_runtime_missing"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="node_runtime_missing")
        return None
    except subprocess.TimeoutExpired:
        _RUNTIME["failures"] += 1
        _RUNTIME["bridge_failures"]["bridge_timeout"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="bridge_timeout")
        return None
    except Exception:
        # Never serialize arbitrary exception text: subprocess/runtime errors can
        # contain command/environment material on some platforms.
        _RUNTIME["failures"] += 1
        _RUNTIME["bridge_failures"]["bridge_execution_error"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="bridge_execution_error")
        return None

    result = _decode_bridge_payload(completed.stdout)
    if not result:
        _RUNTIME["failures"] += 1
        _RUNTIME["bridge_failures"]["invalid_bridge_response"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="invalid_bridge_response")
        return None

    if not bool(result.get("ok")):
        error = str(result.get("error") or "puter_request_failed")[:160]
        # Keep the reason category for operational visibility but never persist
        # allowance amounts returned by the bridge into this public repository.
        category = error.split(":", 1)[0]
        _RUNTIME["failures"] += 1
        _RUNTIME["bridge_failures"][category] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error=category)
        return None

    content = result.get("text")
    if not isinstance(content, str) or not content.strip():
        _RUNTIME["failures"] += 1
        _RUNTIME["bridge_failures"]["empty_response"] += 1
        _append_attempt(attempts, model=policy.model, ok=False, error="empty_response")
        return None

    _RUNTIME["successes"] += 1
    _append_attempt(
        attempts,
        model=str(result.get("model") or policy.model),
        ok=True,
        error=None,
        billing_mode="user_pays_operator_token",
        allowance_guard="passed",
    )
    logger.info(
        "Puter User-Pays fallback succeeded",
        extra={"model": str(result.get("model") or policy.model), "chars": len(content)},
    )
    return content.strip(), PROVIDER


def puter_fallback_authority_llm(
    config,
    prompt: str,
    max_tokens: int = 3000,
    attempts=None,
    sleep_fn=time.sleep,
):
    if _INNER_AUTHORITY_CALL is None:
        raise RuntimeError("v17 authority fallback is not installed")

    kwargs = {"max_tokens": max_tokens, "attempts": attempts}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = _INNER_AUTHORITY_CALL(config, prompt, **kwargs)
    if result:
        return result

    # The v16 hardening layer promotes its providers to the premium 4,400-token
    # completion budget. Match that budget for Puter so fallback success does
    # not structurally under-provision long-form reports.
    effective_max = max(int(max_tokens or 0), int(PREMIUM_COMPLETION_TOKENS))
    return _try_puter(prompt, effective_max, attempts)


def puter_fallback_key_judgements_llm(
    config,
    prompt: str,
    max_tokens: int = 2000,
    attempts=None,
    sleep_fn=time.sleep,
):
    if _INNER_KEY_JUDGEMENTS_CALL is None:
        raise RuntimeError("v17 key-judgement fallback is not installed")

    kwargs = {"max_tokens": max_tokens, "attempts": attempts}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = _INNER_KEY_JUDGEMENTS_CALL(config, prompt, **kwargs)
    if result:
        return result
    return _try_puter(prompt, int(max_tokens), attempts)


def telemetry_snapshot() -> dict:
    policy = PuterPolicy.from_env()
    return {
        "version": "v17",
        "marker": MARKER,
        "provider": PROVIDER,
        "operator_opt_in_enabled": bool(policy.enabled),
        "public_data_only": bool(policy.public_data_only),
        "token_configured": bool(policy.auth_token),
        "model": policy.model,
        "max_calls_per_run": policy.max_calls_per_run,
        "allowance_reserve_guard_configured": policy.min_remaining_microcents > 0,
        "attempts": int(_RUNTIME["attempts"]),
        "successes": int(_RUNTIME["successes"]),
        "failures": int(_RUNTIME["failures"]),
        "actual_calls": int(_RUNTIME["actual_calls"]),
        "policy_blocks": dict(_RUNTIME["policy_blocks"]),
        "bridge_failures": dict(_RUNTIME["bridge_failures"]),
        "telemetry_contains_token": False,
        "telemetry_contains_allowance_amounts": False,
    }


def write_run_report_with_v17_telemetry(report: dict, logs_dir: str) -> None:
    if _INNER_WRITE_RUN_REPORT is None:
        raise RuntimeError("v17 run-report telemetry binding is not installed")
    report["puter_user_pays_v17"] = telemetry_snapshot()
    _INNER_WRITE_RUN_REPORT(report, logs_dir)


def install_puter_user_pays_v17(main_module) -> None:
    """Install after v16 hardening; Puter is an opt-in final fallback only."""
    global _INNER_AUTHORITY_CALL, _INNER_KEY_JUDGEMENTS_CALL
    global _INNER_WRITE_RUN_REPORT, _INSTALLED
    if _INSTALLED:
        return

    _INNER_AUTHORITY_CALL = _authority.call_llm
    _INNER_KEY_JUDGEMENTS_CALL = _key_judgements.call_llm
    _INNER_WRITE_RUN_REPORT = main_module._write_run_report

    # Provider identity is part of the analytical-depth/publication contract.
    _compiler._LLM_PROVIDER_SOURCES = frozenset(set(_compiler._LLM_PROVIDER_SOURCES) | {PROVIDER})
    _publication._LLM_SOURCES = frozenset(set(_publication._LLM_SOURCES) | {PROVIDER})
    _depth.LLM_AUTHORED_SOURCES = frozenset(set(_depth.LLM_AUTHORED_SOURCES) | {PROVIDER})

    _authority.call_llm = puter_fallback_authority_llm
    _key_judgements.call_llm = puter_fallback_key_judgements_llm
    main_module._write_run_report = write_run_report_with_v17_telemetry

    if _authority.call_llm is not puter_fallback_authority_llm:
        raise RuntimeError("v17 failed to bind authority_transformer.call_llm")
    if _key_judgements.call_llm is not puter_fallback_key_judgements_llm:
        raise RuntimeError("v17 failed to bind key_judgements.call_llm")
    if main_module._write_run_report is not write_run_report_with_v17_telemetry:
        raise RuntimeError("v17 failed to bind run-report telemetry")

    _INSTALLED = True
    logger.info(
        "P0 v17 Puter User-Pays fallback installed",
        extra={
            "marker": MARKER,
            "routing": "v16_free_mesh->puter_opt_in->safe_defer",
            "operator_opt_in_default": False,
            "public_data_only_required": True,
            "allowance_guard": True,
            "telemetry_contains_secrets": False,
        },
    )
