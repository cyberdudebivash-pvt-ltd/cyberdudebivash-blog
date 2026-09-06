"""Final production hardening for the v16 zero-cost inference mesh.

This layer installs immediately after ``premium_zero_cost_mesh_v16`` and owns
only two cross-cutting concerns:

1. Long-form authority generation receives the established 4,400-token premium
   completion budget on *every* free provider, not only the legacy Groq path.
   The public 2,200-word quality floor remains unchanged and authoritative.
2. Every run report receives non-secret provider telemetry derived from the
   existing attempt ledger. Credentials, prompts, response bodies and generated
   content are never persisted here.

The underlying routing order, evidence gates, quota ledger and Dossier integrity
controls are not modified.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Callable, Optional

from . import authority_transformer as _authority
from . import key_judgements as _key_judgements
from . import premium_zero_cost_mesh_v16 as _mesh
from .premium_provider_budget import PREMIUM_COMPLETION_TOKENS
from .logger import setup_logger

logger = setup_logger("premium_zero_cost_mesh_v16_hardening")

MARKER = "CDB-ZERO-COST-MESH-V16-HARDENING"

_INNER_AUTHORITY_CALL: Optional[Callable] = None
_INNER_KEY_JUDGEMENTS_CALL: Optional[Callable] = None
_INNER_WRITE_RUN_REPORT: Optional[Callable] = None
_INSTALLED = False

_TELEMETRY = {
    "attempts": Counter(),
    "successes": Counter(),
    "failures": Counter(),
    "authority_calls": 0,
    "key_judgement_calls": 0,
}


def _record_rows(rows: list[dict]) -> None:
    for row in rows:
        provider = str(row.get("provider") or "unknown")
        _TELEMETRY["attempts"][provider] += 1
        if bool(row.get("ok")):
            _TELEMETRY["successes"][provider] += 1
        else:
            _TELEMETRY["failures"][provider] += 1


def _invoke_and_record(inner: Callable, config, prompt: str, *, max_tokens: int, attempts, sleep_fn):
    ledger = attempts if attempts is not None else []
    start = len(ledger)
    kwargs = {"max_tokens": max_tokens, "attempts": ledger}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = inner(config, prompt, **kwargs)
    _record_rows(ledger[start:])
    return result


def premium_budget_zero_cost_authority_llm(
    config,
    prompt: str,
    max_tokens: int = 3000,
    attempts=None,
    sleep_fn=time.sleep,
):
    if _INNER_AUTHORITY_CALL is None:
        raise RuntimeError("v16 premium-budget hardening is not installed")
    _TELEMETRY["authority_calls"] += 1
    # The legacy provider-budget layer already established 4,400 as the safe
    # long-form completion ceiling. Alternate free providers must get the same
    # budget or they can succeed at transport while predictably failing depth.
    effective_max = max(int(max_tokens or 0), int(PREMIUM_COMPLETION_TOKENS))
    return _invoke_and_record(
        _INNER_AUTHORITY_CALL,
        config,
        prompt,
        max_tokens=effective_max,
        attempts=attempts,
        sleep_fn=sleep_fn,
    )


def observed_zero_cost_key_judgements_llm(
    config,
    prompt: str,
    max_tokens: int = 2000,
    attempts=None,
    sleep_fn=time.sleep,
):
    if _INNER_KEY_JUDGEMENTS_CALL is None:
        raise RuntimeError("v16 key-judgement observability binding is not installed")
    _TELEMETRY["key_judgement_calls"] += 1
    # Keep this smaller structured task at its caller-owned budget; forcing the
    # 4,400-token long-form ceiling here would waste free capacity.
    return _invoke_and_record(
        _INNER_KEY_JUDGEMENTS_CALL,
        config,
        prompt,
        max_tokens=int(max_tokens),
        attempts=attempts,
        sleep_fn=sleep_fn,
    )


def telemetry_snapshot() -> dict:
    base = _mesh.telemetry_snapshot()
    return {
        **base,
        "hardening_marker": MARKER,
        "attempt_ledger": dict(_TELEMETRY["attempts"]),
        "success_ledger": dict(_TELEMETRY["successes"]),
        "failure_ledger": dict(_TELEMETRY["failures"]),
        "authority_calls": int(_TELEMETRY["authority_calls"]),
        "key_judgement_calls": int(_TELEMETRY["key_judgement_calls"]),
        "authority_completion_token_floor": int(PREMIUM_COMPLETION_TOKENS),
    }


def write_run_report_with_v16_telemetry(report: dict, logs_dir: str) -> None:
    if _INNER_WRITE_RUN_REPORT is None:
        raise RuntimeError("v16 run-report telemetry binding is not installed")
    report["zero_cost_mesh_v16"] = telemetry_snapshot()
    _INNER_WRITE_RUN_REPORT(report, logs_dir)


def install_zero_cost_mesh_v16_hardening(main_module) -> None:
    global _INNER_AUTHORITY_CALL, _INNER_KEY_JUDGEMENTS_CALL
    global _INNER_WRITE_RUN_REPORT, _INSTALLED
    if _INSTALLED:
        return

    _INNER_AUTHORITY_CALL = _authority.call_llm
    _INNER_KEY_JUDGEMENTS_CALL = _key_judgements.call_llm
    _INNER_WRITE_RUN_REPORT = main_module._write_run_report

    _authority.call_llm = premium_budget_zero_cost_authority_llm
    _key_judgements.call_llm = observed_zero_cost_key_judgements_llm
    main_module._write_run_report = write_run_report_with_v16_telemetry

    if _authority.call_llm is not premium_budget_zero_cost_authority_llm:
        raise RuntimeError("v16 hardening failed to own authority_transformer.call_llm")
    if _key_judgements.call_llm is not observed_zero_cost_key_judgements_llm:
        raise RuntimeError("v16 hardening failed to own key_judgements.call_llm")
    if main_module._write_run_report is not write_run_report_with_v16_telemetry:
        raise RuntimeError("v16 hardening failed to bind run-report telemetry")

    _INSTALLED = True
    logger.info(
        "P0 v16 zero-cost mesh hardening installed",
        extra={
            "marker": MARKER,
            "authority_completion_token_floor": PREMIUM_COMPLETION_TOKENS,
            "telemetry_contains_secrets": False,
        },
    )
