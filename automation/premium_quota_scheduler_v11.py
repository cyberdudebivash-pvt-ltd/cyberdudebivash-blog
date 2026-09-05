"""P0 v11 quota-aware chunk scheduler for the premium Blogger CTI pipeline.

Production run #8624 proved v10 fixed Stage-5 reachability, but the continuation
rescue still failed for a second, independent reason: when no explicit
``sleep_fn`` reached Stage-5, v9 intentionally substituted a no-op sleeper.
Groq returned Retry-After values of 11-12 seconds, but the rescue immediately
retried in milliseconds, converted the short Qwen model into a durable cooldown,
and exhausted all continuation passes without adding a fragment.

The same run also showed scarce Qwen OTPM being consumed by earlier 4,400-token
full-body fallback requests even though those models expose a 1,000 OTPM ceiling.
That leaves no capacity for the <=900-token recovery workload they are actually
suited to.

v11 makes provider capacity a scheduling constraint rather than an exception:
* Qwen Groq models are reserved for <=900-token chunk work; oversized requests
  are skipped before transport, preserving their OTPM budget.
* Short Qwen calls always honor real provider Retry-After pacing in production.
* If the long-form provider chain returns no candidate, Qwen may seed a report
  with a bounded first chunk and then continue in bounded chunks.
* Combined candidates still must satisfy the unchanged semantic floor and the
  active Stage-4 evidence-admission boundary before they can win.

No publication, evidence, ReportX, hashing, Blogger, or fetch-back gate is
weakened by this scheduler.
"""
from __future__ import annotations

import time
from collections import Counter
from typing import Callable, Optional

from . import authority_transformer as _authority
from . import llm_client as _llm
from . import premium_capacity_recovery as _capacity
from .logger import setup_logger

logger = setup_logger("premium_quota_scheduler_v11")

MARKER = "CDB-PREMIUM-QUOTA-SCHEDULER-V11"
SHORT_QWEN_MAX_TOKENS = 900
MAX_CHUNK_PASSES = 4

_ORIGINAL_TRY_PROVIDER: Optional[Callable] = None
_INNER_LLM_CALL: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "oversized_qwen_skips": 0,
    "seed_attempts": 0,
    "seed_successes": 0,
    "continuation_attempts": 0,
    "continuation_successes": 0,
    "chunk_models": Counter(),
}


def _is_short_qwen(name: str, model: str) -> bool:
    return str(name or "").lower() == "groq" and "qwen" in str(model or "").lower()


def quota_aware_try_provider(*, name, url, api_key, model, prompt, max_tokens, extra_headers, sleep_fn, attempts):
    """Reserve Qwen for bounded chunk work and honor real Retry-After pacing."""
    if _ORIGINAL_TRY_PROVIDER is None:
        raise RuntimeError("v11 quota scheduler is not installed")

    if _is_short_qwen(name, model) and int(max_tokens or 0) > SHORT_QWEN_MAX_TOKENS:
        _RUNTIME["oversized_qwen_skips"] += 1
        logger.info(
            "v11 reserved short-capacity Qwen model from oversized premium request",
            extra={
                "provider": name,
                "model": model,
                "requested_max_tokens": int(max_tokens or 0),
                "reserved_max_tokens": SHORT_QWEN_MAX_TOKENS,
            },
        )
        if attempts is not None:
            attempts.append({
                "provider": str(name),
                "model": str(model),
                "ok": False,
                "error": "V11_RESERVED_FOR_CHUNKS",
            })
        return None

    effective_sleep = time.sleep if _is_short_qwen(name, model) else sleep_fn
    return _ORIGINAL_TRY_PROVIDER(
        name=name,
        url=url,
        api_key=api_key,
        model=model,
        prompt=prompt,
        max_tokens=max_tokens,
        extra_headers=extra_headers,
        sleep_fn=effective_sleep,
        attempts=attempts,
    )


def _seed_prompt(original_prompt: str) -> str:
    return (
        original_prompt
        + "\n\nP0 QUOTA-AWARE SEED PASS\n"
        + "Return the first bounded HTML analysis fragment only. Keep it source-bounded and decision-useful. "
        + "Prioritize substantive <p> and <li> elements. Do not invent facts, ATT&CK IDs, IOCs, exploit status, "
        + "patch versions, victim impact, attribution, future events, statistics, or customer exposure. "
        + "Do not emit References in this seed fragment."
    )


def _call_short_qwen(config, prompt: str, model: str, ledger: list[dict]):
    _RUNTIME["chunk_models"][model] += 1
    return _llm._try_provider(
        name="groq",
        url=_llm._GROQ_URL,
        api_key=config.groq_api_key,
        model=model,
        prompt=prompt,
        max_tokens=SHORT_QWEN_MAX_TOKENS,
        extra_headers={},
        sleep_fn=time.sleep,
        attempts=ledger,
    )


def quota_aware_capacity_llm(config, prompt: str, max_tokens: int = 3000, attempts=None, sleep_fn=None):
    """Run the evidence-gated long-form chain, then recover via paced chunks."""
    if _INNER_LLM_CALL is None:
        raise RuntimeError("v11 quota-aware runtime binding is not installed")

    ledger = attempts if attempts is not None else []
    kwargs = {"max_tokens": max_tokens, "attempts": ledger}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = _INNER_LLM_CALL(config, prompt, **kwargs)

    models = _capacity._eligible_short_models(config) if getattr(config, "groq_api_key", None) else []
    if result:
        content, provider = result
        if _capacity._active_contract_complete(content) or not _capacity._rescue_needed(content) or not models:
            return result
        combined = content
        start_pass = 1
        logger.warning(
            "v11 starting paced continuation recovery",
            extra={"metrics": _capacity._semantic_metrics(combined), "models": models},
        )
    else:
        if not models:
            return None
        _RUNTIME["seed_attempts"] += 1
        combined = ""
        provider = "groq"
        seed = _call_short_qwen(config, _seed_prompt(prompt), models[0], ledger)
        if not seed:
            logger.warning("v11 bounded Qwen seed unavailable; preserving fail-closed behavior")
            return None
        safe_seed = _capacity._safe_fragment_html(seed)
        if not safe_seed:
            return None
        combined = safe_seed
        _RUNTIME["seed_successes"] += 1
        start_pass = 2
        logger.info(
            "v11 bounded Qwen seed acquired",
            extra={"model": models[0], "metrics": _capacity._semantic_metrics(combined)},
        )

    _RUNTIME["continuation_attempts"] += 1
    for pass_index in range(start_pass, MAX_CHUNK_PASSES + 1):
        if _capacity._active_contract_complete(combined):
            _RUNTIME["continuation_successes"] += 1
            return combined, "groq"
        model = models[(pass_index - 1) % len(models)]
        fragment = _call_short_qwen(
            config,
            _capacity._continuation_prompt(prompt, combined, pass_index),
            model,
            ledger,
        )
        if not fragment:
            continue
        safe_fragment = _capacity._safe_fragment_html(fragment)
        if not safe_fragment:
            continue
        combined += safe_fragment

    if _capacity._active_contract_complete(combined):
        _RUNTIME["continuation_successes"] += 1
        logger.info(
            "v11 paced chunk recovery reached unchanged semantic/evidence contract",
            extra={"metrics": _capacity._semantic_metrics(combined)},
        )
        return combined, "groq"

    logger.warning(
        "v11 paced chunk recovery exhausted without lowering public quality floors",
        extra={"metrics": _capacity._semantic_metrics(combined), "passes": MAX_CHUNK_PASSES},
    )
    return (combined, provider) if combined else result


def telemetry_snapshot() -> dict:
    return {
        "version": "v11",
        "oversized_qwen_skips": int(_RUNTIME["oversized_qwen_skips"]),
        "seed_attempts": int(_RUNTIME["seed_attempts"]),
        "seed_successes": int(_RUNTIME["seed_successes"]),
        "continuation_attempts": int(_RUNTIME["continuation_attempts"]),
        "continuation_successes": int(_RUNTIME["continuation_successes"]),
        "chunk_models": dict(_RUNTIME["chunk_models"]),
        "short_qwen_max_tokens": SHORT_QWEN_MAX_TOKENS,
        "max_chunk_passes": MAX_CHUNK_PASSES,
    }


def install_quota_aware_scheduler_v11(main_module) -> None:
    """Install last, after v10, so this owns the final live provider consumer."""
    del main_module
    global _ORIGINAL_TRY_PROVIDER, _INNER_LLM_CALL, _INSTALLED
    if _INSTALLED:
        return

    if _llm._try_provider is not quota_aware_try_provider:
        _ORIGINAL_TRY_PROVIDER = _llm._try_provider
        _llm._try_provider = quota_aware_try_provider

    live = _authority.call_llm
    if live is quota_aware_capacity_llm:
        _INSTALLED = True
        return

    # v10 should have made Stage-5 the live consumer and retained Stage-4 as its
    # inner callable. Use Stage-5's saved inner directly to avoid nesting the v9
    # no-op pacing implementation around v11.
    inner = _capacity._ORIGINAL_PREMIUM_LLM_CALL
    if inner is None or inner is quota_aware_capacity_llm:
        raise RuntimeError("v11 cannot establish the Stage-4 inner generation binding")
    _INNER_LLM_CALL = inner
    _authority.call_llm = quota_aware_capacity_llm

    if _authority.call_llm is not quota_aware_capacity_llm:
        raise RuntimeError("v11 failed to bind the live authority_transformer.call_llm consumer")

    _INSTALLED = True
    logger.info(
        "P0 v11 quota-aware chunk scheduler installed",
        extra={
            "marker": MARKER,
            "live_consumer": "authority_transformer.call_llm",
            "short_qwen_max_tokens": SHORT_QWEN_MAX_TOKENS,
            "max_chunk_passes": MAX_CHUNK_PASSES,
            "retry_after_pacing": "REAL_TIME_SLEEP",
        },
    )
