"""P0 v12 quota-window deferral semantics for Blogger syndication.

Production run #8628 proved the v11 scheduler itself was active, but the run
started while the durable provider ledger already marked every Groq premium
model unavailable until a near-term provider reset. The pipeline then spent a
run discovering five valid reports, could not acquire any premium LLM seed,
and converted five correct integrity holds into a systemic FAILED status.

This module does not relax publication quality. It only distinguishes a
self-healing, provider-declared capacity window from a broken pipeline:

* terminal Blogger/auth/unexpected failures remain FAILED;
* genuine evidence/quality failures with provider capacity remain subject to
  the existing systemic outage guard;
* a 0/N run where every selected report is held, v11 attempted seed recovery,
  no seed succeeded, and durable provider cooldowns are active is classified
  DEGRADED/DEFERRED rather than FAILED. Reports remain on the existing retry
  queue and no thin artifact can publish.
"""
from __future__ import annotations

from typing import Callable, Optional

from . import premium_quota_scheduler_v11 as _v11
from . import provider_quota_ledger as _quota
from .logger import setup_logger

logger = setup_logger("premium_quota_deferral_v12")

MARKER = "CDB-PREMIUM-QUOTA-DEFERRAL-V12"
_ORIGINAL_PIPELINE_RUN_STATUS: Optional[Callable] = None
_INSTALLED = False
_TERMINAL_STATUSES = {"auth_error", "error"}


def _is_provider_capacity_deferral(report: dict) -> tuple[bool, dict]:
    attempted = int(report.get("discovered", 0) or 0)
    published = int(report.get("published", 0) or 0)
    failed = int(report.get("failed", 0) or 0)
    blocked = int(report.get("integrity_blocked", 0) or 0)
    posts = report.get("posts") or []

    if report.get("dry_run") or attempted < 2 or published != 0:
        return False, {}
    if blocked != attempted or failed != attempted:
        return False, {}
    if any(str(post.get("status") or "") in _TERMINAL_STATUSES for post in posts if isinstance(post, dict)):
        return False, {}

    quota = _quota.telemetry_snapshot()
    v11 = _v11.telemetry_snapshot()
    active = list(quota.get("active_cooldowns") or [])
    seed_attempts = int(v11.get("seed_attempts", 0) or 0)
    seed_successes = int(v11.get("seed_successes", 0) or 0)

    # This is intentionally strict: do not downgrade an evidence outage merely
    # because one unrelated provider model is cooling down. We require the live
    # v11 recovery path to have attempted provider-capacity seed work, no seed to
    # have succeeded, and durable quota state to prove an active reset window.
    deferred = bool(active) and seed_attempts > 0 and seed_successes == 0
    evidence = {
        "active_cooldown_count": len(active),
        "active_cooldowns": active,
        "v11_seed_attempts": seed_attempts,
        "v11_seed_successes": seed_successes,
        "v11_continuation_attempts": int(v11.get("continuation_attempts", 0) or 0),
        "v11_continuation_successes": int(v11.get("continuation_successes", 0) or 0),
    }
    return deferred, evidence


def quota_aware_pipeline_run_status(report: dict) -> str:
    if _ORIGINAL_PIPELINE_RUN_STATUS is None:
        raise RuntimeError("v12 quota deferral runtime is not installed")

    base = _ORIGINAL_PIPELINE_RUN_STATUS(report)
    if base != "FAILED":
        return base

    deferred, evidence = _is_provider_capacity_deferral(report)
    if not deferred:
        return base

    report["provider_capacity_deferred"] = True
    report["provider_capacity"] = evidence
    logger.warning(
        "Premium publication deferred by active provider quota window; preserving retry queue",
        extra=evidence,
    )
    return "DEGRADED"


def install_quota_deferral_v12(main_module) -> None:
    """Install after v11 and the historical systemic outage guard."""
    global _ORIGINAL_PIPELINE_RUN_STATUS, _INSTALLED
    if _INSTALLED:
        return
    live = main_module._pipeline_run_status
    if live is quota_aware_pipeline_run_status:
        _INSTALLED = True
        return
    _ORIGINAL_PIPELINE_RUN_STATUS = live
    main_module._pipeline_run_status = quota_aware_pipeline_run_status
    _INSTALLED = True
    logger.info(
        "P0 v12 provider quota deferral semantics installed",
        extra={"marker": MARKER, "provider_capacity_status": "DEGRADED_DEFERRED"},
    )
