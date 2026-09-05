"""P0 v13 provider-capacity deferral semantics for Blogger syndication.

Production run #8628 proved v11 could correctly fail closed when all premium
Groq models were already cooling down. Production run #8629 exposed the next
edge case: one bounded Qwen seed succeeded before the remaining provider
capacity collapsed, all four premium Groq models then entered durable TPD
cooldowns, ten later calls were skipped by the durable quota ledger, no
continuation completed, and all five selected reports were still integrity-held.
The v12 rule required zero seed successes, so that capacity-dominant window was
misclassified as a systemic FAILED run.

This layer does not relax publication quality. It only converts an already-
FAILED 0/N run to DEGRADED/DEFERRED when telemetry proves provider exhaustion
is dominant rather than incidental:

* every attempted report remains integrity-held and nothing was published;
* no Blogger auth/unexpected terminal failure occurred;
* at least two provider/model cooldowns are simultaneously active;
* v11 attempted bounded seed recovery but recovered fewer seeds than reports;
* no continuation recovery completed; and
* durable cooldown skips are at least the attempted report count.

A single unrelated cooldown, a successful continuation, or usable provider
capacity therefore cannot mask a real evidence/quality outage. Reports remain
on the existing retry queue and no thin artifact can publish.
"""
from __future__ import annotations

from typing import Callable, Optional

from . import premium_quota_scheduler_v11 as _v11
from . import provider_quota_ledger as _quota
from .logger import setup_logger

logger = setup_logger("premium_quota_deferral_v12")

MARKER = "CDB-PREMIUM-QUOTA-DEFERRAL-V13"
_ORIGINAL_PIPELINE_RUN_STATUS: Optional[Callable] = None
_INSTALLED = False
_TERMINAL_STATUSES = {"auth_error", "error"}
_MIN_ACTIVE_COOLDOWNS = 2


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
    if any(
        str(post.get("status") or "") in _TERMINAL_STATUSES
        for post in posts
        if isinstance(post, dict)
    ):
        return False, {}

    quota = _quota.telemetry_snapshot()
    v11 = _v11.telemetry_snapshot()
    active = list(quota.get("active_cooldowns") or [])
    active_count = len(active)
    durable_skips = int(quota.get("durable_provider_skips", 0) or 0)
    seed_attempts = int(v11.get("seed_attempts", 0) or 0)
    seed_successes = int(v11.get("seed_successes", 0) or 0)
    continuation_attempts = int(v11.get("continuation_attempts", 0) or 0)
    continuation_successes = int(v11.get("continuation_successes", 0) or 0)

    capacity_dominant = (
        active_count >= _MIN_ACTIVE_COOLDOWNS
        and seed_attempts > 0
        and seed_successes < attempted
        and continuation_successes == 0
        and durable_skips >= attempted
    )

    evidence = {
        "active_cooldown_count": active_count,
        "active_cooldowns": active,
        "durable_provider_skips": durable_skips,
        "v11_seed_attempts": seed_attempts,
        "v11_seed_successes": seed_successes,
        "v11_continuation_attempts": continuation_attempts,
        "v11_continuation_successes": continuation_successes,
        "capacity_dominant": capacity_dominant,
    }
    return capacity_dominant, evidence


def quota_aware_pipeline_run_status(report: dict) -> str:
    if _ORIGINAL_PIPELINE_RUN_STATUS is None:
        raise RuntimeError("v13 quota deferral runtime is not installed")

    base = _ORIGINAL_PIPELINE_RUN_STATUS(report)
    if base != "FAILED":
        return base

    deferred, evidence = _is_provider_capacity_deferral(report)
    if not deferred:
        return base

    report["provider_capacity_deferred"] = True
    report["provider_capacity"] = evidence
    logger.warning(
        "Premium publication deferred by dominant provider quota exhaustion; preserving retry queue",
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
        "P0 v13 provider quota deferral semantics installed",
        extra={
            "marker": MARKER,
            "provider_capacity_status": "DEGRADED_DEFERRED",
            "minimum_active_cooldowns": _MIN_ACTIVE_COOLDOWNS,
        },
    )
