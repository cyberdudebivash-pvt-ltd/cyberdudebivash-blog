"""P0 v13 capacity-aware publication allocation for the premium CTI factory.

Production acceptance after Dossier v10 exposed an availability/selection
mismatch: the factory can have a large candidate pool while multiple premium
Groq models are already in durable TPD cooldown.  The family-fair scheduler
still selected thin candidates that require model expansion to satisfy the
unchanged premium semantic floor, so the run spent scarce provider attempts
only to fail closed with zero publications.

This layer changes scheduling only.  It never lowers the public quality floor,
changes evidence admission, trusts previously generated report prose, or turns
provider failure into publish permission.

When at least two provider/model TPD cooldowns are already active at allocation
time, only candidates with enough *normalized source evidence* to plausibly
clear the existing provider-independent compiler path are admitted to the
finite five-post batch.  The existing factory scheduler remains authoritative
for family/fresh/retry fairness inside that qualified pool.  If no candidate is
source-rich enough, the run is explicitly deferred rather than burning model
calls on artifacts known to depend on unavailable capacity.

Generated first-party HTML is deliberately NOT counted as source richness just
because it is canonical.  Only ``DiscoveredArticle.full_content``/``summary``
and normalized structured fields are measured, preserving the current ReportX
source boundary.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Callable, Optional

from bs4 import BeautifulSoup

from . import premium_publication as _premium
from . import provider_quota_ledger as _quota
from . import publication_scheduler as _scheduler
from .logger import setup_logger

logger = setup_logger("premium_capacity_allocator_v13")

MARKER = "CDB-PREMIUM-CAPACITY-ALLOCATOR-V13"
MIN_ACTIVE_TPD_COOLDOWNS = 2

# These are derived from the unchanged public semantic floor rather than being
# independent quality thresholds.  A candidate must bring substantial real
# source material before deterministic structure is allowed to substitute for
# temporarily unavailable model capacity.
MIN_RICH_EVIDENCE_WORDS = max(1, int(_premium.MIN_VISIBLE_WORDS * 0.80))
MIN_STRUCTURED_EVIDENCE_WORDS = max(1, int(_premium.MIN_VISIBLE_WORDS * 0.55))
MIN_DENSE_STRUCTURED_EVIDENCE_WORDS = max(1, int(_premium.MIN_VISIBLE_WORDS * 0.40))
MIN_STRUCTURED_FIELDS = 6
MIN_DENSE_STRUCTURED_FIELDS = 10

_ORIGINAL_SELECT: Optional[Callable] = None
_ORIGINAL_WRITE_RUN_REPORT: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "capacity_aware_runs": 0,
    "qualified_candidates": 0,
    "deferred_candidates": 0,
    "selected_candidates": 0,
}

_STRUCTURED_FIELDS = (
    "cve_id",
    "cvss_score",
    "cvss_vector",
    "cwe_ids",
    "affected_vendor",
    "affected_product",
    "epss_score",
    "epss_percentile",
    "kev_listed",
    "kev_date_added",
    "kev_due_date",
    "kev_required_action",
    "ransomware_group",
    "ransomware_sector",
    "ransomware_country",
)


def _visible_source_text(article) -> str:
    raw = str(getattr(article, "full_content", None) or getattr(article, "summary", "") or "")
    soup = BeautifulSoup(raw, "html.parser")
    for node in soup(["script", "style", "noscript", "iframe", "object", "embed"]):
        node.decompose()
    return " ".join(soup.stripped_strings)


def _source_word_count(article) -> int:
    return len(re.findall(r"\b[\w][\w'./:+-]*\b", _visible_source_text(article), flags=re.UNICODE))


def _structured_evidence_count(article) -> int:
    count = 0
    for field in _STRUCTURED_FIELDS:
        value = getattr(article, field, None)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set, dict)) and not value:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        count += 1
    return count


def _provider_independent_candidate(article) -> bool:
    """Conservative admission for a report that may have no external LLM.

    This is intentionally stricter than ordinary scheduling.  It is not a
    publication gate: downstream ReportX, evidence admission, compiler-input
    floors, Dossier v8, Blogger fetch-back, and all other gates still run and
    remain authoritative.
    """
    words = _source_word_count(article)
    structured = _structured_evidence_count(article)
    return (
        words >= MIN_RICH_EVIDENCE_WORDS
        or (words >= MIN_STRUCTURED_EVIDENCE_WORDS and structured >= MIN_STRUCTURED_FIELDS)
        or (
            words >= MIN_DENSE_STRUCTURED_EVIDENCE_WORDS
            and structured >= MIN_DENSE_STRUCTURED_FIELDS
        )
    )


def _active_tpd_cooldowns() -> list[dict]:
    snapshot = _quota.telemetry_snapshot()
    return [
        item
        for item in (snapshot.get("active_cooldowns") or [])
        if isinstance(item, dict) and str(item.get("limit_type") or "").upper() == "TPD"
    ]


def _capacity_constrained() -> tuple[bool, list[dict]]:
    active = _active_tpd_cooldowns()
    return len(active) >= MIN_ACTIVE_TPD_COOLDOWNS, active


def _zero_selected_metrics(metrics: dict) -> dict:
    result = dict(metrics)
    result.update({
        "fresh_selected": 0,
        "retry_selected": 0,
        "strategic_selected": 0,
        "vulnerability_selected": 0,
        "canonical_selected": 0,
        "selected_families": {},
        "selected_sources": {},
    })
    return result


def capacity_aware_select_publication_batch(
    retry_articles,
    fresh_articles,
    max_posts: int,
):
    """Preserve normal scheduling unless durable telemetry proves saturation."""
    if _ORIGINAL_SELECT is None:
        raise RuntimeError("capacity-aware allocator is not installed")

    # The baseline call is selection-only (no transformation/network/provider
    # work).  It preserves the existing candidate accounting and gives us the
    # exact production scheduler's view of the pool.
    baseline = _ORIGINAL_SELECT(retry_articles, fresh_articles, max_posts)
    constrained, active = _capacity_constrained()
    if not constrained:
        return baseline

    _RUNTIME["capacity_aware_runs"] += 1
    qualified_fresh = [article for article in fresh_articles if _provider_independent_candidate(article)]
    qualified_retry = [article for article in retry_articles if _provider_independent_candidate(article)]

    # Let the already-proven factory scheduler own fairness within the safe
    # source-rich subset.  It still deduplicates and enforces the live burst cap.
    qualified = _ORIGINAL_SELECT(qualified_retry, qualified_fresh, max_posts)
    qualified_count = int(qualified.metrics.get("candidate_count", 0) or 0)
    total_count = int(baseline.metrics.get("candidate_count", 0) or 0)
    deferred_count = max(0, total_count - qualified_count)

    _RUNTIME["qualified_candidates"] += qualified_count
    _RUNTIME["deferred_candidates"] += deferred_count
    _RUNTIME["selected_candidates"] += len(qualified.articles)

    if qualified.articles:
        metrics = dict(qualified.metrics)
        # Candidate pool metrics describe discovery supply, not only the
        # constrained subset.  Keep the baseline accounting for observability.
        for key in ("candidate_count", "fresh_candidates", "retry_candidates"):
            if key in baseline.metrics:
                metrics[key] = baseline.metrics[key]
    else:
        metrics = _zero_selected_metrics(baseline.metrics)

    metrics.update({
        "capacity_aware_selection": True,
        "provider_capacity_constrained": True,
        "active_tpd_cooldown_count": len(active),
        "provider_independent_candidates": qualified_count,
        "provider_capacity_deferred_candidates": deferred_count,
        "capacity_allocator_marker": MARKER,
    })

    logger.warning(
        "Provider capacity constrained; publication allocator admitted only source-rich candidates",
        extra={
            "active_tpd_cooldowns": len(active),
            "candidate_count": total_count,
            "provider_independent_candidates": qualified_count,
            "selected": len(qualified.articles),
            "deferred": deferred_count,
        },
    )
    return _scheduler.PublicationSelection(list(qualified.articles), metrics)


def _capacity_write_run_report(report: dict, logs_dir: str) -> None:
    if _ORIGINAL_WRITE_RUN_REPORT is None:
        raise RuntimeError("capacity-aware allocator run-report wrapper is not installed")

    constrained = bool(report.get("provider_capacity_constrained"))
    candidates = int(report.get("candidate_count", 0) or 0)
    attempted = int(report.get("discovered", 0) or 0)
    published = int(report.get("published", 0) or 0)
    qualified = int(report.get("provider_independent_candidates", 0) or 0)

    # A capacity-driven zero-selection is not "no intel" and not a healthy
    # publication run.  Make the deferred state explicit without manufacturing
    # failed posts or weakening downstream integrity semantics.
    if constrained and candidates > 0 and attempted == 0 and published == 0:
        report["run_status"] = "DEGRADED"
        report["provider_capacity_deferred"] = True
        report["provider_capacity"] = {
            "reason": "active TPD cooldowns left no source-rich candidate eligible for provider-independent premium generation",
            "active_tpd_cooldown_count": int(report.get("active_tpd_cooldown_count", 0) or 0),
            "provider_independent_candidates": qualified,
            "deferred_candidates": int(report.get("provider_capacity_deferred_candidates", candidates) or 0),
            "allocator": MARKER,
        }

    report["capacity_allocator_v13"] = {
        "marker": MARKER,
        "capacity_aware_runs": int(_RUNTIME["capacity_aware_runs"]),
        "qualified_candidates": int(_RUNTIME["qualified_candidates"]),
        "deferred_candidates": int(_RUNTIME["deferred_candidates"]),
        "selected_candidates": int(_RUNTIME["selected_candidates"]),
        "min_active_tpd_cooldowns": MIN_ACTIVE_TPD_COOLDOWNS,
        "min_rich_evidence_words": MIN_RICH_EVIDENCE_WORDS,
        "min_structured_evidence_words": MIN_STRUCTURED_EVIDENCE_WORDS,
        "min_dense_structured_evidence_words": MIN_DENSE_STRUCTURED_EVIDENCE_WORDS,
    }
    _ORIGINAL_WRITE_RUN_REPORT(report, logs_dir)


def install_capacity_aware_allocator_v13(main_module) -> None:
    """Install after factory scheduling and durable quota telemetry exist."""
    global _ORIGINAL_SELECT, _ORIGINAL_WRITE_RUN_REPORT, _INSTALLED
    if _INSTALLED:
        return

    live_select = main_module.select_publication_batch
    if live_select is capacity_aware_select_publication_batch:
        _INSTALLED = True
        return

    _ORIGINAL_SELECT = live_select
    _ORIGINAL_WRITE_RUN_REPORT = main_module._write_run_report
    main_module.select_publication_batch = capacity_aware_select_publication_batch
    main_module._write_run_report = _capacity_write_run_report
    _INSTALLED = True

    logger.info(
        "P0 capacity-aware publication allocator installed",
        extra={
            "marker": MARKER,
            "min_active_tpd_cooldowns": MIN_ACTIVE_TPD_COOLDOWNS,
            "min_rich_evidence_words": MIN_RICH_EVIDENCE_WORDS,
            "public_quality_floor_unchanged": _premium.MIN_VISIBLE_WORDS,
        },
    )
