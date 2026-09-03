"""P0 recovery guard for premium Blogger report completion.

Production incident 2026-09-03: scheduled syndication remained green while
fresh articles were discovered and LLM requests succeeded, but the premium
public-report gate rejected every generated article. The smaller Groq
fallback models were commonly spending the fixed 4,400-token completion
budget on the first half of the 25-section contract and never reaching late
mandatory sections such as Executive Recommendations and References.

This module deliberately does *not* lower any evidence, word, heading, or
LLM-authorship gate. It fixes the generation side of the contract instead:

* rebalance the fixed completion budget so the model must finish all 25
  headings before expanding early sections;
* when a Groq response is HTTP-successful but structurally incomplete, try
  the still-unused Groq fallback models (independent model quotas on the same
  configured key) and select the strongest evidence-bounded candidate;
* surface a batch-wide premium-gate outage as FAILED rather than allowing a
  misleading green workflow when two or more selected reports all fail the
  same publication-quality barrier.

The module is installed after premium_provider_budget and before
premium_publication.install_runtime_overrides(), so the existing ReportX
integrity gates, Blogger fetch-back verification, and publication transaction
remain authoritative.
"""

from __future__ import annotations

import re
import time
from typing import Callable, Optional

from . import llm_client as _llm
from . import premium_provider_budget as _budget
from . import premium_publication as _premium
from .content_discovery import DiscoveredArticle
from .logger import setup_logger

logger = setup_logger("premium_incident_recovery")

_RAW_MIN_VISIBLE_WORDS = 1800
_MAX_QUALITY_FALLBACKS = 3

_ORIGINAL_PROMPT_BUILDER: Optional[Callable] = None
_ORIGINAL_PREMIUM_LLM_CALL: Optional[Callable] = None
_ORIGINAL_PIPELINE_RUN_STATUS: Optional[Callable] = None

_TARGET_RE = re.compile(
    r"Target\s+2,400-3,200\s+useful\s+words;[^\n]*",
    flags=re.IGNORECASE,
)
_TARGET_REPLACEMENT = (
    "Target 2,300-2,700 useful visible words; keep early sections concise "
    "(normally no more than about 110 visible words each), reserve at least "
    "20% of completion capacity for sections 21-25, and shorten earlier prose "
    "before ever omitting a mandatory heading. Never pad or repeat the source."
)
_FINAL_CHECK_PREFIX = "Before returning, silently check:"
_FINAL_CHECK_REPLACEMENT = (
    "Before returning, silently check: all 25 exact headings are present, "
    "especially Executive Recommendations and References; if space is tight, "
    "compress earlier sections rather than the section list;"
)


def _shrink_source_excerpt_to_ceiling(prompt: str) -> str:
    """Keep a rebalanced prompt inside the provider-safe character ceiling.

    The provider-budget layer already caps the source excerpt. The recovery
    wording adds only a small amount of instruction text, but a future source
    metadata expansion could leave no headroom. If that happens, remove only
    the necessary middle bytes from SOURCE EXCERPT while preserving its head,
    tail, structured evidence, and the untrusted-data boundary.
    """
    ceiling = _budget.PREMIUM_PROMPT_CHAR_CEILING
    if len(prompt) <= ceiling:
        return prompt

    start_marker = "\nSOURCE EXCERPT\n"
    end_marker = "\n>>> UNTRUSTED SOURCE DATA END"
    start = prompt.find(start_marker)
    end = prompt.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise ValueError(
            f"premium recovery prompt exceeds provider-safe character ceiling: {len(prompt)} > {ceiling}"
        )

    body_start = start + len(start_marker)
    excerpt = prompt[body_start:end]
    excess = len(prompt) - ceiling
    target = len(excerpt) - excess - 96
    if target < 800:
        raise ValueError(
            f"premium recovery prompt cannot be reduced safely: {len(prompt)} > {ceiling}"
        )

    head = target * 2 // 3
    tail = target - head
    shortened = (
        excerpt[:head]
        + "\n...[recovery prompt budget boundary]...\n"
        + excerpt[-tail:]
    )
    result = prompt[:body_start] + shortened + prompt[end:]
    if len(result) > ceiling:
        raise ValueError(
            f"premium recovery prompt still exceeds provider-safe character ceiling: {len(result)} > {ceiling}"
        )
    return result


def build_completion_safe_prompt(article: DiscoveredArticle) -> str:
    if _ORIGINAL_PROMPT_BUILDER is None:
        raise RuntimeError("premium incident recovery is not installed")

    prompt = _ORIGINAL_PROMPT_BUILDER(article)
    updated, replacements = _TARGET_RE.subn(_TARGET_REPLACEMENT, prompt, count=1)
    if replacements == 0:
        # Fail-safe for future prompt wording drift: preserve the upstream
        # contract and add the smallest possible completion-order override.
        updated += (
            "\nOUTPUT-BUDGET OVERRIDE: complete all 25 mandatory headings before "
            "expanding early sections; reserve output for Executive "
            "Recommendations and References; never omit a heading to gain depth.\n"
        )

    if _FINAL_CHECK_PREFIX in updated:
        updated = updated.replace(
            _FINAL_CHECK_PREFIX,
            _FINAL_CHECK_REPLACEMENT,
            1,
        )

    return _shrink_source_excerpt_to_ceiling(updated)


def _normalized_heading_set(content: str) -> set[str]:
    return {_premium._normalized_heading(value) for value in _premium._headings(content)}


def _raw_contract_metrics(content: str) -> tuple[int, int, int]:
    headings = _normalized_heading_set(content)
    core_hits = len(headings.intersection(_premium._CORE_HEADINGS))
    return _premium._word_count(content), len(headings), core_hits


def _raw_contract_complete(content: str) -> bool:
    words, heading_count, core_hits = _raw_contract_metrics(content)
    return (
        words >= _RAW_MIN_VISIBLE_WORDS
        and heading_count >= _premium.MIN_DISTINCT_HEADINGS
        and core_hits == len(_premium._CORE_HEADINGS)
    )


def _candidate_score(content: str) -> tuple[int, int, int]:
    words, heading_count, core_hits = _raw_contract_metrics(content)
    # Core-heading coverage dominates because the live premium gate requires
    # every core section. Heading count then outranks raw word volume so a
    # verbose, truncated first-half report cannot beat a complete structure.
    return core_hits, min(heading_count, 25), min(words, 3200)


def _configured_groq_models(config) -> list[str]:
    models: list[str] = []
    seen: set[str] = set()
    for model in [config.llm_model_groq, *config.llm_model_groq_fallbacks]:
        if model and model not in seen:
            seen.add(model)
            models.append(model)
    return models


def _latest_successful_groq_model(entries: list[dict]) -> Optional[str]:
    for entry in reversed(entries):
        if entry.get("provider") == "groq" and entry.get("ok") is True and entry.get("model"):
            return str(entry["model"])
    return None


def call_quality_aware_premium_llm(
    config,
    prompt: str,
    max_tokens: int = 3000,
    attempts=None,
    sleep_fn=time.sleep,
):
    """Use HTTP success *and* report-contract completeness as failover signal.

    llm_client.call_llm intentionally returns the first provider/model that
    answers successfully. For ordinary prompts that is correct. For a strict
    25-section publication contract, however, an HTTP 200 containing a
    truncated half-report is not usable and must not prevent still-unused
    Groq models from being tried. This wrapper adds that premium-only policy
    without changing the generic LLM client.
    """
    if _ORIGINAL_PREMIUM_LLM_CALL is None:
        raise RuntimeError("premium incident recovery is not installed")

    ledger = attempts if attempts is not None else []
    start = len(ledger)
    first = _ORIGINAL_PREMIUM_LLM_CALL(
        config,
        prompt,
        max_tokens=max_tokens,
        attempts=ledger,
        sleep_fn=sleep_fn,
    )
    if not first:
        return None

    content, provider = first
    candidates: list[tuple[str, str]] = [(content, provider)]
    if _raw_contract_complete(content):
        return first

    if provider != "groq" or not config.groq_api_key:
        return first

    successful_model = _latest_successful_groq_model(ledger[start:])
    models = _configured_groq_models(config)
    if not successful_model or successful_model not in models:
        return first

    remaining = models[models.index(successful_model) + 1 :]
    if not remaining:
        return first

    words, headings, core_hits = _raw_contract_metrics(content)
    logger.warning(
        "Premium LLM response was structurally incomplete; trying unused Groq fallback model",
        extra={
            "model": successful_model,
            "visible_words": words,
            "distinct_headings": headings,
            "core_headings": core_hits,
            "remaining_models": remaining[:_MAX_QUALITY_FALLBACKS],
        },
    )

    # These are different, not-yet-attempted Groq models. Their free-tier
    # quotas are model-scoped, so we can try them directly rather than rerun
    # the whole provider chain (which would waste time on already-known 429s
    # and unfunded providers). _try_provider retains the bounded 429 logic and
    # records each attempt in the same audit ledger.
    for model in remaining[:_MAX_QUALITY_FALLBACKS]:
        candidate = _llm._try_provider(
            name="groq",
            url=_llm._GROQ_URL,
            api_key=config.groq_api_key,
            model=model,
            prompt=prompt,
            max_tokens=_budget.PREMIUM_COMPLETION_TOKENS,
            extra_headers={},
            sleep_fn=sleep_fn,
            attempts=ledger,
        )
        if not candidate:
            continue
        candidates.append((candidate, "groq"))
        if _raw_contract_complete(candidate):
            logger.info(
                "Premium structural recovery succeeded on Groq fallback model",
                extra={"model": model, "metrics": _raw_contract_metrics(candidate)},
            )
            return candidate, "groq"

    # No candidate reached the pre-publication structural target. Return the
    # strongest response, never a weaker last response. The unchanged premium
    # and evidence-integrity gates still make the final fail-closed decision.
    return max(candidates, key=lambda item: _candidate_score(item[0]))


def _availability_guard_status(report: dict) -> str:
    if _ORIGINAL_PIPELINE_RUN_STATUS is None:
        raise RuntimeError("premium publication availability guard is not installed")

    base = _ORIGINAL_PIPELINE_RUN_STATUS(report)
    if report.get("dry_run"):
        return base

    attempted = int(report.get("discovered", 0) or 0)
    published = int(report.get("published", 0) or 0)
    blocked = int(report.get("integrity_blocked", 0) or 0)
    failed = int(report.get("failed", 0) or 0)

    if attempted >= 2 and published == 0 and blocked == attempted and failed == attempted:
        logger.error(
            "Systemic premium publication outage: every selected report was integrity-blocked",
            extra={"attempted": attempted, "integrity_blocked": blocked},
        )
        return "FAILED"
    return base


def install_incident_recovery_overrides(main_module) -> None:
    """Install premium-only completion recovery and availability semantics."""
    global _ORIGINAL_PROMPT_BUILDER, _ORIGINAL_PREMIUM_LLM_CALL, _ORIGINAL_PIPELINE_RUN_STATUS

    if _premium.build_premium_analyst_prompt is not build_completion_safe_prompt:
        _ORIGINAL_PROMPT_BUILDER = _premium.build_premium_analyst_prompt
        _premium.build_premium_analyst_prompt = build_completion_safe_prompt

    if _premium._premium_llm_call is not call_quality_aware_premium_llm:
        _ORIGINAL_PREMIUM_LLM_CALL = _premium._premium_llm_call
        _premium._premium_llm_call = call_quality_aware_premium_llm

    if main_module._pipeline_run_status is not _availability_guard_status:
        _ORIGINAL_PIPELINE_RUN_STATUS = main_module._pipeline_run_status
        main_module._pipeline_run_status = _availability_guard_status
