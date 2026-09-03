"""P0 recovery guard for premium Blogger report completion.

Production incident 2026-09-03: scheduled syndication remained green while
fresh articles were discovered and LLM requests succeeded, but the premium
public-report gate rejected every generated article. The smaller Groq
fallback models were commonly spending the fixed completion budget on the
first half of the 25-section contract and never reaching late mandatory
sections such as Executive Recommendations and References.

The first post-#164 production run exposed a second mismatch: recovery could
stop on a response that met its coarse word/core-heading preflight while the
authoritative public gate later rejected the same artifact for independent
heading, paragraph, or list-item density.  The strict contract guard now owns
those exact semantics; this module drives model failover until that guard says
the candidate is genuinely publication-shaped.

This module deliberately does *not* lower any evidence, word, heading,
paragraph, list, ReportX, product-tier, LLM-authorship, artifact-integrity, or
Blogger fetch-back gate. It fixes the generation side of the contract.
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
_SEMANTIC_OUTPUT_RULES = """
P0 PUBLIC-SEMANTIC OUTPUT CONTRACT
- Emit every one of the 25 mandatory sections as its own independently closed <h3>Exact Heading</h3> element. Numeric prefixes are allowed, but never combine two section names into one heading and never leave nested/unclosed heading tags.
- Across the complete report emit at least 18 substantive <p> elements, each containing at least eight useful words, and at least 18 substantive <li> elements, each containing at least four useful words.
- Satisfy paragraph/list density with evidence-specific facts, decisions, validation steps, collection requirements, or explicitly stated evidence gaps. Never create unsupported facts, indicators, exploitation claims, breach claims, or filler merely to reach a count.
- Use valid HTML structure only; do not substitute Markdown heading markers or Markdown dash bullets for the required <h3>, <p>, and <li> elements.
"""
_FINAL_CHECK_PREFIX = "Before returning, silently check:"
_FINAL_CHECK_REPLACEMENT = (
    "Before returning, silently check: all 25 exact independent <h3> headings "
    "are present, at least 18 substantive <p> elements and at least 18 "
    "substantive <li> elements are present, and Executive Recommendations and "
    "References are included; if space is tight, compress earlier prose rather "
    "than the section list or semantic structure;"
)


def _shrink_source_excerpt_to_ceiling(prompt: str) -> str:
    """Keep a rebalanced prompt inside the provider-safe character ceiling."""
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
        updated += (
            "\nOUTPUT-BUDGET OVERRIDE: complete all 25 mandatory headings before "
            "expanding early sections; reserve output for Executive "
            "Recommendations and References; never omit a heading to gain depth.\n"
        )

    # The authoritative public gate checks semantic HTML density in addition
    # to words/headings.  Put those requirements in the generation contract so
    # fallback selection is not forced to choose between equally malformed
    # outputs after the fact.
    updated += _SEMANTIC_OUTPUT_RULES

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
    """Use HTTP success *and* report-contract completeness as failover signal."""
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
