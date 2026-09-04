"""P0 Stage-3 release hardening for the live premium CTI factory.

The first real Stage-2 production canary proved that the deterministic compiler,
ReportX safety gates, Blogger transaction, and fetch-back integrity remained
fail-closed, but it also exposed four remaining yield defects:

* fallback candidate selection still ranked incomplete generations by legacy
  heading ownership instead of the pre-compiler semantic density contract;
* compact source quantities such as ``5K`` were not equivalent to a rendered
  ``5,000`` even though the value was source-grounded;
* unsupported exploitation/breach language could be introduced or survive
  after the earlier generation-time repair layer, immediately before the final
  publication integrity gate;
* a provider/model that repeatedly fails a long-form request with an explicit
  OTPM reservation ceiling can be retried again for a later candidate in the
  same Actions process.

This module is deliberately additive and is installed after Stage-2. It does
not reduce any public quality threshold, evidence requirement, ReportX control,
artifact hash binding, or Blogger fetch-back verification. Its only purpose is
to make recovery and normalization agree with the already-authoritative gates.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from statistics import mean
from typing import Callable, Optional
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

from . import authority_transformer as _authority
from . import llm_client as _llm
from . import premium_incident_recovery as _recovery
from . import premium_publication as _premium
from . import premium_yield_hardening as _hardening
from . import report_integrity as _integrity
from .logger import setup_logger

logger = setup_logger("premium_release_hardening")

_ORIGINAL_CANDIDATE_SCORE: Optional[Callable] = None
_ORIGINAL_RAW_CONTRACT_COMPLETE: Optional[Callable] = None
_ORIGINAL_GROUNDED_NUMBERS: Optional[Callable] = None
_ORIGINAL_ASSEMBLE_HTML: Optional[Callable] = None
_ORIGINAL_RAW_OPENAI_CALL: Optional[Callable] = None
_ORIGINAL_TRY_PROVIDER: Optional[Callable] = None
_ORIGINAL_RUN_REPORT_WRITER: Optional[Callable] = None
_INSTALLED = False

# Learned only after the underlying provider call has exhausted its own bounded
# retries and still returns an explicit OTPM reservation-ceiling failure. This
# is intentionally process-local: the live canary showed one apparently similar
# 429 followed by a successful retry, so persisting the hint across future jobs
# would overfit ambiguous provider behavior.
_OTPM_CEILINGS: dict[tuple[str, str], int] = {}

_TELEMETRY = {
    "semantic_candidate_scores": 0,
    "compact_numeric_expansions": 0,
    "final_evidence_repairs": 0,
    "otpm_ceiling_hints": 0,
    "otpm_capability_skips": 0,
}

_COMPACT_NUMBER_RE = re.compile(
    r"(?<![\w.])(\d+(?:\.\d+)?)([kmb])\b|"
    r"(?<![\w.])(\d+(?:\.\d+)?)\s+(thousand|million|billion)\b",
    re.IGNORECASE,
)
_COMPACT_MULTIPLIERS = {
    "k": Decimal("1000"),
    "thousand": Decimal("1000"),
    "m": Decimal("1000000"),
    "million": Decimal("1000000"),
    "b": Decimal("1000000000"),
    "billion": Decimal("1000000000"),
}
_OTPM_LIMIT_RE = re.compile(
    r"(?:output\s+tokens\s+per\s+minute|\botpm\b).*?"
    r"limit\s+(\d[\d,]*).*?requested\s+(\d[\d,]*)",
    re.IGNORECASE | re.DOTALL,
)
_PROVIDER_BY_HOST = {
    "api.groq.com": "groq",
    "openrouter.ai": "openrouter",
    "api.deepseek.com": "deepseek",
}


def _analytical_word_count(content: str) -> int:
    """Count analytical body words while excluding model-owned heading labels."""
    soup = BeautifulSoup(content or "", "html.parser")
    for heading in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
        heading.decompose()
    return _premium._word_count(str(soup))


def _semantic_metrics(content: str) -> tuple[int, int, int]:
    """Return the heading-independent pre-compiler semantic release metrics."""
    words = _analytical_word_count(content)
    paragraphs, list_items = _premium._semantic_counts(content)
    return words, paragraphs, list_items


def semantic_preflight_complete(content: str) -> bool:
    """Stop model failover only when all heading-independent density floors pass."""
    words, paragraphs, list_items = _semantic_metrics(content)
    return (
        words >= _premium.MIN_VISIBLE_WORDS
        and paragraphs >= _premium.MIN_PARAGRAPHS
        and list_items >= _premium.MIN_LIST_ITEMS
    )


def semantic_candidate_score(content: str) -> tuple[int, int, float, float, int, int, int]:
    """Rank fallback candidates by closeness to the real semantic public floor.

    Renderer-owned headings are intentionally absent from the score. A candidate
    that clears all three semantic floors always outranks one that does not. If
    none clears them all, balanced closeness to the weakest floor wins before
    raw verbosity, preventing a 3k-word eight-paragraph response from beating a
    genuinely denser candidate merely because it is longer.
    """
    words, paragraphs, list_items = _semantic_metrics(content)
    word_ratio = words / max(1, _premium.MIN_VISIBLE_WORDS)
    paragraph_ratio = paragraphs / max(1, _premium.MIN_PARAGRAPHS)
    list_ratio = list_items / max(1, _premium.MIN_LIST_ITEMS)
    ratios = (word_ratio, paragraph_ratio, list_ratio)
    ready = int(all(value >= 1.0 for value in ratios))
    floors_met = sum(1 for value in ratios if value >= 1.0)
    _TELEMETRY["semantic_candidate_scores"] += 1
    return (
        ready,
        floors_met,
        round(min(ratios), 6),
        round(mean(min(value, 1.5) for value in ratios), 6),
        min(words, 5000),
        min(paragraphs, 100),
        min(list_items, 100),
    )


def _canonical_decimal(value: Decimal) -> str:
    """Render one non-negative Decimal without separators or trailing zeros."""
    normalized = format(value, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"


def grounded_numbers_with_compact_suffixes(source_text: str) -> set[str]:
    """Extend quantitative grounding with exact K/M/B and word-scale values.

    Single-letter suffixes must be attached to the number (``5K``, ``2.5M``),
    which avoids interpreting ordinary unit expressions such as ``5 m`` as five
    million. Word scales require whitespace (``1.2 billion``). Only exact
    arithmetic expansion is added; no fuzzy numeric tolerance is introduced.
    """
    grounded = set(_ORIGINAL_GROUNDED_NUMBERS(source_text) if _ORIGINAL_GROUNDED_NUMBERS else ())
    for match in _COMPACT_NUMBER_RE.finditer(str(source_text or "")):
        raw_number = match.group(1) or match.group(3)
        raw_scale = (match.group(2) or match.group(4) or "").lower()
        multiplier = _COMPACT_MULTIPLIERS.get(raw_scale)
        if not raw_number or multiplier is None:
            continue
        try:
            expanded = Decimal(raw_number) * multiplier
        except InvalidOperation:
            continue
        if expanded < 0 or expanded > Decimal("1000000000000000000"):
            continue
        canonical = _canonical_decimal(expanded)
        if canonical not in grounded:
            grounded.add(canonical)
            _TELEMETRY["compact_numeric_expansions"] += 1
    return grounded


def _evidence_repair_prompt(context) -> str:
    """Build only the trusted boundary fields consumed by the existing repair."""
    return (
        f"CDB_EXPLOITATION_STATUS: {getattr(context, 'exploitation_status', '')}\n"
        f"CDB_EVIDENCE_FAMILY: {getattr(context, 'family', '')}\n"
    )


def final_evidence_boundary_assemble_html(
    self,
    article,
    body_content: str,
    seo_data: dict,
    context,
    image_url=None,
):
    """Apply final semantic accounting and evidence repair before artifact hash.

    Stage-2's compiler remains the structural authority. Its assembler first
    captures input metrics and compiles the public section contract. Stage-3
    then replaces only the stored word metric with a heading-independent count
    and repairs evidence language in the final HTML. Both changes occur before
    ``transform()`` computes the certified artifact hash.
    """
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("premium release hardening is not installed")
    assembled = _ORIGINAL_ASSEMBLE_HTML(
        self,
        article,
        body_content,
        seo_data,
        context,
        image_url=image_url,
    )
    metrics = getattr(self, "_cdb_compiler_input_metrics", None)
    if isinstance(metrics, dict):
        metrics["words"] = _analytical_word_count(body_content)

    repaired, changes = _hardening._repair_evidence_language(
        assembled,
        _evidence_repair_prompt(context),
    )
    if changes:
        _TELEMETRY["final_evidence_repairs"] += int(changes)
        logger.info(
            "Final pre-hash evidence boundary repair applied",
            extra={
                "changes": int(changes),
                "family": getattr(context, "family", ""),
                "exploitation_status": getattr(context, "exploitation_status", ""),
            },
        )
    return repaired


def _provider_for_url(url: str) -> str:
    """Resolve a stable provider identity from an exact parsed API hostname."""
    try:
        host = (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    if not host:
        return "unknown"
    return _PROVIDER_BY_HOST.get(host, host)


def _otpm_ceiling(response: requests.Response) -> Optional[int]:
    """Extract an explicit OTPM reservation ceiling from a provider 429 body."""
    if response is None or getattr(response, "status_code", None) != 429:
        return None
    try:
        text = str(response.text or "")
    except Exception:
        return None
    lowered = text.lower()
    if "expected output tokens exceed the enforced limit" not in lowered and "reduce max_tokens" not in lowered:
        return None
    match = _OTPM_LIMIT_RE.search(text)
    if not match:
        return None
    try:
        limit = int(match.group(1).replace(",", ""))
        requested = int(match.group(2).replace(",", ""))
    except (TypeError, ValueError):
        return None
    if limit <= 0 or requested <= limit or limit > 10_000_000:
        return None
    return limit


def learn_otpm_ceiling(
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
    sleep_fn,
):
    """Learn a same-process long-form ceiling only after bounded retries fail.

    The original provider call keeps its proven retry behavior. A ceiling is
    recorded only if the final exception still carries the provider's explicit
    OTPM reservation message, avoiding overreaction to a transient first 429
    that later succeeds within the same bounded call.
    """
    if _ORIGINAL_RAW_OPENAI_CALL is None:
        raise RuntimeError("premium release hardening is not installed")
    try:
        return _ORIGINAL_RAW_OPENAI_CALL(
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
        ceiling = _otpm_ceiling(response)
        if ceiling is not None:
            key = (_provider_for_url(url), str(model))
            previous = _OTPM_CEILINGS.get(key)
            _OTPM_CEILINGS[key] = ceiling if previous is None else min(previous, ceiling)
            _TELEMETRY["otpm_ceiling_hints"] += 1
            logger.info(
                "Provider OTPM ceiling learned for this production process",
                extra={
                    "provider": key[0],
                    "model": key[1],
                    "max_output_tokens": _OTPM_CEILINGS[key],
                },
            )
        raise


def capability_aware_try_provider(
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
    """Skip repeated long-form calls proven incompatible in this process."""
    if _ORIGINAL_TRY_PROVIDER is None:
        raise RuntimeError("premium release hardening is not installed")
    provider = _provider_for_url(url)
    ceiling = _OTPM_CEILINGS.get((provider, str(model)))
    if ceiling is not None and int(max_tokens or 0) > ceiling:
        _TELEMETRY["otpm_capability_skips"] += 1
        logger.info(
            "Skipping repeated provider/model request above observed OTPM ceiling",
            extra={
                "provider": str(name or provider),
                "model": model,
                "requested_max_tokens": int(max_tokens or 0),
                "observed_max_output_tokens": ceiling,
            },
        )
        if attempts is not None:
            attempts.append({
                "provider": str(name or provider),
                "model": model,
                "ok": False,
                "error": "observed_otpm_ceiling",
                "requested_max_tokens": int(max_tokens or 0),
                "observed_max_output_tokens": ceiling,
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


def _release_write_run_report(report: dict, logs_dir: str) -> None:
    """Attach non-secret Stage-3 release-hardening telemetry to each run."""
    if _ORIGINAL_RUN_REPORT_WRITER is None:
        raise RuntimeError("premium release hardening run-report wrapper is not installed")
    report["premium_release_hardening"] = {
        **{key: int(value) for key, value in _TELEMETRY.items()},
        "observed_otpm_ceilings": [
            {
                "provider": provider,
                "model": model,
                "max_output_tokens": limit,
            }
            for (provider, model), limit in sorted(_OTPM_CEILINGS.items())
        ],
    }
    _ORIGINAL_RUN_REPORT_WRITER(report, logs_dir)


def install_release_hardening(main_module) -> None:
    """Install Stage-3 last so it sees the complete Stage-2 runtime graph."""
    global _ORIGINAL_CANDIDATE_SCORE, _ORIGINAL_RAW_CONTRACT_COMPLETE
    global _ORIGINAL_GROUNDED_NUMBERS, _ORIGINAL_ASSEMBLE_HTML
    global _ORIGINAL_RAW_OPENAI_CALL, _ORIGINAL_TRY_PROVIDER
    global _ORIGINAL_RUN_REPORT_WRITER, _INSTALLED
    if _INSTALLED:
        return

    _ORIGINAL_CANDIDATE_SCORE = _recovery._candidate_score
    _ORIGINAL_RAW_CONTRACT_COMPLETE = _recovery._raw_contract_complete
    _ORIGINAL_GROUNDED_NUMBERS = _integrity._grounded_numbers
    _ORIGINAL_ASSEMBLE_HTML = _authority.AuthorityTransformer._assemble_html
    _ORIGINAL_RAW_OPENAI_CALL = _hardening._ORIGINAL_OPENAI_CALL
    _ORIGINAL_TRY_PROVIDER = _llm._try_provider
    _ORIGINAL_RUN_REPORT_WRITER = main_module._write_run_report

    if _ORIGINAL_RAW_OPENAI_CALL is None:
        raise RuntimeError("premium yield hardening must be installed before Stage-3")

    _recovery._candidate_score = semantic_candidate_score
    _recovery._raw_contract_complete = semantic_preflight_complete
    _integrity._grounded_numbers = grounded_numbers_with_compact_suffixes
    _authority.AuthorityTransformer._assemble_html = final_evidence_boundary_assemble_html

    # Keep the existing quota-aware and durable wrappers intact. We replace only
    # the raw call captured inside premium_yield_hardening so a final failed
    # request can teach the outer provider selector about this process's model
    # capability without bypassing any existing backoff or quota telemetry.
    _hardening._ORIGINAL_OPENAI_CALL = learn_otpm_ceiling
    _llm._try_provider = capability_aware_try_provider
    main_module._write_run_report = _release_write_run_report

    _INSTALLED = True
    logger.info(
        "P0 Stage-3 premium release hardening installed",
        extra={
            "candidate_ranking": "PRECOMPILER_SEMANTIC_DENSITY",
            "semantic_word_count": "EXCLUDES_MODEL_HEADINGS",
            "compact_numeric_grounding": "EXACT_K_M_B_EXPANSION",
            "final_evidence_repair": "PRE_HASH",
            "otpm_scope": "PROCESS_LOCAL_AFTER_FINAL_FAILURE",
        },
    )
