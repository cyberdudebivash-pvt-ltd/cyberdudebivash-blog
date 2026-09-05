"""P0 Stage-5 capacity/yield recovery for the premium CTI factory.

Production runs #8621/#8622 proved a specific provider-capability mismatch:
long-form premium generation needs >=2,200 analytical words plus 18 paragraphs
and 18 list items, while both configured Qwen Groq models expose a 1,000 OTPM
ceiling and the GPT-OSS models can be temporarily unavailable under daily-token
quota. A single 4,400-token request is therefore not a reliable recovery path.

This module adds a bounded continuation rescue without lowering any public
quality or evidence gate. It is installed after Stage-4 evidence admission so
combined candidates are evaluated by the existing evidence-safe semantic
contract before they can win. Short-capability Qwen models are used only for
<=900-token continuation fragments, never as an excuse to publish a thin body.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Callable, Optional

from bs4 import BeautifulSoup

from . import llm_client as _llm
from . import premium_incident_recovery as _recovery
from . import premium_provider_budget as _budget
from . import premium_publication as _premium
from .logger import setup_logger

logger = setup_logger("premium_capacity_recovery")

MARKER = "CDB-PREMIUM-CAPACITY-RECOVERY-V9"
CONTINUATION_MAX_TOKENS = 900
MAX_CONTINUATION_PASSES = 3
MIN_RESCUE_WORDS = 350

_ORIGINAL_PREMIUM_LLM_CALL: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "rescue_attempts": 0,
    "rescue_successes": 0,
    "rescue_fragments": 0,
    "rescue_models": Counter(),
}


def _safe_fragment_html(raw: str) -> str:
    """Keep continuation output as body-level semantic HTML only."""
    soup = BeautifulSoup(raw or "", "html.parser")
    for node in soup(["script", "style", "iframe", "object", "embed", "form", "input", "button"]):
        node.decompose()
    # Continuations may not create model-owned public structure or references.
    for heading in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
        label = " ".join(heading.stripped_strings).strip()
        if re.search(r"\breferences?\b", label, re.I):
            heading.decompose()
        else:
            heading.unwrap()
    for tag in soup.find_all(True):
        if tag.name not in {"p", "ul", "ol", "li", "strong", "em", "b", "i", "br", "pre", "code", "table", "thead", "tbody", "tr", "th", "td"}:
            tag.unwrap()
        elif tag.name not in {"table", "thead", "tbody", "tr", "th", "td"}:
            tag.attrs = {}
    return str(soup).strip()


def _semantic_metrics(content: str) -> tuple[int, int, int]:
    """Use the active Stage-3 semantic accounting when available."""
    try:
        from . import premium_release_hardening as _release
        return _release._semantic_metrics(content)
    except Exception:
        paragraphs, list_items = _premium._semantic_counts(content)
        return _premium._word_count(content), paragraphs, list_items


def _rescue_needed(content: str) -> bool:
    words, _, _ = _semantic_metrics(content)
    return words >= MIN_RESCUE_WORDS and not _recovery._raw_contract_complete(content)


def _remaining_requirement(content: str) -> tuple[int, int, int]:
    words, paragraphs, list_items = _semantic_metrics(content)
    return (
        max(0, _premium.MIN_VISIBLE_WORDS - words),
        max(0, _premium.MIN_PARAGRAPHS - paragraphs),
        max(0, _premium.MIN_LIST_ITEMS - list_items),
    )


def _continuation_prompt(original_prompt: str, current: str, pass_index: int) -> str:
    missing_words, missing_paragraphs, missing_items = _remaining_requirement(current)
    # Reuse the already evidence-bounded source prompt. Keep only the tail of the
    # current candidate so the model can avoid repetition without exploding TPM.
    current_text = BeautifulSoup(current or "", "html.parser").get_text(" ", strip=True)
    tail = current_text[-3500:]
    prompt = f"""{original_prompt}

P0 CAPACITY CONTINUATION PASS {pass_index}/{MAX_CONTINUATION_PASSES}
The existing analytical body is below the unchanged premium semantic floor.
Return ONLY a continuation HTML fragment. Do not repeat or rewrite prior text.
Do not emit headings, section names, References, source URLs, or a preamble.
Use only <p>, <ul>/<li>, <ol>/<li>, <table>, and inline emphasis/code tags.
Add decision-useful source-bounded analysis, validation logic, telemetry needs,
intelligence gaps, alternatives, and evidence-conditioned operational actions.
Never invent a fact, ATT&CK ID, IOC, exploit status, patch/version, victim impact,
breach confirmation, attribution, future event, statistic, or customer exposure.
If evidence is insufficient, state the exact evidence gap and what would resolve it.
Current deficit: about {missing_words} analytical words, {missing_paragraphs} substantive paragraphs,
and {missing_items} substantive list items. Prefer multiple concise substantive paragraphs
and evidence-specific list items over long generic prose.

TAIL OF EXISTING BODY — context only, do not repeat:
{tail}
"""
    return prompt[: _budget.PREMIUM_PROMPT_CHAR_CEILING]


def _eligible_short_models(config) -> list[str]:
    """Return configured Qwen-style Groq models suited to <=900-token fragments."""
    models = []
    seen = set()
    for model in [getattr(config, "llm_model_groq", None), *getattr(config, "llm_model_groq_fallbacks", ())]:
        if not model or model in seen:
            continue
        seen.add(model)
        lower = str(model).lower()
        if "qwen" in lower:
            models.append(str(model))
    return models


def capacity_aware_premium_llm(config, prompt: str, max_tokens: int = 3000, attempts=None, sleep_fn=None):
    """Run the proven generator first, then bounded semantic continuations."""
    if _ORIGINAL_PREMIUM_LLM_CALL is None:
        raise RuntimeError("premium capacity recovery is not installed")
    ledger = attempts if attempts is not None else []
    kwargs = {"max_tokens": max_tokens, "attempts": ledger}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = _ORIGINAL_PREMIUM_LLM_CALL(config, prompt, **kwargs)
    if not result:
        return result
    content, provider = result
    if _recovery._raw_contract_complete(content) or not _rescue_needed(content):
        return result
    if not getattr(config, "groq_api_key", None):
        return result

    models = _eligible_short_models(config)
    if not models:
        return result

    _RUNTIME["rescue_attempts"] += 1
    combined = content
    logger.warning(
        "Premium candidate below semantic floor; starting bounded quota-aware continuation rescue",
        extra={"metrics": _semantic_metrics(combined), "models": models, "max_tokens": CONTINUATION_MAX_TOKENS},
    )

    for pass_index in range(1, MAX_CONTINUATION_PASSES + 1):
        model = models[(pass_index - 1) % len(models)]
        fragment = _llm._try_provider(
            name="groq",
            url=_llm._GROQ_URL,
            api_key=config.groq_api_key,
            model=model,
            prompt=_continuation_prompt(prompt, combined, pass_index),
            max_tokens=CONTINUATION_MAX_TOKENS,
            extra_headers={},
            sleep_fn=sleep_fn or (lambda _seconds: None),
            attempts=ledger,
        )
        _RUNTIME["rescue_models"][model] += 1
        if not fragment:
            continue
        safe_fragment = _safe_fragment_html(fragment)
        if not safe_fragment:
            continue
        _RUNTIME["rescue_fragments"] += 1
        candidate = combined + safe_fragment
        # The active Stage-4 wrapper is intentionally consulted here. This
        # keeps evidence admission authoritative for the combined candidate.
        combined = candidate
        if _recovery._raw_contract_complete(combined):
            _RUNTIME["rescue_successes"] += 1
            logger.info(
                "Premium continuation rescue reached the unchanged semantic/evidence contract",
                extra={"model": model, "pass": pass_index, "metrics": _semantic_metrics(combined)},
            )
            return combined, "groq"

    logger.warning(
        "Premium continuation rescue exhausted without lowering public quality floors",
        extra={"metrics": _semantic_metrics(combined), "passes": MAX_CONTINUATION_PASSES},
    )
    # Return the best enriched body; the unchanged downstream gates remain the
    # final authority and will hold it if it is still below contract.
    return combined, provider


def telemetry_snapshot() -> dict:
    return {
        "version": "v9",
        "rescue_attempts": int(_RUNTIME["rescue_attempts"]),
        "rescue_successes": int(_RUNTIME["rescue_successes"]),
        "rescue_fragments": int(_RUNTIME["rescue_fragments"]),
        "rescue_models": dict(_RUNTIME["rescue_models"]),
        "continuation_max_tokens": CONTINUATION_MAX_TOKENS,
        "max_continuation_passes": MAX_CONTINUATION_PASSES,
    }


def install_premium_capacity_recovery(main_module) -> None:
    """Install after Stage-4 so continuation acceptance inherits v8 evidence gates."""
    del main_module
    global _ORIGINAL_PREMIUM_LLM_CALL, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_PREMIUM_LLM_CALL = _premium._premium_llm_call
    _premium._premium_llm_call = capacity_aware_premium_llm
    _INSTALLED = True
    logger.info(
        "P0 Stage-5 provider-capability premium yield recovery installed",
        extra={"version": "v9", "continuation_max_tokens": CONTINUATION_MAX_TOKENS, "passes": MAX_CONTINUATION_PASSES},
    )
