"""P0 Stage-5 capacity/yield recovery for the premium CTI factory.

Production runs #8621/#8622 proved a specific provider-capability mismatch:
long-form premium generation needs >=2,200 analytical words plus 18 paragraphs
and 18 list items, while both configured Qwen Groq models expose a 1,000 OTPM
ceiling and the GPT-OSS models can be temporarily unavailable under daily-token
quota. A single 4,400-token request is therefore not a reliable recovery path.

This module adds a bounded continuation rescue without lowering any public
quality or evidence gate. It is installed after Stage-4 evidence admission so
combined candidates are evaluated against the same semantic floors and, while
an article is active, directly against the v8 evidence boundary. Short-capacity
Qwen models are used only for <=900-token continuation fragments, never as an
excuse to publish a thin body.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Callable, Optional

from bs4 import BeautifulSoup

from . import llm_client as _llm
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
    """Keep continuation output as body-level semantic HTML only.

    LLM fragments are untrusted, frequently malformed HTML. BeautifulSoup can
    legally parse malformed/nested heading markup into a tree where decomposing
    one heading also detaches another heading that was already captured by
    ``find_all``. Calling ``unwrap`` on that detached node raises ``ValueError``
    and used to turn an otherwise fail-closed provider-capacity condition into a
    terminal pipeline exception (production Blogger run #8630).

    Every destructive mutation therefore verifies that the node is still part
    of the active soup tree before touching it. The sanitizer remains fail-safe:
    active content is removed, References headings are removed, structural model
    headings are flattened, and only the same body-level allowlist survives.
    """
    soup = BeautifulSoup(raw or "", "html.parser")

    for node in list(soup(["script", "style", "iframe", "object", "embed", "form", "input", "button"])):
        if node.parent is not None:
            node.decompose()

    # Snapshotting is intentional, but malformed/nested headings can cause an
    # earlier decompose() to detach a later snapshot entry. Guard every mutation.
    for heading in list(soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])):
        if heading.parent is None:
            continue
        label = " ".join(heading.stripped_strings).strip()
        if re.search(r"\breferences?\b", label, re.I):
            heading.decompose()
        else:
            heading.unwrap()

    # Re-query after heading mutations so detached descendants are never carried
    # into the generic allowlist pass.
    for tag in list(soup.find_all(True)):
        if tag.parent is None:
            continue
        if tag.name not in {"p", "ul", "ol", "li", "strong", "em", "b", "i", "br", "pre", "code", "table", "thead", "tbody", "tr", "th", "td"}:
            tag.unwrap()
        elif tag.name not in {"table", "thead", "tbody", "tr", "th", "td"}:
            tag.attrs = {}

    return str(soup).strip()


def _semantic_metrics(content: str) -> tuple[int, int, int]:
    """Use the Stage-3 heading-independent semantic accounting when available."""
    try:
        from . import premium_release_hardening as _release
        return _release._semantic_metrics(content)
    except Exception:
        paragraphs, list_items = _premium._semantic_counts(content)
        return _premium._word_count(content), paragraphs, list_items


def _semantic_floor_complete(content: str) -> bool:
    words, paragraphs, list_items = _semantic_metrics(content)
    return (
        words >= _premium.MIN_VISIBLE_WORDS
        and paragraphs >= _premium.MIN_PARAGRAPHS
        and list_items >= _premium.MIN_LIST_ITEMS
    )


def _active_contract_complete(content: str) -> bool:
    """Apply unchanged semantic floors and the live v8 evidence boundary.

    Do not depend on the historical ``_raw_contract_complete`` monkeypatch chain:
    in isolated tests that symbol still means the obsolete model-heading contract,
    while in production it is replaced several times. Stage-5 owns semantic
    continuation acceptance explicitly and asks Stage-4's active article context
    to certify the combined candidate whenever that context exists.
    """
    if not _semantic_floor_complete(content):
        return False
    try:
        from . import generation_evidence_admission as _admission
        article = _admission._CURRENT_ARTICLE.get()
        if article is not None and _admission.evaluate_generation_evidence(article, content):
            return False
    except Exception as exc:
        try:
            from . import generation_evidence_admission as _admission
            if _admission._CURRENT_ARTICLE.get() is not None:
                logger.error("Stage-5 evidence admission evaluation failed", extra={"error": str(exc)})
                return False
        except Exception:
            pass
    return True


def _rescue_needed(content: str) -> bool:
    words, _, _ = _semantic_metrics(content)
    return words >= MIN_RESCUE_WORDS and not _active_contract_complete(content)


def _remaining_requirement(content: str) -> tuple[int, int, int]:
    words, paragraphs, list_items = _semantic_metrics(content)
    return (
        max(0, _premium.MIN_VISIBLE_WORDS - words),
        max(0, _premium.MIN_PARAGRAPHS - paragraphs),
        max(0, _premium.MIN_LIST_ITEMS - list_items),
    )


def _continuation_prompt(original_prompt: str, existing: str, pass_index: int) -> str:
    need_words, need_paragraphs, need_items = _remaining_requirement(existing)
    return (
        original_prompt
        + "\n\nP0 PREMIUM CONTINUATION PASS "
        + str(pass_index)
        + "\nYou are extending an already generated source-bounded premium CTI analysis. "
        + "Return ONLY additional body-level HTML fragments using <p>, <ul>/<ol>, and <li> where useful. "
        + "Do not emit a title, section heading, References section, metadata, scorecard, or wrapper element. "
        + "Never invent a fact, IOC, CVE property, ATT&CK mapping, exploitation state, patch version, victim impact, "
        + "attribution, statistic, or customer exposure that is not supported by the supplied source evidence. "
        + "Preserve uncertainty and source-attributed language. Add distinct analytical depth and decision-useful "
        + "validation/hunting/mitigation reasoning; do not repeat the existing text.\n"
        + f"Current deficit: at least {need_words} additional semantic words, {need_paragraphs} substantive "
        + f"paragraphs, and {need_items} substantive list items remain before the unchanged public floor can be met.\n"
        + "EXISTING BODY (do not repeat):\n"
        + existing[-12000:]
    )


def _eligible_short_models(config) -> list[str]:
    ordered = [config.llm_model_groq, *list(config.llm_model_groq_fallbacks or ())]
    models: list[str] = []
    for model in ordered:
        model = str(model or "").strip()
        if not model or "qwen" not in model.lower() or model in models:
            continue
        models.append(model)
    return models


def capacity_aware_premium_llm(config, prompt: str, max_tokens: int = 3000, attempts=None, sleep_fn=None):
    """Try the established premium chain, then bounded Qwen continuation rescue."""
    if _ORIGINAL_PREMIUM_LLM_CALL is None:
        raise RuntimeError("Stage-5 premium capacity recovery is not installed")

    ledger = attempts if attempts is not None else []
    kwargs = {"max_tokens": max_tokens, "attempts": ledger}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = _ORIGINAL_PREMIUM_LLM_CALL(config, prompt, **kwargs)
    if not result:
        return result

    content, provider = result
    if _active_contract_complete(content) or not _rescue_needed(content):
        return result

    models = _eligible_short_models(config)
    if not models or not getattr(config, "groq_api_key", None):
        return result

    _RUNTIME["rescue_attempts"] += 1
    combined = content
    logger.warning(
        "Premium candidate below semantic floor; starting bounded quota-aware continuation rescue",
        extra={"metrics": _semantic_metrics(content), "models": models},
    )

    for pass_index in range(1, MAX_CONTINUATION_PASSES + 1):
        model = models[(pass_index - 1) % len(models)]
        _RUNTIME["rescue_models"][model] += 1
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
        if not fragment:
            continue
        safe_fragment = _safe_fragment_html(fragment)
        if not safe_fragment:
            continue
        combined += safe_fragment
        _RUNTIME["rescue_fragments"] += 1
        if _active_contract_complete(combined):
            _RUNTIME["rescue_successes"] += 1
            logger.info(
                "Bounded continuation rescue reached unchanged premium/evidence contract",
                extra={"model": model, "pass": pass_index, "metrics": _semantic_metrics(combined)},
            )
            return combined, "groq"

    logger.warning(
        "Bounded continuation rescue exhausted without lowering public quality floors",
        extra={"metrics": _semantic_metrics(combined), "passes": MAX_CONTINUATION_PASSES},
    )
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
    """Install after Stage-4 so evidence admission remains the inner authority."""
    del main_module
    global _ORIGINAL_PREMIUM_LLM_CALL, _INSTALLED
    if _INSTALLED:
        return
    from . import authority_transformer as _authority

    live = _authority.call_llm
    if live is capacity_aware_premium_llm:
        _INSTALLED = True
        return
    _ORIGINAL_PREMIUM_LLM_CALL = live
    _authority.call_llm = capacity_aware_premium_llm
    _INSTALLED = True
    logger.info(
        "P0 Stage-5 provider-capability premium yield recovery installed",
        extra={
            "version": "v9",
            "continuation_max_tokens": CONTINUATION_MAX_TOKENS,
            "passes": MAX_CONTINUATION_PASSES,
        },
    )
