"""Generation-time evidence admission gate for premium CTI narratives.

An LLM candidate must satisfy the existing semantic generation contract *and*
this narrow evidence contract before it can win provider failover. The gate
uses only truth states already owned by ReportContext/DiscoveredArticle and
never synthesizes replacement facts. ReportX, the deterministic compiler,
publication integrity, artifact hashing and Blogger fetch-back remain the
independent downstream authorities.
"""
from __future__ import annotations

import contextvars
import hashlib
import re
from collections import Counter
from typing import Callable, Optional

from bs4 import BeautifulSoup, Tag

from . import authority_transformer as _authority
from . import premium_incident_recovery as _recovery
from .content_discovery import DiscoveredArticle
from .logger import setup_logger
from .report_integrity import (
    _CONFIRMED_EXPLOITATION_PATTERNS,
    _PATCH_AVAILABLE_PATTERNS,
    _RANSOMWARE_CLAIM_CONFIRMED_BREACH_PATTERNS,
    _is_negated_immediately_before,
    build_report_context,
)

logger = setup_logger("generation_evidence_admission")
MARKER = "CDB-GENERATION-EVIDENCE-ADMISSION-V8"

_CURRENT_ARTICLE: contextvars.ContextVar[Optional[DiscoveredArticle]] = contextvars.ContextVar(
    "cdb_generation_article", default=None
)
_CURRENT_TELEMETRY: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "cdb_generation_admission_telemetry", default=None
)
_ORIGINAL_TRANSFORM: Optional[Callable] = None
_ORIGINAL_CALL_LLM: Optional[Callable] = None
_ORIGINAL_COMPLETE: Optional[Callable] = None
_ORIGINAL_SCORE: Optional[Callable] = None

_ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_KEV_LISTED_RE = re.compile(
    r"\b(?:is|was|has been|already|currently)?\s*(?:listed|included|added)\s+"
    r"(?:in|to|on)\s+(?:the\s+)?(?:CISA\s+)?(?:Known Exploited Vulnerabilities|KEV)\b",
    re.I,
)
_KEV_NOT_LISTED_RE = re.compile(
    r"\b(?:is|was|has been)?\s*(?:not|isn.t|wasn.t)\s+(?:listed|included|added)\s+"
    r"(?:in|to|on)\s+(?:the\s+)?(?:CISA\s+)?(?:Known Exploited Vulnerabilities|KEV)\b",
    re.I,
)
# Covers both "upgrade to version 2.8.175" and the live failure shape
# "upgrade GeoDirectory to version 2.8.175" without treating a bare version
# mention as remediation evidence.
_SPECIFIC_PATCH_RE = re.compile(
    r"\b(?:upgrade|update|patch|move)\b[^.?!\n]{0,70}\b(?:to|onto)\s+"
    r"(?:[A-Za-z0-9_.+\-]+\s+){0,5}(?:version|release)?\s*v?\d+(?:\.\d+){1,4}\b",
    re.I,
)
_FORECAST_PREDICTION_RE = re.compile(
    r"\b(?:within\s+the\s+next\s+\d+\s*(?:days?|weeks?|months?|years?)|"
    r"(?:threat\s+actors?|attackers?|exploitation|attacks?|scanning|malware|ransomware)\s+"
    r"(?:will|are\s+likely\s+to|is\s+likely\s+to|are\s+expected\s+to|is\s+expected\s+to)|"
    r"it\s+is\s+likely\s+that\s+(?:threat\s+actors?|attackers?))\b",
    re.I,
)
_SAFE_FORECAST_RE = re.compile(
    r"\b(?:no new future event is predicted|not established in cited evidence|forecast is not established)\b",
    re.I,
)


def _source_text(article: DiscoveredArticle) -> str:
    return " ".join(str(value or "") for value in (article.title, article.summary, article.full_content))


def _plain(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    for node in soup(["script", "style", "noscript"]):
        node.decompose()
    return re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()


def _forecast_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    for heading in soup.find_all(["h2", "h3", "h4", "strong", "b"]):
        label = re.sub(r"^[\s\d.():-]+", "", heading.get_text(" ", strip=True)).strip().lower()
        if label not in {"forecast", "forecast / outlook", "forecast & outlook", "forecast and outlook"}:
            continue
        parts: list[str] = []
        sibling = heading.next_sibling
        while sibling is not None:
            if isinstance(sibling, Tag) and sibling.name in {"h2", "h3", "h4"}:
                break
            if isinstance(sibling, Tag):
                parts.append(sibling.get_text(" ", strip=True))
            sibling = sibling.next_sibling
        return re.sub(r"\s+", " ", " ".join(parts)).strip()
    return ""


def _has_unnegated(text: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            if not _is_negated_immediately_before(text, match.start()):
                return True
    return False


def evaluate_generation_evidence(article: DiscoveredArticle, html: str) -> tuple[str, ...]:
    """Return deterministic high-impact admission failures for one LLM body."""
    if not html:
        return ("EMPTY_GENERATION",)

    context = build_report_context(article)
    text = _plain(html)
    source = _source_text(article)
    issues: list[str] = []

    source_attack_ids = {value.upper() for value in _ATTACK_ID_RE.findall(source)}
    generated_attack_ids = {value.upper() for value in _ATTACK_ID_RE.findall(text)}
    unsupported_attack = sorted(generated_attack_ids - source_attack_ids)
    if unsupported_attack:
        issues.append("ATTACK_ID_UNSUPPORTED:" + ",".join(unsupported_attack[:8]))

    says_not_listed = bool(_KEV_NOT_LISTED_RE.search(text))
    says_listed = bool(_KEV_LISTED_RE.search(text)) and not says_not_listed
    if article.kev_listed is None and (says_listed or says_not_listed):
        issues.append("KEV_UNKNOWN_PROMOTED")
    elif article.kev_listed is True and says_not_listed:
        issues.append("KEV_TRUE_CONTRADICTED")
    elif article.kev_listed is False and says_listed:
        issues.append("KEV_FALSE_CONTRADICTED")

    if context.exploitation_status != "confirmed" and _has_unnegated(text, _CONFIRMED_EXPLOITATION_PATTERNS):
        issues.append("EXPLOITATION_UNSUPPORTED")

    if context.patch_status not in {"available", "required_action"}:
        if _has_unnegated(text, _PATCH_AVAILABLE_PATTERNS) or _SPECIFIC_PATCH_RE.search(text):
            issues.append("REMEDIATION_UNSUPPORTED")

    if context.family == "ransomware_claim" and _has_unnegated(
        text, _RANSOMWARE_CLAIM_CONFIRMED_BREACH_PATTERNS
    ):
        issues.append("RANSOMWARE_CLAIM_PROMOTED")

    forecast = _forecast_text(html)
    if forecast and not _SAFE_FORECAST_RE.search(forecast) and _FORECAST_PREDICTION_RE.search(forecast):
        if not _FORECAST_PREDICTION_RE.search(source):
            issues.append("FORECAST_UNSUPPORTED")

    return tuple(dict.fromkeys(issues))


def _record_assessment(content: str, issues: tuple[str, ...]) -> None:
    telemetry = _CURRENT_TELEMETRY.get()
    if telemetry is None:
        return
    digest = hashlib.sha256((content or "").encode("utf-8")).hexdigest()[:16]
    seen = telemetry.setdefault("_seen", set())
    if digest in seen:
        return
    seen.add(digest)
    telemetry["evaluated_candidates"] = int(telemetry.get("evaluated_candidates", 0)) + 1
    if issues:
        telemetry["rejected_candidates"] = int(telemetry.get("rejected_candidates", 0)) + 1
        reasons = telemetry.setdefault("reason_counts", Counter())
        for issue in issues:
            reasons[issue.split(":", 1)[0]] += 1


def _admission_complete(content: str) -> bool:
    if _ORIGINAL_COMPLETE is None or not _ORIGINAL_COMPLETE(content):
        return False
    article = _CURRENT_ARTICLE.get()
    if article is None:
        return True
    issues = evaluate_generation_evidence(article, content)
    _record_assessment(content, issues)
    return not issues


def _admission_score(content: str):
    if _ORIGINAL_SCORE is None:
        return (0, 0, 0, 0, 0)
    base = _ORIGINAL_SCORE(content)
    article = _CURRENT_ARTICLE.get()
    if article is None:
        return (1, 0, *base)
    issues = evaluate_generation_evidence(article, content)
    _record_assessment(content, issues)
    return (1 if not issues else 0, -len(issues), *base)


def _admission_call_llm(config, prompt: str, max_tokens: int = 3000, attempts=None, sleep_fn=None):
    if _ORIGINAL_CALL_LLM is None:
        raise RuntimeError("generation evidence admission gate is not installed")
    kwargs = {"max_tokens": max_tokens, "attempts": attempts}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = _ORIGINAL_CALL_LLM(config, prompt, **kwargs)
    if not result:
        return result
    content, provider = result
    article = _CURRENT_ARTICLE.get()
    if article is None:
        return result
    issues = evaluate_generation_evidence(article, content)
    _record_assessment(content, issues)
    if issues:
        logger.warning(
            "Generation candidate rejected by evidence admission gate",
            extra={"provider": provider, "reason_codes": [item.split(":", 1)[0] for item in issues]},
        )
        return None
    return result


def _contextual_transform(self, article: DiscoveredArticle) -> dict:
    if _ORIGINAL_TRANSFORM is None:
        raise RuntimeError("generation evidence admission transform wrapper is not installed")
    telemetry: dict = {
        "version": "v8",
        "evaluated_candidates": 0,
        "rejected_candidates": 0,
        "reason_counts": Counter(),
        "enforced": True,
    }
    article_token = _CURRENT_ARTICLE.set(article)
    telemetry_token = _CURRENT_TELEMETRY.set(telemetry)
    try:
        result = _ORIGINAL_TRANSFORM(self, article)
        if isinstance(result, dict):
            result["generation_evidence_admission"] = {
                "version": "v8",
                "evaluated_candidates": int(telemetry["evaluated_candidates"]),
                "rejected_candidates": int(telemetry["rejected_candidates"]),
                "reason_counts": dict(telemetry["reason_counts"]),
                "enforced": True,
            }
        return result
    finally:
        _CURRENT_TELEMETRY.reset(telemetry_token)
        _CURRENT_ARTICLE.reset(article_token)


def install_generation_evidence_admission(main_module) -> None:
    """Install after all runtime wrappers so recovery and the final LLM result are gated."""
    global _ORIGINAL_TRANSFORM, _ORIGINAL_CALL_LLM, _ORIGINAL_COMPLETE, _ORIGINAL_SCORE

    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None or getattr(transformer.transform, "_cdb_generation_admission_v8", False):
        return

    _ORIGINAL_COMPLETE = _recovery._raw_contract_complete
    _ORIGINAL_SCORE = _recovery._candidate_score
    _recovery._raw_contract_complete = _admission_complete
    _recovery._candidate_score = _admission_score

    _ORIGINAL_CALL_LLM = _authority.call_llm
    _authority.call_llm = _admission_call_llm

    _ORIGINAL_TRANSFORM = transformer.transform
    _contextual_transform._cdb_generation_admission_v8 = True
    transformer.transform = _contextual_transform
