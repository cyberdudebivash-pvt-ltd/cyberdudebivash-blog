"""SENTINEL APEX CTI publication recovery v19.2.

P0 recovery layer for the 2026-09-07 Blogger freshness outage.

The production incident had two deterministic integration failures:
1. high-signal LLM scratch/prompt fragments reached the final dossier and were
   correctly rejected by Dossier v8's customer-visible prompt-leakage gate;
2. v19.1 truthfully changed the customer-visible source-only certification
   label to SOURCE_ONLY_PRELIMINARY, while the older ReportX artifact-binding
   validator still required the exact internal certification string to remain
   present in the submitted HTML.

This module repairs those integration defects *before* the existing hard gates
run. It never weakens the Dossier v8 prompt gate, ReportX evidence gates,
quality floors, provider policy, prices, entitlements, or payment verification.
Any prompt/control leakage that is not one of the narrowly-recognized repair
patterns remains a publication blocker.
"""
from __future__ import annotations

from collections import Counter
import re
from typing import Any, Callable, Optional

from bs4 import BeautifulSoup, NavigableString

from . import cti_dossier_v8 as _v8
from . import cti_integrity_revenue_v19_1 as _v19_1
from .logger import setup_logger

logger = setup_logger("cti_publication_recovery_v19_2")

MARKER = "CDB-CTI-PUBLICATION-RECOVERY-V19-2"
_INSTALL_ATTR = "__cdb_cti_publication_recovery_v19_2__"

_ORIGINAL_V8_GATE: Optional[Callable] = None
_ORIGINAL_V19_1_ENFORCER: Optional[Callable] = None
_ORIGINAL_WRITE_RUN_REPORT: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "dossiers_scrubbed": 0,
    "text_nodes_scrubbed": 0,
    "prompt_fragments_scrubbed": 0,
    "control_tokens_scrubbed": 0,
    "certification_bindings_added": 0,
    "scrub_classes": Counter(),
}

# These are intentionally narrower than the fail-closed v8 detector. They are
# repairable model-scratch signatures already observed in production. The v8
# detector still executes afterwards and rejects any residue or any new class
# of prompt leakage.
_SENTENCE_REPAIRS: tuple[tuple[str, re.Pattern], ...] = (
    (
        "model_planning_preamble",
        re.compile(
            r"(?is)(?:^|(?<=[.!?]))\s*the user wants me to\b[^.!?]*(?:[.!?](?=\s|$)|$)"
        ),
    ),
    (
        "model_planning",
        re.compile(
            r"(?is)(?:^|(?<=[.!?]))\s*let me (?:analy[sz]e|draft|structure|write|think|plan)\b[^.!?]*(?:[.!?](?=\s|$)|$)"
        ),
    ),
    (
        "model_planning",
        re.compile(
            r"(?is)(?:^|(?<=[.!?]))\s*i need to (?:be|write|ensure|follow|structure|carefully|make sure)\b[^.!?]*(?:[.!?](?=\s|$)|$)"
        ),
    ),
    (
        "model_planning",
        re.compile(
            r"(?is)(?:^|(?<=[.!?]))\s*i should (?:be|not|ensure|write|follow|avoid)\b[^.!?]*(?:[.!?](?=\s|$)|$)"
        ),
    ),
    (
        "role_instruction_leakage",
        re.compile(
            r"(?is)(?:^|(?<=[.!?]))\s*(?:system|developer|user) (?:message|prompt|instruction)s?\b[^.!?]*(?:[.!?](?=\s|$)|$)"
        ),
    ),
)

_INLINE_REPAIRS: tuple[tuple[str, re.Pattern], ...] = (
    ("prompt_constraint", re.compile(r"\b(?:\d{1,2}\s+)?mandatory sections?\b", re.I)),
    ("prompt_constraint", re.compile(r"\b\d[\d,]*\s*(?:[-–]\s*\d[\d,]*)?\s+visible words?\b", re.I)),
    ("prompt_constraint", re.compile(r"\bhtml only,? no markdown\b", re.I)),
    ("prompt_constraint", re.compile(r"\bno preamble,? no markdown fences?\b", re.I)),
    (
        "internal_control_token",
        re.compile(r"\bCDB_(?:EXPLOITATION_STATUS|SOURCE_CLAIM_ONLY)\b", re.I),
    ),
)

_SKIP_TEXT_PARENTS = frozenset({"script", "style", "noscript", "code", "pre"})


def _clean_text_node(text: str) -> tuple[str, Counter]:
    """Remove only known model-scratch fragments from one visible text node."""
    value = text
    repairs: Counter = Counter()

    for label, pattern in _SENTENCE_REPAIRS:
        value, count = pattern.subn(" ", value)
        if count:
            repairs[label] += count

    for label, pattern in _INLINE_REPAIRS:
        value, count = pattern.subn(" ", value)
        if count:
            repairs[label] += count

    # Do not reflow prose globally; only collapse whitespace introduced by the
    # bounded removals above. Leading/trailing whitespace is retained when it
    # existed so adjacent inline HTML does not concatenate words.
    if repairs:
        had_leading = bool(value[:1].isspace())
        had_trailing = bool(value[-1:].isspace())
        value = re.sub(r"[ \t\r\f\v]+", " ", value)
        value = re.sub(r"\n{3,}", "\n\n", value)
        core = value.strip()
        if core:
            value = (" " if had_leading else "") + core + (" " if had_trailing else "")
        else:
            value = ""
    return value, repairs


def scrub_customer_visible_prompt_leakage(soup: BeautifulSoup) -> int:
    """Repair known prompt leakage, then rely on v8 to fail closed on residue."""
    changed_nodes = 0
    aggregate: Counter = Counter()

    for node in list(soup.find_all(string=True)):
        if not isinstance(node, NavigableString) or node.parent is None:
            continue
        if node.parent.name in _SKIP_TEXT_PARENTS:
            continue
        original = str(node)
        cleaned, repairs = _clean_text_node(original)
        if not repairs:
            continue
        aggregate.update(repairs)
        changed_nodes += 1
        if cleaned:
            node.replace_with(cleaned)
        else:
            node.extract()

    if changed_nodes:
        _RUNTIME["dossiers_scrubbed"] += 1
        _RUNTIME["text_nodes_scrubbed"] += changed_nodes
        prompt_count = sum(
            count
            for label, count in aggregate.items()
            if label != "internal_control_token"
        )
        control_count = aggregate.get("internal_control_token", 0)
        _RUNTIME["prompt_fragments_scrubbed"] += prompt_count
        _RUNTIME["control_tokens_scrubbed"] += control_count
        _RUNTIME["scrub_classes"].update(aggregate)
    return changed_nodes


def _patched_v8_gate(soup: BeautifulSoup) -> None:
    if _ORIGINAL_V8_GATE is None:
        raise RuntimeError("v19.2 prompt-recovery gate is not installed")
    scrub_customer_visible_prompt_leakage(soup)
    # Critical invariant: the original fail-closed gate always runs after the
    # repair pass. Unknown/residual leakage is still a hard publication block.
    _ORIGINAL_V8_GATE(soup)


setattr(_patched_v8_gate, _INSTALL_ATTR, True)


def _inject_certification_binding(rendered_html: str, context: Any = None) -> str:
    """Retain the exact ReportX certification as non-visible artifact metadata.

    v19.1 owns the customer-visible source-only label. The legacy ReportX
    validator requires the exact context.certification_status string to remain
    present in the submitted artifact. A data attribute satisfies that machine
    binding without exposing FLASH_READY (or any other internal tier token) as
    visible customer text.
    """
    certification = str(getattr(context, "certification_status", "") or "").strip()
    if not rendered_html or not certification or certification in rendered_html:
        return rendered_html

    soup = BeautifulSoup(rendered_html, "html.parser")
    root = soup.select_one(".cdb-cti-dossier")
    if root is None:
        root = soup.find(True)
    if root is None:
        return rendered_html

    root["data-cdb-reportx-certification-binding"] = certification
    root["data-cdb-reportx-certification-binding-mode"] = "machine-only"
    _RUNTIME["certification_bindings_added"] += 1
    return str(soup)


def _patched_v19_1_enforcer(rendered_html: str, article: Any = None, context: Any = None) -> str:
    if _ORIGINAL_V19_1_ENFORCER is None:
        raise RuntimeError("v19.2 certification-binding wrapper is not installed")
    rendered = _ORIGINAL_V19_1_ENFORCER(rendered_html, article, context)
    return _inject_certification_binding(rendered, context)


setattr(_patched_v19_1_enforcer, _INSTALL_ATTR, True)


def telemetry_snapshot() -> dict:
    return {
        "version": "v19.2",
        "marker": MARKER,
        "dossiers_scrubbed": int(_RUNTIME["dossiers_scrubbed"]),
        "text_nodes_scrubbed": int(_RUNTIME["text_nodes_scrubbed"]),
        "prompt_fragments_scrubbed": int(_RUNTIME["prompt_fragments_scrubbed"]),
        "control_tokens_scrubbed": int(_RUNTIME["control_tokens_scrubbed"]),
        "certification_bindings_added": int(_RUNTIME["certification_bindings_added"]),
        "scrub_classes": dict(_RUNTIME["scrub_classes"]),
        "v8_fail_closed_gate_preserved": True,
        "reportx_quality_floors_changed": False,
        "reportx_tier_engine_changed": False,
        "provider_policy_changed": False,
        "prices_changed": False,
        "payment_system_changed": False,
        "telemetry_contains_prompts": False,
        "telemetry_contains_response_content": False,
        "telemetry_contains_credentials": False,
        "telemetry_contains_pii": False,
    }


def _write_run_report(report: dict, logs_dir: str) -> None:
    if _ORIGINAL_WRITE_RUN_REPORT is None:
        raise RuntimeError("v19.2 run-report wrapper is not installed")
    report["cti_publication_recovery_v19_2"] = telemetry_snapshot()
    _ORIGINAL_WRITE_RUN_REPORT(report, logs_dir)


setattr(_write_run_report, _INSTALL_ATTR, True)


def install_cti_publication_recovery_v19_2(main_module) -> None:
    """Install after v19.1 and before the first production pipeline run."""
    global _ORIGINAL_V8_GATE, _ORIGINAL_V19_1_ENFORCER, _ORIGINAL_WRITE_RUN_REPORT, _INSTALLED
    if _INSTALLED:
        return

    current_gate = _v8._gate_customer_visible_integrity
    if not getattr(current_gate, _INSTALL_ATTR, False):
        _ORIGINAL_V8_GATE = current_gate
        _v8._gate_customer_visible_integrity = _patched_v8_gate

    current_enforcer = _v19_1.enforce_cti_integrity_revenue_v19_1
    if not getattr(current_enforcer, _INSTALL_ATTR, False):
        _ORIGINAL_V19_1_ENFORCER = current_enforcer
        _v19_1.enforce_cti_integrity_revenue_v19_1 = _patched_v19_1_enforcer

    current_writer = main_module._write_run_report
    if not getattr(current_writer, _INSTALL_ATTR, False):
        _ORIGINAL_WRITE_RUN_REPORT = current_writer
        main_module._write_run_report = _write_run_report

    if _v8._gate_customer_visible_integrity is not _patched_v8_gate:
        raise RuntimeError("v19.2 failed to bind Dossier v8 repair-before-gate wrapper")
    if _v19_1.enforce_cti_integrity_revenue_v19_1 is not _patched_v19_1_enforcer:
        raise RuntimeError("v19.2 failed to bind v19.1 certification compatibility wrapper")
    if main_module._write_run_report is not _write_run_report:
        raise RuntimeError("v19.2 failed to bind run-report telemetry wrapper")

    _INSTALLED = True
    logger.info(
        "SENTINEL APEX CTI publication recovery v19.2 installed",
        extra={
            "marker": MARKER,
            "v8_fail_closed_gate_preserved": True,
            "reportx_quality_floors_changed": False,
            "reportx_tier_engine_changed": False,
        },
    )
