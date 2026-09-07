"""SENTINEL APEX™ ASTRA Cash Conversion Engine v19.

P0 commercial objective
-----------------------
Remove an unnecessary pricing-page hop between a qualified CTI reader and the
repository's existing paid subscription checkout. v19 is intentionally a thin
outer presentation/attribution layer: it does not alter intelligence content,
quality gates, prices, entitlements, provider routing, or payment verification.

Production invariants
---------------------
- v18 remains responsible for deciding which tier to recommend.
- api/_lib/payment-utils.js remains the canonical plan/price source.
- api/v1/billing remains the canonical payment/entitlement authority.
- paid CTI CTAs are rewritten only to /buy.html?plan=<tier>&checkout=1.
- public documentation CTAs remain public and are never paywalled.
- presentation is fail-open; a conversion-layer defect cannot block a report.
- telemetry is aggregate only: no email, API key, order/payment ID, prompt,
  report body, customer data, or credential is persisted.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Optional
from urllib.parse import urlencode

from bs4 import BeautifulSoup

from . import authority_transformer as _authority
from .logger import setup_logger

logger = setup_logger("astra_cash_conversion_v19")

MARKER = "CDB-ASTRA-CASH-CONVERSION-V19"
_INSTALL_ATTR = "__cdb_astra_cash_conversion_v19__"
BUY_URL = "https://blog.cyberdudebivash.in/buy.html"
PAID_TIERS = frozenset({"starter", "pro", "enterprise"})

_INNER_ASSEMBLE_HTML: Optional[Callable] = None
_INNER_WRITE_RUN_REPORT: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "panels_seen": 0,
    "panels_rewritten": 0,
    "checkout_links_created": 0,
    "checkout_links_by_tier": Counter(),
}


def _safe_token(value: object, default: str = "general_intelligence") -> str:
    text = str(value or default).strip().lower()
    cleaned = "".join(ch if (ch.isalnum() or ch in "_.-") else "_" for ch in text)
    return cleaned[:100] or default


def direct_checkout_url(tier: str, family: str, cta: str) -> str:
    """Build a deterministic, attribution-safe direct subscription URL."""
    normalized_tier = _safe_token(tier, "")
    if normalized_tier not in PAID_TIERS:
        raise ValueError(f"unsupported paid tier: {tier!r}")
    normalized_family = _safe_token(family)
    normalized_cta = _safe_token(cta, "paid_cta")
    query = urlencode({
        "plan": normalized_tier,
        "checkout": "1",
        "utm_source": "sentinel_apex_report",
        "utm_medium": "cti_dossier",
        "utm_campaign": "astra_cash_conversion_v19",
        "utm_content": f"{normalized_tier}_{normalized_family}_{normalized_cta}"[:100],
    })
    return f"{BUY_URL}?{query}"


def _checkout_label(tier: str) -> str:
    return {
        "starter": "START API STARTER CHECKOUT →",
        "pro": "START SOC PRO CHECKOUT →",
        "enterprise": "START ENTERPRISE CHECKOUT →",
    }[tier]


def enhance_cash_conversion(rendered_html: str, article: Any = None, context: Any = None) -> str:
    """Rewrite v18 paid CTAs to the focused v19 checkout surface.

    The function is idempotent and fail-open. It never creates a paid CTA when
    the upstream v18 commercial panel is absent.
    """
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        panel = soup.select_one(".cdbv18-commercial[data-astra-revenue-v18='true']")
        if panel is None:
            return rendered_html

        _RUNTIME["panels_seen"] += 1
        family = _safe_token(
            panel.get("data-report-family")
            or getattr(context, "family", None)
            or "general_intelligence"
        )
        rewritten = 0

        for anchor in panel.select("a[data-cdb-tier]"):
            tier = _safe_token(anchor.get("data-cdb-tier"), "")
            if tier not in PAID_TIERS:
                continue
            cta = _safe_token(anchor.get("data-cdb-v18-cta"), "paid_cta")
            anchor["href"] = direct_checkout_url(tier, family, cta)
            anchor["data-cdb-v19-direct-checkout"] = "true"
            anchor["data-cdb-v19-plan"] = tier
            anchor.string = _checkout_label(tier)
            rewritten += 1
            _RUNTIME["checkout_links_created"] += 1
            _RUNTIME["checkout_links_by_tier"][tier] += 1

        if rewritten:
            note = soup.new_tag("div")
            note["class"] = ["cdbv19-checkout-note"]
            note["data-cdb-v19-checkout-boundary"] = "true"
            note.string = (
                "DIRECT CHECKOUT // Canonical plan pricing is loaded from the billing API. "
                "Razorpay instant checkout is offered where available; verified UPI/bank "
                "fallback remains available. Paid access changes delivery and entitlement, "
                "never intelligence certainty."
            )
            boundary = panel.select_one(".cdbv18-boundary")
            if boundary is not None:
                boundary.insert_after(note)
            else:
                panel.insert(0, note)

            style = soup.new_tag("style")
            style["id"] = "cdb-astra-cash-conversion-v19-css"
            style.string = (
                ".cdbv19-checkout-note{margin:0 0 11px;padding:8px 10px;border:1px solid "
                "rgba(0,255,224,.16);border-radius:8px;background:rgba(0,255,224,.025);"
                "color:#bcd4df;font:750 8px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;"
                "letter-spacing:.025em}.cdbv18-grid a[data-cdb-v19-direct-checkout=true],"
                ".cdbv18-primary a[data-cdb-v19-direct-checkout=true]{border-color:rgba(0,255,224,.42);"
                "color:#70ffe9!important;background:rgba(0,255,224,.035)}"
            )
            soup.insert(0, style)
            _RUNTIME["panels_rewritten"] += 1

        return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->" if rewritten else rendered_html
    except Exception as exc:
        logger.warning(
            "ASTRA v19 cash conversion presentation skipped",
            extra={"error": type(exc).__name__},
        )
        return rendered_html


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url=None):
    if _INNER_ASSEMBLE_HTML is None:
        raise RuntimeError("ASTRA v19 cash conversion is not installed")
    rendered = _INNER_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return enhance_cash_conversion(rendered, article, context)


setattr(_patched_assemble_html, _INSTALL_ATTR, True)


def telemetry_snapshot() -> dict:
    return {
        "version": "v19",
        "marker": MARKER,
        "commercial_objective": "shorten_qualified_reader_to_verified_subscription_checkout",
        "panels_seen": int(_RUNTIME["panels_seen"]),
        "panels_rewritten": int(_RUNTIME["panels_rewritten"]),
        "checkout_links_created": int(_RUNTIME["checkout_links_created"]),
        "checkout_links_by_tier": dict(_RUNTIME["checkout_links_by_tier"]),
        "checkout_surface": "/buy.html",
        "canonical_pricing_source": "api/_lib/payment-utils.js",
        "canonical_payment_authority": "api/v1/billing",
        "quality_or_evidence_gate_changed": False,
        "provider_policy_changed": False,
        "telemetry_contains_pii": False,
        "telemetry_contains_credentials": False,
        "telemetry_contains_payment_identifiers": False,
        "revenue_guaranteed": False,
    }


def _write_run_report(report: dict, logs_dir: str) -> None:
    if _INNER_WRITE_RUN_REPORT is None:
        raise RuntimeError("ASTRA v19 run-report wrapper is not installed")
    report["astra_cash_conversion_v19"] = telemetry_snapshot()
    _INNER_WRITE_RUN_REPORT(report, logs_dir)


def install_astra_cash_conversion_v19(main_module) -> None:
    """Install last, outside v18, so v18 recommendation logic remains inner."""
    global _INNER_ASSEMBLE_HTML, _INNER_WRITE_RUN_REPORT, _INSTALLED
    if _INSTALLED:
        return

    transformer = getattr(main_module, "AuthorityTransformer", None) or _authority.AuthorityTransformer
    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        _INSTALLED = True
        return

    _INNER_ASSEMBLE_HTML = current
    _INNER_WRITE_RUN_REPORT = main_module._write_run_report
    transformer._assemble_html = _patched_assemble_html
    main_module._write_run_report = _write_run_report

    if transformer._assemble_html is not _patched_assemble_html:
        raise RuntimeError("ASTRA v19 failed to bind final commercial presentation")
    if main_module._write_run_report is not _write_run_report:
        raise RuntimeError("ASTRA v19 failed to bind aggregate conversion telemetry")

    _INSTALLED = True
    logger.info(
        "SENTINEL APEX ASTRA Cash Conversion Engine v19 installed",
        extra={
            "marker": MARKER,
            "direct_checkout_surface": "/buy.html",
            "new_billing_system_created": False,
            "pricing_changed": False,
            "quality_gate_changed": False,
        },
    )
