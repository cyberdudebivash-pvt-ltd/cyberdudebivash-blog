"""SENTINEL APEX CTI IOC State Reconciliation.

Fixes a structural blind spot behind a real "IOC STATE: NOT ESTABLISHED
despite a rendered indicator" contradiction: a public dossier can display
premium_evidence_compiler.py's static, always-negative IOC placeholder text
even on a report where authority_transformer.py's IOC extractor found and
rendered a real, defanged hash/IP/domain elsewhere on the same page.

Root cause: premium_evidence_compiler._section_payloads() renders the
canonical `<h3>Indicators & Observables</h3>` section unconditionally via
_gap(), a static "Not established in cited evidence" fallback that takes no
IOC data as input at all (premium_evidence_compiler.py:294-296). Separately,
authority_transformer._render_iocs_html() renders real, deterministically
extracted indicators (never fabricated -- see its own docstring) into a
second, genuinely populated section titled "Indicators / Observables", but
via report_renderer._section(), which wraps the title in a plain <div>, not
an <h2>/<h3> (report_renderer.py:45-52). Every downstream label reader --
cti_dossier_v9._semantic_state, cti_integrity_revenue_v19_1._capabilities --
locates sections via soup.find_all(["h2","h3"]) only, so they only ever see
the compiler's hardcoded placeholder and are structurally blind to the real,
populated section sitting right below it on the same artifact.

This layer never extracts, fabricates, or upgrades evidence -- it only
reconciles a stale presentation label against evidence *already rendered
elsewhere on the same artifact*, the same convergence pattern already
shipped for severity in
cti_evidence_convergence_v7._repair_command_severity. It is a pure
presentation repair: if no real indicator section is present, the canonical
"Not established" text is left untouched, preserving this repo's fail-closed
anti-hallucination policy.

Installed last in the chain (after rapid_intel_lane_v19_3) so it observes
the fully-rendered artifact, including the real IOC section produced
earlier in the pipeline.
"""
from __future__ import annotations

import re
from typing import Optional

from bs4 import BeautifulSoup, Tag

MARKER = "CDB-CTI-IOC-STATE-RECONCILIATION"
_INSTALL_ATTR = "__cdb_cti_ioc_state_reconciliation__"
_ORIGINAL_ASSEMBLE_HTML = None

_CANONICAL_IOC_HEADING = "indicators & observables"
_NOT_ESTABLISHED_TOKENS = (
    "not established in cited evidence",
    "not established",
    "withheld_insufficient_evidence",
)
_INDICATOR_LABEL_RE = re.compile(
    r"\b(MD5|SHA-1|SHA-256|IPv4|Domain|URL|Email|CVE|Registry Key):", re.I
)
_RECONCILED_IOC_BODY = (
    "VERIFIED ARTIFACTS AVAILABLE. Indicators extracted directly from the "
    "sourced article are published below in the Indicators / Observables "
    "section (defanged for safe display)."
)


def _normalize(text: str) -> str:
    value = re.sub(r"\s+", " ", text or "").strip().lower()
    return value.replace("–", "-").replace("—", "-")


def _section_nodes(heading: Tag) -> list[Tag]:
    # Stops at the next h2/h3 heading *or* the next <section> boundary --
    # authority_transformer's real IOC block is a <section data-section=...>
    # with no h2/h3 of its own (its title lives in a <div>, the very defect
    # this module reconciles), so a heading-only stop condition would treat
    # it as part of the compiler's placeholder body and delete it.
    nodes: list[Tag] = []
    sibling = heading.next_sibling
    while sibling is not None:
        nxt = sibling.next_sibling
        if isinstance(sibling, Tag) and sibling.name in {"h2", "h3", "section"}:
            break
        if isinstance(sibling, Tag):
            nodes.append(sibling)
        sibling = nxt
    return nodes


def _canonical_ioc_heading(soup: BeautifulSoup) -> Optional[Tag]:
    for heading in soup.find_all(["h2", "h3"]):
        if _normalize(heading.get_text(" ", strip=True)) == _CANONICAL_IOC_HEADING:
            return heading
    return None


def _canonical_body_is_not_established(heading: Tag) -> bool:
    nodes = _section_nodes(heading)
    body = _normalize(" ".join(node.get_text(" ", strip=True) for node in nodes))
    return not body or any(token in body for token in _NOT_ESTABLISHED_TOKENS)


def _real_ioc_section_has_values(soup: BeautifulSoup) -> bool:
    # authority_transformer._render_iocs_html() only ever emits this
    # data-section when at least one defanged indicator was rendered as a
    # "<Label>: value" bullet -- an empty extraction returns "" and no
    # section is rendered at all, so a match here is real, not inferred.
    section = soup.select_one('section[data-section="indicators-/-observables"]')
    if section is None:
        return False
    return bool(_INDICATOR_LABEL_RE.search(section.get_text(" ", strip=True)))


def reconcile_ioc_state(rendered_html: str) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        heading = _canonical_ioc_heading(soup)
        if heading is None or not _canonical_body_is_not_established(heading):
            return rendered_html
        if not _real_ioc_section_has_values(soup):
            return rendered_html

        for node in _section_nodes(heading):
            node.decompose()
        paragraph = soup.new_tag("p")
        paragraph["data-cdb-ioc-state-reconciled"] = "true"
        paragraph.string = _RECONCILED_IOC_BODY
        heading.insert_after(paragraph)
        return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"
    except Exception:
        # Reconciliation is presentation-only and must never block or alter
        # publication of the underlying intelligence.
        return rendered_html


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url=None):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI IOC state reconciliation is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return reconcile_ioc_state(rendered)


setattr(_patched_assemble_html, _INSTALL_ATTR, True)


def install_cti_ioc_state_reconciliation(main_module) -> None:
    """Install last so the fully-rendered artifact -- including the real,
    populated Indicators / Observables section -- is visible to this layer."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer

    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return

    _ORIGINAL_ASSEMBLE_HTML = current
    transformer._assemble_html = _patched_assemble_html
