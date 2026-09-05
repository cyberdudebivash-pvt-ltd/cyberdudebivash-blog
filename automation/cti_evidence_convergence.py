"""SENTINEL APEX CTI Dossier v6 evidence convergence layer.

Runs strictly after the v5 dossier renderer and before the final artifact hash.
It performs two evidence-preserving repairs observed in live production:
1) collapse legacy numbered analyst subsections nested inside the top-level
   Technical Analysis section when an authoritative canonical section exists
   elsewhere in the report; and
2) repair an UNSPECIFIED command-deck severity from structured CVSS evidence
   already present in the rendered report or normalized article object.

The layer never invents ATT&CK mappings, IOCs, exploitation state, TLP,
customer exposure, or compliance claims. It is fail-open so presentation
convergence can never block fresh CTI publication.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from bs4 import BeautifulSoup, Tag

MARKER = "CDB-CTI-EVIDENCE-CONVERGENCE-V6"
_ORIGINAL_ASSEMBLE_HTML = None

# Canonical sections already rendered elsewhere in the deterministic/ReportX
# report. If these reappear as legacy numbered subsections inside the long-form
# Technical Analysis block, the nested copies are redundant and may conflict.
_CANONICAL = {
    "executive summary",
    "key judgements",
    "verified facts",
    "threat classification",
    "threat severity assessment",
    "evidence & source assessment",
    "timeline & chronology",
    "business impact",
    "enterprise exposure assessment",
    "report-type deep dive",
    "mitre att&ck assessment",
    "indicators & observables",
    "detection engineering guidance",
    "detection validation & required telemetry",
    "threat hunting queries",
    "soc analyst playbook",
    "incident response & containment decision plan",
    "remediation & validation plan",
    "executive decision matrix",
    "executive recommendations",
    "intelligence gaps & collection requirements",
    "analytic confidence & limitations",
    "forecast & outlook",
    "references",
}

_ALIASES = {
    "forecast / outlook": "forecast & outlook",
    "forecast and outlook": "forecast & outlook",
    "mitre attack assessment": "mitre att&ck assessment",
    "mitre att ck assessment": "mitre att&ck assessment",
    "indicators / observables": "indicators & observables",
    "incident response and containment decision plan": "incident response & containment decision plan",
    "remediation and validation plan": "remediation & validation plan",
    "intelligence gaps and collection requirements": "intelligence gaps & collection requirements",
    "analytic confidence and limitations": "analytic confidence & limitations",
    "evidence and source assessment": "evidence & source assessment",
    "timeline and chronology": "timeline & chronology",
}

_NUMBERED = re.compile(r"^\s*(\d{1,2})\s*[.)-]\s*(.+?)\s*$")
_CVSS_LABEL = re.compile(r"\bCVSS(?:\s+Score)?\s*[:\-]?\s*(10(?:\.0)?|[0-9](?:\.\d+)?)\b", re.I)


def _normalize(text: str) -> str:
    value = re.sub(r"\s+", " ", text or "").strip().lower()
    value = value.replace("–", "-").replace("—", "-")
    value = re.sub(r"^[\s\d.():-]+", "", value).strip()
    return _ALIASES.get(value, value)


def _cvss_to_severity(value: float) -> Optional[str]:
    if not 0.0 <= value <= 10.0:
        return None
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    if value > 0.0:
        return "LOW"
    return None


def _structured_cvss(article: Any, soup: BeautifulSoup) -> Optional[float]:
    for attr in ("cvss_score", "cvss"):
        raw = getattr(article, attr, None)
        if raw is not None:
            try:
                value = float(raw)
            except (TypeError, ValueError):
                value = -1.0
            if 0.0 <= value <= 10.0:
                return value

    # Production v5 can receive a normalized article without cvss_score even
    # though the deterministic Executive Risk Command Center already rendered a
    # verified CVSS tile. Read that rendered structured evidence before falling
    # back to any prose. This is display convergence, not new threat inference.
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
    match = _CVSS_LABEL.search(text)
    if match:
        try:
            value = float(match.group(1))
        except ValueError:
            return None
        if 0.0 <= value <= 10.0:
            return value
    return None


def _repair_command_severity(soup: BeautifulSoup, article: Any) -> None:
    severity_node = soup.select_one(".cdbd-kpi-severity strong")
    if severity_node is None:
        return
    current = severity_node.get_text(" ", strip=True).upper()
    if current not in {"UNSPECIFIED", "NOT EXPOSED", "UNKNOWN", ""}:
        return
    score = _structured_cvss(article, soup)
    if score is None:
        return
    severity = _cvss_to_severity(score)
    if not severity:
        return
    severity_node.string = severity

    command = soup.select_one(".cdbd-command")
    if command is not None:
        classes = [c for c in command.get("class", []) if not str(c).startswith("cdbd-sev-")]
        classes.append(f"cdbd-sev-{severity.lower()}")
        command["class"] = classes


def _top_level_section_nodes(heading: Tag) -> list[Tag]:
    nodes: list[Tag] = []
    sibling = heading.next_sibling
    while sibling is not None:
        nxt = sibling.next_sibling
        if isinstance(sibling, Tag) and sibling.name in {"h2", "h3"}:
            break
        if isinstance(sibling, Tag):
            nodes.append(sibling)
        sibling = nxt
    return nodes


def _numbered_heading(block: Tag) -> Optional[str]:
    """Return the semantic title when a block is a numbered subsection label."""
    candidates: list[Tag] = []
    if block.name in {"h4", "h5", "h6", "strong", "b"}:
        candidates.append(block)
    first = block.find(["strong", "b", "h4", "h5", "h6"])
    if first is not None and first not in candidates:
        candidates.append(first)

    for candidate in candidates:
        text = re.sub(r"\s+", " ", candidate.get_text(" ", strip=True)).strip()
        match = _NUMBERED.match(text)
        if not match:
            continue
        # Only treat the containing block as a heading when the candidate is the
        # block itself or essentially the entire block. This avoids deleting a
        # normal paragraph that happens to contain a numbered bold phrase.
        block_text = re.sub(r"\s+", " ", block.get_text(" ", strip=True)).strip()
        if candidate is block or block_text == text:
            return _normalize(match.group(2))
    return None


def _collapse_legacy_technical_analysis(soup: BeautifulSoup) -> None:
    """Remove duplicated numbered analyst sections nested in Technical Analysis.

    The live report format places a 1..24 analyst report under one h3 named
    Technical Analysis, while deterministic ReportX sections exist before/after
    it. We preserve the nested 'Technical Analysis' body itself and any unique
    non-canonical subsection, but remove nested copies of canonical sections.
    """
    target: Optional[Tag] = None
    for heading in soup.find_all(["h2", "h3"]):
        if _normalize(heading.get_text(" ", strip=True)) == "technical analysis":
            target = heading
            break
    if target is None:
        return

    nodes = _top_level_section_nodes(target)
    starts: list[tuple[int, str]] = []
    for idx, node in enumerate(nodes):
        title = _numbered_heading(node)
        if title:
            starts.append((idx, title))
    if not starts:
        return

    for pos, (start_idx, title) in enumerate(starts):
        end_idx = starts[pos + 1][0] if pos + 1 < len(starts) else len(nodes)
        segment = nodes[start_idx:end_idx]
        if title == "technical analysis":
            # Keep the actual deep technical body but remove its redundant
            # numbered subheading under the already-visible top-level heading.
            if segment:
                segment[0].decompose()
            continue
        if title in _CANONICAL:
            for node in segment:
                node.decompose()


def converge_cti_dossier(rendered_html: str, article: Any = None) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        _repair_command_severity(soup, article)
        _collapse_legacy_technical_analysis(soup)
        return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"
    except Exception:
        # Fresh intelligence availability outranks presentation convergence.
        return rendered_html


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url=None):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI evidence convergence layer is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return converge_cti_dossier(rendered, article)


def install_cti_evidence_convergence(main_module) -> None:
    """Install after Dossier v5 so convergence is included in certified bytes."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    if getattr(transformer._assemble_html, "__name__", "") == "_patched_assemble_html":
        return
    _ORIGINAL_ASSEMBLE_HTML = transformer._assemble_html
    transformer._assemble_html = _patched_assemble_html
