"""SENTINEL APEX CTI Dossier v7 runtime-safe evidence convergence.

This layer fixes the production installation collision discovered after v6 was
merged: both Dossier v5 and v6 used a wrapper named ``_patched_assemble_html``,
so v6's name-only idempotency check incorrectly concluded that it was already
installed and returned without wrapping the renderer.

v7 uses an explicit function marker instead of a function-name check, repairs
command-deck severity only from existing structured CVSS evidence, and removes
legacy canonical subsections nested inside Technical Analysis when the same
canonical section is rendered elsewhere by the deterministic ReportX layer.
Both numbered and unnumbered standalone subsection headings are supported.

The layer is presentation/evidence convergence only. It never creates threat
facts, ATT&CK mappings, IOCs, exploitation state, remediation state, TLP,
customer exposure, or compliance claims.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from bs4 import BeautifulSoup, Tag

MARKER = "CDB-CTI-EVIDENCE-CONVERGENCE-V7"
_INSTALL_ATTR = "__cdb_cti_evidence_convergence_v7__"
_ORIGINAL_ASSEMBLE_HTML = None

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

_NUMBERED = re.compile(r"^\s*\d{1,2}\s*[.)-]\s*(.+?)\s*$")
_CVSS_LABEL = re.compile(
    r"\bCVSS(?:\s+(?:Base\s+)?Score)?\s*[:\-]?\s*(10(?:\.0)?|[0-9](?:\.\d+)?)\b",
    re.I,
)


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
        if raw is None:
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if 0.0 <= value <= 10.0:
            return value

    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
    match = _CVSS_LABEL.search(text)
    if not match:
        return None
    try:
        value = float(match.group(1))
    except ValueError:
        return None
    return value if 0.0 <= value <= 10.0 else None


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
    if severity is None:
        return
    severity_node.string = severity

    command = soup.select_one(".cdbd-command")
    if command is not None:
        classes = [
            c for c in command.get("class", [])
            if not str(c).startswith("cdbd-sev-")
        ]
        classes.append(f"cdbd-sev-{severity.lower()}")
        command["class"] = classes


def _section_nodes(heading: Tag) -> list[Tag]:
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


def _standalone_subheading(block: Tag) -> Optional[str]:
    """Return a canonical semantic heading from a standalone nested block."""
    candidates: list[Tag] = []
    if block.name in {"h4", "h5", "h6", "strong", "b"}:
        candidates.append(block)
    first = block.find(["strong", "b", "h4", "h5", "h6"])
    if first is not None and first not in candidates:
        candidates.append(first)

    block_text = re.sub(r"\s+", " ", block.get_text(" ", strip=True)).strip()
    for candidate in candidates:
        text = re.sub(r"\s+", " ", candidate.get_text(" ", strip=True)).strip()
        if candidate is not block and block_text != text:
            continue
        numbered = _NUMBERED.match(text)
        semantic = _normalize(numbered.group(1) if numbered else text)
        if semantic == "technical analysis" or semantic in _CANONICAL:
            return semantic
    return None


def _canonical_top_level_sections(soup: BeautifulSoup, target: Tag) -> set[str]:
    result: set[str] = set()
    for heading in soup.find_all(["h2", "h3"]):
        if heading is target:
            continue
        semantic = _normalize(heading.get_text(" ", strip=True))
        if semantic in _CANONICAL:
            result.add(semantic)
    return result


def _collapse_legacy_technical_analysis(soup: BeautifulSoup) -> None:
    target: Optional[Tag] = None
    for heading in soup.find_all(["h2", "h3"]):
        if _normalize(heading.get_text(" ", strip=True)) == "technical analysis":
            target = heading
            break
    if target is None:
        return

    authoritative = _canonical_top_level_sections(soup, target)
    nodes = _section_nodes(target)
    starts: list[tuple[int, str]] = []
    for idx, node in enumerate(nodes):
        title = _standalone_subheading(node)
        if title:
            starts.append((idx, title))
    if not starts:
        return

    for pos, (start_idx, title) in enumerate(starts):
        end_idx = starts[pos + 1][0] if pos + 1 < len(starts) else len(nodes)
        segment = nodes[start_idx:end_idx]

        if title == "technical analysis":
            # The parent h2/h3 already carries this label; retain its unique body.
            if segment:
                segment[0].decompose()
            continue

        # Never delete a nested section unless an authoritative top-level
        # deterministic equivalent is actually present in this same artifact.
        if title in authoritative:
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
        # Presentation convergence must never stall fresh intelligence delivery.
        return rendered_html


def _patched_assemble_html(
    self,
    article,
    body_content: str,
    seo_data: dict,
    context,
    image_url=None,
):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI v7 evidence convergence layer is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(
        self, article, body_content, seo_data, context, image_url
    )
    return converge_cti_dossier(rendered, article)


setattr(_patched_assemble_html, _INSTALL_ATTR, True)


def install_cti_evidence_convergence_v7(main_module) -> None:
    """Install after v5/v6 using an explicit marker, never a name collision."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer

    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return

    _ORIGINAL_ASSEMBLE_HTML = current
    transformer._assemble_html = _patched_assemble_html
