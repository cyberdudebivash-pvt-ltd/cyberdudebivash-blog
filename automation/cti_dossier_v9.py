"""SENTINEL APEX CTI Dossier v9 — evidence-safe intelligence command layer.

Installs strictly after Dossier v8. v8 remains the fail-closed integrity layer
(prompt/reasoning leakage + duplicate canonical sections). v9 adds richer
enterprise SOC/CTI presentation derived only from already-rendered ReportX
content and ReportContext metadata.

This layer deliberately does NOT:
- assign TLP markings;
- claim SOC 2 compliance/certification;
- manufacture numeric confidence/risk scores;
- infer customer exposure or compromise;
- create IOCs, ATT&CK mappings, CVEs, exploit state, or vendor statements.
"""
from __future__ import annotations

import html as _html
import re
from typing import Any, Optional

from bs4 import BeautifulSoup, Tag

MARKER = "CDB-CTI-DOSSIER-V9"
_INSTALL_ATTR = "__cdb_cti_dossier_v9__"
_ORIGINAL_ASSEMBLE_HTML = None

_ALIASES = {
    "mitre attack assessment": "mitre att&ck assessment",
    "mitre att ck assessment": "mitre att&ck assessment",
    "indicators / observables": "indicators & observables",
    "evidence and source assessment": "evidence & source assessment",
    "timeline and chronology": "timeline & chronology",
    "analytic confidence and limitations": "analytic confidence & limitations",
    "intelligence gaps and collection requirements": "intelligence gaps & collection requirements",
}


def _normalize(text: str) -> str:
    value = re.sub(r"\s+", " ", text or "").strip().lower()
    value = value.replace("–", "-").replace("—", "-")
    value = re.sub(r"^[\s\d.():-]+", "", value).strip()
    return _ALIASES.get(value, value)


def _heading(soup: BeautifulSoup, semantic: str) -> Optional[Tag]:
    for heading in soup.find_all(["h2", "h3"]):
        if _normalize(heading.get_text(" ", strip=True)) == semantic:
            return heading
    return None


def _section_nodes(heading: Optional[Tag]) -> list[Tag]:
    if heading is None:
        return []
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


def _section_text(soup: BeautifulSoup, semantic: str) -> str:
    text = " ".join(node.get_text(" ", strip=True) for node in _section_nodes(_heading(soup, semantic)))
    return re.sub(r"\s+", " ", text).strip()


def _clip(text: str, limit: int = 280) -> str:
    clean = re.sub(r"\s+", " ", text or "").strip()
    if len(clean) <= limit:
        return clean
    cut = clean[: limit + 1].rsplit(" ", 1)[0].rstrip(" ,;:")
    return cut + "…"


def _safe(value: Any, fallback: str = "NOT ESTABLISHED") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _kpi_value(soup: BeautifulSoup, label: str, fallback: str = "NOT ESTABLISHED") -> str:
    wanted = label.upper()
    for card in soup.select(".cdbd-kpi"):
        name = card.find("span")
        value = card.find("strong")
        if name and value and name.get_text(" ", strip=True).upper() == wanted:
            return _safe(value.get_text(" ", strip=True), fallback)
    return fallback


def _semantic_state(soup: BeautifulSoup, semantic: str, present: str = "PRESENT") -> str:
    text = _section_text(soup, semantic)
    if not text:
        return "NOT PRESENT"
    low = text.lower()
    if any(token in low for token in (
        "not established in cited evidence",
        "not established",
        "withheld_insufficient_evidence",
        "insufficient evidence",
    )):
        return "NOT ESTABLISHED"
    return present


def _corroboration_state(soup: BeautifulSoup) -> str:
    text = _section_text(soup, "evidence & source assessment").lower()
    if not text:
        return "NOT ASSESSED"
    if any(token in text for token in ("independent second source", "not been found", "single identified source", "no independent")):
        return "NOT ESTABLISHED"
    if any(token in text for token in ("independently corroborated", "multiple independent", "corroborated by")):
        return "CORROBORATED"
    return "SOURCE ASSESSED"


def _confidence_matrix_html(soup: BeautifulSoup) -> str:
    confidence = _kpi_value(soup, "CONFIDENCE", "UNSPECIFIED")
    source = _kpi_value(soup, "SOURCE", "SOURCE LINKED")
    dimensions = (
        ("ANALYTIC CONFIDENCE", confidence),
        ("SOURCE BASIS", source),
        ("CORROBORATION", _corroboration_state(soup)),
        ("TECHNICAL SPECIFICITY", _semantic_state(soup, "technical analysis", "EVIDENCE PRESENT")),
        ("OBSERVABLE COVERAGE", _semantic_state(soup, "indicators & observables", "EVIDENCE PRESENT")),
        ("INTERNAL OBSERVABILITY", "REQUIRES CUSTOMER TELEMETRY"),
    )
    cells = "".join(
        f'<div class="cdbv9-state"><span>{_html.escape(label)}</span><strong>{_html.escape(state)}</strong></div>'
        for label, state in dimensions
    )
    return f"""
<section class="cdbv9-panel" aria-label="Intelligence confidence and evidence matrix">
  <div class="cdbv9-head"><span>INTELLIGENCE CONFIDENCE // EVIDENCE MATRIX</span><b>NON-PROBABILISTIC</b></div>
  <div class="cdbv9-state-grid">{cells}</div>
  <p class="cdbv9-note">States reflect the rendered evidence product. They are not statistical probabilities and do not establish customer-specific exposure.</p>
</section>"""


def _decision_state_html(soup: BeautifulSoup, context: Any) -> str:
    exploitation = _safe(getattr(context, "exploitation_label", None))
    remediation = _safe(getattr(context, "patch_label", None))
    attck = _semantic_state(soup, "mitre att&ck assessment", "SUPPORTED CONTENT PRESENT")
    iocs = _semantic_state(soup, "indicators & observables", "SUPPORTED CONTENT PRESENT")
    detection = _semantic_state(soup, "detection engineering guidance", "GUIDANCE PRESENT")
    exposure = "REQUIRES INTERNAL VALIDATION"
    compromise = "NOT ESTABLISHED BY PUBLIC INTELLIGENCE"
    cells = (
        ("EXPLOITATION", exploitation),
        ("REMEDIATION", remediation),
        ("ATT&CK", attck),
        ("OBSERVABLES", iocs),
        ("DETECTION", detection),
        ("CUSTOMER EXPOSURE", exposure),
        ("CUSTOMER COMPROMISE", compromise),
        ("ESCALATION", "TELEMETRY-CONDITIONED"),
    )
    html = "".join(
        f'<div class="cdbv9-decision"><span>{_html.escape(label)}</span><strong>{_html.escape(state)}</strong></div>'
        for label, state in cells
    )
    return f"""
<section class="cdbv9-panel cdbv9-decision-panel" aria-label="Enterprise exposure decision engine">
  <div class="cdbv9-head"><span>ENTERPRISE EXPOSURE DECISION ENGINE</span><b>ZERO-ASSUMPTION</b></div>
  <div class="cdbv9-decision-grid">{html}</div>
  <div class="cdbv9-escalation"><span>INTELLIGENCE</span><i></i><span>EXPOSURE VALIDATED</span><i></i><span>SUSPICIOUS ACTIVITY</span><i></i><span>CONFIRMED INCIDENT</span></div>
</section>"""


def _attack_surface_html(context: Any) -> str:
    family = _safe(getattr(context, "family", None), "general_intelligence")
    if family == "ai_security":
        stages = ("EXTERNAL / MACHINE-READABLE INPUT", "AI / AGENT TRUST BOUNDARY", "TOOL / PACKAGE / SHELL ACTION", "ENTERPRISE TELEMETRY", "SOC DECISION")
    elif family in {"cve_advisory", "cisa_kev", "cisa_advisory"}:
        stages = ("PUBLIC VULNERABILITY EVIDENCE", "ASSET / VERSION VALIDATION", "REACHABLE ATTACK SURFACE", "SECURITY TELEMETRY", "REMEDIATION DECISION")
    elif family in {"ransomware_claim", "ransomware_reporting"}:
        stages = ("PUBLIC / ACTOR CLAIM", "INDEPENDENT CORROBORATION", "INTERNAL EXPOSURE CHECK", "INCIDENT TELEMETRY", "IR DECISION")
    else:
        stages = ("SOURCE SIGNAL", "EVIDENCE VALIDATION", "ENTERPRISE RELEVANCE", "SECURITY TELEMETRY", "SOC DECISION")
    flow = []
    for idx, stage in enumerate(stages, start=1):
        flow.append(f'<span><b>{idx:02d}</b>{_html.escape(stage)}</span>')
        if idx != len(stages):
            flow.append('<i aria-hidden="true"></i>')
    return f"""
<section class="cdbv9-panel" aria-label="Analytical attack surface control path">
  <div class="cdbv9-head"><span>ATTACK SURFACE // CONTROL PATH</span><b>ANALYTICAL MODEL</b></div>
  <div class="cdbv9-flow">{''.join(flow)}</div>
  <p class="cdbv9-note">This control path organizes validation and telemetry decisions. It is not a claim that every stage occurred in the reported event.</p>
</section>"""


def _timeline_html(soup: BeautifulSoup) -> str:
    text = _section_text(soup, "timeline & chronology")
    if not text:
        return ""
    events = [part.strip() for part in re.split(r"(?<=[.!?])\s+", text) if len(part.strip().split()) >= 5][:6]
    if not events:
        events = [_clip(text, 500)]
    items = "".join(
        f'<article><b>{idx:02d}</b><p>{_html.escape(_clip(event, 260))}</p></article>'
        for idx, event in enumerate(events, start=1)
    )
    return f"""
<section class="cdbv9-panel" aria-label="Source-linked chronology">
  <div class="cdbv9-head"><span>INTELLIGENCE TIMELINE // CHRONOLOGY</span><b>SOURCE-LINKED</b></div>
  <div class="cdbv9-timeline">{items}</div>
</section>"""


def _framework_ribbon_html() -> str:
    stages = ("GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER")
    return """
<section class="cdbv9-framework" aria-label="Cybersecurity risk management lifecycle">
  <span class="cdbv9-framework-label">SOC / IR DECISION LIFECYCLE</span>
  <div>%s</div>
  <small>Framework-oriented navigation only; not a compliance or attestation statement.</small>
</section>""" % "".join(f"<b>{stage}</b>" for stage in stages)


def _quality_html(soup: BeautifulSoup) -> str:
    controls = (
        ("PROMPT / REASONING LEAKAGE", "BLOCKED BY V8"),
        ("DUPLICATE CANONICAL SECTIONS", "BLOCKED BY V8"),
        ("SOURCE / PROVENANCE", "RETAINED" if _heading(soup, "references") else "CHECK SOURCE RECORD"),
        ("ATT&CK STATE", _semantic_state(soup, "mitre att&ck assessment", "EVIDENCE-CONDITIONED")),
        ("IOC STATE", _semantic_state(soup, "indicators & observables", "EVIDENCE-CONDITIONED")),
        ("EXPOSURE CLAIM", "INTERNAL TELEMETRY REQUIRED"),
    )
    cells = "".join(
        f'<span><i></i>{_html.escape(label)}<b>{_html.escape(state)}</b></span>'
        for label, state in controls
    )
    return f'<section class="cdbv9-quality" aria-label="Publication and analytical quality controls">{cells}</section>'


def _styles() -> str:
    return r"""<style id="cdb-cti-dossier-v9-css">
.cdbv9-panel{margin:16px 0;padding:17px;border:1px solid rgba(55,225,255,.23);border-radius:15px;background:linear-gradient(145deg,rgba(7,22,37,.94),rgba(4,10,18,.96));box-shadow:0 20px 58px rgba(0,0,0,.24);position:relative;overflow:hidden}.cdbv9-panel:before{content:"";position:absolute;inset:0 auto auto 0;width:72px;height:1px;background:linear-gradient(90deg,var(--cyan),transparent);box-shadow:0 0 22px rgba(41,217,255,.7)}.cdbv9-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;color:var(--cyan);font:900 9px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.13em}.cdbv9-head b{padding:5px 8px;border:1px solid rgba(162,109,255,.25);border-radius:999px;background:rgba(162,109,255,.07);color:#d8c6ff!important;font-size:8px}.cdbv9-state-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.cdbv9-state,.cdbv9-decision{padding:12px;border:1px solid rgba(142,166,189,.13);border-radius:10px;background:rgba(0,0,0,.2)}.cdbv9-state span,.cdbv9-decision span{display:block;margin-bottom:7px;color:var(--muted);font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.09em}.cdbv9-state strong,.cdbv9-decision strong{display:block;color:#fff!important;font-size:10px;line-height:1.4;overflow-wrap:anywhere}.cdbv9-note{margin:11px 0 0!important;padding:9px 10px;border-left:2px solid rgba(41,217,255,.42);background:rgba(41,217,255,.035);color:var(--muted)!important;font-size:10.5px!important;line-height:1.55!important}.cdbv9-decision-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.cdbv9-escalation,.cdbv9-flow{display:grid;grid-template-columns:auto 1fr auto 1fr auto 1fr auto;align-items:center;gap:8px;margin-top:13px;overflow:auto}.cdbv9-escalation span,.cdbv9-flow span{display:flex;align-items:center;gap:7px;white-space:nowrap;padding:9px 10px;border:1px solid rgba(142,166,189,.14);border-radius:9px;background:rgba(0,0,0,.22);color:#d9e8f5;font:850 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.07em}.cdbv9-escalation i,.cdbv9-flow i{height:1px;min-width:24px;background:linear-gradient(90deg,rgba(41,217,255,.12),var(--cyan),rgba(41,217,255,.12));position:relative;overflow:hidden}.cdbv9-escalation i:after,.cdbv9-flow i:after{content:"";position:absolute;width:35%;inset:0 auto 0 -35%;background:#fff;opacity:.62;animation:cdbv9-flow 3.1s linear infinite}.cdbv9-flow{grid-template-columns:auto 1fr auto 1fr auto 1fr auto 1fr auto}.cdbv9-flow span b{display:grid;place-items:center;width:22px;height:22px;border:1px solid rgba(41,217,255,.32);border-radius:50%;color:var(--cyan)!important}.cdbv9-timeline{display:grid;gap:9px;border-left:1px solid rgba(41,217,255,.25);margin-left:10px;padding-left:16px}.cdbv9-timeline article{position:relative;padding:11px 12px;border:1px solid rgba(142,166,189,.13);border-radius:10px;background:rgba(0,0,0,.19)}.cdbv9-timeline article:before{content:"";position:absolute;left:-21px;top:16px;width:8px;height:8px;border-radius:50%;background:var(--cyan);box-shadow:0 0 15px rgba(41,217,255,.7)}.cdbv9-timeline b{color:var(--cyan)!important;font:900 8px/1 ui-monospace,SFMono-Regular,Consolas,monospace}.cdbv9-timeline p{margin:5px 0 0!important;color:#d9e8f5!important;font-size:11px!important;line-height:1.55!important}.cdbv9-framework{margin:14px 0;padding:13px 15px;border:1px solid rgba(61,226,146,.18);border-radius:12px;background:rgba(61,226,146,.035)}.cdbv9-framework-label{display:block;margin-bottom:9px;color:var(--green);font:900 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.11em}.cdbv9-framework>div{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px}.cdbv9-framework b{padding:8px;text-align:center;border:1px solid rgba(61,226,146,.16);border-radius:8px;background:rgba(0,0,0,.15);color:#dcfff0!important;font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.05em}.cdbv9-framework small{display:block;margin-top:8px;color:var(--muted);font-size:9px}.cdbv9-quality{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin:13px 0 18px}.cdbv9-quality>span{display:flex;align-items:center;gap:7px;padding:9px 10px;border:1px solid rgba(61,226,146,.15);border-radius:9px;background:rgba(61,226,146,.03);color:var(--muted);font:800 8px/1.25 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.05em}.cdbv9-quality i{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 10px rgba(61,226,146,.6)}.cdbv9-quality b{margin-left:auto;color:var(--green)!important;font-size:8px;text-align:right}@keyframes cdbv9-flow{0%{left:-35%}100%{left:140%}}@media(max-width:980px){.cdbv9-state-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv9-decision-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv9-quality{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv9-framework>div{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:680px){.cdbv9-state-grid,.cdbv9-decision-grid,.cdbv9-quality{grid-template-columns:1fr}.cdbv9-framework>div{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv9-panel{padding:12px}.cdbv9-flow{grid-template-columns:auto 24px auto 24px auto 24px auto 24px auto}.cdbv9-escalation{grid-template-columns:auto 24px auto 24px auto 24px auto}}@media(prefers-reduced-motion:reduce){.cdbv9-escalation i:after,.cdbv9-flow i:after{animation:none!important}}@media print{.cdbv9-panel,.cdbv9-framework,.cdbv9-quality{box-shadow:none!important;background:#fff!important;color:#111!important;break-inside:avoid}.cdbv9-state strong,.cdbv9-decision strong,.cdbv9-timeline p{color:#111!important}}
</style>"""


def _inject_after(target: Tag, fragment: str) -> None:
    parsed = BeautifulSoup(fragment, "html.parser")
    for node in reversed(list(parsed.contents)):
        target.insert_after(node)


def enhance_cti_dossier_v9(rendered_html: str, article: Any = None, context: Any = None) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        command = soup.select_one(".cdbd-command")
        if command is not None:
            modules = (
                _quality_html(soup)
                + _confidence_matrix_html(soup)
                + _decision_state_html(soup, context)
                + _attack_surface_html(context)
                + _timeline_html(soup)
                + _framework_ribbon_html()
            )
            _inject_after(command, modules)
        soup.insert(0, BeautifulSoup(_styles(), "html.parser"))
        return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"
    except Exception:
        # v8 is the fail-closed integrity layer. v9 is presentation-only and
        # therefore remains fail-open so visual enrichment cannot stop publishing.
        return rendered_html


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url: Optional[str] = None):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI dossier v9 layer is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return enhance_cti_dossier_v9(rendered, article, context)


setattr(_patched_assemble_html, _INSTALL_ATTR, True)


def install_cti_dossier_v9(main_module) -> None:
    """Install after v8 so v8 integrity gates remain authoritative."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return
    _ORIGINAL_ASSEMBLE_HTML = current
    transformer._assemble_html = _patched_assemble_html
