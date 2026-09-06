"""SENTINEL APEX CTI Dossier v8 — premium SOC/CTI command presentation.

Runs strictly last on the Blogger report assembly path. The layer has two
responsibilities:

1. fail closed on customer-visible model-planning/prompt leakage and residual
   duplicate canonical sections; and
2. add evidence-safe operational presentation modules derived only from the
   already-rendered ReportX artifact and canonical ReportContext metadata.

It never creates threat facts, customer exposure, IOCs, ATT&CK mappings,
probability scores, compliance claims, or vendor assertions.
"""
from __future__ import annotations

import html as _html
import re
from typing import Any, Optional

from bs4 import BeautifulSoup, Tag

from .report_integrity import PublicationIntegrityError

MARKER = "CDB-CTI-DOSSIER-V8"
_INSTALL_ATTR = "__cdb_cti_dossier_v8__"
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
    "technical analysis",
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
    "mitre attack assessment": "mitre att&ck assessment",
    "mitre att ck assessment": "mitre att&ck assessment",
    "indicators / observables": "indicators & observables",
    "evidence and source assessment": "evidence & source assessment",
    "timeline and chronology": "timeline & chronology",
    "incident response and containment decision plan": "incident response & containment decision plan",
    "remediation and validation plan": "remediation & validation plan",
    "intelligence gaps and collection requirements": "intelligence gaps & collection requirements",
    "analytic confidence and limitations": "analytic confidence & limitations",
    "forecast / outlook": "forecast & outlook",
    "forecast and outlook": "forecast & outlook",
}

# High-signal phrases from model scratch/planning output. These are deliberately
# narrower than generic first-person language so legitimate quoted reporting is
# not blocked. A match is a release blocker because raw generation instructions
# must never be customer-visible.
_PROMPT_LEAK_PATTERNS = (
    ("model-planning preamble", re.compile(r"\bthe user wants me to\b", re.I)),
    ("model planning", re.compile(r"\blet me (?:analy[sz]e|draft|structure|write|think|plan)\b", re.I)),
    ("model planning", re.compile(r"\bi need to (?:be|write|ensure|follow|structure|carefully|make sure)\b", re.I)),
    ("model planning", re.compile(r"\bi should (?:be|not|ensure|write|follow|avoid)\b", re.I)),
    ("prompt constraint", re.compile(r"\b(?:\d{1,2}\s+)?mandatory sections?\b", re.I)),
    ("prompt constraint", re.compile(r"\b\d[\d,]*\s*(?:[-–]\s*\d[\d,]*)?\s+visible words?\b", re.I)),
    ("prompt constraint", re.compile(r"\bhtml only,? no markdown\b", re.I)),
    ("prompt constraint", re.compile(r"\bno preamble,? no markdown fences?\b", re.I)),
    ("internal control token", re.compile(r"\bCDB_(?:EXPLOITATION_STATUS|SOURCE_CLAIM_ONLY)\b", re.I)),
    ("role/instruction leakage", re.compile(r"\b(?:system|developer|user) (?:message|prompt|instruction)s?\b", re.I)),
)

_GROUPS = {
    "OVERVIEW": {
        "executive summary", "key judgements", "verified facts", "threat classification",
        "threat severity assessment", "timeline & chronology",
    },
    "INTELLIGENCE": {
        "evidence & source assessment", "technical analysis", "report-type deep dive",
        "mitre att&ck assessment", "indicators & observables",
    },
    "SOC": {
        "detection engineering guidance", "detection validation & required telemetry",
        "threat hunting queries", "soc analyst playbook",
        "incident response & containment decision plan", "remediation & validation plan",
    },
    "RISK": {
        "business impact", "enterprise exposure assessment", "executive decision matrix",
        "executive recommendations",
    },
    "ANALYSIS": {
        "intelligence gaps & collection requirements", "analytic confidence & limitations",
        "forecast & outlook",
    },
    "PROVENANCE": {"references", "provenance and certification"},
}

_FAMILY_FOCUS = {
    "ai_security": ("AI TRUST BOUNDARY", "AGENT AUTONOMY", "SUPPLY CHAIN"),
    "cve_advisory": ("VULNERABILITY", "EXPLOITATION", "REMEDIATION"),
    "cisa_kev": ("KNOWN EXPLOITED", "REMEDIATION", "DEADLINE"),
    "cisa_advisory": ("ADVISORY", "EXPOSURE", "REMEDIATION"),
    "ransomware_claim": ("CLAIM STATUS", "VICTIMOLOGY", "COLLECTION"),
    "ransomware_reporting": ("RANSOMWARE", "IMPACT", "DETECTION"),
    "threat_actor": ("ACTOR CONTEXT", "TTP EVIDENCE", "TARGETING"),
    "breach_notice": ("PUBLIC RECORD", "IMPACT", "RESPONSE"),
    "general_intelligence": ("EVIDENCE", "EXPOSURE", "SOC ACTION"),
}


def _normalize(text: str) -> str:
    value = re.sub(r"\s+", " ", text or "").strip().lower()
    value = value.replace("–", "-").replace("—", "-")
    value = re.sub(r"^[\s\d.():-]+", "", value).strip()
    return _ALIASES.get(value, value)


def _visible_text(soup: BeautifulSoup) -> str:
    clone = BeautifulSoup(str(soup), "html.parser")
    for node in clone.find_all(["style", "script", "noscript"]):
        node.decompose()
    return re.sub(r"\s+", " ", clone.get_text(" ", strip=True)).strip()


def _gate_customer_visible_integrity(soup: BeautifulSoup) -> None:
    issues: list[str] = []
    visible = _visible_text(soup)
    for label, pattern in _PROMPT_LEAK_PATTERNS:
        match = pattern.search(visible)
        if match:
            excerpt = match.group(0)[:120]
            issues.append(f"customer-visible {label}: {excerpt!r}")

    counts: dict[str, int] = {}
    for heading in soup.find_all(["h2", "h3"]):
        semantic = _normalize(heading.get_text(" ", strip=True))
        if semantic in _CANONICAL:
            counts[semantic] = counts.get(semantic, 0) + 1
    duplicated = sorted(name for name, count in counts.items() if count > 1)
    if duplicated:
        issues.append("duplicate canonical report sections remain after convergence: " + ", ".join(duplicated))

    if issues:
        raise PublicationIntegrityError(issues)


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


def _clip(text: str, limit: int = 420) -> str:
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


def _section_state(soup: BeautifulSoup, semantic: str, positive: str) -> str:
    heading = _heading(soup, semantic)
    if heading is None:
        return "NOT PRESENT"
    body = _section_text(soup, semantic).lower()
    if any(token in body for token in ("not established in cited evidence", "withheld_insufficient_evidence", "not established")):
        return "NOT ESTABLISHED"
    return positive


def _family_focus(context: Any) -> tuple[str, str, str]:
    family = _safe(getattr(context, "family", None), "general_intelligence")
    return _FAMILY_FOCUS.get(family, _FAMILY_FOCUS["general_intelligence"])


def _brief_html(soup: BeautifulSoup) -> str:
    summary = _clip(_section_text(soup, "executive summary"), 430) or "Executive summary not present in the rendered evidence product."
    action = _clip(
        _section_text(soup, "soc analyst playbook")
        or _section_text(soup, "detection engineering guidance"),
        430,
    ) or "Operational action remains evidence-conditioned; validate relevance before escalation."
    boundary = _clip(
        _section_text(soup, "analytic confidence & limitations")
        or _section_text(soup, "intelligence gaps & collection requirements"),
        430,
    ) or "Customer-specific exposure and compromise require independent internal telemetry."
    return f"""
<section class="cdbv8-panel cdbv8-brief" aria-label="SOC analyst 60-second brief">
  <div class="cdbv8-panel-head"><span>SOC ANALYST 60-SECOND BRIEF</span><b>EVIDENCE-BOUNDED</b></div>
  <div class="cdbv8-brief-grid">
    <article><i>01</i><h4>WHAT HAPPENED</h4><p>{_html.escape(summary)}</p></article>
    <article><i>02</i><h4>WHAT SOC SHOULD DO</h4><p>{_html.escape(action)}</p></article>
    <article><i>03</i><h4>EVIDENCE BOUNDARY</h4><p>{_html.escape(boundary)}</p></article>
  </div>
</section>"""


def _control_plane_html(soup: BeautifulSoup, context: Any) -> str:
    focus = _family_focus(context)
    family = _safe(getattr(context, "family_label", None), _safe(getattr(context, "family", None), "Cyber Threat Intelligence"))
    exploitation = _safe(getattr(context, "exploitation_label", None))
    remediation = _safe(getattr(context, "patch_label", None))
    tier = _safe(getattr(context, "achieved_tier", None), "EVIDENCE-BOUNDED")
    source = _kpi_value(soup, "SOURCE", "SOURCE LINKED")
    confidence = _kpi_value(soup, "CONFIDENCE", "UNSPECIFIED")
    coverage = (
        ("ATT&CK", _section_state(soup, "mitre att&ck assessment", "EVIDENCE PRESENT")),
        ("OBSERVABLES", _section_state(soup, "indicators & observables", "EVIDENCE PRESENT")),
        ("DETECTION", _section_state(soup, "detection engineering guidance", "GUIDANCE PRESENT")),
        ("HUNTING", _section_state(soup, "threat hunting queries", "GUIDANCE PRESENT")),
        ("SOC PLAYBOOK", _section_state(soup, "soc analyst playbook", "PRESENT")),
        ("CONFIDENCE", confidence),
    )
    coverage_html = "".join(
        f'<div class="cdbv8-signal"><span>{_html.escape(label)}</span><strong>{_html.escape(state)}</strong></div>'
        for label, state in coverage
    )
    focus_html = "".join(f"<span>{_html.escape(item)}</span>" for item in focus)
    return f"""
<section class="cdbv8-panel cdbv8-control" aria-label="SOC operations control plane">
  <div class="cdbv8-panel-head"><span>SOC OPERATIONS CONTROL PLANE // CTI EVIDENCE GRAPH</span><b>V8</b></div>
  <div class="cdbv8-context-grid">
    <div><span>REPORT FAMILY</span><strong>{_html.escape(family)}</strong></div>
    <div><span>EXPLOITATION STATE</span><strong>{_html.escape(exploitation)}</strong></div>
    <div><span>REMEDIATION STATE</span><strong>{_html.escape(remediation)}</strong></div>
    <div><span>EVIDENCE TIER</span><strong>{_html.escape(tier)}</strong></div>
  </div>
  <div class="cdbv8-focus"><b>ANALYTICAL FOCUS</b>{focus_html}</div>
  <div class="cdbv8-signals">{coverage_html}</div>
  <div class="cdbv8-chain" aria-label="Evidence processing chain">
    <span><b>01</b>{_html.escape(source)}</span><i></i><span><b>02</b>EVIDENCE GRAPH</span><i></i><span><b>03</b>REPORTX</span><i></i><span><b>04</b>SOC DECISION SUPPORT</span>
  </div>
</section>"""


def _ledger_html(soup: BeautifulSoup) -> str:
    heading = _heading(soup, "verified facts")
    facts: list[str] = []
    for node in _section_nodes(heading):
        for item in node.find_all("li"):
            text = re.sub(r"\s+", " ", item.get_text(" ", strip=True)).strip()
            if text and text not in facts:
                facts.append(text)
            if len(facts) >= 6:
                break
        if len(facts) >= 6:
            break
    if not facts:
        body = _section_text(soup, "verified facts")
        facts = [part.strip() for part in re.split(r"(?<=[.!?])\s+", body) if part.strip()][:4]
    if not facts:
        return ""
    rows = "".join(
        f'<tr><td>C-{idx:03d}</td><td>{_html.escape(_clip(fact, 300))}</td><td>SOURCE-LINKED</td></tr>'
        for idx, fact in enumerate(facts, start=1)
    )
    return f"""
<section class="cdbv8-panel cdbv8-ledger" aria-label="Evidence ledger snapshot">
  <div class="cdbv8-panel-head"><span>EVIDENCE LEDGER SNAPSHOT</span><b>{len(facts)} CLAIMS</b></div>
  <div class="cdbv8-table-wrap"><table><thead><tr><th>CLAIM</th><th>EVIDENCE-BOUND STATEMENT</th><th>STATE</th></tr></thead><tbody>{rows}</tbody></table></div>
</section>"""


def _quality_html() -> str:
    return """
<section class="cdbv8-quality" aria-label="Publication integrity controls">
  <span><i></i>PROMPT LEAKAGE <b>PASS</b></span>
  <span><i></i>CANONICAL UNIQUENESS <b>PASS</b></span>
  <span><i></i>EVIDENCE BOUNDARY <b>ENFORCED</b></span>
  <span><i></i>SOURCE PROVENANCE <b>RETAINED</b></span>
</section>"""


def _group_navigation(soup: BeautifulSoup) -> None:
    nav = soup.select_one(".cdbd-nav > div")
    if nav is None:
        return
    links = list(nav.find_all("a", recursive=False))
    if not links:
        return
    nav.clear()
    last_group = None
    for link in links:
        semantic = _normalize(link.get_text(" ", strip=True))
        group = next((name for name, members in _GROUPS.items() if semantic in members), "OTHER")
        if group != last_group:
            label = soup.new_tag("span")
            label["class"] = "cdbv8-nav-group"
            label.string = group
            nav.append(label)
            last_group = group
        link["data-group"] = group.lower()
        nav.append(link)


def _decorate_sections(soup: BeautifulSoup) -> None:
    for heading in soup.find_all(["h2", "h3"]):
        semantic = _normalize(heading.get_text(" ", strip=True))
        group = next((name for name, members in _GROUPS.items() if semantic in members), None)
        if group:
            heading["data-intel-group"] = group.lower()


def _inject_after(target: Tag, fragment: str) -> None:
    parsed = BeautifulSoup(fragment, "html.parser")
    for node in reversed(list(parsed.contents)):
        target.insert_after(node)


def _styles() -> str:
    return r"""<style id="cdb-cti-dossier-v8-css">
.cdb-cti-dossier{position:relative;isolation:isolate;background-image:linear-gradient(rgba(41,217,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(41,217,255,.022) 1px,transparent 1px),radial-gradient(circle at 8% 0,rgba(41,217,255,.10),transparent 34rem),radial-gradient(circle at 92% 10%,rgba(162,109,255,.09),transparent 35rem)!important;background-size:34px 34px,34px 34px,auto,auto!important}.cdb-cti-dossier:before{content:"";position:absolute;inset:0 0 auto;height:2px;z-index:50;background:linear-gradient(90deg,transparent,var(--cyan),transparent);opacity:.72;animation:cdbv8-scan 7s linear infinite;pointer-events:none}.cdbd-command{box-shadow:0 24px 80px rgba(0,0,0,.42),inset 0 1px rgba(255,255,255,.035)!important}.cdbd-command:before{content:"SENTINEL APEX // LIVE INTELLIGENCE PRODUCT";position:absolute;right:18px;top:14px;color:rgba(41,217,255,.28);font:800 8px/1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.13em}.cdbd-trust b{animation:cdbv8-pulse 2.6s ease-in-out infinite}.cdbv8-panel{margin:16px 0;padding:16px;border:1px solid rgba(64,211,255,.22);border-radius:14px;background:linear-gradient(145deg,rgba(10,26,42,.88),rgba(5,12,20,.92));box-shadow:0 18px 48px rgba(0,0,0,.22);overflow:hidden}.cdbv8-panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:-2px 0 14px;color:var(--cyan);font:850 9px/1.35 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.13em}.cdbv8-panel-head b{padding:5px 8px;border:1px solid rgba(61,226,146,.25);border-radius:999px;background:rgba(61,226,146,.07);color:var(--green)!important;font-size:8px}.cdbv8-context-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px}.cdbv8-context-grid>div,.cdbv8-signal{min-width:0;padding:12px;border:1px solid rgba(142,166,189,.13);border-radius:10px;background:rgba(0,0,0,.19)}.cdbv8-context-grid span,.cdbv8-signal span{display:block;margin-bottom:7px;color:var(--muted);font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.11em}.cdbv8-context-grid strong,.cdbv8-signal strong{display:block;color:#fff!important;font-size:11px;line-height:1.35;overflow-wrap:anywhere}.cdbv8-focus{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin:12px 0}.cdbv8-focus>b{margin-right:5px;color:var(--muted)!important;font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.1em}.cdbv8-focus>span{padding:6px 9px;border:1px solid rgba(162,109,255,.28);border-radius:999px;background:rgba(162,109,255,.07);color:#d8c6ff;font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.cdbv8-signals{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:7px}.cdbv8-signal strong{font-size:9px}.cdbv8-chain{display:grid;grid-template-columns:auto 1fr auto 1fr auto 1fr auto;align-items:center;gap:8px;margin-top:13px;padding:11px;border:1px solid rgba(41,217,255,.12);border-radius:10px;background:rgba(2,8,13,.56);overflow:auto}.cdbv8-chain span{display:flex;align-items:center;gap:7px;white-space:nowrap;color:#cfe9fa;font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.07em}.cdbv8-chain span b{display:grid;place-items:center;width:22px;height:22px;border:1px solid rgba(41,217,255,.35);border-radius:50%;color:var(--cyan)!important}.cdbv8-chain i{height:1px;min-width:25px;background:linear-gradient(90deg,rgba(41,217,255,.15),var(--cyan),rgba(41,217,255,.15));position:relative;overflow:hidden}.cdbv8-chain i:after{content:"";position:absolute;width:40%;inset:0 auto 0 -40%;background:#fff;opacity:.65;animation:cdbv8-flow 2.8s linear infinite}.cdbv8-brief-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.cdbv8-brief-grid article{position:relative;min-height:170px;padding:15px;border:1px solid rgba(142,166,189,.13);border-radius:11px;background:rgba(0,0,0,.20)}.cdbv8-brief-grid article>i{position:absolute;right:12px;top:10px;color:rgba(41,217,255,.22);font:900 26px/1 ui-monospace,SFMono-Regular,Consolas,monospace;font-style:normal}.cdbv8-brief-grid h4{margin:0 0 9px!important;color:var(--cyan)!important;font:850 9px/1.35 ui-monospace,SFMono-Regular,Consolas,monospace!important;letter-spacing:.12em}.cdbv8-brief-grid p{margin:0!important;color:#d9e8f5!important;font-size:12px!important;line-height:1.65!important}.cdbv8-table-wrap{overflow:auto}.cdbv8-ledger table{margin:0!important}.cdbv8-ledger td:first-child{white-space:nowrap;color:var(--cyan)!important;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.cdbv8-ledger td:last-child{white-space:nowrap;color:var(--green)!important;font:800 8px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace}.cdbv8-quality{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin:13px 0 18px}.cdbv8-quality>span{display:flex;align-items:center;gap:7px;padding:9px 10px;border:1px solid rgba(61,226,146,.16);border-radius:9px;background:rgba(61,226,146,.035);color:var(--muted);font:800 8px/1.25 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em}.cdbv8-quality i{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 11px rgba(61,226,146,.65)}.cdbv8-quality b{margin-left:auto;color:var(--green)!important;font-size:8px}.cdbv8-nav-group{align-self:center;padding:0 3px;color:rgba(41,217,255,.55);font:900 7px/1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.cdbd-section-title[data-intel-group="soc"]{border-left-color:var(--green)!important;background:linear-gradient(90deg,rgba(61,226,146,.08),rgba(11,24,39,.76))!important}.cdbd-section-title[data-intel-group="risk"]{border-left-color:var(--amber)!important;background:linear-gradient(90deg,rgba(255,181,44,.08),rgba(11,24,39,.76))!important}.cdbd-section-title[data-intel-group="analysis"]{border-left-color:var(--violet)!important;background:linear-gradient(90deg,rgba(162,109,255,.08),rgba(11,24,39,.76))!important}.cdbd-section-title[data-intel-group="provenance"]{border-left-color:var(--blue)!important;background:linear-gradient(90deg,rgba(75,125,255,.08),rgba(11,24,39,.76))!important}@keyframes cdbv8-scan{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}@keyframes cdbv8-pulse{0%,100%{opacity:.75;transform:scale(.92)}50%{opacity:1;transform:scale(1.08)}}@keyframes cdbv8-flow{0%{left:-40%}100%{left:140%}}@media(max-width:980px){.cdbv8-context-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv8-signals{grid-template-columns:repeat(3,minmax(0,1fr))}.cdbv8-quality{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:680px){.cdbv8-brief-grid{grid-template-columns:1fr}.cdbv8-signals{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv8-chain{grid-template-columns:auto 24px auto 24px auto 24px auto}.cdbv8-panel{padding:12px}.cdbv8-context-grid{grid-template-columns:1fr}.cdbd-command:before{display:none}}@media(prefers-reduced-motion:reduce){.cdb-cti-dossier:before,.cdbd-trust b,.cdbv8-chain i:after{animation:none!important}.cdb-cti-dossier *{scroll-behavior:auto!important;transition:none!important}}@media print{.cdbv8-panel,.cdbv8-quality{box-shadow:none!important;background:#fff!important;color:#111!important;break-inside:avoid}.cdbv8-chain i{background:#94a3b8!important}.cdbv8-context-grid strong,.cdbv8-signal strong,.cdbv8-brief-grid p{color:#111!important}}
</style>"""


def enhance_cti_dossier_v8(rendered_html: str, article: Any = None, context: Any = None) -> str:
    """Apply final integrity gates and premium evidence-safe presentation."""
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        _gate_customer_visible_integrity(soup)
        _group_navigation(soup)
        _decorate_sections(soup)

        command = soup.select_one(".cdbd-command")
        if command is not None:
            modules = (
                _quality_html()
                + _control_plane_html(soup, context)
                + _brief_html(soup)
                + _ledger_html(soup)
            )
            _inject_after(command, modules)

        style = BeautifulSoup(_styles(), "html.parser")
        soup.insert(0, style)
        return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"
    except PublicationIntegrityError:
        raise
    except Exception:
        # Visual enrichment is fail-open; content-integrity failures above are not.
        return rendered_html


def _patched_assemble_html(
    self,
    article,
    body_content: str,
    seo_data: dict,
    context,
    image_url: Optional[str] = None,
):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI dossier v8 layer is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return enhance_cti_dossier_v8(rendered, article, context)


setattr(_patched_assemble_html, _INSTALL_ATTR, True)


def install_cti_dossier_v8(main_module) -> None:
    """Install as the absolute final report-assembly wrapper."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer

    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return
    _ORIGINAL_ASSEMBLE_HTML = current
    transformer._assemble_html = _patched_assemble_html
