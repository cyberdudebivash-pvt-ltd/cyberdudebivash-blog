"""SENTINEL APEX CTI Dossier v10 — evidence-first operational enrichment.

Conflict-resolution layer for PR #184. Installs strictly after Dossier v9 and
preserves the existing v8/v9 runtime. It surfaces additional evidence already
present in the rendered ReportX artifact and removes two legacy/applicability
presentation defects without creating new intelligence.

Hard invariants:
- v8 remains the fail-closed prompt/reasoning and canonical-duplication gate.
- v9 remains the primary SOC/CTI command-center presentation layer.
- v10 never assigns TLP, claims SOC 2 compliance/certification, invents numeric
  risk/confidence, confirms customer exposure/compromise, or creates ATT&CK,
  IOC, CVE, exploitation, attribution, vendor, or remediation facts.
"""
from __future__ import annotations

import html as _html
import re
from typing import Any, Optional

from bs4 import BeautifulSoup, Tag

MARKER = "CDB-CTI-DOSSIER-V10"
_INSTALL_ATTR = "__cdb_cti_dossier_v10__"
_ORIGINAL_ASSEMBLE_HTML = None

_VULN_FAMILIES = {"cve_advisory", "cisa_kev", "cisa_advisory"}

_EXPOSURE_QUESTIONS = {
    "ai_security": (
        "Is the cited AI model, agent, framework, or capability present in approved or shadow use?",
        "Can the relevant agent execute shell, package-manager, filesystem, browser, MCP, API, or tool actions?",
        "Can external documentation, repository instructions, llms.txt, prompts, or machine-readable content influence agent actions?",
        "Does the agent have outbound network access from developer, CI/CD, cloud, or production-adjacent environments?",
        "Can the agent access delegated credentials, secrets, tokens, source code, package registries, or deployment systems?",
    ),
    "cve_advisory": (
        "Is the affected product or dependency present in the authoritative asset/software inventory?",
        "Does the deployed version or configuration intersect the cited affected condition?",
        "Is the affected surface internet-facing, identity-sensitive, privileged, or business-critical?",
        "Is authoritative vendor/CISA remediation available and change-controlled for this environment?",
        "Do EDR, network, identity, application, or vulnerability telemetry sources cover the cited behavior?",
    ),
    "cisa_kev": (
        "Is the KEV-listed product present in the environment and within the affected condition?",
        "Has the cited CISA required action and due date been mapped to an accountable owner?",
        "Can compensating controls reduce exposure until authoritative remediation is validated?",
        "Is telemetry sufficient to look for evidence-supported prior activity?",
        "Has remediation effectiveness been independently verified after change?",
    ),
    "cisa_advisory": (
        "Does the environment contain the technology, service, identity boundary, or dependency named by the advisory?",
        "Is the cited affected condition confirmed against internal inventory and configuration evidence?",
        "Are authoritative mitigations applicable to this deployment topology?",
        "Does current telemetry cover the source-backed behavior required for validation?",
        "Is evidence preserved before any destructive containment action?",
    ),
    "ransomware_claim": (
        "Does the named organization, brand, subsidiary, or supplier relationship intersect the enterprise environment?",
        "Is there independent internal telemetry corroborating the third-party leak-site claim?",
        "Are identity, endpoint, network, cloud, backup, and data-access logs preserved for scoped validation?",
        "Are actor-specific IOCs/TTPs actually source-backed before being used for hunting?",
        "Has incident status been withheld until internal evidence supports escalation?",
    ),
    "ransomware_reporting": (
        "Are the cited technologies, sectors, geographies, or access patterns relevant to the environment?",
        "Are source-backed actor behaviors represented in available detection telemetry?",
        "Are identity, endpoint, network, cloud, email, and backup controls observable and testable?",
        "Can hunting pivots be tied to cited observables or behaviors rather than generic ransomware assumptions?",
        "Are recovery and evidence-preservation dependencies documented before an incident occurs?",
    ),
    "threat_actor": (
        "Does source-backed targeting overlap enterprise sectors, geographies, technologies, or identities?",
        "Are only corroborated aliases, infrastructure, malware, and ATT&CK behaviors being operationalized?",
        "Can current telemetry observe the source-backed behaviors relevant to this actor?",
        "Are hunt pivots bounded to cited evidence and time windows?",
        "Is attribution kept separate from customer-specific incident determination?",
    ),
    "breach_notice": (
        "Is there a direct supplier, identity, SaaS, data-sharing, customer, or dependency relationship with the affected entity?",
        "Does the public notice establish data categories or systems relevant to enterprise exposure?",
        "Is any internal credential, token, account, or integration rotation actually warranted by the cited evidence?",
        "Are contractual, privacy, legal, or regulatory decisions being made by accountable owners using verified scope?",
        "Has internal impact been kept distinct from the public breach record?",
    ),
    "general_intelligence": (
        "Does the cited technology, service, identity, dependency, sector, or behavior exist in the environment?",
        "Is internal telemetry available to confirm or reject enterprise relevance?",
        "Are operational pivots limited to source-backed observables and behaviors?",
        "Is public-source reporting being kept separate from confirmed customer impact?",
        "Is the validation decision timestamped and evidence-preserved for later re-evaluation?",
    ),
}


def _normalize(text: str) -> str:
    value = re.sub(r"\s+", " ", text or "").strip().lower()
    value = value.replace("–", "-").replace("—", "-")
    value = re.sub(r"^[\s\d.():►■-]+", "", value).strip()
    aliases = {
        "evidence and source assessment": "evidence & source assessment",
        "intelligence gaps and collection requirements": "intelligence gaps & collection requirements",
        "analytic confidence and limitations": "analytic confidence & limitations",
        "timeline and chronology": "timeline & chronology",
    }
    return aliases.get(value, value)


def _heading(soup: BeautifulSoup, semantic: str) -> Optional[Tag]:
    for node in soup.find_all(["h2", "h3"]):
        if _normalize(node.get_text(" ", strip=True)) == semantic:
            return node
    return None


def _section_nodes(heading: Optional[Tag]) -> list[Tag]:
    if heading is None:
        return []
    out: list[Tag] = []
    sibling = heading.next_sibling
    while sibling is not None:
        nxt = sibling.next_sibling
        if isinstance(sibling, Tag) and sibling.name in {"h2", "h3"}:
            break
        if isinstance(sibling, Tag):
            out.append(sibling)
        sibling = nxt
    return out


def _section_text(soup: BeautifulSoup, semantic: str) -> str:
    return re.sub(
        r"\s+", " ",
        " ".join(node.get_text(" ", strip=True) for node in _section_nodes(_heading(soup, semantic))),
    ).strip()


def _section_items(soup: BeautifulSoup, semantic: str, limit: int = 6) -> list[str]:
    items: list[str] = []
    for node in _section_nodes(_heading(soup, semantic)):
        for li in node.find_all("li"):
            text = re.sub(r"\s+", " ", li.get_text(" ", strip=True)).strip()
            if text and text not in items:
                items.append(text)
            if len(items) >= limit:
                return items
    return items


def _clip(text: str, limit: int = 300) -> str:
    clean = re.sub(r"\s+", " ", text or "").strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit + 1].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"


def _source_name(article: Any, soup: BeautifulSoup) -> str:
    explicit = str(getattr(article, "source_publisher", None) or "").strip()
    if explicit:
        return explicit
    facts = _section_text(soup, "verified facts")
    match = re.search(r"Source publisher:\s*([^.;|]+)", facts, re.I)
    return match.group(1).strip() if match else "SOURCE-LINKED PUBLIC RECORD"


def _remove_nonapplicable_kev_unknown(soup: BeautifulSoup, article: Any, context: Any) -> None:
    family = str(getattr(context, "family", None) or "")
    if getattr(article, "cve_id", None) or family in _VULN_FAMILIES:
        return
    for label in list(soup.find_all("div")):
        if label.get_text(" ", strip=True).upper() != "CISA KEV":
            continue
        tile = label.parent if isinstance(label.parent, Tag) else None
        if tile is None:
            continue
        text = tile.get_text(" ", strip=True).lower()
        if "unknown" in text and "no negative claim" in text:
            tile.decompose()


def _remove_legacy_generic_decision_center(soup: BeautifulSoup) -> None:
    """Remove only the legacy role-card module, never canonical ReportX decisions."""
    for heading in list(soup.find_all("div")):
        if _normalize(heading.get_text(" ", strip=True)) != "executive decision center":
            continue
        cards = heading.find_next_sibling()
        if not isinstance(cards, Tag):
            continue
        card_text = cards.get_text(" ", strip=True).lower()
        legacy_markers = ("ceo summary", "board summary", "ciso summary", "devsecops summary", "cloud summary")
        if not any(marker in card_text for marker in legacy_markers):
            continue
        cards.decompose()
        heading.decompose()


def _confidence_html(soup: BeautifulSoup) -> str:
    all_text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
    source_rel = re.search(r"Source Reliability:\s*([A-F])\b", all_text, re.I)
    credibility = re.search(r"Information Credibility:\s*([1-6])(?:\s*\(([^)]+)\))?", all_text, re.I)
    overall = re.search(r"Overall Analytical Confidence:\s*(HIGH|MEDIUM|LOW)\b", all_text, re.I)
    evidence = _section_text(soup, "evidence & source assessment").lower()
    gaps = _section_text(soup, "intelligence gaps & collection requirements").lower()
    if ("single" in evidence and "source" in evidence) or "second source" in gaps:
        corroboration = "SINGLE-SOURCE / OPEN GAP"
    elif "independent" in evidence and "corrobor" in evidence:
        corroboration = "INDEPENDENT CORROBORATION PRESENT"
    else:
        corroboration = "NOT EXPLICITLY ESTABLISHED"
    source_value = source_rel.group(1).upper() if source_rel else "NOT EXPLICITLY SCORED"
    if credibility:
        cred_value = credibility.group(1)
        if credibility.group(2):
            cred_value += f" — {credibility.group(2)}"
    else:
        cred_value = "NOT EXPLICITLY SCORED"
    overall_value = overall.group(1).upper() if overall else "EVIDENCE-BOUNDED"
    cells = (
        ("SOURCE RELIABILITY", source_value),
        ("INFORMATION CREDIBILITY", cred_value),
        ("CORROBORATION", corroboration),
        ("ANALYTIC CONFIDENCE", overall_value),
    )
    rendered = "".join(
        f'<div><span>{_html.escape(label)}</span><strong>{_html.escape(value)}</strong></div>'
        for label, value in cells
    )
    return f"""
<section class="cdbv10-panel cdbv10-confidence" aria-label="Qualitative intelligence confidence matrix">
  <div class="cdbv10-head"><span>SOURCE CONFIDENCE &amp; CORROBORATION</span><b>QUALITATIVE · NOT PROBABILITY</b></div>
  <div class="cdbv10-confidence-grid">{rendered}</div>
</section>"""


def _evidence_graph_html(soup: BeautifulSoup, article: Any, context: Any) -> str:
    source = _source_name(article, soup)
    facts = _section_items(soup, "verified facts", 4)
    if not facts:
        text = _section_text(soup, "verified facts")
        if text:
            facts = [_clip(text, 240)]
    fact_nodes = "".join(
        f'<div class="cdbv10-fact"><i>C-{idx:03d}</i><span>{_html.escape(_clip(fact, 220))}</span></div>'
        for idx, fact in enumerate(facts, start=1)
    ) or '<div class="cdbv10-fact muted"><i>GAP</i><span>No discrete verified-fact list was rendered.</span></div>'
    report_id = str(getattr(context, "report_id", None) or "REPORTX")
    return f"""
<section class="cdbv10-panel cdbv10-evidence" aria-label="Evidence graph visualization">
  <div class="cdbv10-head"><span>EVIDENCE GRAPH // CLAIM TRACEABILITY</span><b>NO SYNTHETIC NODES</b></div>
  <div class="cdbv10-graph">
    <div class="cdbv10-node source"><small>SOURCE</small><strong>{_html.escape(source)}</strong></div>
    <i class="cdbv10-edge"></i>
    <div class="cdbv10-facts">{fact_nodes}</div>
    <i class="cdbv10-edge"></i>
    <div class="cdbv10-node reportx"><small>REPORTX</small><strong>{_html.escape(report_id)}</strong></div>
    <i class="cdbv10-edge"></i>
    <div class="cdbv10-node soc"><small>DECISION LAYER</small><strong>SOC VALIDATION</strong></div>
  </div>
</section>"""


def _exposure_html(context: Any) -> str:
    family = str(getattr(context, "family", None) or "general_intelligence")
    questions = _EXPOSURE_QUESTIONS.get(family, _EXPOSURE_QUESTIONS["general_intelligence"])
    rows = "".join(
        f'<li><span class="cdbv10-check" aria-hidden="true"></span><span>{_html.escape(q)}</span></li>'
        for q in questions
    )
    return f"""
<section class="cdbv10-panel cdbv10-exposure" aria-label="Enterprise exposure validation checklist">
  <div class="cdbv10-head"><span>ENTERPRISE EXPOSURE VALIDATION CHECKLIST</span><b>STATUS · NOT ASSESSED</b></div>
  <div class="cdbv10-boundary">Validation aid only — not a customer risk score. Exposure is confirmed only by internal inventory/telemetry or separately corroborated evidence.</div>
  <ol>{rows}</ol>
</section>"""


def _gaps_html(soup: BeautifulSoup) -> str:
    gaps = _section_items(soup, "intelligence gaps & collection requirements", 6)
    if not gaps:
        return ""
    rows = "".join(
        f'<div class="cdbv10-gap"><i>GAP-{idx:03d}</i><span>{_html.escape(_clip(gap, 300))}</span><b>OPEN</b></div>'
        for idx, gap in enumerate(gaps, start=1)
    )
    return f"""
<section class="cdbv10-panel cdbv10-gaps" aria-label="Intelligence gap tracker">
  <div class="cdbv10-head"><span>INTELLIGENCE GAP &amp; COLLECTION TRACKER</span><b>{len(gaps)} OPEN</b></div>
  <div class="cdbv10-gap-list">{rows}</div>
</section>"""


def _chronology_html(article: Any, context: Any) -> str:
    published = str(getattr(article, "published_at", None) or "NOT PROVIDED").strip()
    generated = str(getattr(context, "generated_at", None) or "NOT PROVIDED").strip()
    source_hash = str(getattr(context, "source_record_hash", None) or "").strip()
    hash_label = source_hash[:16] + "…" if len(source_hash) > 16 else (source_hash or "NOT PROVIDED")
    points = (
        ("01", "SOURCE PUBLISHED", published),
        ("02", "EVIDENCE NORMALIZED", "REPORTCONTEXT + REPORTX"),
        ("03", "SOURCE RECORD SEALED", hash_label),
        ("04", "DOSSIER GENERATED", generated),
        ("05", "PUBLICATION CONTROL", "FAIL-CLOSED INTEGRITY GATE"),
    )
    items = "".join(
        f'<div><i>{n}</i><span>{_html.escape(label)}</span><strong>{_html.escape(value)}</strong></div>'
        for n, label, value in points
    )
    return f"""
<section class="cdbv10-panel cdbv10-chronology" aria-label="Evidence chronology and provenance">
  <div class="cdbv10-head"><span>INTELLIGENCE CHRONOLOGY &amp; PROVENANCE RAIL</span><b>SOURCE → PUBLICATION</b></div>
  <div class="cdbv10-timeline">{items}</div>
</section>"""


def _decision_support_html(soup: BeautifulSoup) -> str:
    decisions = _section_items(soup, "executive decision matrix", 4)
    recommendations = _section_items(soup, "executive recommendations", 4)
    source = decisions or recommendations
    if not source:
        return ""
    cards = "".join(
        f'<article><i>D-{idx:02d}</i><p>{_html.escape(_clip(text, 330))}</p></article>'
        for idx, text in enumerate(source, start=1)
    )
    return f"""
<section class="cdbv10-panel cdbv10-decisions" aria-label="Evidence-bound executive decision support">
  <div class="cdbv10-head"><span>EXECUTIVE DECISION SUPPORT</span><b>CANONICAL REPORTX SOURCE</b></div>
  <div class="cdbv10-decision-grid">{cards}</div>
</section>"""


def _capability_html(soup: BeautifulSoup) -> str:
    navigator = None
    for link in soup.find_all("a", href=True):
        text = link.get_text(" ", strip=True).lower()
        if "navigator" in text and "mitre" in text:
            navigator = link.get("href")
            break
    nav_link = (
        f'<a href="{_html.escape(str(navigator), quote=True)}" download="mitre-navigator-layer.json">ATT&amp;CK NAVIGATOR LAYER</a>'
        if navigator else ""
    )
    return f"""
<section class="cdbv10-capabilities" aria-label="Machine-readable intelligence capabilities">
  <span>INTELLIGENCE OUTPUTS</span>
  <a href="https://intel.cyberdudebivash.com/api/docs" target="_blank" rel="noopener">API DOCUMENTATION</a>
  <a href="https://intel.cyberdudebivash.com/api/docs" target="_blank" rel="noopener">STIX 2.1 · ENTERPRISE IOC API</a>
  {nav_link}
  <b>PUBLIC DOSSIER · SOURCE-LINKED</b>
</section>"""


def _styles() -> str:
    return r"""<style id="cdb-cti-dossier-v10-css">
.cdbv10-panel{position:relative;margin:16px 0;padding:16px;border:1px solid rgba(44,207,255,.20);border-radius:14px;background:linear-gradient(145deg,rgba(7,20,33,.96),rgba(4,10,17,.96));box-shadow:0 20px 58px rgba(0,0,0,.24);overflow:hidden}.cdbv10-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;color:var(--cyan,#29d9ff);font:850 9px/1.35 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.13em}.cdbv10-head b{padding:5px 8px;border:1px solid rgba(41,217,255,.18);border-radius:999px;background:rgba(41,217,255,.05);color:#a8ddf2!important;font-size:7px;white-space:nowrap}.cdbv10-confidence-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.cdbv10-confidence-grid>div{padding:13px;border:1px solid rgba(145,173,197,.14);border-radius:10px;background:rgba(0,0,0,.22)}.cdbv10-confidence-grid span,.cdbv10-node small{display:block;margin-bottom:7px;color:var(--muted,#8ea6bd);font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.1em}.cdbv10-confidence-grid strong,.cdbv10-node strong{display:block;color:#eef8ff!important;font-size:10px;line-height:1.45;overflow-wrap:anywhere}.cdbv10-graph{display:grid;grid-template-columns:minmax(120px,.8fr) 42px minmax(250px,2fr) 42px minmax(130px,.9fr) 42px minmax(130px,.9fr);align-items:center;gap:8px}.cdbv10-node,.cdbv10-fact{border:1px solid rgba(41,217,255,.17);border-radius:10px;background:rgba(0,0,0,.26);padding:12px}.cdbv10-facts{display:grid;gap:6px}.cdbv10-fact{display:grid;grid-template-columns:auto 1fr;gap:9px;align-items:start;padding:9px}.cdbv10-fact i,.cdbv10-gap i{color:var(--cyan,#29d9ff);font:800 7px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;font-style:normal}.cdbv10-fact span{color:#cfdeeb;font-size:9px;line-height:1.45}.cdbv10-edge{display:block;height:1px;background:linear-gradient(90deg,rgba(41,217,255,.12),var(--cyan,#29d9ff),rgba(41,217,255,.12));position:relative;overflow:hidden}.cdbv10-edge:after{content:"";position:absolute;width:35%;inset:0 auto 0 -35%;background:#fff;opacity:.6;animation:cdbv10-flow 3s linear infinite}.cdbv10-boundary{margin-bottom:11px;padding:10px 12px;border-left:3px solid var(--amber,#ffb52c);background:rgba(255,181,44,.05);color:#dce8f2;font-size:10px;line-height:1.55}.cdbv10-exposure ol{list-style:none!important;margin:0!important;padding:0!important;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.cdbv10-exposure li{display:flex;gap:9px;align-items:flex-start;margin:0!important;padding:10px!important;border:1px solid rgba(145,173,197,.12);border-radius:9px;background:rgba(0,0,0,.18);color:#d6e4ef;font-size:10px;line-height:1.5}.cdbv10-check{flex:0 0 13px;width:13px;height:13px;margin-top:1px;border:1px solid rgba(41,217,255,.42);border-radius:3px;background:rgba(41,217,255,.04)}.cdbv10-gap-list{display:grid;gap:7px}.cdbv10-gap{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:start;padding:10px 11px;border:1px solid rgba(255,181,44,.13);border-radius:9px;background:rgba(255,181,44,.025)}.cdbv10-gap span{color:#d7e4ee;font-size:10px;line-height:1.5}.cdbv10-gap b{padding:3px 6px;border:1px solid rgba(255,181,44,.2);border-radius:999px;color:var(--amber,#ffb52c)!important;font:800 7px/1 ui-monospace,SFMono-Regular,Consolas,monospace}.cdbv10-timeline{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:6px}.cdbv10-timeline>div{padding:11px;border-top:2px solid rgba(41,217,255,.28);background:rgba(0,0,0,.18);border-radius:0 0 8px 8px}.cdbv10-timeline i{display:inline-grid;place-items:center;width:22px;height:22px;margin-bottom:8px;border:1px solid rgba(41,217,255,.3);border-radius:50%;color:var(--cyan,#29d9ff);font:800 7px/1 ui-monospace,SFMono-Regular,Consolas,monospace;font-style:normal}.cdbv10-timeline span,.cdbv10-timeline strong{display:block}.cdbv10-timeline span{color:var(--muted,#8ea6bd);font:800 7px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.cdbv10-timeline strong{margin-top:5px;color:#eaf5fc!important;font-size:8px;line-height:1.45;overflow-wrap:anywhere}.cdbv10-decision-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.cdbv10-decision-grid article{position:relative;padding:12px 12px 12px 42px;border:1px solid rgba(162,109,255,.14);border-radius:10px;background:rgba(162,109,255,.03)}.cdbv10-decision-grid i{position:absolute;left:11px;top:12px;color:#b993ff;font:800 7px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;font-style:normal}.cdbv10-decision-grid p{margin:0!important;color:#dbe7f0!important;font-size:10px!important;line-height:1.55!important}.cdbv10-capabilities{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin:14px 0 18px;padding:10px;border:1px solid rgba(41,217,255,.15);border-radius:10px;background:rgba(3,12,20,.9);font:800 7px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.cdbv10-capabilities>span{color:var(--muted,#8ea6bd);margin-right:4px}.cdbv10-capabilities a{padding:6px 8px;border:1px solid rgba(41,217,255,.18);border-radius:999px;color:var(--cyan,#29d9ff)!important;text-decoration:none!important}.cdbv10-capabilities b{margin-left:auto;color:var(--green,#3de292)!important;font-size:7px}@keyframes cdbv10-flow{0%{left:-35%}100%{left:140%}}@media(max-width:1050px){.cdbv10-graph{grid-template-columns:1fr}.cdbv10-edge{width:1px;height:22px;margin:auto}.cdbv10-timeline{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv10-confidence-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:680px){.cdbv10-exposure ol,.cdbv10-decision-grid,.cdbv10-confidence-grid,.cdbv10-timeline{grid-template-columns:1fr}.cdbv10-panel{padding:12px}.cdbv10-head{align-items:flex-start;flex-direction:column}.cdbv10-capabilities b{margin-left:0;width:100%}}@media(prefers-reduced-motion:reduce){.cdbv10-edge:after{animation:none!important}}@media print{.cdbv10-panel,.cdbv10-capabilities{box-shadow:none!important;background:#fff!important;color:#111!important;break-inside:avoid}.cdbv10-confidence-grid strong,.cdbv10-node strong,.cdbv10-fact span,.cdbv10-exposure li,.cdbv10-gap span,.cdbv10-timeline strong,.cdbv10-decision-grid p{color:#111!important}}
</style>"""


def _inject_after(target: Tag, fragment: str) -> None:
    parsed = BeautifulSoup(fragment, "html.parser")
    for node in reversed(list(parsed.contents)):
        target.insert_after(node)


def enhance_cti_dossier_v10(rendered_html: str, article: Any = None, context: Any = None) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        _remove_nonapplicable_kev_unknown(soup, article, context)
        _remove_legacy_generic_decision_center(soup)

        anchor = (
            soup.select_one(".cdbv9-framework")
            or soup.select_one(".cdbv8-ledger")
            or soup.select_one(".cdbv8-brief")
            or soup.select_one(".cdbd-command")
        )
        if anchor is not None:
            modules = (
                _confidence_html(soup)
                + _evidence_graph_html(soup, article, context)
                + _exposure_html(context)
                + _chronology_html(article, context)
                + _decision_support_html(soup)
                + _gaps_html(soup)
                + _capability_html(soup)
            )
            _inject_after(anchor, modules)

        soup.insert(0, BeautifulSoup(_styles(), "html.parser"))
        return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"
    except Exception:
        # Presentation/applicability enrichment is fail-open. v8 already ran and
        # remains the independent fail-closed customer-content integrity gate.
        return rendered_html


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url: Optional[str] = None):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI dossier v10 layer is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return enhance_cti_dossier_v10(rendered, article, context)


setattr(_patched_assemble_html, _INSTALL_ATTR, True)


def install_cti_dossier_v10(main_module) -> None:
    """Install after v9 without replacing v8/v9 behavior."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return
    _ORIGINAL_ASSEMBLE_HTML = current
    transformer._assemble_html = _patched_assemble_html
