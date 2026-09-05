"""SENTINEL APEX CTI Dossier Presentation v4.

Presentation-only final-stage decorator for Blogger intelligence reports.
It executes after ReportX/evidence compilation and before the exact artifact
hash is computed, so the certified bytes are the same bytes submitted to
Blogger. It never creates threat facts, scores, ATT&CK mappings, IOCs or
compliance claims; metadata displayed in the command deck is derived only
from the already-rendered report or canonical ReportContext fields.
"""
from __future__ import annotations

import html as _html
import re
from typing import Any, Optional

from bs4 import BeautifulSoup

MARKER = "CDB-CTI-DOSSIER-V4"
ROOT_CLASS = "cdb-cti-dossier"
_ORIGINAL_ASSEMBLE_HTML = None

_SEVERITY_RE = re.compile(
    r"(?:severity(?:\s+is\s+assessed\s+as|\s*[:\-])|priority\s*[:\-])\s*"
    r"(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b",
    re.IGNORECASE,
)
_CONFIDENCE_RE = re.compile(
    r"(?:analytic\s+confidence|confidence(?:\s+in\s+severity\s+rating)?)"
    r"\s*(?:is|:)?\s*(HIGH|MEDIUM|LOW)\b",
    re.IGNORECASE,
)
_TLP_RE = re.compile(r"\b(TLP:(?:CLEAR|GREEN|AMBER(?:\+STRICT)?|RED))\b", re.IGNORECASE)


def _plain(report_html: str) -> str:
    soup = BeautifulSoup(report_html or "", "html.parser")
    return re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()


def _first(pattern: re.Pattern[str], text: str, default: str) -> str:
    match = pattern.search(text)
    return match.group(1).upper() if match else default


def _safe(value: Any, fallback: str = "NOT EXPOSED") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _metadata(report_html: str, article: Any, context: Any) -> dict[str, str]:
    """Return display metadata without inferring missing intelligence facts."""
    plain = _plain(report_html)
    report_id = _safe(getattr(context, "report_id", None))
    certification = _safe(getattr(context, "certification_status", None), "EVIDENCE BOUNDED")

    source = _safe(getattr(article, "source", None), "SOURCE LINKED")
    if source == "SOURCE LINKED":
        source_match = re.search(r"Source publisher\s*:\s*([^|•]{2,100}?)(?=\s+Source published|$)", plain, re.I)
        if source_match:
            source = source_match.group(1).strip()

    category = "CYBER THREAT INTELLIGENCE"
    labels = getattr(article, "labels", None) or []
    if labels:
        category = str(labels[0]).strip() or category

    generated = "NOT EXPOSED"
    gen = re.search(r"Generated UTC\s*([0-9T:+.\-Z]{10,40})", plain, re.I)
    if gen:
        generated = gen.group(1)

    return {
        "title": _safe(getattr(article, "title", None), "Threat Intelligence Report"),
        "report_id": report_id,
        "severity": _first(_SEVERITY_RE, plain, "UNSPECIFIED"),
        "confidence": _first(_CONFIDENCE_RE, plain, "UNSPECIFIED"),
        "tlp": _first(_TLP_RE, plain, "TLP:UNSPECIFIED"),
        "category": category,
        "source": source,
        "generated": generated,
        "certification": certification,
    }


def _kpi(label: str, value: str, extra: str = "") -> str:
    return (
        f'<div class="cdbd-kpi {extra}"><span>{_html.escape(label)}</span>'
        f'<strong>{_html.escape(value)}</strong></div>'
    )


def _command_deck(meta: dict[str, str]) -> str:
    sev = meta["severity"].lower()
    return f"""
<section class="cdbd-command cdbd-sev-{_html.escape(sev)}" aria-label="Sentinel APEX intelligence command deck">
  <div class="cdbd-eyebrow"><span>CYBERDUDEBIVASH® INTEL FACTORY</span><span>SENTINEL APEX™ // ADVANCED CTI DOSSIER</span></div>
  <div class="cdbd-title">{_html.escape(meta['title'])}</div>
  <div class="cdbd-identity"><span>{_html.escape(meta['category'])}</span><i></i><span>{_html.escape(meta['report_id'])}</span></div>
  <div class="cdbd-kpis">
    {_kpi('SEVERITY', meta['severity'], 'cdbd-kpi-severity')}
    {_kpi('CONFIDENCE', meta['confidence'])}
    {_kpi('TLP', meta['tlp'])}
    {_kpi('SOURCE', meta['source'])}
    {_kpi('GENERATED UTC', meta['generated'])}
    {_kpi('CERTIFICATION', meta['certification'])}
  </div>
  <div class="cdbd-trust"><b></b><span>EVIDENCE-PRESERVING PRESENTATION</span><span>SOURCE-LINKED</span><span>REPORTX BOUNDARIES RETAINED</span></div>
</section>"""


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:72] or "section"


def _decorate_structure(soup: BeautifulSoup) -> list[tuple[str, str]]:
    """Add semantic visual classes/anchors without changing report claims."""
    nav: list[tuple[str, str]] = []
    used: dict[str, int] = {}
    for heading in soup.find_all(["h2", "h3"]):
        label = re.sub(r"\s+", " ", heading.get_text(" ", strip=True)).strip()
        if not label:
            continue
        base = _slug(label)
        used[base] = used.get(base, 0) + 1
        anchor = base if used[base] == 1 else f"{base}-{used[base]}"
        if not heading.get("id"):
            heading["id"] = anchor
        else:
            anchor = str(heading["id"])
        heading["class"] = list(heading.get("class", [])) + ["cdbd-section-title"]
        if len(nav) < 32:
            nav.append((anchor, label))

    for table in soup.find_all("table"):
        table["class"] = list(table.get("class", [])) + ["cdbd-matrix"]
    for block in soup.find_all(["pre", "code"]):
        block["class"] = list(block.get("class", [])) + ["cdbd-telemetry"]
    return nav


def _nav_html(nav: list[tuple[str, str]]) -> str:
    if not nav:
        return ""
    links = "".join(
        f'<a href="#{_html.escape(anchor, quote=True)}">{_html.escape(label[:48])}</a>'
        for anchor, label in nav
    )
    return f'<nav class="cdbd-nav" aria-label="Report navigation"><b>INTEL DOSSIER</b><div>{links}</div></nav>'


def _styles() -> str:
    # Every selector is rooted under .cdb-cti-dossier to prevent Blogger-theme
    # collisions. !important is used only where Blogger's theme/legacy inline
    # report rules would otherwise override the dossier presentation.
    return r"""<style id="cdb-cti-dossier-v4-css">
.cdb-cti-dossier{--bg:#03070c;--s:#07111c;--p:#0b1827;--p2:#102238;--line:rgba(64,211,255,.23);--cyan:#29d9ff;--blue:#4b7dff;--violet:#a26dff;--green:#3de292;--amber:#ffb52c;--orange:#ff7a18;--red:#ff4055;--text:#eff8ff;--muted:#8ea6bd;color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.72;background:radial-gradient(circle at 8% 0,rgba(41,217,255,.085),transparent 32rem),radial-gradient(circle at 92% 12%,rgba(162,109,255,.07),transparent 34rem),var(--bg);padding:clamp(12px,2.6vw,30px);border:1px solid rgba(41,217,255,.12);border-radius:18px;box-shadow:0 28px 90px rgba(0,0,0,.32)}
.cdb-cti-dossier *{box-sizing:border-box}.cdb-cti-dossier a{color:var(--cyan)!important;text-underline-offset:3px}.cdbd-command{position:relative;overflow:hidden;background:linear-gradient(135deg,rgba(12,27,45,.98),rgba(3,7,12,.99));border:1px solid var(--line);border-top:4px solid var(--cyan);border-radius:16px;padding:clamp(20px,4vw,42px);margin:0 0 16px;box-shadow:0 20px 65px rgba(0,0,0,.36)}.cdbd-command:after{content:"";position:absolute;width:460px;height:460px;right:-140px;bottom:-330px;border-radius:50%;background:radial-gradient(circle,rgba(41,217,255,.18),transparent 68%);pointer-events:none}.cdbd-sev-critical{border-top-color:var(--red)}.cdbd-sev-high{border-top-color:var(--orange)}.cdbd-sev-medium{border-top-color:var(--amber)}.cdbd-eyebrow{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--cyan);font:800 10px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.16em}.cdbd-title{max-width:1100px;margin:20px 0 11px;color:#fff;font-size:clamp(27px,4.6vw,52px);line-height:1.06;font-weight:900;letter-spacing:-.035em;text-wrap:balance}.cdbd-identity{display:flex;gap:10px;align-items:center;flex-wrap:wrap;color:var(--muted);font:700 10px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase}.cdbd-identity i{width:5px;height:5px;border-radius:50%;background:var(--cyan)}.cdbd-kpis{position:relative;z-index:1;display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:9px;margin-top:27px}.cdbd-kpi{min-height:78px;padding:12px;border:1px solid rgba(142,166,189,.18);border-radius:10px;background:rgba(0,0,0,.25);display:flex;flex-direction:column;justify-content:space-between;min-width:0}.cdbd-kpi span{color:var(--muted);font:800 8px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.13em}.cdbd-kpi strong{color:#fff!important;font-size:12px;line-height:1.25;overflow-wrap:anywhere}.cdbd-kpi-severity strong{color:var(--orange)!important}.cdbd-sev-critical .cdbd-kpi-severity strong{color:var(--red)!important}.cdbd-sev-medium .cdbd-kpi-severity strong{color:var(--amber)!important}.cdbd-trust{position:relative;z-index:1;display:flex;align-items:center;gap:13px;flex-wrap:wrap;margin-top:15px;color:var(--muted);font:750 9px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.cdbd-trust b{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 14px rgba(61,226,146,.7)}
.cdbd-nav{position:sticky;top:7px;z-index:25;display:flex;align-items:center;gap:10px;margin:0 0 20px;padding:9px 11px;border:1px solid var(--line);border-radius:11px;background:rgba(3,7,12,.94);backdrop-filter:blur(14px)}.cdbd-nav>b{flex:0 0 auto;color:var(--cyan)!important;font:850 9px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.13em}.cdbd-nav>div{display:flex;gap:6px;overflow-x:auto;scrollbar-width:thin;padding-bottom:2px}.cdbd-nav a{flex:0 0 auto;padding:6px 9px;border:1px solid rgba(142,166,189,.15);border-radius:999px;background:var(--p);color:var(--muted)!important;text-decoration:none!important;font-size:9px;font-weight:750;white-space:nowrap}.cdbd-nav a:hover{color:#fff!important;border-color:var(--cyan)}
.cdbd-body{max-width:1160px;margin:0 auto}.cdb-cti-dossier .cdbd-section-title{scroll-margin-top:74px;margin:28px 0 12px!important;padding:13px 16px!important;color:#fff!important;background:linear-gradient(90deg,rgba(41,217,255,.10),rgba(11,24,39,.76))!important;border:1px solid var(--line)!important;border-left:4px solid var(--cyan)!important;border-radius:10px!important;font-size:clamp(17px,2vw,22px)!important;line-height:1.25!important;letter-spacing:-.01em!important}.cdb-cti-dossier h4{color:var(--cyan)!important}.cdb-cti-dossier p{color:#dce8f4!important;margin:9px 0 14px!important}.cdb-cti-dossier strong{color:#fff!important}.cdb-cti-dossier ul,.cdb-cti-dossier ol{margin:12px 0 18px!important;padding:14px 18px 14px 34px!important;border:1px solid rgba(142,166,189,.12)!important;border-left:3px solid rgba(41,217,255,.35)!important;border-radius:0 10px 10px 0!important;background:rgba(11,24,39,.48)!important}.cdb-cti-dossier li{color:#dce8f4!important;margin:6px 0!important}.cdb-cti-dossier li::marker{color:var(--cyan)}.cdb-cti-dossier blockquote{padding:16px 19px!important;border:1px solid rgba(255,181,44,.22)!important;border-left:4px solid var(--amber)!important;border-radius:10px!important;background:rgba(255,181,44,.055)!important;color:#fff!important}
.cdb-cti-dossier table{width:100%!important;border-collapse:separate!important;border-spacing:0!important;display:table!important;margin:17px 0 22px!important;border:1px solid var(--line)!important;border-radius:12px!important;overflow:hidden!important;background:var(--p)!important;box-shadow:0 14px 34px rgba(0,0,0,.16)}.cdb-cti-dossier th{padding:12px!important;background:#0a1c2d!important;color:var(--cyan)!important;border:0!important;border-bottom:1px solid var(--line)!important;text-align:left!important;font:850 9px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace!important;letter-spacing:.08em!important;text-transform:uppercase}.cdb-cti-dossier td{padding:12px!important;color:#dce8f4!important;border:0!important;border-bottom:1px solid rgba(142,166,189,.11)!important;vertical-align:top!important}.cdb-cti-dossier tr:last-child td{border-bottom:0!important}.cdb-cti-dossier tr:hover td{background:rgba(41,217,255,.035)!important}.cdb-cti-dossier pre{padding:15px!important;overflow:auto!important;border:1px solid var(--line)!important;border-radius:11px!important;background:#02060a!important;color:#bcefff!important}.cdb-cti-dossier code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace!important;background:#06131d!important;color:#aef0ff!important;border:1px solid rgba(41,217,255,.13)!important;border-radius:5px!important;padding:2px 5px!important}.cdb-cti-dossier img,.cdb-cti-dossier svg{max-width:100%!important;height:auto}.cdb-cti-dossier [style*="background:#0"],.cdb-cti-dossier [style*="background: #0"]{border-radius:10px}.cdb-cti-dossier hr{border:0!important;border-top:1px solid rgba(142,166,189,.18)!important;margin:28px 0!important}
@media(max-width:980px){.cdbd-kpis{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:640px){.cdb-cti-dossier{padding:9px;border-radius:0}.cdbd-command{padding:18px 13px}.cdbd-eyebrow span{display:block;width:100%;margin-bottom:3px}.cdbd-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbd-kpi{min-height:68px}.cdbd-nav{top:0;border-radius:8px}.cdb-cti-dossier table{display:block!important;overflow-x:auto!important}.cdbd-title{font-size:29px}.cdbd-trust{gap:7px}}
@media print{.cdb-cti-dossier{background:#fff!important;color:#111!important;padding:0!important;border:0!important;box-shadow:none!important}.cdbd-nav{display:none!important}.cdbd-command{background:#fff!important;box-shadow:none!important;break-inside:avoid}.cdbd-title,.cdbd-kpi strong,.cdb-cti-dossier .cdbd-section-title,.cdb-cti-dossier strong{color:#111!important}.cdb-cti-dossier p,.cdb-cti-dossier li,.cdb-cti-dossier td{color:#222!important}.cdb-cti-dossier ul,.cdb-cti-dossier ol,.cdb-cti-dossier table,.cdb-cti-dossier .cdbd-section-title{background:#fff!important;break-inside:avoid}.cdbd-kpi{background:#fff!important;border-color:#cbd5e1!important}}
</style>"""


def decorate_cti_dossier(report_html: str, article: Any, context: Any) -> str:
    """Decorate an already-composed report. Idempotent and fail-open."""
    if not report_html or MARKER in report_html:
        return report_html
    try:
        soup = BeautifulSoup(report_html, "html.parser")
        nav = _decorate_structure(soup)
        original = str(soup)
        meta = _metadata(original, article, context)
        return (
            f"<!-- {MARKER} -->{_styles()}<article class=\"{ROOT_CLASS}\">"
            f"{_command_deck(meta)}{_nav_html(nav)}<div class=\"cdbd-body\">{original}</div>"
            f"</article><!-- /{MARKER} -->"
        )
    except Exception:
        # Presentation may never become a publication availability dependency.
        # ReportX validation remains authoritative; a cosmetic failure leaves the
        # already-certified content unchanged rather than losing fresh CTI.
        return report_html


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url: Optional[str] = None):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI dossier presentation layer is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return decorate_cti_dossier(rendered, article, context)


def install_cti_dossier_presentation(main_module) -> None:
    """Install strictly last, wrapping the complete production renderer stack."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    if getattr(transformer._assemble_html, "__name__", "") == "_patched_assemble_html":
        return
    _ORIGINAL_ASSEMBLE_HTML = transformer._assemble_html
    transformer._assemble_html = _patched_assemble_html
