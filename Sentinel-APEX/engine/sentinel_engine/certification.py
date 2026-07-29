"""Enterprise Intelligence Certification Framework (EICF v1).

Composes the existing quality gate (``quality.py``), the canonical JS
renderer (``Sentinel-APEX/renderer/report-renderer.js``, via
``certify-rendering.js``), and direct checks against a report's already-
shipped publication artifacts into ONE certification pass: a qualitative
scorecard (Pass / Needs Review / Fail / Not Applicable) per domain, plus a
structured Release Governance record.

Nothing here re-implements a check that already exists elsewhere:

- Intelligence / Evidence / Detection Quality are entirely derived from
  ``quality.gate_report()``'s findings (see ``DOMAIN_FOR_GATE``) — this
  module only buckets and labels them into the three domains.
- Rendering Quality shells out to the canonical Node renderer; Markdown
  parsing is never duplicated in Python.
- Publication Quality reads the already-rendered, already-shipped HTML file
  and checks for the presence of facts already produced elsewhere
  (``fetch-live-intel.js`` / ``publish-report.js``) — it generates nothing.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .models import GateFinding
from .quality import gate_corpus, gate_report
from .report_ingest import build_pipeline_result
from .report_parser import ParsedReport, parse_report
from .scoring import IntelligenceScore

PASS = "Pass"
NEEDS_REVIEW = "Needs Review"
FAIL = "Fail"
NOT_APPLICABLE = "Not Applicable"

# Every GateFinding.gate tag quality.py can produce, mapped to the
# certification domain EICF v1 defines. test_certification.py asserts this
# covers every tag gate_report()/gate_corpus() can actually emit, so a
# future gate added without a matching entry here fails loudly instead of
# silently landing in a catch-all bucket.
DOMAIN_FOR_GATE: dict[str, str] = {
    "structure": "Intelligence Quality",
    "attack": "Intelligence Quality",
    "confidence": "Evidence Quality",
    "content-integrity": "Evidence Quality",
    "hype-language": "Evidence Quality",
    "reference-completeness": "Evidence Quality",
    "ioc-defanging": "Detection Quality",
    "sigma": "Detection Quality",
    "yara": "Detection Quality",
    "stix": "Detection Quality",
    "empty-detection": "Detection Quality",
    "corpus-duplication": "Evidence Quality",
    "corpus-ioc-reuse": "Evidence Quality",
}

GATE_DOMAINS = ("Intelligence Quality", "Evidence Quality", "Detection Quality")
ALL_DOMAINS = GATE_DOMAINS + ("Rendering Quality", "Publication Quality")


@dataclass
class DomainVerdict:
    domain: str
    verdict: str
    blocks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def verdict_for(blocks: list, warnings: list) -> str:
    if blocks:
        return FAIL
    if warnings:
        return NEEDS_REVIEW
    return PASS


def _bucket_gate_findings(findings: list[GateFinding]) -> dict[str, DomainVerdict]:
    buckets = {d: DomainVerdict(domain=d, verdict=PASS) for d in GATE_DOMAINS}
    for f in findings:
        domain = DOMAIN_FOR_GATE.get(f.gate, "Intelligence Quality")
        bucket = buckets[domain]
        (bucket.blocks if f.severity == "block" else bucket.warnings).append(
            f"[{f.gate}] {f.message}"
        )
    for bucket in buckets.values():
        bucket.verdict = verdict_for(bucket.blocks, bucket.warnings)
    return buckets


@dataclass
class RenderingResult:
    ran: bool
    ok: bool = False
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def _default_rendering_script() -> str:
    return str(Path(__file__).resolve().parents[2] / "renderer" / "certify-rendering.js")


def check_rendering(report_path: str, node_bin: str = "node",
                     script_path: str | None = None) -> RenderingResult:
    """Rendering Quality domain — shells out to ``certify-rendering.js``,
    which itself only calls ``report-renderer.js``'s ``parseReport()``/
    ``toHTMLDocument()``. A failure to even run the check (node missing,
    script missing, timeout) is reported distinctly (``ran=False``) from a
    real rendering defect (``ran=True, ok=False``) — an environment problem
    should read as "could not verify," never as a false claim that the
    report's rendering is broken.
    """
    script = script_path or _default_rendering_script()
    try:
        proc = subprocess.run(
            [node_bin, script, report_path],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return RenderingResult(ran=False, issues=[f"could not run rendering check: {exc}"])
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return RenderingResult(
            ran=False,
            issues=[f"rendering check produced non-JSON output (exit {proc.returncode}): "
                    f"{(proc.stderr or proc.stdout)[:300]}"],
        )
    return RenderingResult(
        ran=True, ok=bool(data.get("ok")),
        issues=list(data.get("issues", [])), warnings=list(data.get("warnings", [])),
        raw=data,
    )


@dataclass
class PublicationResult:
    checked: bool
    ok: bool = True
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# (html substring, human label) — facts already produced by
# fetch-live-intel.js / publish-report.js that this domain verifies are
# actually present in the shipped file; it generates none of them.
_REQUIRED_HTML_FACTS = (
    ('rel="canonical"', "canonical URL tag"),
    ('property="og:title"', "Open Graph title tag"),
    ('property="og:image"', "Open Graph image tag"),
    ('property="og:type"', "Open Graph type tag"),
    ('"@type":"Article"', "Article structured data (JSON-LD)"),
    ('name="robots"', "robots meta tag"),
)


def check_publication(html_path: str | None, slug: str,
                       sitemap_path: str | None = None,
                       index_path: str | None = None) -> PublicationResult:
    """Publication Quality domain — reads the already-shipped HTML/sitemap/
    index files and checks for presence of facts; generates nothing. Not
    applicable (not a failure) when no ``html_path`` is given, e.g.
    certifying a report before it has been published at all."""
    if not html_path:
        return PublicationResult(checked=False, warnings=[
            "no published HTML path given — Publication Quality not checked"
        ])
    path = Path(html_path)
    if not path.exists():
        return PublicationResult(checked=True, ok=False,
                                  issues=[f"published HTML not found: {html_path}"])
    html = path.read_text(errors="replace")

    issues = [
        f"missing {label} ({needle!r} not found)"
        for needle, label in _REQUIRED_HTML_FACTS if needle not in html
    ]
    warnings: list[str] = []
    if sitemap_path and Path(sitemap_path).exists():
        if slug not in Path(sitemap_path).read_text(errors="replace"):
            warnings.append(f"slug {slug!r} not found in {Path(sitemap_path).name}")
    if index_path and Path(index_path).exists():
        if slug not in Path(index_path).read_text(errors="replace"):
            warnings.append(f"slug {slug!r} not linked from {Path(index_path).name} navigation")

    return PublicationResult(checked=True, ok=not issues, issues=issues, warnings=warnings)


@dataclass
class CertificationReport:
    report_id: str
    title: str
    severity: str
    domains: dict[str, DomainVerdict]
    decision: str  # CERTIFIED | CERTIFIED WITH CONDITIONS | NOT CERTIFIED
    # GTIEP v1: a hand-authored report now has a real, computable score
    # (report_ingest.build_pipeline_result -> scoring.score), resolving
    # platform/open-issues.md Issue 3 item 3. Optional/None only as a
    # defensive default if certify() is ever called on something that
    # somehow can't be scored — not expected in normal operation.
    score: IntelligenceScore | None = None


def _overall_decision(verdicts: list[str]) -> str:
    if FAIL in verdicts:
        return "NOT CERTIFIED"
    if NEEDS_REVIEW in verdicts:
        return "CERTIFIED WITH CONDITIONS"
    return "CERTIFIED"


def certify(report_path: str, html_path: str | None = None,
            sitemap_path: str | None = None, index_path: str | None = None,
            node_bin: str = "node", corpus: dict[str, ParsedReport] | None = None,
            _rendering_check=check_rendering) -> CertificationReport:
    """Run all five certification domains for one report and return the
    aggregate verdict. ``_rendering_check`` is injectable so unit tests can
    stub out the Node subprocess call; production callers (``cli.py``) use
    the real default."""
    text = Path(report_path).read_text(errors="replace")
    report = parse_report(text)

    findings = list(gate_report(report).findings)
    if corpus:
        findings += gate_corpus(corpus).findings
    domains = _bucket_gate_findings(findings)

    rendering = _rendering_check(report_path, node_bin=node_bin)
    if not rendering.ran:
        r_verdict = NOT_APPLICABLE
    elif not rendering.ok:
        r_verdict = FAIL
    elif rendering.warnings:
        r_verdict = NEEDS_REVIEW
    else:
        r_verdict = PASS
    domains["Rendering Quality"] = DomainVerdict(
        "Rendering Quality", r_verdict, list(rendering.issues), list(rendering.warnings)
    )

    slug = Path(html_path).stem if html_path else Path(report_path).stem
    publication = check_publication(html_path, slug, sitemap_path, index_path)
    if not publication.checked:
        p_verdict = NOT_APPLICABLE
    elif not publication.ok:
        p_verdict = FAIL
    elif publication.warnings:
        p_verdict = NEEDS_REVIEW
    else:
        p_verdict = PASS
    domains["Publication Quality"] = DomainVerdict(
        "Publication Quality", p_verdict, list(publication.issues), list(publication.warnings)
    )

    decision = _overall_decision([domains[d].verdict for d in ALL_DOMAINS])

    # GTIEP v1: build_pipeline_result() is the first thing that can score a
    # hand-authored report at all (see report_ingest.py's docstring) — this
    # re-parses front matter/sections already read above, not re-reading
    # the file a second time, so the cost is a pure-function re-derivation,
    # not new I/O.
    pipeline_result = build_pipeline_result(report)

    return CertificationReport(
        report_id=str(report.metadata.get("report_id") or Path(report_path).stem),
        title=report.title, severity=report.severity,
        domains=domains, decision=decision, score=pipeline_result.score,
    )


# --------------------------------------------------------------------------
# Release Governance document
# --------------------------------------------------------------------------

def _scorecard_table(cert: CertificationReport) -> str:
    lines = ["| Domain | Verdict |", "|---|---|"]
    for name in ALL_DOMAINS:
        lines.append(f"| {name} | {cert.domains[name].verdict} |")
    return "\n".join(lines)


def _findings_section(heading: str, dv: DomainVerdict) -> str:
    lines = [f"## {heading}", "", f"**Verdict:** {dv.verdict}", ""]
    if dv.blocks:
        lines.append("**Blocking findings:**")
        lines += [f"- {b}" for b in dv.blocks]
        lines.append("")
    if dv.warnings:
        lines.append("**Warnings:**")
        lines += [f"- {w}" for w in dv.warnings]
        lines.append("")
    if not dv.blocks and not dv.warnings:
        lines.append("No findings.")
        lines.append("")
    return "\n".join(lines)


def _executive_summary(cert: CertificationReport) -> str:
    failing = [n for n in ALL_DOMAINS if cert.domains[n].verdict == FAIL]
    review = [n for n in ALL_DOMAINS if cert.domains[n].verdict == NEEDS_REVIEW]
    na = [n for n in ALL_DOMAINS if cert.domains[n].verdict == NOT_APPLICABLE]
    if cert.decision == "CERTIFIED":
        body = (
            f"**{cert.report_id}** passed all applicable certification domains "
            f"with no blocking or advisory findings. Eligible for publication "
            f"as certified."
        )
    elif cert.decision == "CERTIFIED WITH CONDITIONS":
        body = (
            f"**{cert.report_id}** has no blocking findings but carries "
            f"advisory findings in: {', '.join(review)}. Eligible for "
            f"publication; the advisory items should be reviewed by an "
            f"analyst but do not themselves block release."
        )
    else:
        body = (
            f"**{cert.report_id}** has blocking findings in: "
            f"{', '.join(failing)}. **Not eligible for publication** until "
            f"resolved and re-certified."
        )
    if na:
        body += f" Not checked in this pass (see Known Limitations): {', '.join(na)}."
    return body


def render_release_governance_markdown(cert: CertificationReport) -> str:
    """The per-report Release Governance document EICF v1 specifies: a
    9-part structure, plus one justified addition (Publication Findings —
    EICF v1's own Certification Domains section names Publication Quality
    as a fifth domain, but its Required Output list only names four
    Findings sections; omitting the fifth domain's results here would mean
    reporting less than what was actually certified)."""
    d = cert.domains
    parts = [
        f"# Release Governance Record — {cert.report_id}",
        "",
        f"**Title:** {cert.title or '(untitled)'}  ",
        f"**Severity:** {cert.severity or 'not set'}  ",
        f"**Certification Decision:** {cert.decision}",
        "",
        "## Executive Summary",
        "",
        _executive_summary(cert),
        "",
        "## Certification Summary",
        "",
        _scorecard_table(cert),
        "",
        _findings_section("Quality Findings", d["Intelligence Quality"]),
        _findings_section("Evidence Findings", d["Evidence Quality"]),
        _findings_section("Detection Findings", d["Detection Quality"]),
        _findings_section("Rendering Findings", d["Rendering Quality"]),
        _findings_section("Publication Findings", d["Publication Quality"]),
        "## Commercial Assessment",
        "",
        _commercial_assessment(cert),
        "",
        "## Known Limitations",
        "",
        _known_limitations(cert),
        "",
        "## Certification Decision",
        "",
        f"**{cert.decision}**",
        "",
    ]
    return "\n".join(parts)


def _commercial_assessment(cert: CertificationReport) -> str:
    lines = []
    if cert.severity in ("CRITICAL", "HIGH"):
        lines.append(
            f"Severity **{cert.severity}** qualifies this report for "
            "enterprise subscription distribution and executive-briefing "
            "channels on urgency alone, subject to the certification "
            "decision above."
        )
    if d_verdict := cert.domains.get("Detection Quality"):
        if d_verdict.verdict in (PASS, NEEDS_REVIEW):
            lines.append(
                "Detection content (Sigma/YARA/Suricata, where present) "
                "passed structural validation, supporting detection-pack "
                "and MSSP delivery channels."
            )
    if cert.score is not None:
        s = cert.score
        lines.append(
            f"Quantitative score (GTIEP v1 quality framework): **{s.overall}/100**, "
            f"tier **{s.tier}** (threshold {s.threshold}, "
            f"{'eligible' if s.eligible else 'not eligible'})."
        )
        lines.append(
            "This is the first time a hand-authored report has had a real, "
            "reproducible score — see `Sentinel-APEX/engine/sentinel_engine/"
            "report_ingest.py`'s `build_pipeline_result()` and "
            "`platform/open-issues.md` Issue 3 item 3. Whether the current "
            "threshold and weighting are the *right* bar for this report's "
            "shape (low public-IOC-count, high analytical depth) remains "
            "an open product-tiering question this score does not by "
            "itself resolve — it only makes the question answerable with "
            "real, per-dimension data instead of no data at all."
        )
    else:
        lines.append(
            "No quantitative commercial/tier score could be computed for "
            "this report — see `platform/open-issues.md` Issue 3 item 3."
        )
    return "\n".join(f"- {line}" for line in lines)


def _known_limitations(cert: CertificationReport) -> str:
    lines = [
        "- Commercial/tier scoring for hand-authored reports is now "
        "quantitative (GTIEP v1), but the threshold/weighting was tuned "
        "against automated-pipeline content originally — whether it's the "
        "right bar for this report shape is still an open product "
        "question (see Commercial Assessment above; "
        "`platform/open-issues.md` Issue 3 item 3).",
        "- Rendering Quality requires a working `node` runtime in the "
        "certifying environment; if the check could not run at all, its "
        "verdict is \"Not Applicable,\" not a false pass or fail.",
        "- Publication Quality checks *presence* of required tags/fields "
        "in the shipped HTML, not their rendered correctness end-to-end "
        "(e.g. that the OG image actually renders as intended) — that was "
        "verified once, manually, via Playwright screenshot at first "
        "publication (EIPP v1), not re-verified automatically here.",
        "- ATT&CK technique ID validation runs against a curated subset of "
        "MITRE ATT&CK Enterprise (`attack_mapper.KNOWN_TECHNIQUES`), not "
        "the full framework; unrecognized-but-well-formed IDs warn for "
        "manual verification rather than block.",
        "- Corpus-level gates (cross-report duplication/IOC reuse) only "
        "run when a corpus is explicitly supplied; a single-report "
        "certification pass cannot detect templated content across "
        "reports on its own.",
    ]
    return "\n".join(lines)
