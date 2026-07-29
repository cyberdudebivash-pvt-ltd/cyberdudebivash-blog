"""Pipeline orchestrator: source -> normalize -> enrich -> correlate ->
detect -> draft -> self-gate.

The output draft contains ONLY evidence-backed content: extracted IOCs
(defanged), technique mappings with their triggering evidence, enrichment
values that came back from live authoritative sources, and prior context
from the knowledge graph. Sections with no evidence are omitted, never
padded with boilerplate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detection_builder import DetectionArtifacts, build_all
from .enrichment import Enricher
from .ioc_extractor import defang
from .knowledge_graph import KnowledgeGraph
from .models import CVEEnrichment, GateResult, NormalizedDoc, SourceDocument
from .normalizer import normalize
from .scoring import DEFAULT_THRESHOLD, IntelligenceScore, score
from .sigma_builder import build_rules


@dataclass
class PipelineResult:
    report_id: str
    normalized: NormalizedDoc
    enrichments: list[CVEEnrichment] = field(default_factory=list)
    prior_context: list[str] = field(default_factory=list)
    sigma_rules: list[str] = field(default_factory=list)
    detections: list[DetectionArtifacts] = field(default_factory=list)
    suricata_rules: list[str] = field(default_factory=list)
    draft_markdown: str = ""
    gate: GateResult = field(default_factory=GateResult)
    score: IntelligenceScore | None = None
    # Section name -> body, for a hand-authored (Markdown-sectioned) report.
    # Left empty for this automated pipeline (never set below) — populated
    # only by report_ingest.py's build_pipeline_result() for published
    # analyst reports. scoring.py's GTIEP v1 dimensions read this and
    # degrade to a documented neutral default when it's empty, so this
    # addition changes nothing about how automated reports score.
    raw_sections: dict[str, str] = field(default_factory=dict)


def run(
    source: SourceDocument,
    report_id: str,
    enricher: Enricher | None = None,
    graph: KnowledgeGraph | None = None,
    threshold: int = DEFAULT_THRESHOLD,
) -> PipelineResult:
    doc = normalize(source)
    result = PipelineResult(report_id=report_id, normalized=doc)

    if enricher is not None:
        result.enrichments = [enricher.enrich_cve(cve) for cve in doc.cves]

    if graph is not None:
        result.prior_context = graph.prior_context(doc)
        graph.ingest(doc, report_id)

    references = [source.source_url] if source.source_url else []
    result.sigma_rules = build_rules(doc.techniques, references=references)
    iocs = [i for i in doc.iocs if i.type.value != "cve"]
    result.detections, result.suricata_rules = build_all(
        doc.techniques, iocs=iocs, references=references
    )
    # Score before rendering so the draft can carry the publication decision.
    result.score = score(result, threshold=threshold)
    result.draft_markdown = render_draft(result, source)
    return result


_DIM_LABELS = {
    "evidence_quality": "Evidence Quality",
    "original_analysis": "Original Analysis",
    "detection_value": "Detection Value",
    "soc_value": "SOC Value",
    "dfir_value": "DFIR Value",
    "executive_value": "Executive Value",
    "commercial_value": "Commercial Value",
    "analyst_confidence": "Analyst Confidence",
    "seo_value": "SEO Value",
}


def _render_score(s) -> list[str]:
    decision = "PUBLISH" if s.eligible else "HOLD — below threshold"
    lines = [
        "## Intelligence Score",
        "",
        f"- **Overall publication score:** {s.overall}/100 "
        f"(threshold {s.threshold}) → **{decision}**",
        f"- **Commercial tier:** {s.tier}",
        "",
        "| Dimension | Score | Basis |",
        "|---|---|---|",
    ]
    for key, label in _DIM_LABELS.items():
        lines.append(f"| {label} | {s.dimensions.get(key, 0)} | {s.rationale.get(key, '')} |")
    lines.append("")
    return lines


def render_draft(result: PipelineResult, source: SourceDocument) -> str:
    doc = result.normalized
    lines: list[str] = [
        f"# {doc.title}",
        "",
        f"- **Report ID:** {result.report_id}",
        f"- **Source:** {source.source_url or source.source_name or 'n/a'}",
        f"- **Published:** {doc.published or 'unknown'}",
        "",
    ]
    if result.score is not None:
        lines += _render_score(result.score)
    lines += ["## Verified Facts", ""]
    if doc.cves:
        lines.append(f"- CVEs referenced in source: {', '.join(doc.cves)}")
    if doc.entities:
        for e in doc.entities:
            lines.append(f"- Named {e.type.replace('_', ' ')}: **{e.name}**")
    if not doc.cves and not doc.entities:
        lines.append("- No named entities or CVEs identified in source material.")

    for enr in result.enrichments:
        lines += ["", f"## Enrichment — {enr.cve_id}", ""]
        if enr.status == "enriched":
            if enr.cvss_score is not None:
                lines.append(f"- CVSS: **{enr.cvss_score}** (`{enr.cvss_vector}`)")
            if enr.epss_score is not None:
                lines.append(
                    f"- EPSS: **{enr.epss_score:.4f}** "
                    f"(percentile {enr.epss_percentile:.2%})"
                )
            if enr.kev_listed is not None:
                lines.append(
                    "- CISA KEV: **listed — known exploited**"
                    if enr.kev_listed else "- CISA KEV: not listed at report time"
                )
            if enr.description:
                lines.append(f"- NVD description: {enr.description}")
        else:
            lines.append(
                "- Enrichment sources unreachable at build time — "
                "scores intentionally omitted (never estimated)."
            )

    if result.prior_context:
        lines += ["", "## Prior Intelligence Context", ""]
        lines += [f"- {note}" for note in result.prior_context]

    if doc.techniques:
        lines += ["", "## MITRE ATT&CK Mapping (evidence-based)", ""]
        for t in doc.techniques:
            lines.append(
                f"- **{t.technique_id}** {t.name} ({t.tactic}) — "
                f"{t.confidence.value} CONFIDENCE — evidence: “{t.evidence}”"
            )

    iocs = [i for i in doc.iocs if i.type.value != "cve"]
    if iocs:
        lines += ["", "## IOC Intelligence", ""]
        for ioc in iocs:
            lines.append(f"- `{defang(ioc.value, ioc.type)}` ({ioc.type.value})")
    else:
        lines += [
            "", "## IOC Intelligence", "",
            "- No confirmed public IOCs in source material at report time.",
        ]

    if result.detections:
        lines += ["", "## Detection Engineering (multi-platform)", ""]
        for art in result.detections:
            lines += [f"### {art.technique_id} — {art.title}", ""]
            fmt_lang = {"sigma": "yaml", "kql": "kql",
                        "splunk": "spl", "osquery": "sql"}
            fmt_label = {"sigma": "Sigma (SIEM-agnostic)",
                         "kql": "Microsoft Defender / Sentinel (KQL)",
                         "splunk": "Splunk (SPL)", "osquery": "OSQuery"}
            for fmt, body in art.formats().items():
                lines += [f"**{fmt_label[fmt]}**", "",
                          f"```{fmt_lang[fmt]}", body.rstrip(), "```", ""]
    elif result.sigma_rules:
        lines += ["", "## Detection Rules (Sigma)", ""]
        for rule in result.sigma_rules:
            lines += ["```yaml", rule.rstrip(), "```", ""]

    if result.suricata_rules:
        lines += ["", "## Network Detection (Suricata)", "",
                  "```suricata"]
        lines += [r for r in result.suricata_rules]
        lines += ["```", ""]

    return "\n".join(lines).rstrip() + "\n"
