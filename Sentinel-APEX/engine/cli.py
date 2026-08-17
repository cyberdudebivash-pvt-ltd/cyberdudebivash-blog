#!/usr/bin/env python3
"""SENTINEL APEX Intelligence Engine CLI.

Usage (from Sentinel-APEX/engine/):

  python3 cli.py normalize <source.txt> [--url URL]
      Normalize a raw source article; print extracted evidence as JSON.

  python3 cli.py gate <report.txt> [more reports...]
      Run publication quality gates on published report dump(s).
      With 2+ reports, corpus-level duplication gates also run.
      Exit code 1 if any report fails a blocking gate.

  python3 cli.py run <source.txt> --id RPT-ID [--url URL] [--graph kg.json] [--enrich]
      Full pipeline: normalize -> (enrich) -> correlate -> detect -> draft.
      Prints the gated draft markdown; persists the knowledge graph if given.

  python3 cli.py enrich <CVE-ID>
      Live NVD/EPSS/KEV enrichment for one CVE (network required).

  python3 cli.py detect <source.txt> [--url URL]
      Compile multi-platform detections (Sigma/KQL/Splunk/OSQuery + Suricata)
      from a raw source's evidence. Prints each format.

  python3 cli.py score <source.txt> --id RPT-ID [--url URL] [--graph kg.json]
                       [--enrich] [--threshold N]
      Run the full pipeline and print the intelligence score (10 dimensions,
      overall publication score, tier, eligibility) as JSON. Exit 0 if
      publish-eligible, 2 if held below threshold.

  python3 cli.py certify <report.md> [--html published.html] [--sitemap sitemap.xml]
                         [--index index.html] [--node node]
      Enterprise Intelligence Certification Framework (EICF v1): runs the
      quality gate, the canonical renderer, and (if --html is given) the
      shipped publication artifacts through all five certification domains
      and prints a Release Governance Markdown record. Exit 0 if CERTIFIED
      or CERTIFIED WITH CONDITIONS, 1 if NOT CERTIFIED.

  python3 cli.py graph <report.md> --id REPORT-ID [--graph kg.json]
      GIKEP v1: ingest one already-published, quality-gated report
      (Sentinel-APEX/reports/published/) into the knowledge graph.
      `run`/`score` already do this for the pre-publication pipeline's own
      NormalizedDoc; this is the equivalent for a final, hand-authored
      report file, which had no path into the graph before. Prints any
      prior context the graph already had, then the graph's stats as JSON.

  python3 cli.py reportx-gate <bundle.json> [--as-of YYYY-MM-DD] [--json]
      ReportX commercial-readiness validator (docs/reportx/). Loads a
      ReportBundle from JSON (sentinel_engine.reportx.bundle_io schema),
      evaluates all 23 commercial-readiness controls, and prints the
      COMMERCIAL READINESS matrix. Add --json for the machine-readable
      form. Exit 0 only on a true 23/23 PASS; exit 1 otherwise (any FAIL
      or BLOCKED row) -- never exits 0 on a partial result.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel_engine import certification, pipeline, quality, report_parser  # noqa: E402
from sentinel_engine.detection_builder import build_all  # noqa: E402
from sentinel_engine.enrichment import Enricher  # noqa: E402
from sentinel_engine.ioc_extractor import IOCType  # noqa: E402
from sentinel_engine.knowledge_graph import KnowledgeGraph  # noqa: E402
from sentinel_engine.models import SourceDocument  # noqa: E402
from sentinel_engine.normalizer import normalize  # noqa: E402
from sentinel_engine.report_ingest import normalize_report  # noqa: E402


def cmd_normalize(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    doc = normalize(SourceDocument(raw_text=text, source_url=args.url or ""))
    print(json.dumps(doc.to_dict(), indent=2))
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    reports = {
        Path(p).name: report_parser.parse_report(
            Path(p).read_text(errors="replace")
        )
        for p in args.reports
    }
    failed = False
    for name, parsed in sorted(reports.items()):
        result = quality.gate_report(parsed)
        status = "PASS" if result.passed else "FAIL"
        failed |= not result.passed
        print(f"[{status}] {name} — {parsed.title[:70]}")
        for f in result.findings:
            print(f"    {f.severity.upper():5s} [{f.gate}] {f.message}")
    if len(reports) > 1:
        print("\n== corpus gates ==")
        corpus = quality.gate_corpus(reports)
        failed |= not corpus.passed
        if not corpus.findings:
            print("    no corpus-level findings")
        for f in corpus.findings:
            print(f"    {f.severity.upper():5s} [{f.gate}] {f.message}")
    return 1 if failed else 0


def cmd_run(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    source = SourceDocument(raw_text=text, source_url=args.url or "")
    graph = KnowledgeGraph.load(args.graph) if args.graph else None
    enricher = Enricher() if args.enrich else None
    result = pipeline.run(source, args.id, enricher=enricher, graph=graph)
    if graph is not None and args.graph:
        graph.save(args.graph)
    print(result.draft_markdown)
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    record = Enricher().enrich_cve(args.cve_id)
    print(json.dumps(dataclasses.asdict(record), indent=2))
    return 0 if record.status == "enriched" else 1


def cmd_detect(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    doc = normalize(SourceDocument(raw_text=text, source_url=args.url or ""))
    iocs = [i for i in doc.iocs if i.type != IOCType.CVE]
    refs = [args.url] if args.url else []
    artifacts, suricata = build_all(doc.techniques, iocs=iocs, references=refs)
    if not artifacts and not suricata:
        print("No detections: source yielded no mapped techniques or network IOCs.")
        return 0
    for art in artifacts:
        print(f"\n===== {art.technique_id} — {art.title} =====")
        for fmt, body in art.formats().items():
            print(f"\n--- {fmt} ---\n{body}")
    if suricata:
        print("\n===== Suricata (network) =====")
        for rule in suricata:
            print(rule)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    source = SourceDocument(raw_text=text, source_url=args.url or "")
    graph = KnowledgeGraph.load(args.graph) if args.graph else None
    enricher = Enricher() if args.enrich else None
    result = pipeline.run(
        source, args.id, enricher=enricher, graph=graph, threshold=args.threshold
    )
    if graph is not None and args.graph:
        graph.save(args.graph)
    print(json.dumps(result.score.to_dict(), indent=2))
    return 0 if result.score.eligible else 2


def cmd_graph(args: argparse.Namespace) -> int:
    report = report_parser.parse_report(Path(args.report).read_text(errors="replace"))
    doc = normalize_report(report)
    graph = KnowledgeGraph.load(args.graph) if args.graph else KnowledgeGraph()
    prior = graph.prior_context(doc)
    graph.ingest(doc, args.id)
    if args.graph:
        graph.save(args.graph)
    if prior:
        print("== prior context ==")
        for note in prior:
            print(f"  - {note}")
    print(json.dumps(graph.stats(), indent=2))
    return 0


def cmd_certify(args: argparse.Namespace) -> int:
    cert = certification.certify(
        args.report, html_path=args.html or None,
        sitemap_path=args.sitemap or None, index_path=args.index or None,
        node_bin=args.node,
    )
    print(certification.render_release_governance_markdown(cert))
    return 1 if cert.decision == "NOT CERTIFIED" else 0


def cmd_reportx_gate(args: argparse.Namespace) -> int:
    from datetime import date as date_cls

    from sentinel_engine.reportx.bundle_io import run_gate_on_file

    as_of = date_cls.fromisoformat(args.as_of) if args.as_of else None
    markdown, as_json = run_gate_on_file(args.bundle, as_of=as_of)
    print(as_json if args.json else markdown)
    return 0 if "FINAL VERDICT: COMMERCIAL-READY (23/23 PASS)" in markdown else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("normalize", help="normalize a raw source article")
    p.add_argument("source")
    p.add_argument("--url", default="")
    p.set_defaults(func=cmd_normalize)

    p = sub.add_parser("gate", help="quality-gate published report dumps")
    p.add_argument("reports", nargs="+")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("run", help="full pipeline on a raw source")
    p.add_argument("source")
    p.add_argument("--id", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--graph", default="")
    p.add_argument("--enrich", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("enrich", help="live CVE enrichment (NVD/EPSS/KEV)")
    p.add_argument("cve_id")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("detect", help="compile multi-platform detections")
    p.add_argument("source")
    p.add_argument("--url", default="")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("score", help="intelligence scoring + publication decision")
    p.add_argument("source")
    p.add_argument("--id", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--graph", default="")
    p.add_argument("--enrich", action="store_true")
    p.add_argument("--threshold", type=int, default=60)
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("graph", help="ingest a published report into the knowledge graph")
    p.add_argument("report")
    p.add_argument("--id", required=True)
    p.add_argument("--graph", default="")
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("certify", help="run the EICF v1 certification framework on one report")
    p.add_argument("report")
    p.add_argument("--html", default="", help="path to the already-published HTML page, if any")
    p.add_argument("--sitemap", default="", help="path to sitemap.xml, for the Publication Quality domain")
    p.add_argument("--index", default="", help="path to index.html, for the Publication Quality domain")
    p.add_argument("--node", default="node", help="node binary to invoke for the Rendering Quality domain")
    p.set_defaults(func=cmd_certify)

    p = sub.add_parser("reportx-gate", help="ReportX commercial-readiness validator (23-control matrix)")
    p.add_argument("bundle", help="path to a ReportBundle JSON file")
    p.add_argument("--as-of", default="", help="ISO date to evaluate statistics freshness against (default: today)")
    p.add_argument("--json", action="store_true", help="print the machine-readable JSON form instead of Markdown")
    p.set_defaults(func=cmd_reportx_gate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
