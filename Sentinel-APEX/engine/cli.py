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
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel_engine import pipeline, quality, report_parser  # noqa: E402
from sentinel_engine.enrichment import Enricher  # noqa: E402
from sentinel_engine.knowledge_graph import KnowledgeGraph  # noqa: E402
from sentinel_engine.models import SourceDocument  # noqa: E402
from sentinel_engine.normalizer import normalize  # noqa: E402


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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
