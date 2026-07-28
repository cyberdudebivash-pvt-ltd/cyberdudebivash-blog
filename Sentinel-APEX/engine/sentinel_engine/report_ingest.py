"""Adapter: a published, hand-authored ParsedReport -> NormalizedDoc.

knowledge_graph.py's KnowledgeGraph.ingest() only accepts a NormalizedDoc,
and until this module existed the only place that built one was
normalizer.py's automated SourceDocument -> NormalizedDoc path (GIKEP v1
found this: KnowledgeGraph() is never constructed anywhere in production
code, and NormalizedDoc() is never constructed anywhere except
normalizer.py — so Sentinel-APEX/reports/published/ reports, the ones that
actually passed the quality gate, had never once been ingested into the
graph).

Deliberately thin, mirroring normalizer.py's own composition exactly: reuse
the same extractors, unchanged, against the report's section bodies (not
report.raw) so the front-matter `sources:` URL list is never handed to
extract_iocs/extract_cves at all -- it is structured metadata, not prose to
mine, and feeding it in would sit before the body's own References section
marker where the already-tested citation-URL exclusion (ioc_extractor.py)
cannot reach it. Section bodies alone reconstruct the authored prose in
document order, References section included in its natural position, so
that exclusion logic applies exactly as it already does for the automated
pipeline's reports.
"""

from __future__ import annotations

import re

from .attack_mapper import map_techniques
from .entities import extract_entities
from .ioc_extractor import extract_cves, extract_iocs
from .models import NormalizedDoc
from .report_parser import ParsedReport

# Fenced code/YAML blocks (e.g. an embedded Sigma rule) describe detection
# logic, not analyst-asserted evidence: a rule's own `falsepositives:` or
# `selection_child:` list legitimately names exactly the process/technique
# keywords the mapper looks for (mshta.exe, powershell.exe, "scheduled
# tasks" as a *benign* example) without asserting any of it was observed in
# this incident. Confirmed empirically against SA-2026-0001: its embedded
# Sigma rule alone produced four spurious technique matches (T1053.005,
# T1059.001, T1059.003, T1218.005) before this exclusion existed.
_RE_FENCED_CODE = re.compile(r"```.*?```", re.DOTALL)


def normalize_report(report: ParsedReport) -> NormalizedDoc:
    # Section names are preserved (not just bodies) so a standalone
    # "References" line survives into the reconstructed text -- ioc_extractor's
    # citation-marker exclusion requires exactly that line shape, and a
    # ParsedReport's sections dict has already stripped the `##` heading
    # markers by this point.
    text = "\n\n".join(f"{name}\n{body}" for name, body in report.sections.items())
    text = _RE_FENCED_CODE.sub("", text)
    return NormalizedDoc(
        title=report.title,
        text=text,
        source_url="",
        source_name=str(report.metadata.get("analyst") or "Sentinel APEX"),
        published=str(report.metadata.get("date") or ""),
        iocs=extract_iocs(text),
        cves=extract_cves(text),
        techniques=map_techniques(text),
        entities=extract_entities(text),
    )
