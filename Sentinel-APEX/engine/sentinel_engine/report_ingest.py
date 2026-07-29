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
from .pipeline import PipelineResult
from .quality import gate_report
from .report_parser import ParsedReport
from .scoring import DEFAULT_THRESHOLD, score

# Fenced code/YAML blocks (e.g. an embedded Sigma rule) describe detection
# logic, not analyst-asserted evidence: a rule's own `falsepositives:` or
# `selection_child:` list legitimately names exactly the process/technique
# keywords the mapper looks for (mshta.exe, powershell.exe, "scheduled
# tasks" as a *benign* example) without asserting any of it was observed in
# this incident. Confirmed empirically against SA-2026-0001: its embedded
# Sigma rule alone produced four spurious technique matches (T1053.005,
# T1059.001, T1059.003, T1218.005) before this exclusion existed.
_RE_FENCED_CODE = re.compile(r"```.*?```", re.DOTALL)

# The 14 official MITRE ATT&CK Enterprise tactic names. A report's own
# "MITRE ATT&CK Mapping" table states one of these per row as a structural
# classification label (the Tactic column) -- not evidentiary prose -- but
# several collide with attack_mapper.py's own _LEXICON phrase patterns,
# because ATT&CK's tactic vocabulary and everyday technique-describing prose
# share the same words: "Command and Control" -> T1071, "Lateral Movement"
# -> T1021, "Privilege Escalation" -> T1068, "Exfiltration" -> T1041 (via the
# `exfiltrat` substring). Confirmed against SA-2026-0003: its table states
# "Command and Control" as T1105's tactic label, which produced a false
# T1071 mapping with no supporting evidence anywhere in the report
# (platform/open-issues.md Issue 9). The other three collisions are latent
# -- not yet observed in a published report -- but share the exact same
# mechanism, so are closed here rather than left for a fourth occurrence.
_ATTACK_TACTIC_NAMES = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
)
_RE_ATTACK_SECTION_NAME = re.compile(r"att&ck|mitre", re.IGNORECASE)
_RE_TACTIC_CELL = re.compile(
    r"\|\s*(?:" + "|".join(re.escape(t) for t in _ATTACK_TACTIC_NAMES) + r")\s*\|"
)


def _blank_tactic_labels(section_body: str) -> str:
    """Blank a table's own Tactic-column values within an ATT&CK/MITRE-named
    section, so attack_mapper.py's keyword-lexicon pass can't mistake this
    platform's own tactic classification labels for evidentiary prose.
    Scoped to an exact, pipe-bounded cell match against the closed, official
    14-tactic vocabulary -- the Technique ID and Evidence columns, and any
    prose using these same words outside a table cell, are untouched, so the
    explicit-technique-ID citation pass (which reads the ID column) is
    unaffected."""
    return _RE_TACTIC_CELL.sub("| |", section_body)


def normalize_report(report: ParsedReport) -> NormalizedDoc:
    # Section names are preserved (not just bodies) so a standalone
    # "References" line survives into the reconstructed text -- ioc_extractor's
    # citation-marker exclusion requires exactly that line shape, and a
    # ParsedReport's sections dict has already stripped the `##` heading
    # markers by this point.
    text = "\n\n".join(f"{name}\n{body}" for name, body in report.sections.items())
    text = _RE_FENCED_CODE.sub("", text)

    # A second variant, used only for technique mapping: an ATT&CK/MITRE-
    # named section's own Tactic-column labels are structural output, not
    # evidentiary prose (see _blank_tactic_labels). IOC/CVE/entity extraction
    # deliberately keep reading the unmodified `text` above -- this defect is
    # specific to map_techniques()'s keyword-lexicon pass and out of scope
    # for the other three extractors.
    text_for_techniques = "\n\n".join(
        f"{name}\n{_blank_tactic_labels(body) if _RE_ATTACK_SECTION_NAME.search(name) else body}"
        for name, body in report.sections.items()
    )
    text_for_techniques = _RE_FENCED_CODE.sub("", text_for_techniques)

    return NormalizedDoc(
        title=report.title,
        text=text,
        source_url="",
        source_name=str(report.metadata.get("analyst") or "Sentinel APEX"),
        published=str(report.metadata.get("date") or ""),
        iocs=extract_iocs(text),
        cves=extract_cves(text),
        techniques=map_techniques(text_for_techniques),
        entities=extract_entities(text),
    )


def build_pipeline_result(report: ParsedReport, threshold: int = DEFAULT_THRESHOLD) -> PipelineResult:
    """A hand-authored report has never had a scoreable PipelineResult before
    this (GTIEP v1) — `certification.py`'s commercial assessment explicitly
    refuses to produce a number for hand-authored reports because none
    existed (`platform/open-issues.md` Issue 3 item 3). This builds one:
    `normalized` via `normalize_report()` above (unchanged), `gate` via the
    same `gate_report()` the CLI's `gate` subcommand already runs, and
    `raw_sections=report.sections` so `scoring.py`'s GTIEP v1 dimensions
    (report structure, defensive guidance, embedded detection content, ...)
    have real data instead of degrading to their neutral defaults.
    `enrichments`/`prior_context`/`sigma_rules` stay at their empty
    defaults — a hand-authored report's evidence for those lives in its own
    prose, not in engine-computed artifacts, and inventing fake ones here
    would be exactly the fabrication this platform's content governance
    prohibits."""
    doc = normalize_report(report)
    gate = gate_report(report)
    result = PipelineResult(
        report_id=str(report.metadata.get("report_id") or ""),
        normalized=doc,
        gate=gate,
        raw_sections=dict(report.sections),
    )
    result.score = score(result, threshold=threshold, gate=gate)
    return result
