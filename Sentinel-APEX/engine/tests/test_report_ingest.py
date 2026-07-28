from pathlib import Path

from sentinel_engine.knowledge_graph import KnowledgeGraph
from sentinel_engine.report_ingest import normalize_report
from sentinel_engine.report_parser import parse_report

REPORTS_ROOT = Path(__file__).parent.parent.parent / "reports"
REAL_REPORT = REPORTS_ROOT / "published" / "SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md"
REAL_REPORT_0003 = REPORTS_ROOT / "published" / "SA-2026-0003-teamcity-cve-2024-27198-27199-auth-bypass.md"


def _real_report():
    return parse_report(REAL_REPORT.read_text())


def _real_report_0003():
    return parse_report(REAL_REPORT_0003.read_text())


def test_normalize_report_extracts_the_real_cves():
    doc = normalize_report(_real_report())
    assert doc.cves == ["CVE-2026-45659", "CVE-2026-50522", "CVE-2026-56164", "CVE-2026-58644"]


def test_normalize_report_extracts_clean_attack_techniques_only():
    # T1190 and T1505.003 are cleanly, explicitly cited with no hedge in
    # their own table row. T1552.001/T1606 are cited too but aren't in the
    # curated KNOWN_TECHNIQUES set (existing, correct behavior -- the
    # quality gate warns on those, it doesn't silently drop them from
    # review). See also test_attack_mapper.py's markdown-table-row test.
    ids = {t.technique_id for t in normalize_report(_real_report()).techniques}
    assert "T1190" in ids
    assert "T1505.003" in ids


def test_normalize_report_excludes_the_embedded_sigma_rule_from_technique_mapping():
    # Before the fenced-code exclusion, the embedded Sigma rule's own
    # selection/falsepositive criteria (mshta.exe, powershell.exe, "scheduled
    # tasks" as a named *benign* case) produced four spurious technique
    # matches that were never asserted by the analyst's own prose.
    ids = {t.technique_id for t in normalize_report(_real_report()).techniques}
    assert "T1053.005" not in ids
    assert "T1059.001" not in ids
    assert "T1059.003" not in ids
    assert "T1218.005" not in ids


def test_normalize_report_excludes_front_matter_source_urls_from_iocs():
    # The front-matter `sources:` list (nvd.nist.gov, cisa.gov, ...) is
    # structured metadata, not prose citing IOCs -- and even if it were fed
    # in, ioc_extractor's citation-marker exclusion needs a standalone
    # "References" line, which only exists because section names are
    # preserved when reconstructing text (see report_ingest.py).
    iocs = normalize_report(_real_report()).iocs
    values = {i.value for i in iocs}
    assert not any("nvd.nist.gov" in v or "cisa.gov" in v or "thehackernews" in v for v in values)


def test_normalize_report_title_and_published_come_from_front_matter():
    doc = normalize_report(_real_report())
    assert "SharePoint" in doc.title
    assert doc.published == "2026-07-27"


def test_normalize_report_excludes_attack_table_tactic_label_false_positive():
    # SA-2026-0003's own MITRE ATT&CK Mapping table states "Command and
    # Control" as the Tactic label for its T1105 row -- standard ATT&CK
    # vocabulary, not a claim that a C2 channel was used. Before
    # _blank_tactic_labels, this matched _LEXICON's c2/command-and-control
    # pattern and produced a false T1071 mapping with no supporting evidence
    # anywhere in the report (platform/open-issues.md Issue 9).
    ids = {t.technique_id for t in normalize_report(_real_report_0003()).techniques}
    assert "T1071" not in ids


def test_normalize_report_still_maps_the_genuine_sa_2026_0003_techniques():
    # The tactic-label fix must not cost the report's real, correctly-cited
    # techniques -- including T1105 itself, cited via the same table row the
    # false T1071 positive came from (the ID column is untouched).
    ids = {t.technique_id for t in normalize_report(_real_report_0003()).techniques}
    assert {"T1190", "T1059.003", "T1105", "T1486", "T1027"}.issubset(ids)


def test_real_report_can_be_ingested_into_the_knowledge_graph(tmp_path):
    # This is the actual gap GIKEP v1 found: KnowledgeGraph.ingest() was
    # fully coded and tested, but nothing in production code ever built a
    # NormalizedDoc from a published, quality-gated report to feed it --
    # SA-2026-0001 had never once been ingested into the graph.
    kg = KnowledgeGraph()
    kg.ingest(normalize_report(_real_report()), "SA-2026-0001")
    stats = kg.stats()
    assert stats["by_type"]["cve"] == 4
    assert stats["by_type"]["technique"] >= 2
    assert stats["by_type"]["vendor"] >= 1

    path = tmp_path / "kg.json"
    kg.save(path)
    loaded = KnowledgeGraph.load(path)
    assert loaded.stats() == stats
