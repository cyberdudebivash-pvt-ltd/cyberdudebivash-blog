from pathlib import Path

from sentinel_engine import pipeline
from sentinel_engine.enrichment import Enricher
from sentinel_engine.knowledge_graph import KnowledgeGraph
from sentinel_engine.models import SourceDocument

FIXTURES = Path(__file__).parent / "fixtures"


def _source():
    return SourceDocument(
        raw_text=(FIXTURES / "raw-source-sample.txt").read_text(),
        source_url="https://example.org/advisory",
    )


def test_pipeline_end_to_end_offline():
    kg = KnowledgeGraph()
    offline = Enricher(fetch_json=lambda url: None)
    result = pipeline.run(_source(), "RPT-001", enricher=offline, graph=kg)

    md = result.draft_markdown
    # evidence-backed content present
    assert "CVE-2024-4577" in md
    assert "LockBit" in md
    assert "T1059.001" in md
    # IOCs are defanged in the draft
    assert "45[.]61[.]136[.]39" in md
    assert "45.61.136.39" not in md
    # offline enrichment is honest, not fabricated
    assert "scores intentionally omitted" in md
    # scraper noise never reaches the draft
    assert "submitted by" not in md
    # detection rules derived from evidence
    assert "Shadow Copy Deletion" in md
    # graph learned from the report
    assert kg.stats()["entities"] > 0


def test_second_run_gains_prior_context():
    kg = KnowledgeGraph()
    pipeline.run(_source(), "RPT-001", graph=kg)
    result = pipeline.run(_source(), "RPT-002", graph=kg)
    assert result.prior_context
    assert "Prior Intelligence Context" in result.draft_markdown


def test_no_evidence_sections_omitted():
    source = SourceDocument(
        raw_text="A vendor announced a new security conference for analysts. "
        "Registration opens next month and covers general industry topics.",
        source_url="https://example.org/news",
    )
    result = pipeline.run(source, "RPT-003")
    md = result.draft_markdown
    assert "MITRE ATT&CK Mapping" not in md  # no techniques -> no section
    assert "No confirmed public IOCs" in md
    assert result.sigma_rules == []
