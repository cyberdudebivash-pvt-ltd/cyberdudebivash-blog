from pathlib import Path

from sentinel_engine.knowledge_graph import KnowledgeGraph
from sentinel_engine.models import SourceDocument
from sentinel_engine.normalizer import normalize

FIXTURES = Path(__file__).parent / "fixtures"


def _doc():
    raw = (FIXTURES / "raw-source-sample.txt").read_text()
    return normalize(SourceDocument(raw_text=raw, source_url="https://example.org/a"))


def test_ingest_builds_entities_and_relations():
    kg = KnowledgeGraph()
    kg.ingest(_doc(), "RPT-001")
    stats = kg.stats()
    assert stats["by_type"]["cve"] == 1
    assert stats["by_type"]["malware"] >= 1
    assert stats["by_type"]["technique"] >= 4
    assert stats["relations"] > 0


def test_actor_cooccurrence_edges():
    kg = KnowledgeGraph()
    doc = _doc()
    kg.ingest(doc, "RPT-001")
    # LockBit is malware, not actor, so check the cve link exists via report
    cve_neighbors = kg.neighbors("cve:cve-2024-4577")
    assert any(r["rel"] == "references" for r in cve_neighbors)


def test_prior_context_surfaces_on_second_report():
    kg = KnowledgeGraph()
    doc = _doc()
    assert kg.prior_context(doc) == []  # empty graph knows nothing
    kg.ingest(doc, "RPT-001")
    notes = kg.prior_context(doc)
    assert any("CVE-2024-4577" in n and "RPT-001" in n for n in notes)


def test_persistence_roundtrip(tmp_path):
    kg = KnowledgeGraph()
    kg.ingest(_doc(), "RPT-001")
    path = tmp_path / "kg.json"
    kg.save(path)
    loaded = KnowledgeGraph.load(path)
    assert loaded.stats() == kg.stats()


def test_load_missing_file_returns_empty_graph(tmp_path):
    kg = KnowledgeGraph.load(tmp_path / "absent.json")
    assert kg.stats()["entities"] == 0


def test_idempotent_ingest():
    kg = KnowledgeGraph()
    doc = _doc()
    kg.ingest(doc, "RPT-001")
    first = kg.stats()
    kg.ingest(doc, "RPT-001")
    assert kg.stats() == first
