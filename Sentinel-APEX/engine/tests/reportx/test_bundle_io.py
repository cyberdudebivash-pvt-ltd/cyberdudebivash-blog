import json
from pathlib import Path

import pytest

from sentinel_engine.reportx.bundle_io import bundle_from_dict, run_gate_on_file
from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness

MINIMAL_BUNDLE = {
    "report_id": "test-1",
    "sources": [
        {"source_id": "s1", "url": "https://example.com", "publisher": "Example",
         "source_type": "JOURNALISM", "source_role": "PRIMARY_EVENT_SOURCE",
         "retrieved_at": "2026-08-18T00:00:00Z", "content_sha256": "a" * 64},
    ],
    "evidence": [
        {"evidence_id": "e1", "source_id": "s1", "excerpt": "quote"},
    ],
    "claims": [
        {"claim_id": "c1", "claim_type": "VICTIM_IDENTITY", "text": "x",
         "status": "REPORTED", "evidence_refs": ["e1"], "source_refs": ["s1"]},
    ],
    "rendered_text": "## Summary\n\nSome reported content.\n",
}


class TestBundleFromDict:
    def test_minimal_bundle_round_trips_into_a_working_evidence_graph(self):
        bundle = bundle_from_dict(MINIMAL_BUNDLE)
        assert bundle.report_id == "test-1"
        assert "s1" in bundle.graph.sources
        assert "e1" in bundle.graph.evidence
        assert "c1" in bundle.graph.claims
        assert bundle.graph.claims["c1"].has_evidence()

    def test_evaluator_runs_without_error_on_loaded_bundle(self):
        bundle = bundle_from_dict(MINIMAL_BUNDLE)
        results = evaluate_commercial_readiness(bundle)
        assert len(results) == 23  # the full matrix, even if most rows are BLOCKED

    def test_missing_optional_sections_produce_blocked_not_a_crash(self):
        bundle = bundle_from_dict({"report_id": "bare", "sources": [], "claims": []})
        results = evaluate_commercial_readiness(bundle)
        assert any(r.status == "BLOCKED" for r in results)


class TestRunGateOnFile:
    def test_cli_entry_point_reads_a_real_file(self, tmp_path):
        bundle_path = tmp_path / "bundle.json"
        bundle_path.write_text(json.dumps(MINIMAL_BUNDLE))
        markdown, as_json = run_gate_on_file(str(bundle_path))
        assert "COMMERCIAL READINESS" in markdown
        parsed = json.loads(as_json)
        assert len(parsed) == 23
