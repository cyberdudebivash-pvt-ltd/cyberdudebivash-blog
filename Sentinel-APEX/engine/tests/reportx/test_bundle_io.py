import importlib.util
import json
import sys
from pathlib import Path

import pytest

from sentinel_engine.reportx.bundle_io import bundle_from_dict, bundle_to_dict, export_report_json, run_gate_on_file
from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness
from sentinel_engine.reportx.threat_schemas import RansomwareVictimClaim

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


FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"

# Every golden ransomware fixture module (System 3's real, research-backed
# acceptance cases) plus the two hand-written CVE JSON fixtures -- used
# here to prove bundle_to_dict()/bundle_from_dict() round-trip losslessly
# for every kind of real bundle this repo actually has, not just a
# hand-crafted minimal example. This is the concrete evidence behind
# REPORTX-ROLLOUT-RUNBOOK.md Phase 3's claim that the JSON interchange
# format is ready for a JS consumer.
_RANSOMWARE_FIXTURE_MODULES = [
    "qilin_spoonful_of_comfort", "panzer_sagasta_sro", "qilin_mulino_padano",
    "medusalocker_twal_family_it_lab", "medusalocker_all_parts_dry_cleaning",
    "aurora_lloyd_coils_europe", "dragonforce_vermont_xcenter",
    "medusalocker_idex_group", "medusalocker_bija_industrie",
]


def _load_fixture_bundle(modname: str):
    spec = importlib.util.spec_from_file_location(modname, FIXTURES_DIR / f"{modname}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module.build_bundle()


class TestThreatProductsRoundTrip:
    """Closes the gap the golden ransomware fixtures originally had to
    work around by constructing bundles directly in Python: threat_products
    (RansomwareVictimClaim's three-layer model) now survives a real JSON
    round-trip losslessly, verified against every real fixture in this
    repo, not a synthetic example."""

    @pytest.mark.parametrize("modname", _RANSOMWARE_FIXTURE_MODULES)
    def test_gate_results_are_identical_before_and_after_a_json_round_trip(self, modname):
        bundle = _load_fixture_bundle(modname)
        original = [(r.control_id, r.status) for r in evaluate_commercial_readiness(bundle)]

        # Round-trip through actual JSON text (not just the dict), so this
        # also catches anything that isn't JSON-serializable.
        reexported = json.loads(json.dumps(bundle_to_dict(bundle)))
        reloaded = bundle_from_dict(reexported)
        reloaded_results = [(r.control_id, r.status) for r in evaluate_commercial_readiness(reloaded)]

        assert reloaded_results == original

    @pytest.mark.parametrize("modname", _RANSOMWARE_FIXTURE_MODULES)
    def test_reloaded_threat_product_is_the_correct_isolated_schema(self, modname):
        bundle = _load_fixture_bundle(modname)
        reexported = json.loads(json.dumps(bundle_to_dict(bundle)))
        reloaded = bundle_from_dict(reexported)

        assert len(reloaded.threat_products) == 1
        product = reloaded.threat_products[0]
        assert isinstance(product, RansomwareVictimClaim)
        # The isolation guarantee must survive the round-trip too: no
        # linked vulnerability in any of these fixtures, so the four
        # markers must still be NOT_APPLICABLE after reload.
        assert not product.has_linked_vulnerability()
        assert product.cisa_kev_state.value == "NOT_APPLICABLE"
        assert product.cvss_state.value == "NOT_APPLICABLE"
        assert product.patch_state.value == "NOT_APPLICABLE"
        assert product.exploit_cve_status.value == "NOT_APPLICABLE"

    @pytest.mark.parametrize("modname", _RANSOMWARE_FIXTURE_MODULES)
    def test_victim_observation_fields_survive_the_round_trip(self, modname):
        bundle = _load_fixture_bundle(modname)
        original_product = bundle.threat_products[0]
        reexported = json.loads(json.dumps(bundle_to_dict(bundle)))
        reloaded = bundle_from_dict(reexported)
        reloaded_product = reloaded.threat_products[0]

        assert reloaded_product.victim_observation.victim_name == original_product.victim_observation.victim_name
        assert reloaded_product.victim_observation.country == original_product.victim_observation.country
        assert reloaded_product.actor_context.sectors == original_product.actor_context.sectors


class TestCVEJSONFixturesRoundTrip:
    @pytest.mark.parametrize("fixture_name", ["cve-2025-62593-ray-BEFORE.json", "cve-2025-62593-ray-AFTER.json"])
    def test_gate_results_are_identical_before_and_after_a_json_round_trip(self, fixture_name):
        d = json.loads((FIXTURES_DIR / fixture_name).read_text())
        bundle = bundle_from_dict(d)
        original = [(r.control_id, r.status) for r in evaluate_commercial_readiness(bundle)]

        reexported = json.loads(json.dumps(bundle_to_dict(bundle)))
        reloaded = bundle_from_dict(reexported)
        reloaded_results = [(r.control_id, r.status) for r in evaluate_commercial_readiness(reloaded)]

        assert reloaded_results == original


class TestExportReportJson:
    def test_export_shape_carries_bundle_and_precomputed_gate_results(self):
        bundle = bundle_from_dict(MINIMAL_BUNDLE)
        export = export_report_json(bundle)
        assert set(export.keys()) == {"bundle", "commercial_readiness"}
        assert export["commercial_readiness"]["total_count"] == 23
        assert export["commercial_readiness"]["pass_count"] == sum(
            1 for c in export["commercial_readiness"]["controls"] if c["status"] == "PASS"
        )

    def test_verdict_string_matches_the_pass_count(self):
        bundle = bundle_from_dict(MINIMAL_BUNDLE)
        export = export_report_json(bundle)
        cr = export["commercial_readiness"]
        expected = "COMMERCIAL-READY" if cr["pass_count"] == cr["total_count"] else "NOT COMMERCIAL-READY"
        assert cr["verdict"] == expected

    def test_export_is_actually_json_serializable(self):
        bundle = bundle_from_dict(MINIMAL_BUNDLE)
        # Must not raise -- this is the exact artifact a JS consumer reads.
        text = json.dumps(export_report_json(bundle))
        reparsed = json.loads(text)
        assert reparsed["bundle"]["report_id"] == "test-1"
