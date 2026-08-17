import hashlib
import json
from pathlib import Path

import pytest

from sentinel_engine.reportx.reviewer_pack import render_reviewer_pack_markdown

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
EXPORT_PATH = FIXTURES_DIR / "qilin-spoonful-of-comfort-exported-bundle.json"


@pytest.fixture(scope="module")
def export():
    assert EXPORT_PATH.is_file(), f"expected {EXPORT_PATH}"
    return json.loads(EXPORT_PATH.read_text())


class TestReviewerPackContent:
    def test_pack_includes_the_real_report_id_and_artifact_hash(self, export):
        pack = render_reviewer_pack_markdown(export)
        assert export["bundle"]["report_id"] in pack
        expected_hash = hashlib.sha256(export["bundle"]["rendered_text"].encode("utf-8")).hexdigest()
        assert expected_hash in pack

    def test_pack_includes_every_control_row(self, export):
        pack = render_reviewer_pack_markdown(export)
        for c in export["commercial_readiness"]["controls"]:
            assert c["name"] in pack

    def test_pack_includes_the_real_verdict_and_pass_count(self, export):
        pack = render_reviewer_pack_markdown(export)
        cr = export["commercial_readiness"]
        assert f"{cr['pass_count']} / {cr['total_count']} PASS — {cr['verdict']}" in pack

    def test_pack_includes_every_source_and_claim(self, export):
        pack = render_reviewer_pack_markdown(export)
        for s in export["bundle"]["sources"]:
            assert s["source_id"] in pack
        for c in export["bundle"]["claims"]:
            assert c["claim_id"] in pack

    def test_pack_notes_render_preview_path_when_given(self, export):
        pack = render_reviewer_pack_markdown(export, render_preview_path="/tmp/preview.html")
        assert "/tmp/preview.html" in pack

    def test_pack_omits_render_preview_line_when_not_given(self, export):
        pack = render_reviewer_pack_markdown(export)
        assert "Render preview" not in pack

    def test_pack_reflects_no_existing_review_when_none_present(self, export):
        assert export["bundle"]["review"] is None
        pack = render_reviewer_pack_markdown(export)
        assert "Existing Review Record" not in pack

    def test_pack_shows_changes_since_previous_when_given(self, export):
        # A synthetic "previous" export with different rendered_text --
        # not claiming it's a real prior artifact, just exercising the diff path.
        previous = json.loads(json.dumps(export))  # deep copy
        previous["bundle"]["rendered_text"] = "different text entirely"
        pack = render_reviewer_pack_markdown(export, previous_export=previous)
        assert "Changes Since Previous Artifact" in pack
        assert "Artifact changed" in pack

    def test_pack_shows_no_change_when_previous_is_identical(self, export):
        previous = json.loads(json.dumps(export))
        pack = render_reviewer_pack_markdown(export, previous_export=previous)
        assert "No change" in pack

    def test_pack_never_fabricates_content_for_empty_sections(self, export):
        # This fixture has no forecasts/hypotheses/metrics/detection rules --
        # the pack must say so explicitly, not omit the section or invent content.
        pack = render_reviewer_pack_markdown(export)
        assert export["bundle"]["forecasts"] == []
        assert export["bundle"]["metrics"] == []
        assert "## Forecasts" in pack
        assert "## Statistics (Metrics Registry)" in pack
