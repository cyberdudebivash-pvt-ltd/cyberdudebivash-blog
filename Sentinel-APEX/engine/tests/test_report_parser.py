from pathlib import Path

import yaml

from sentinel_engine.report_parser import parse_report

FIXTURES = Path(__file__).parent / "fixtures"


def _report(name):
    return parse_report((FIXTURES / name).read_text(errors="replace"))


def test_parses_published_report_sections():
    report = _report("INTEL-REPORT-1.txt")
    assert report.severity == "MEDIUM"
    assert "Pegasus" in report.title
    for section in ("Executive Summary", "Verified Facts", "Technical Analysis",
                    "MITRE ATT&CK Mapping", "IOC Intelligence"):
        assert report.has_section(section), section


def test_sigma_yaml_extracted_and_parseable():
    report = _report("INTEL-REPORT-1.txt")
    assert report.sigma_yaml.startswith("title:")
    rule = yaml.safe_load(report.sigma_yaml)
    assert rule["logsource"]["product"] == "windows"
    assert "condition" in rule["detection"]


def test_section_lookup_is_fragment_based():
    report = _report("INTEL-REPORT-7.txt")
    assert report.section("Executive Summary")
    assert report.section("does-not-exist") == ""


# ── YAML front matter (real hand-authored reports; legacy ►-format fixtures
# have none, so absence must stay a graceful no-op, not an error) ──────────
def test_front_matter_metadata_is_parsed_and_preferred():
    from sentinel_engine.report_parser import parse_report
    text = (
        "---\n"
        "title: \"Front Matter Title\"\n"
        "severity: \"critical\"\n"
        "report_id: \"SA-2026-9999\"\n"
        "---\n\n"
        "## Executive Summary\n\nBody.\n"
    )
    report = parse_report(text)
    assert report.metadata["report_id"] == "SA-2026-9999"
    assert report.title == "Front Matter Title"
    assert report.severity == "CRITICAL"  # normalized to uppercase


def test_no_front_matter_falls_back_to_legacy_extraction():
    report = _report("INTEL-REPORT-1.txt")
    assert report.metadata == {}
    assert report.severity == "MEDIUM"  # still extracted via the old text scan


def test_malformed_front_matter_does_not_throw():
    from sentinel_engine.report_parser import parse_report
    text = "---\ntitle: \"unterminated\n---\n\n## Section\n\nBody.\n"
    report = parse_report(text)  # must not raise
    assert report.metadata == {}
    assert report.has_section("Section")


def test_invalid_severity_value_in_front_matter_falls_back():
    from sentinel_engine.report_parser import parse_report
    text = "---\nseverity: \"not-a-real-severity\"\n---\n\n## S\n\nMEDIUM\n"
    report = parse_report(text)
    assert report.severity == "MEDIUM"  # falls back to text-scan extraction
