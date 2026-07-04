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
