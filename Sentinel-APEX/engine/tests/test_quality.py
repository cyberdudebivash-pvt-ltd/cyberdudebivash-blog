from pathlib import Path

from sentinel_engine.quality import gate_corpus, gate_report, validate_sigma
from sentinel_engine.report_parser import parse_report

FIXTURES = Path(__file__).parent / "fixtures"

MINIMAL_GOOD = """
July 04, 2026
Example Campaign Report With A Sufficiently Long Title

CRITICAL
► Executive Summary
Actors exploited a flaw. We assess with elevated risk (HIGH CONFIDENCE).
► Verified Facts
Confirmed by vendor advisory.
► Technical Analysis
The intrusion used encoded PowerShell to stage payloads, established
persistence through registry Run keys, and deleted volume shadow copies
before deploying ransomware. Operators moved laterally over SMB using
compromised credentials and exfiltrated staged archives over an encrypted
channel to attacker-controlled infrastructure prior to encryption. This
section deliberately exceeds the thin-content threshold used by the gate.
► MITRE ATT&CK Mapping
T1059.001 PowerShell, T1490 Inhibit System Recovery (MEDIUM CONFIDENCE)
► IOC Intelligence
hxxp://evil[.]example-c2[.]top/payload and 45[.]61[.]136[.]39
"""


def _report(name):
    return parse_report((FIXTURES / name).read_text(errors="replace"))


def test_minimal_good_report_passes():
    result = gate_report(parse_report(MINIMAL_GOOD))
    assert result.passed, [f.message for f in result.blocks]


def test_missing_sections_block():
    result = gate_report(parse_report("► Executive Summary\nonly this"))
    gates = {f.gate for f in result.blocks}
    assert "structure" in gates
    assert not result.passed


def test_live_ioc_in_ioc_section_blocks():
    bad = MINIMAL_GOOD.replace(
        "hxxp://evil[.]example-c2[.]top/payload and 45[.]61[.]136[.]39",
        "http://evil.example-c2.top/payload and 45.61.136.39",
    )
    result = gate_report(parse_report(bad))
    assert any(f.gate == "ioc-defanging" for f in result.blocks)


def test_unverifiable_attack_id_warns():
    bad = MINIMAL_GOOD.replace("T1490", "T9999")
    result = gate_report(parse_report(bad))
    assert any("T9999" in f.message for f in result.warnings)


def test_no_attack_ids_blocks():
    bad = MINIMAL_GOOD.replace("T1059.001", "").replace("T1490", "")
    result = gate_report(parse_report(bad))
    assert any(f.gate == "attack" for f in result.blocks)


def test_assessment_without_confidence_blocks():
    bad = MINIMAL_GOOD.replace(" (HIGH CONFIDENCE)", "").replace(
        " (MEDIUM CONFIDENCE)", ""
    )
    result = gate_report(parse_report(bad))
    assert any(f.gate == "confidence" for f in result.blocks)


def test_scraper_noise_in_analysis_blocks():
    bad = MINIMAL_GOOD.replace(
        "This\nsection deliberately",
        "submitted by /u/leaked [link] [comments] This\nsection deliberately",
    )
    result = gate_report(parse_report(bad))
    assert any(f.gate == "content-integrity" for f in result.blocks)


def test_validate_sigma_accepts_valid_rule():
    rule = """
title: Test Rule
id: 00000000-0000-0000-0000-000000000000
description: A test.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
  condition: selection
level: high
"""
    assert validate_sigma(rule) == []


def test_validate_sigma_flags_undefined_selection_and_bad_level():
    rule = """
title: Broken
id: x
description: d
logsource:
  product: windows
detection:
  selection:
    Image: a
  condition: selection and other_thing
level: severe
"""
    problems = validate_sigma(rule)
    assert any("other_thing" in p for p in problems)
    assert any("level invalid" in p for p in problems)


def test_published_report_fails_gate_on_scraper_leak():
    # INTEL-REPORT-1 (real production output) leaked raw Reddit scrape text
    # into its Technical Analysis — the gate must catch it.
    result = gate_report(_report("INTEL-REPORT-1.txt"))
    assert any(f.gate == "content-integrity" for f in result.blocks)


def test_corpus_gate_flags_identical_sigma_rules():
    a = _report("INTEL-REPORT-1.txt")
    result = gate_corpus({"report-a.txt": a, "report-b.txt": a})
    assert any(f.gate == "corpus-duplication" and f.severity == "block"
               for f in result.findings)


def test_corpus_gate_clean_on_distinct_reports():
    result = gate_corpus({
        "a": _report("INTEL-REPORT-1.txt"),
        "b": _report("INTEL-REPORT-7.txt"),
    })
    # different sigma rules -> no identical-rule block
    assert not any(f.severity == "block" for f in result.findings)
