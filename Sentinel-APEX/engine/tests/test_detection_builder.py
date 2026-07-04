import yaml

from sentinel_engine.attack_mapper import map_techniques
from sentinel_engine.detection_builder import (
    DetectionArtifacts,
    build_all,
    build_for_technique,
    to_suricata_rules,
    validate_kql,
    validate_osquery,
    validate_splunk,
    validate_suricata,
)
from sentinel_engine.detection_specs import REGISTRY, Platform
from sentinel_engine.ioc_extractor import extract_iocs
from sentinel_engine.models import IOC, IOCType
from sentinel_engine.quality import validate_sigma

DATE = "2026/07/04"
REFS = ["https://example.org/advisory"]


def _art(tid):
    return build_for_technique(tid, REFS, DATE)


# --- format generation ----------------------------------------------------

def test_powershell_all_formats_generated():
    art = _art("T1059.001")
    fmts = art.formats()
    assert set(fmts) == {"sigma", "kql", "splunk", "osquery"}


def test_lsass_spec_omits_osquery():
    # process_access has no OSQuery table -> osquery not emitted, honestly
    art = _art("T1003.001")
    assert "osquery" not in art.formats()
    assert "kql" in art.formats()


def test_generated_sigma_passes_gate():
    for tid in REGISTRY:
        art = _art(tid)
        assert validate_sigma(art.sigma) == [], tid


def test_kql_starts_with_table_and_has_where():
    art = _art("T1059.001")
    assert art.kql.splitlines()[0] == "DeviceProcessEvents"
    assert "| where" in art.kql
    assert validate_kql(art.kql) == []


def test_kql_negation_rendered():
    art = _art("T1547.001")  # has a negated trusted-path filter
    assert "not (" in art.kql
    assert validate_kql(art.kql) == []


def test_splunk_valid_and_balanced():
    art = _art("T1204.002")
    assert validate_splunk(art.splunk) == []
    assert "tstats" in art.splunk


def test_osquery_valid_select():
    art = _art("T1547.001")
    assert art.osquery.startswith("SELECT")
    assert art.osquery.endswith(";")
    assert validate_osquery(art.osquery) == []


def test_unknown_technique_returns_none():
    assert build_for_technique("T9999", REFS, DATE) is None


# --- Suricata from IOCs ----------------------------------------------------

def test_suricata_for_domain_ip_url():
    iocs = [
        IOC("evil-c2.top", IOCType.DOMAIN),
        IOC("45.61.136.39", IOCType.IPV4),
        IOC("http://bad.example/malware.bin", IOCType.URL),
    ]
    rules = to_suricata_rules(iocs)
    assert len(rules) == 3
    for r in rules:
        assert validate_suricata(r) == []
    assert any("dns.query" in r for r in rules)
    assert any("http.host" in r for r in rules)


def test_suricata_skips_non_network_iocs():
    iocs = [IOC("a" * 64, IOCType.SHA256), IOC("CVE-2024-1", IOCType.CVE)]
    assert to_suricata_rules(iocs) == []


def test_suricata_sids_unique_and_incrementing():
    iocs = [IOC("a.top", IOCType.DOMAIN), IOC("b.top", IOCType.DOMAIN)]
    rules = to_suricata_rules(iocs, start_sid=5000)
    assert "sid:5000;" in rules[0]
    assert "sid:5001;" in rules[1]


def test_suricata_escapes_content():
    iocs = [IOC('bad"; drop.top', IOCType.DOMAIN)]
    rule = to_suricata_rules(iocs)[0]
    assert validate_suricata(rule) == []
    assert '\\"' in rule or '\\;' in rule


# --- validators reject broken content -------------------------------------

def test_validate_kql_rejects_leading_pipe():
    assert validate_kql("| where x == 1") != []


def test_validate_osquery_requires_semicolon():
    assert any("semicolon" in p for p in validate_osquery("SELECT * FROM t WHERE a=1"))


def test_validate_splunk_unbalanced_parens():
    assert any("parentheses" in p for p in validate_splunk("| tstats count where (a=1"))


def test_validate_suricata_missing_sid():
    bad = 'alert ip $HOME_NET any -> 1.2.3.4 any (msg:"x";)'
    assert any("sid" in p for p in validate_suricata(bad))


# --- integration through build_all ----------------------------------------

def test_build_all_end_to_end():
    text = (
        "attackers ran encoded PowerShell, deleted volume shadow copies with "
        "vssadmin, and beaconed to hxxp://evil-c2[.]top/x from 203[.]0[.]113[.]7"
    )
    mappings = map_techniques(text)
    iocs = [i for i in extract_iocs(text) if i.type != IOCType.CVE]
    artifacts, suricata = build_all(mappings, iocs=iocs, references=REFS)

    titles = {a.title for a in artifacts}
    assert "Suspicious Encoded PowerShell Invocation" in titles
    assert "Shadow Copy Deletion Preceding Ransomware Encryption" in titles
    assert suricata  # network IOCs present
    # every generated artifact validates in its own format
    for art in artifacts:
        assert validate_sigma(art.sigma) == []
        if art.kql:
            assert validate_kql(art.kql) == []


def test_no_techniques_no_detections():
    artifacts, suricata = build_all([], iocs=[], references=REFS)
    assert artifacts == []
    assert suricata == []
