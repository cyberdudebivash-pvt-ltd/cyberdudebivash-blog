import yaml

from sentinel_engine.attack_mapper import map_techniques
from sentinel_engine.quality import validate_sigma
from sentinel_engine.sigma_builder import build_rules, buildable_techniques


def test_rules_built_only_for_evidenced_techniques():
    mappings = map_techniques(
        "operators ran encoded PowerShell and deleted volume shadow copies "
        "with vssadmin before encrypting files"
    )
    rules = build_rules(mappings, references=["https://example.org/advisory"])
    titles = [yaml.safe_load(r)["title"] for r in rules]
    assert "Suspicious Encoded PowerShell Invocation" in titles
    assert "Shadow Copy Deletion Preceding Ransomware Encryption" in titles


def test_no_generic_fallback_rule():
    mappings = map_techniques("a phishing email was reported")  # T1566: no logic
    assert "T1566" not in buildable_techniques()
    assert build_rules(mappings) == []


def test_every_emitted_rule_passes_the_quality_gate():
    mappings = map_techniques(
        "encoded PowerShell, mshta http payloads, lsass credential dump, "
        "registry Run keys persistence, macro-enabled malicious document"
    )
    rules = build_rules(mappings)
    assert rules
    for rule in rules:
        assert validate_sigma(rule) == []


def test_rule_ids_deterministic():
    mappings = map_techniques("encoded PowerShell execution observed")
    a = yaml.safe_load(build_rules(mappings)[0])
    b = yaml.safe_load(build_rules(mappings)[0])
    assert a["id"] == b["id"]


def test_evidence_embedded_in_description():
    mappings = map_techniques("attackers used vssadmin delete shadows /all")
    rule = yaml.safe_load(build_rules(mappings)[0])
    assert "Evidence basis" in rule["description"]
    assert "vssadmin" in rule["description"]
