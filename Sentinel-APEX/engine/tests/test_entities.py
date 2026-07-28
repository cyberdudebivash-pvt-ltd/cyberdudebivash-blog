from sentinel_engine.entities import extract_entities


def _names(entities):
    return {e.name for e in entities}


def test_no_match_returns_empty():
    assert extract_entities("The quarterly budget review is scheduled for May.") == []


def test_known_actor_and_malware_extracted_with_type():
    entities = extract_entities("APT29 deployed LockBit against the target.")
    by_name = {e.name: e for e in entities}
    assert by_name["APT29"].type == "threat_actor"
    assert by_name["LockBit"].type == "malware"


def test_alias_resolves_to_canonical_name():
    entities = extract_entities("Midnight Blizzard compromised the mail server.")
    assert "APT29" in _names(entities)


def test_teamcity_and_jetbrains_extracted():
    # Found producing SA-2026-0003 (JetBrains TeamCity, CVE-2024-27198/27199):
    # neither the vendor nor the product had a lexicon entry at all, so the
    # report's own central subject extracted zero entities before this fix —
    # the same class of gap already logged for SharePoint in Issue 9.
    entities = extract_entities(
        "JetBrains TeamCity On-Premises before 2023.11.4 is affected."
    )
    by_name = {e.name: e for e in entities}
    assert by_name["JetBrains"].type == "vendor"
    assert by_name["TeamCity"].type == "product"


def test_bianlian_and_jasmin_ransomware_extracted_as_malware():
    entities = extract_entities(
        "BianLian ransomware and a separate strain, Jasmin, both exploited the flaw."
    )
    by_name = {e.name: e for e in entities}
    assert by_name["BianLian"].type == "malware"
    assert by_name["Jasmin"].type == "malware"
