from sentinel_engine.attack_mapper import (
    extract_technique_ids,
    is_valid_technique_id,
    map_techniques,
)
from sentinel_engine.models import Confidence


def _ids(mappings):
    return {m.technique_id for m in mappings}


def test_maps_with_evidence():
    text = "The actor used encoded PowerShell and deleted volume shadow copies via vssadmin."
    mappings = map_techniques(text)
    ids = _ids(mappings)
    assert "T1059.001" in ids
    assert "T1490" in ids
    for m in mappings:
        assert m.evidence  # every mapping is traceable to a phrase


def test_no_evidence_no_mapping():
    assert map_techniques("The quarterly budget review is scheduled for May.") == []


def test_ransomware_maps_to_impact():
    mappings = map_techniques("LockBit ransomware encrypted files across the estate")
    assert "T1486" in _ids(mappings)


def test_explicit_ids_extracted_high_confidence():
    mappings = map_techniques("The advisory cites T1574.002 activity.")
    m = next(x for x in mappings if x.technique_id == "T1574.002")
    assert m.confidence == Confidence.HIGH


def test_id_validation():
    assert is_valid_technique_id("T1566.001")
    assert not is_valid_technique_id("T9999")
    assert not is_valid_technique_id("T1566.999")


def test_extract_technique_ids():
    assert extract_technique_ids("uses T1055 then T1041.") == ["T1041", "T1055"]


def test_negated_ransomware_mention_does_not_map():
    text = (
        "No source used in this report describes ransomware, encryption, or any "
        "impact-tactic behavior tied to this campaign."
    )
    assert map_techniques(text) == []


def test_hedged_attribution_sentence_does_not_falsely_map_impact():
    # The real false positive found producing SA-2026-0001: a sentence about
    # attribution being unresolved, with no genuine ransomware/encryption
    # content anywhere, must not map T1486 at any confidence.
    text = (
        "Any confirmed ransomware or data-theft impact tied to this campaign has "
        "not been publicly reported, and attribution to a specific actor remains "
        "unknown at this time."
    )
    assert "T1486" not in _ids(map_techniques(text))


def test_negation_after_the_keyword_in_the_same_sentence_is_still_caught():
    text = "The actor has not been observed deploying ransomware or encrypting files in this campaign."
    assert map_techniques(text) == []


def test_explicit_technique_id_citation_negated_by_rejection_does_not_map():
    text = "T1486 (Data Encrypted for Impact) was considered and rejected as no ransomware activity was observed."
    assert "T1486" not in _ids(map_techniques(text))


def test_genuine_positive_after_an_earlier_negated_mention_still_maps():
    # A negation elsewhere in the document must not suppress a real, later
    # finding — the guard is sentence-scoped, not document-wide.
    text = (
        "Early triage found no ransomware or encrypted files on the initial host. "
        "Three days later, the actor pivoted and ransomware encrypted files across "
        "the finance file server."
    )
    ids = _ids(map_techniques(text))
    assert "T1486" in ids


def test_negation_does_not_suppress_unrelated_techniques_in_the_same_document():
    text = (
        "No ransomware was deployed in this incident. Separately, the actor used "
        "encoded PowerShell for execution."
    )
    ids = _ids(map_techniques(text))
    assert "T1059.001" in ids
    assert "T1486" not in ids


def test_hedge_in_one_markdown_table_row_does_not_suppress_a_clean_citation_in_another():
    # The real bug found in SA-2026-0001 (GIKEP v1): a multi-row markdown
    # table has no sentence-ending punctuation between rows, so the whole
    # table was being treated as one giant "clause" -- a hedge word in ANY
    # row (here, T1606's "not explicitly confirmed") suppressed T1190's
    # citation even though T1190's own row is fully, cleanly supported with
    # no hedge at all.
    text = (
        "| Technique | Name | Tactic | Confidence | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| T1190 | Exploit Public-Facing Application | Initial Access | HIGH |"
        " Unauthenticated RCE against an internet-facing endpoint |\n"
        "| T1606 | Forge Web Credentials | Persistence | MEDIUM |"
        " Analyst assessment; not explicitly confirmed as observed in this campaign |\n"
    )
    ids = _ids(map_techniques(text))
    assert "T1190" in ids
    assert "T1606" not in ids
