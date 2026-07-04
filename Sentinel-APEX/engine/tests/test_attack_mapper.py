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
