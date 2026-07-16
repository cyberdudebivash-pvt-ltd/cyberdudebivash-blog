"""
CYBERDUDEBIVASH® SENTINEL APEX — Enterprise Download Center
Structured-data exports generated from real report content — no PDF/PPTX
generation (would require a new dependency; deliberately out of scope for
now). Currently: MITRE ATT&CK Navigator layer JSON, extracted from the
technique IDs the report itself already cites.
"""

import re
from typing import Optional

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_technique_ids(text: str) -> list[str]:
    """Real technique IDs only — extracted from text the report already
    generated (MITRE ATT&CK Mapping section), never invented."""
    found = _TECHNIQUE_ID_RE.findall(text)
    seen: set = set()
    result = []
    for tid in found:
        if tid not in seen:
            seen.add(tid)
            result.append(tid)
    return result


def build_mitre_navigator_layer(body_content: str, report_title: str) -> Optional[dict]:
    """
    Return a MITRE ATT&CK Navigator layer (v4.5 layer format) covering only
    the techniques this specific report actually cites. Returns None if no
    technique IDs are present — never ships an empty/fabricated layer.
    """
    technique_ids = extract_technique_ids(body_content)
    if not technique_ids:
        return None

    return {
        "name": f"CYBERDUDEBIVASH SENTINEL APEX — {report_title[:80]}",
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated from CYBERDUDEBIVASH SENTINEL APEX threat intelligence report — techniques cited in this report's MITRE ATT&CK Mapping section.",
        "techniques": [
            {"techniqueID": tid, "color": "#a855f7", "comment": "Cited in this report", "enabled": True}
            for tid in technique_ids
        ],
        "gradient": {"colors": ["#ffffff", "#a855f7"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "Technique cited in this report", "color": "#a855f7"}],
    }
