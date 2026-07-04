"""Evidence-driven Sigma rule construction.

Rules are only built from technique mappings that carry evidence, and every
rule is validated by the same ``quality.validate_sigma`` gate that audits
published reports — the builder cannot emit a rule the gate would reject.
"""

from __future__ import annotations

import datetime as _dt
import uuid

import yaml

from .models import TechniqueMapping
from .quality import validate_sigma

_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "sentinel.cyberdudebivash.in")

# Detection logic per technique. Only techniques with real, specific logic
# get a rule — no generic fallback rule is ever emitted.
_TECHNIQUE_DETECTIONS: dict[str, dict] = {
    "T1059.001": {
        "title": "Suspicious Encoded PowerShell Invocation",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": [
                    "-EncodedCommand", "-enc ", "FromBase64String",
                ],
            },
            "condition": "selection",
        },
        "level": "high",
    },
    "T1204.002": {
        "title": "Office Application Spawning Script Interpreter",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "ParentImage|endswith": [
                    "\\outlook.exe", "\\winword.exe",
                    "\\excel.exe", "\\powerpnt.exe",
                ],
                "Image|endswith": [
                    "\\powershell.exe", "\\cmd.exe",
                    "\\wscript.exe", "\\mshta.exe",
                ],
            },
            "condition": "selection",
        },
        "level": "high",
    },
    "T1490": {
        "title": "Shadow Copy Deletion Preceding Ransomware Encryption",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "vssadmin delete shadows",
                    "wmic shadowcopy delete",
                    "bcdedit /set {default} recoveryenabled no",
                ],
            },
            "condition": "selection",
        },
        "level": "critical",
    },
    "T1547.001": {
        "title": "Registry Run Key Persistence From User-Writable Path",
        "logsource": {"product": "windows", "category": "registry_set"},
        "detection": {
            "selection": {
                "TargetObject|contains": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            },
            "filter_trusted": {
                "Image|startswith": ["C:\\Program Files", "C:\\Windows\\"],
            },
            "condition": "selection and not filter_trusted",
        },
        "level": "medium",
    },
    "T1003.001": {
        "title": "LSASS Memory Access by Non-System Process",
        "logsource": {"product": "windows", "category": "process_access"},
        "detection": {
            "selection": {
                "TargetImage|endswith": "\\lsass.exe",
                "GrantedAccess|contains": ["0x1010", "0x1410", "0x1438"],
            },
            "condition": "selection",
        },
        "level": "high",
    },
    "T1218.005": {
        "title": "Mshta Executing Remote or Script Content",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": "\\mshta.exe",
                "CommandLine|contains": ["http", "javascript:", "vbscript:"],
            },
            "condition": "selection",
        },
        "level": "high",
    },
}


def buildable_techniques() -> set[str]:
    return set(_TECHNIQUE_DETECTIONS)


def build_rules(
    mappings: list[TechniqueMapping],
    references: list[str] | None = None,
    date: str | None = None,
) -> list[str]:
    """Build validated Sigma rules for the subset of mapped techniques that
    have specific detection logic. Returns YAML strings."""
    rules: list[str] = []
    date = date or _dt.date.today().isoformat()
    for mapping in mappings:
        spec = _TECHNIQUE_DETECTIONS.get(mapping.technique_id)
        if not spec:
            continue
        rule = {
            "title": spec["title"],
            "id": str(uuid.uuid5(_NAMESPACE, spec["title"])),
            "status": "experimental",
            "description": (
                f"{spec['title']}. Evidence basis: {mapping.evidence[:200]}. "
                "CYBERDUDEBIVASH SENTINEL APEX Detection Engineering."
            ),
            "references": list(references or []),
            "author": "CYBERDUDEBIVASH SENTINEL APEX Detection Engineering",
            "date": date,
            "tags": [
                f"attack.{mapping.tactic}",
                f"attack.{mapping.technique_id.lower()}",
            ],
            "logsource": spec["logsource"],
            "detection": spec["detection"],
            "falsepositives": [
                "Legitimate administrative activity",
                "Authorized security testing",
            ],
            "level": spec["level"],
        }
        rule_yaml = yaml.safe_dump(rule, sort_keys=False, width=100)
        problems = validate_sigma(rule_yaml)
        if problems:  # builder must never emit a rule the gate rejects
            raise ValueError(
                f"generated Sigma rule failed validation: {problems}"
            )
        rules.append(rule_yaml)
    return rules
