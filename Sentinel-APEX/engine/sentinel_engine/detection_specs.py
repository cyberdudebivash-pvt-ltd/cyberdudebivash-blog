"""Normalized, evidence-anchored detection specifications.

A single ``DetectionSpec`` per technique is the source of truth from which
every output format (Sigma, KQL, Splunk SPL, OSQuery) is compiled. This is
what stops the template-stamping the Phase 2 audit found: one canonical,
technique-specific detection — not a generic rule pasted into every report.

Logical field names are mapped to each platform's real schema in
``FIELD_MAP``, so a renderer never invents a field. A spec only lists the
platforms whose data model can actually express it, so no format is emitted
where it would be meaningless.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Op(str, Enum):
    EQ = "eq"
    CONTAINS = "contains"
    ENDSWITH = "endswith"
    STARTSWITH = "startswith"


class DataSource(str, Enum):
    PROCESS_CREATION = "process_creation"
    PROCESS_ACCESS = "process_access"
    REGISTRY_SET = "registry_set"


class Platform(str, Enum):
    SIGMA = "sigma"
    KQL = "kql"
    SPLUNK = "splunk"
    OSQUERY = "osquery"


@dataclass(frozen=True)
class Match:
    """One condition: a logical field, an operator, and one or more values
    (values are OR-ed together; distinct Match objects are AND-ed)."""

    field: str  # logical field name, resolved via FIELD_MAP
    op: Op
    values: tuple[str, ...]
    negate: bool = False  # this clause is an exclusion filter


@dataclass(frozen=True)
class DetectionSpec:
    technique_id: str
    title: str
    level: str  # informational|low|medium|high|critical
    data_source: DataSource
    matches: tuple[Match, ...]
    platforms: tuple[Platform, ...]
    description: str = ""


# Logical field -> per-platform schema. KQL/OSQuery also carry the table the
# data source lives in.
FIELD_MAP: dict[DataSource, dict] = {
    DataSource.PROCESS_CREATION: {
        "_kql_table": "DeviceProcessEvents",
        "_osquery_table": "processes",
        "_splunk_datamodel": "Endpoint.Processes",
        "process_path": {
            "sigma": "Image", "kql": "FolderPath",
            "splunk": "process_path", "osquery": "path",
        },
        "parent_path": {
            "sigma": "ParentImage", "kql": "InitiatingProcessFolderPath",
            "splunk": "parent_process_path", "osquery": None,
        },
        "command_line": {
            "sigma": "CommandLine", "kql": "ProcessCommandLine",
            "splunk": "process", "osquery": "cmdline",
        },
    },
    DataSource.PROCESS_ACCESS: {
        "_kql_table": "DeviceEvents",
        "_osquery_table": None,
        "_splunk_datamodel": "Endpoint.Processes",
        "target_process": {
            "sigma": "TargetImage", "kql": "FileName",
            "splunk": "target_process_path", "osquery": None,
        },
        "granted_access": {
            "sigma": "GrantedAccess", "kql": "AdditionalFields",
            "splunk": "granted_access", "osquery": None,
        },
    },
    DataSource.REGISTRY_SET: {
        "_kql_table": "DeviceRegistryEvents",
        "_osquery_table": "registry",
        "_splunk_datamodel": "Endpoint.Registry",
        "registry_key": {
            "sigma": "TargetObject", "kql": "RegistryKey",
            "splunk": "registry_path", "osquery": "path",
        },
        "image": {
            "sigma": "Image", "kql": "InitiatingProcessFolderPath",
            "splunk": "process_path", "osquery": None,
        },
    },
}


def resolve_field(data_source: DataSource, logical: str, platform: Platform) -> str | None:
    entry = FIELD_MAP[data_source].get(logical)
    if not entry:
        raise KeyError(f"unknown logical field {logical!r} for {data_source.value}")
    return entry.get(platform.value)


def kql_table(data_source: DataSource) -> str | None:
    return FIELD_MAP[data_source].get("_kql_table")


def osquery_table(data_source: DataSource) -> str | None:
    return FIELD_MAP[data_source].get("_osquery_table")


def splunk_datamodel(data_source: DataSource) -> str | None:
    return FIELD_MAP[data_source].get("_splunk_datamodel")


_ALL = (Platform.SIGMA, Platform.KQL, Platform.SPLUNK, Platform.OSQUERY)
_NO_OSQUERY = (Platform.SIGMA, Platform.KQL, Platform.SPLUNK)


# The canonical registry. Keyed by ATT&CK technique. Evidence for each mapped
# technique is supplied at build time from the report; these specs carry only
# the detection logic, which is stable across reports.
REGISTRY: dict[str, DetectionSpec] = {
    "T1059.001": DetectionSpec(
        technique_id="T1059.001",
        title="Suspicious Encoded PowerShell Invocation",
        level="high",
        data_source=DataSource.PROCESS_CREATION,
        description="PowerShell launched with encoded or base64 command payloads.",
        matches=(
            Match("process_path", Op.ENDSWITH, ("\\powershell.exe",)),
            Match("command_line", Op.CONTAINS,
                  ("-EncodedCommand", "-enc ", "FromBase64String")),
        ),
        platforms=_ALL,
    ),
    "T1204.002": DetectionSpec(
        technique_id="T1204.002",
        title="Office Application Spawning Script Interpreter",
        level="high",
        data_source=DataSource.PROCESS_CREATION,
        description="Office parent process spawning a script or shell interpreter.",
        matches=(
            Match("parent_path", Op.ENDSWITH,
                  ("\\outlook.exe", "\\winword.exe", "\\excel.exe", "\\powerpnt.exe")),
            Match("process_path", Op.ENDSWITH,
                  ("\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\mshta.exe")),
        ),
        platforms=_ALL,
    ),
    "T1490": DetectionSpec(
        technique_id="T1490",
        title="Shadow Copy Deletion Preceding Ransomware Encryption",
        level="critical",
        data_source=DataSource.PROCESS_CREATION,
        description="Recovery inhibition via shadow copy / backup catalog deletion.",
        matches=(
            Match("command_line", Op.CONTAINS,
                  ("vssadmin delete shadows", "wmic shadowcopy delete",
                   "recoveryenabled no", "wbadmin delete catalog")),
        ),
        platforms=_ALL,
    ),
    "T1547.001": DetectionSpec(
        technique_id="T1547.001",
        title="Registry Run Key Persistence From User-Writable Path",
        level="medium",
        data_source=DataSource.REGISTRY_SET,
        description="Run/RunOnce key modification establishing boot/logon persistence.",
        matches=(
            Match("registry_key", Op.CONTAINS,
                  ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",)),
            Match("image", Op.STARTSWITH,
                  ("C:\\Program Files", "C:\\Windows\\"), negate=True),
        ),
        platforms=_ALL,
    ),
    "T1003.001": DetectionSpec(
        technique_id="T1003.001",
        title="LSASS Memory Access by Non-System Process",
        level="high",
        data_source=DataSource.PROCESS_ACCESS,
        description="Process handle to lsass.exe with credential-dumping access mask.",
        matches=(
            Match("target_process", Op.ENDSWITH, ("\\lsass.exe",)),
            Match("granted_access", Op.CONTAINS, ("0x1010", "0x1410", "0x1438")),
        ),
        platforms=_NO_OSQUERY,
    ),
    "T1218.005": DetectionSpec(
        technique_id="T1218.005",
        title="Mshta Executing Remote or Script Content",
        level="high",
        data_source=DataSource.PROCESS_CREATION,
        description="mshta.exe used as a proxy to run remote or inline script content.",
        matches=(
            Match("process_path", Op.ENDSWITH, ("\\mshta.exe",)),
            Match("command_line", Op.CONTAINS,
                  ("http", "javascript:", "vbscript:")),
        ),
        platforms=_ALL,
    ),
}


def buildable_techniques() -> set[str]:
    return set(REGISTRY)
