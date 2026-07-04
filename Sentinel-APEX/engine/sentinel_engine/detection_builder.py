"""Compile normalized DetectionSpecs to concrete SIEM/EDR formats.

One spec -> Sigma YAML, Microsoft KQL (Defender/Sentinel), Splunk SPL, and
OSQuery SQL — only for the platforms a spec declares it can express. Network
IOCs additionally compile to Suricata rules. Every generated artifact is run
through a format-specific validator; the builder refuses to emit anything
that does not pass, so downstream consumers never receive a broken rule.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass, field

import yaml

from .detection_specs import (
    REGISTRY,
    DataSource,
    DetectionSpec,
    Match,
    Op,
    Platform,
    kql_table,
    osquery_table,
    resolve_field,
    splunk_datamodel,
)
from .models import IOC, IOCType, TechniqueMapping

_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "sentinel.cyberdudebivash.in")

_SIGMA_LEVELS = ("informational", "low", "medium", "high", "critical")
_SEVERITY_SURICATA = {
    "informational": 3, "low": 3, "medium": 2, "high": 1, "critical": 1,
}


@dataclass
class DetectionArtifacts:
    """All formats generated for a single technique."""

    technique_id: str
    title: str
    sigma: str = ""
    kql: str = ""
    splunk: str = ""
    osquery: str = ""

    def formats(self) -> dict[str, str]:
        return {
            k: v for k, v in {
                "sigma": self.sigma, "kql": self.kql,
                "splunk": self.splunk, "osquery": self.osquery,
            }.items() if v
        }


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _escape(value: str, quote: str) -> str:
    return value.replace("\\", "\\\\").replace(quote, "\\" + quote)


def _sig_modifier(op: Op) -> str:
    return {
        Op.EQ: "", Op.CONTAINS: "|contains",
        Op.ENDSWITH: "|endswith", Op.STARTSWITH: "|startswith",
    }[op]


# --------------------------------------------------------------------------
# Sigma
# --------------------------------------------------------------------------

def to_sigma(spec: DetectionSpec, references: list[str], date: str) -> str:
    selection: dict = {}
    filters: dict = {}
    conditions = ["selection"]
    for i, m in enumerate(spec.matches):
        sigma_field = resolve_field(spec.data_source, m.field, Platform.SIGMA)
        key = sigma_field + _sig_modifier(m.op)
        vals = list(m.values) if len(m.values) > 1 else m.values[0]
        if m.negate:
            fname = f"filter_{i}"
            filters[fname] = {key: vals}
            conditions.append(f"not {fname}")
        else:
            selection[key] = vals
    detection = {"selection": selection, **filters, "condition": " and ".join(conditions)}
    rule = {
        "title": spec.title,
        "id": str(uuid.uuid5(_NAMESPACE, spec.title)),
        "status": "experimental",
        "description": spec.description
        or f"{spec.title}. CYBERDUDEBIVASH SENTINEL APEX Detection Engineering.",
        "references": list(references),
        "author": "CYBERDUDEBIVASH SENTINEL APEX Detection Engineering",
        "date": date,
        "tags": [f"attack.{spec.technique_id.lower()}"],
        "logsource": _sigma_logsource(spec.data_source),
        "detection": detection,
        "falsepositives": ["Legitimate administrative activity",
                           "Authorized security testing"],
        "level": spec.level,
    }
    return yaml.safe_dump(rule, sort_keys=False, width=100)


def _sigma_logsource(ds: DataSource) -> dict:
    return {
        DataSource.PROCESS_CREATION: {"product": "windows", "category": "process_creation"},
        DataSource.PROCESS_ACCESS: {"product": "windows", "category": "process_access"},
        DataSource.REGISTRY_SET: {"product": "windows", "category": "registry_set"},
    }[ds]


# --------------------------------------------------------------------------
# KQL (Microsoft Defender / Sentinel)
# --------------------------------------------------------------------------

def to_kql(spec: DetectionSpec) -> str:
    table = kql_table(spec.data_source)
    clauses = [_kql_clause(spec, m) for m in spec.matches]
    lines = [table] + [f"| where {c}" for c in clauses]
    lines.append(
        "| project Timestamp, DeviceName, "
        + _kql_projection(spec.data_source)
    )
    return "\n".join(lines)


def _kql_clause(spec: DetectionSpec, m: Match) -> str:
    field_name = resolve_field(spec.data_source, m.field, Platform.KQL)
    op = {Op.EQ: "=~", Op.CONTAINS: "contains",
          Op.ENDSWITH: "endswith", Op.STARTSWITH: "startswith"}[m.op]
    terms = [f'{field_name} {op} "{_escape(v, chr(34))}"' for v in m.values]
    inner = " or ".join(terms)
    if len(terms) > 1:
        inner = f"({inner})"
    return f"not ({inner})" if m.negate else inner


def _kql_projection(ds: DataSource) -> str:
    return {
        DataSource.PROCESS_CREATION: "FolderPath, ProcessCommandLine, InitiatingProcessFolderPath",
        DataSource.PROCESS_ACCESS: "FileName, InitiatingProcessFolderPath",
        DataSource.REGISTRY_SET: "RegistryKey, RegistryValueData, InitiatingProcessFolderPath",
    }[ds]


# --------------------------------------------------------------------------
# Splunk SPL
# --------------------------------------------------------------------------

def to_splunk(spec: DetectionSpec) -> str:
    dm = splunk_datamodel(spec.data_source)
    node = dm.split(".")[-1]
    constraints = []
    for m in spec.matches:
        field_name = f"{node}.{resolve_field(spec.data_source, m.field, Platform.SPLUNK)}"
        terms = [_splunk_term(field_name, m.op, v) for v in m.values]
        joined = " OR ".join(terms)
        clause = f"({joined})" if len(terms) > 1 else joined
        constraints.append(f"NOT {clause}" if m.negate else clause)
    where = " ".join(constraints)
    by_fields = _SPLUNK_BY.get(spec.data_source, ("process_path",))
    by_clause = " ".join(f"{node}.{f}" for f in by_fields)
    return (
        f"| tstats count from datamodel={dm.split('.')[0]} where "
        f"nodename={dm} {where} "
        f"by {by_clause} _time"
    )


# fields to group by, per data source — only fields that exist in that CIM node
_SPLUNK_BY = {
    DataSource.PROCESS_CREATION: ("process_path", "parent_process_path"),
    DataSource.PROCESS_ACCESS: ("process_path", "target_process_path"),
    DataSource.REGISTRY_SET: ("process_path", "registry_path"),
}


def _splunk_term(field_name: str, op: Op, value: str) -> str:
    v = value.replace('"', '\\"')
    if op == Op.EQ:
        return f'{field_name}="{v}"'
    if op == Op.ENDSWITH:
        return f'{field_name}="*{v}"'
    if op == Op.STARTSWITH:
        return f'{field_name}="{v}*"'
    return f'{field_name}="*{v}*"'  # contains


# --------------------------------------------------------------------------
# OSQuery
# --------------------------------------------------------------------------

def to_osquery(spec: DetectionSpec) -> str:
    table = osquery_table(spec.data_source)
    where = []
    for m in spec.matches:
        col = resolve_field(spec.data_source, m.field, Platform.OSQUERY)
        if col is None:
            continue
        terms = [_osquery_term(col, m.op, v) for v in m.values]
        clause = "(" + " OR ".join(terms) + ")" if len(terms) > 1 else terms[0]
        where.append(f"NOT {clause}" if m.negate else clause)
    if not where:
        return ""
    return f"SELECT * FROM {table} WHERE " + " AND ".join(where) + ";"


def _osquery_term(col: str, op: Op, value: str) -> str:
    v = value.replace("'", "''")
    if op == Op.EQ:
        return f"{col} = '{v}'"
    if op == Op.ENDSWITH:
        return f"{col} LIKE '%{v}'"
    if op == Op.STARTSWITH:
        return f"{col} LIKE '{v}%'"
    return f"{col} LIKE '%{v}%'"  # contains


# --------------------------------------------------------------------------
# Suricata (from network IOCs, not techniques)
# --------------------------------------------------------------------------

def to_suricata_rules(iocs: list[IOC], start_sid: int = 9_000_001) -> list[str]:
    """Emit Suricata rules for network IOCs (domain/ipv4/url). Non-network
    IOCs (hashes, registry keys) are skipped — Suricata cannot express them."""
    rules: list[str] = []
    sid = start_sid
    for ioc in iocs:
        rule = _suricata_for(ioc, sid)
        if rule:
            rules.append(rule)
            sid += 1
    return rules


def _suricata_for(ioc: IOC, sid: int) -> str:
    def base(proto, dest, label, value, match):
        opts = f'msg:"CYBERDUDEBIVASH SENTINEL APEX - {label} {value}";'
        if match:
            opts += f" {match}"
        opts += f" classtype:trojan-activity; sid:{sid}; rev:1;"
        return f"alert {proto} $HOME_NET any -> {dest} ({opts})"
    if ioc.type == IOCType.IPV4:
        return base("ip", f"{ioc.value} any", "malicious IP", ioc.value, "")
    if ioc.type == IOCType.DOMAIN:
        content = _escape_suricata(ioc.value)
        return base("dns", "any any", "malicious domain", ioc.value,
                    f'dns.query; content:"{content}"; nocase;')
    if ioc.type == IOCType.URL:
        host, path = _split_url(ioc.value)
        parts = []
        if host:
            parts.append(f'http.host; content:"{_escape_suricata(host)}"; nocase;')
        if path and path != "/":
            parts.append(f'http.uri; content:"{_escape_suricata(path)}"; nocase;')
        if not parts:
            return ""
        return base("http", "$EXTERNAL_NET any", "malicious URL", ioc.value,
                    " ".join(parts))
    return ""


def _escape_suricata(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")


def _split_url(url: str) -> tuple[str, str]:
    stripped = url.split("://", 1)[-1]
    host, _, rest = stripped.partition("/")
    return host.split(":")[0], "/" + rest if rest else ""


# --------------------------------------------------------------------------
# validators
# --------------------------------------------------------------------------

def validate_kql(query: str) -> list[str]:
    problems = []
    lines = [l.strip() for l in query.strip().splitlines() if l.strip()]
    if not lines:
        return ["empty KQL query"]
    if lines[0].startswith("|"):
        problems.append("KQL must begin with a table, not a pipe operator")
    for l in lines[1:]:
        if not l.startswith("|"):
            problems.append(f"KQL continuation line missing pipe: {l[:40]!r}")
    if query.count('"') % 2 != 0:
        problems.append("KQL has unbalanced double quotes")
    if "| where" not in query:
        problems.append("KQL has no filtering (| where) clause")
    return problems


def validate_splunk(query: str) -> list[str]:
    problems = []
    q = query.strip()
    if not q.startswith("|") and "search" not in q.split()[0:1]:
        problems.append("SPL should start with a generating command or search")
    if q.count('"') % 2 != 0:
        problems.append("SPL has unbalanced double quotes")
    if q.count("(") != q.count(")"):
        problems.append("SPL has unbalanced parentheses")
    return problems


def validate_osquery(query: str) -> list[str]:
    problems = []
    q = query.strip()
    if not q.endswith(";"):
        problems.append("OSQuery must end with a semicolon")
    if not q.upper().startswith("SELECT"):
        problems.append("OSQuery must be a SELECT statement")
    if " FROM " not in q.upper():
        problems.append("OSQuery missing FROM clause")
    if q.count("(") != q.count(")"):
        problems.append("OSQuery has unbalanced parentheses")
    if q.count("'") % 2 != 0:
        problems.append("OSQuery has unbalanced single quotes")
    return problems


def validate_suricata(rule: str) -> list[str]:
    problems = []
    r = rule.strip()
    if not r.startswith("alert "):
        problems.append("Suricata rule must start with an action (alert)")
    if not (r.endswith(")") and "(" in r):
        problems.append("Suricata rule options block malformed")
    if "sid:" not in r:
        problems.append("Suricata rule missing sid")
    if "msg:" not in r:
        problems.append("Suricata rule missing msg")
    return problems


# --------------------------------------------------------------------------
# top-level build
# --------------------------------------------------------------------------

def build_for_technique(
    technique_id: str, references: list[str], date: str
) -> DetectionArtifacts | None:
    spec = REGISTRY.get(technique_id)
    if not spec:
        return None
    art = DetectionArtifacts(technique_id=spec.technique_id, title=spec.title)

    if Platform.SIGMA in spec.platforms:
        art.sigma = to_sigma(spec, references, date)
    if Platform.KQL in spec.platforms:
        art.kql = to_kql(spec)
        _guard(validate_kql(art.kql), "KQL", spec)
    if Platform.SPLUNK in spec.platforms:
        art.splunk = to_splunk(spec)
        _guard(validate_splunk(art.splunk), "Splunk", spec)
    if Platform.OSQUERY in spec.platforms:
        art.osquery = to_osquery(spec)
        if art.osquery:
            _guard(validate_osquery(art.osquery), "OSQuery", spec)
    return art


def _guard(problems: list[str], fmt: str, spec: DetectionSpec) -> None:
    if problems:
        raise ValueError(
            f"generated {fmt} for {spec.technique_id} failed validation: {problems}"
        )


def build_all(
    mappings: list[TechniqueMapping],
    iocs: list[IOC] | None = None,
    references: list[str] | None = None,
    date: str | None = None,
) -> tuple[list[DetectionArtifacts], list[str]]:
    """Build per-technique multi-format detections plus Suricata rules from
    network IOCs. Returns (technique_artifacts, suricata_rules)."""
    date = date or _dt.date.today().isoformat()
    refs = list(references or [])
    artifacts = []
    for mapping in mappings:
        art = build_for_technique(mapping.technique_id, refs, date)
        if art:
            artifacts.append(art)
    suricata = to_suricata_rules(iocs or [])
    for rule in suricata:
        problems = validate_suricata(rule)
        if problems:
            raise ValueError(f"generated Suricata rule failed validation: {problems}")
    return artifacts, suricata
