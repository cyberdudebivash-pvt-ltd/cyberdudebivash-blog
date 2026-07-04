"""Executable production quality gates.

This replaces the checklist in ``quality/quality-gate.md`` with code: a
report either passes every blocking gate or it is not eligible for
publication. Gates operate on parsed published reports (``ParsedReport``)
and, at corpus level, across a set of reports to catch templated content.
"""

from __future__ import annotations

import re

import yaml

from .attack_mapper import extract_technique_ids, is_valid_technique_id
from .ioc_extractor import DEFAULT_ALLOWLIST, extract_iocs
from .models import GateFinding, GateResult, IOCType
from .normalizer import NOISE_PATTERNS
from .report_parser import SEVERITIES, ParsedReport

REQUIRED_SECTIONS = (
    "Executive Summary",
    "Verified Facts",
    "Technical Analysis",
    "MITRE ATT&CK",
    "IOC Intelligence",
)

SIGMA_REQUIRED_KEYS = ("title", "id", "description", "logsource", "detection", "level")
SIGMA_LEVELS = ("informational", "low", "medium", "high", "critical")

_RE_CONFIDENCE = re.compile(r"\((LOW|MEDIUM|HIGH)\s+CONFIDENCE\)")
_RE_ASSESSMENT = re.compile(
    r"\b(assess(?:ed|ment)?|likely|estimated|probably|we believe|suggests)\b",
    re.IGNORECASE,
)
_RE_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


# --------------------------------------------------------------------------
# per-report gates
# --------------------------------------------------------------------------

def gate_report(report: ParsedReport) -> GateResult:
    findings: list[GateFinding] = []
    findings += _gate_structure(report)
    findings += _gate_attack(report)
    findings += _gate_ioc_defanging(report)
    findings += _gate_sigma(report)
    findings += _gate_confidence(report)
    findings += _gate_content_integrity(report)
    return GateResult(findings=findings)


def _gate_structure(report: ParsedReport) -> list[GateFinding]:
    findings = []
    for section in REQUIRED_SECTIONS:
        if not report.has_section(section):
            findings.append(GateFinding(
                "structure", "block", f"required section missing: {section}"
            ))
    if report.severity not in SEVERITIES:
        findings.append(GateFinding(
            "structure", "block",
            f"severity missing or invalid: {report.severity!r}",
        ))
    if not report.title:
        findings.append(GateFinding("structure", "block", "report title not found"))
    return findings


def _gate_attack(report: ParsedReport) -> list[GateFinding]:
    findings = []
    section = report.section("MITRE ATT&CK")
    ids = extract_technique_ids(section)
    if not ids:
        findings.append(GateFinding(
            "attack", "block", "no ATT&CK technique IDs in MITRE mapping section"
        ))
    for tid in ids:
        if not is_valid_technique_id(tid):
            # well-formed but outside the curated subset: cannot be verified
            # offline, so flag for review rather than hard-block
            findings.append(GateFinding(
                "attack", "warn",
                f"ATT&CK technique ID not in curated validation set: {tid} — "
                "verify against attack.mitre.org before publication",
            ))
    return findings


def _gate_ioc_defanging(report: ParsedReport) -> list[GateFinding]:
    """Live (undefanged) network indicators in the IOC section block release.

    Only the IOC section is held to defanging; reference URLs elsewhere
    (advisories, our own properties) are legitimate live links.
    """
    findings = []
    section = report.section("IOC Intelligence")
    if not section:
        return findings
    # Extract from the section WITHOUT refanging: whatever still matches as a
    # live URL/IP/domain was published in live (clickable/resolvable) form.
    for ioc in extract_iocs_live_only(section):
        findings.append(GateFinding(
            "ioc-defanging", "block",
            f"live (undefanged) {ioc.type.value} in IOC section: {ioc.value}",
        ))
    return findings


def extract_iocs_live_only(section: str):
    """IOCs that appear in live form (i.e., would still match after masking
    all defanged notation instead of refanging it)."""
    masked = (
        section.replace("[.]", " ").replace("(.)", " ")
        .replace("hxxp", " ").replace("[:]", " ").replace("[@]", " ")
    )
    return [
        i for i in extract_iocs(masked, include_context=False)
        if i.type in (IOCType.URL, IOCType.IPV4, IOCType.DOMAIN, IOCType.EMAIL)
    ]


def _gate_sigma(report: ParsedReport) -> list[GateFinding]:
    if not report.has_section("Sigma"):
        return []  # a Sigma rule is not mandatory for every report type
    if not report.sigma_yaml:
        return [GateFinding(
            "sigma", "block", "Sigma section present but no parseable rule body"
        )]
    findings = [
        GateFinding("sigma", "block", msg)
        for msg in validate_sigma(report.sigma_yaml)
    ]
    # consistency: sigma attack tags should be a subset of the report's mapping
    report_ids = {t.lower() for t in extract_technique_ids(report.section("MITRE ATT&CK"))}
    try:
        rule = yaml.safe_load(report.sigma_yaml)
        for tag in (rule or {}).get("tags", []) or []:
            m = _RE_ATTACK_TAG.match(str(tag))
            if m and m.group(1) not in report_ids:
                findings.append(GateFinding(
                    "sigma", "warn",
                    f"Sigma tag {tag} has no matching technique in the report's "
                    "MITRE mapping — rule may be templated, not evidence-driven",
                ))
    except yaml.YAMLError:
        pass
    return findings


def validate_sigma(rule_yaml: str) -> list[str]:
    """Validate one Sigma rule; returns a list of problems (empty = valid)."""
    problems: list[str] = []
    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as exc:
        return [f"Sigma rule is not valid YAML: {exc}"]
    if not isinstance(rule, dict):
        return ["Sigma rule did not parse to a mapping"]

    for key in SIGMA_REQUIRED_KEYS:
        if key not in rule:
            problems.append(f"Sigma rule missing required field: {key}")

    level = str(rule.get("level", "")).lower()
    if "level" in rule and level not in SIGMA_LEVELS:
        problems.append(f"Sigma level invalid: {rule.get('level')!r}")

    detection = rule.get("detection")
    if isinstance(detection, dict):
        condition = str(detection.get("condition", ""))
        if not condition:
            problems.append("Sigma detection has no condition")
        else:
            selections = {k for k in detection if k != "condition"}
            referenced = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition)) - {
                "and", "or", "not", "of", "all", "them", "1"
            }
            for name in referenced:
                if not any(_sigma_ref_matches(name, s) for s in selections):
                    problems.append(
                        f"Sigma condition references undefined selection: {name}"
                    )
        if not any(k for k in detection if k != "condition"):
            problems.append("Sigma detection defines no selections")
    elif "detection" in rule:
        problems.append("Sigma detection is not a mapping")

    for tag in rule.get("tags", []) or []:
        m = _RE_ATTACK_TAG.match(str(tag))
        if m and not is_valid_technique_id(m.group(1).upper()):
            problems.append(f"Sigma tag references unknown technique: {tag}")
    return problems


def _sigma_ref_matches(ref: str, selection: str) -> bool:
    # supports wildcard references like "selection_*"
    if ref == selection:
        return True
    return ref.endswith("*") and selection.startswith(ref[:-1])


def _gate_confidence(report: ParsedReport) -> list[GateFinding]:
    findings = []
    body = "\n".join(report.sections.values())
    labels = _RE_CONFIDENCE.findall(body)
    assessments = _RE_ASSESSMENT.findall(body)
    if assessments and not labels:
        findings.append(GateFinding(
            "confidence", "block",
            "report makes assessments but carries no confidence labels",
        ))
    return findings


def _gate_content_integrity(report: ParsedReport) -> list[GateFinding]:
    findings = []
    analysis = report.section("Technical Analysis")
    for pattern in NOISE_PATTERNS:
        m = pattern.search(analysis)
        if m:
            findings.append(GateFinding(
                "content-integrity", "block",
                f"raw aggregator/scraper text leaked into Technical Analysis: "
                f"{m.group(0)[:60]!r}",
            ))
    if analysis and len(analysis) < 400:
        findings.append(GateFinding(
            "content-integrity", "warn",
            f"Technical Analysis is thin ({len(analysis)} chars) — "
            "likely source passthrough without original analysis",
        ))
    summary = report.section("Executive Summary")
    if summary and analysis and summary[:200].strip() and \
            summary[:200].strip()[:150] in analysis:
        findings.append(GateFinding(
            "content-integrity", "warn",
            "Executive Summary is a verbatim copy of the Technical Analysis "
            "opening — no executive-level synthesis",
        ))
    return findings


# --------------------------------------------------------------------------
# corpus-level gates (templated-content detection)
# --------------------------------------------------------------------------

def _shingles(text: str, n: int = 5) -> set[tuple[str, ...]]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {tuple(words[i : i + n]) for i in range(max(0, len(words) - n + 1))}


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def gate_corpus(reports: dict[str, ParsedReport]) -> GateResult:
    """Cross-report gates: detect templated sections and duplicated detection
    content that make output look machine-stamped rather than analyst-made."""
    findings: list[GateFinding] = []
    names = sorted(reports)

    # identical Sigma rules across unrelated reports
    sigma_titles: dict[str, list[str]] = {}
    for name in names:
        rule = reports[name].sigma_yaml
        if not rule:
            continue
        try:
            title = str((yaml.safe_load(rule) or {}).get("title", "")).strip()
        except yaml.YAMLError:
            continue
        if title:
            sigma_titles.setdefault(title, []).append(name)
    for title, holders in sorted(sigma_titles.items()):
        if len(holders) > 1:
            findings.append(GateFinding(
                "corpus-duplication", "block",
                f"identical Sigma rule ({title!r}) published in "
                f"{len(holders)} reports: {', '.join(holders)} — "
                "detections must be derived from each report's evidence",
            ))

    # near-duplicate operational sections across reports
    for section_name in ("MITRE ATT&CK", "IOC Intelligence", "Threat Hunting"):
        shingle_sets = {
            name: _shingles(reports[name].section(section_name))
            for name in names
        }
        flagged: set[str] = set()
        for i, a in enumerate(names):
            for b in names[i + 1 :]:
                if a in flagged and b in flagged:
                    continue
                sim = jaccard(shingle_sets[a], shingle_sets[b])
                if shingle_sets[a] and sim >= 0.8:
                    findings.append(GateFinding(
                        "corpus-duplication", "warn",
                        f"'{section_name}' section is {sim:.0%} identical "
                        f"between {a} and {b} — templated content",
                    ))
                    flagged.update((a, b))
    return GateResult(findings=findings)
