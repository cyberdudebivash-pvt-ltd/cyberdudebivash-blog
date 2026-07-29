"""Intelligence Scoring Engine — objective, deterministic publication scoring.

This is the analytical gate the whole pipeline funnels through. Every report
is scored across fourteen dimensions computed **only** from artifacts the
engine already produced (evidence, technique mappings, enrichments,
correlation, derived detections, section structure) — no new claims, no
model calls, fully reproducible. A report is publication-eligible only if it
clears the threshold AND carries no blocking quality-gate finding.

The score also drives commercial tiering (FREE / PRO / ENTERPRISE): the same
evidence effort is routed to the audience its analytical value justifies.

Design notes
------------
- Every sub-score is an integer 0–100 with a one-line, auditable rationale.
- Weights are explicit and sum to 1.0 (see ``WEIGHTS``).
- Scoring is a pure function of the ``PipelineResult`` — it never fabricates
  or re-derives; it measures what the evidence layer supports.

GTIEP v1 extension (2026-07-29)
-------------------------------
Five dimensions were added additively — ``technical_accuracy``,
``defensive_guidance``, ``analyst_usability``, ``report_structure``,
``visualizations`` — to align with a proposed 11-category quality
framework, and to resolve `platform/open-issues.md` Issue 3 item 3: this
model previously could only reward *automated-pipeline* detection/IOC
artifacts (`PipelineResult.detections[]`/`.suricata_rules`), so a correct,
gate-passing, hand-authored report with a real, independently-verified
Sigma rule embedded in its own prose (SA-2026-0001) scored as if it had
none. The five new dimensions, plus `_embedded_detection_formats()`
(credited additively inside `_detection_value`), read from a new optional
`PipelineResult.raw_sections` field instead — populated for hand-authored
reports via `report_ingest.py`, left empty (`{}`) for the automated
pipeline, which is why every dimension below degrades to a documented
neutral default rather than crashing or silently scoring zero when it
isn't populated. The original nine dimensions and their relative behavior
for automated-pipeline reports are unchanged; only the weights were
rebalanced so the full set still sums to 1.0.

One dimension — ``technical_accuracy`` — is explicitly a **proxy**, not a
true semantic-correctness verifier: this platform has no ground-truth
oracle to check a claim against, so it scores structural/schema
cleanliness (quality-gate finding severity and count) instead, which is
the only thing actually measurable without one. See its docstring.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .models import Confidence, GateResult, IOCType
from .quality import REQUIRED_SECTIONS, validate_sigma, validate_yara

# Overall-score weighting. Explicit and summing to 1.0 so the composite is
# transparent and tunable. Rebalanced (GTIEP v1) to make room for the five
# new dimensions below while preserving the original nine's relative order.
WEIGHTS: dict[str, float] = {
    "evidence_quality": 0.14,
    "original_analysis": 0.12,
    "detection_value": 0.10,
    "soc_value": 0.06,
    "dfir_value": 0.04,
    "executive_value": 0.06,
    "commercial_value": 0.05,
    "analyst_confidence": 0.04,
    "seo_value": 0.04,
    "technical_accuracy": 0.12,
    "defensive_guidance": 0.08,
    "analyst_usability": 0.07,
    "report_structure": 0.05,
    "visualizations": 0.03,
}

DEFAULT_THRESHOLD = 60

# ATT&CK tactics that carry forensic/DFIR weight.
_FORENSIC_TACTICS = {
    "credential-access", "persistence", "defense-evasion",
    "lateral-movement", "collection", "privilege-escalation", "discovery",
}

_HOST_IOC_TYPES = {
    IOCType.SHA256, IOCType.SHA1, IOCType.MD5, IOCType.REGISTRY_KEY,
}
_NETWORK_IOC_TYPES = {IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL}

_CONFIDENCE_WEIGHT = {
    Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.3,
}

# Extends quality.py's hard-gated REQUIRED_SECTIONS with a broader,
# scored-not-gated completeness check against the full master-prompt.md
# taxonomy (GTIEP v1) — see platform/quality-metrics.md's previously
# "Not computed" report-completeness metric. Deliberately NOT added to
# quality.py's REQUIRED_SECTIONS itself: that would retroactively fail
# every already-certified published report (none have CWE/CAPEC sections
# yet), which is exactly the kind of backward-incompatible change this
# platform's governance prohibits. Scored, not gated.
_RECOMMENDED_SECTIONS = REQUIRED_SECTIONS + (
    "Key Findings", "Kill Chain Analysis", "CVE Analysis", "CWE Analysis",
    "CAPEC Mapping", "Exploit Analysis", "Business Risk Assessment",
    "Threat Hunting", "Incident Response", "Confidence Assessment", "References",
)

_DEFENSIVE_SECTIONS = (
    "Containment Strategy", "Eradication Strategy", "Recovery Guidance",
    "Vulnerability Management Guidance", "Patch Prioritization",
    "Security Architecture Recommendations", "Zero Trust Considerations",
)

_RE_FENCED_BLOCK = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)


@dataclass
class IntelligenceScore:
    dimensions: dict[str, int] = field(default_factory=dict)
    rationale: dict[str, str] = field(default_factory=dict)
    overall: int = 0
    threshold: int = DEFAULT_THRESHOLD
    gate_passed: bool = True
    eligible: bool = False
    tier: str = "BLOCKED"  # BLOCKED | FREE | PRO | ENTERPRISE

    def to_dict(self) -> dict:
        return asdict(self)


def _clamp(v: float) -> int:
    return int(max(0, min(100, round(v))))


# --------------------------------------------------------------------------
# per-dimension scorers (each returns (score, rationale))
# --------------------------------------------------------------------------

def _evidence_quality(r) -> tuple[int, str]:
    doc = r.normalized
    net = [i for i in doc.iocs if i.type in _NETWORK_IOC_TYPES]
    host = [i for i in doc.iocs if i.type in _HOST_IOC_TYPES]
    enriched = sum(1 for e in r.enrichments if e.status == "enriched")
    s = 0
    s += 18 if doc.source_url else 0
    s += min(15, len(doc.cves) * 8)
    s += min(15, (len(net) + len(host)) * 3)
    s += min(20, enriched * 12)
    s += min(17, len(doc.entities) * 5)
    s += min(15, len(doc.techniques) * 3)
    return _clamp(s), (
        f"source={'yes' if doc.source_url else 'no'}, cves={len(doc.cves)}, "
        f"iocs={len(net) + len(host)}, enriched={enriched}, "
        f"entities={len(doc.entities)}, techniques={len(doc.techniques)}"
    )


def _original_analysis(r) -> tuple[int, str]:
    doc = r.normalized
    s = 0
    s += min(25, len(doc.techniques) * 5)          # evidence-based correlation
    s += min(25, len(r.prior_context) * 9)          # historical correlation
    s += min(25, len(r.detections) * 8)             # derived detection engineering
    s += 15 if len(doc.entities) >= 2 else 0        # multi-entity correlation
    s += 10 if any(e.status == "enriched" for e in r.enrichments) else 0
    return _clamp(s), (
        f"techniques={len(doc.techniques)}, prior_context={len(r.prior_context)}, "
        f"detections={len(r.detections)}, entities={len(doc.entities)}"
    )


def _embedded_detection_formats(r) -> set[str]:
    """Scans a hand-authored report's own section text for fenced code
    blocks that are real, structurally-valid Sigma/YARA rules (via
    quality.py's own validators, so a bare mention of the word "sigma"
    doesn't count), or KQL/SPL/Suricata blocks. Exists because
    `PipelineResult.detections[]`/`.suricata_rules` only ever hold
    machine-generated rules — an analyst's own embedded, independently
    verified detection content had no path to credit before this (see
    `platform/open-issues.md` Issue 3 item 3). Returns an empty set for the
    automated pipeline, which never populates `raw_sections`."""
    sections = getattr(r, "raw_sections", None)
    if not sections:
        return set()
    found: set[str] = set()
    full_text = "\n".join(sections.values())
    for lang, body in _RE_FENCED_BLOCK.findall(full_text):
        stripped = body.strip()
        if not stripped:
            continue
        lang_l = lang.lower()
        if lang_l in ("yaml", "yml") or "logsource:" in stripped or "detection:" in stripped:
            if not validate_sigma(stripped):
                found.add("sigma")
        elif lang_l == "yara" or re.match(r"rule\s+\w+\s*\{", stripped):
            if not validate_yara(stripped):
                found.add("yara")
        elif lang_l in ("kql", "spl", "splunk"):
            found.add(lang_l)
        elif "suricata" in lang_l or re.match(r"(alert|drop|reject)\s+\w+", stripped):
            found.add("suricata")
    return found


def _detection_value(r) -> tuple[int, str]:
    formats = sum(len(a.formats()) for a in r.detections)
    embedded = _embedded_detection_formats(r)
    s = formats * 10 + len(r.suricata_rules) * 5 + len(embedded) * 10
    return _clamp(s), (
        f"detection_formats={formats}, suricata_rules={len(r.suricata_rules)}, "
        f"embedded_verified_formats={sorted(embedded) or 'none'}"
    )


def _soc_value(r, detection_value: int) -> tuple[int, str]:
    doc = r.normalized
    net = [i for i in doc.iocs if i.type in _NETWORK_IOC_TYPES]
    s = 0.5 * detection_value
    s += min(30, len(net) * 5)            # block-list / enforcement value
    s += min(20, len(doc.techniques) * 4)  # hunt hypotheses
    return _clamp(s), (
        f"0.5*detection({detection_value}), network_iocs={len(net)}, "
        f"techniques={len(doc.techniques)}"
    )


def _dfir_value(r) -> tuple[int, str]:
    doc = r.normalized
    forensic = [t for t in doc.techniques if t.tactic in _FORENSIC_TACTICS]
    host = [i for i in doc.iocs if i.type in _HOST_IOC_TYPES]
    s = min(45, len(forensic) * 10) + min(35, len(host) * 8)
    s += 20 if any(i.type == IOCType.REGISTRY_KEY for i in doc.iocs) else 0
    return _clamp(s), (
        f"forensic_techniques={len(forensic)}, host_iocs={len(host)}"
    )


def _executive_value(r) -> tuple[int, str]:
    doc = r.normalized
    kev = any(e.kev_listed for e in r.enrichments)
    max_cvss = max((e.cvss_score or 0.0 for e in r.enrichments), default=0.0)
    actors = [e for e in doc.entities if e.type == "threat_actor"]
    malware = [e for e in doc.entities if e.type == "malware"]
    s = 0
    s += 35 if kev else 0
    s += 30 if max_cvss >= 9 else 20 if max_cvss >= 7 else 0
    s += 25 if actors else 0
    s += 10 if malware else 0
    return _clamp(s), (
        f"kev={kev}, max_cvss={max_cvss or 'n/a'}, actors={len(actors)}, "
        f"malware={len(malware)}"
    )


def _commercial_value(r) -> tuple[int, str]:
    doc = r.normalized
    net = [i for i in doc.iocs if i.type in _NETWORK_IOC_TYPES]
    actors = [e for e in doc.entities if e.type == "threat_actor"]
    services = []
    s = 0
    if r.detections:
        s += 30
        services.append("detection-pack")
    if net or doc.cves:
        s += 25
        services.append("intel-api/ioc-feed")
    if actors:
        s += 25
        services.append("apt-consulting")
    if any(e.status == "enriched" for e in r.enrichments):
        s += 20
        services.append("vuln-advisory")
    return _clamp(s), (
        f"services={','.join(services) if services else 'none'}"
    )


def _seo_value(r) -> tuple[int, str]:
    doc = r.normalized
    title_len = len(doc.title or "")
    s = 0
    s += 20 if 30 <= title_len <= 75 else 8 if title_len else 0
    s += 20 if doc.cves else 0
    s += 15 if any(e.type in ("vendor", "product") for e in doc.entities) else 0
    s += min(15, len(doc.techniques) * 3)
    s += min(15, len(doc.entities) * 4)
    s += 15 if doc.source_url else 0
    return _clamp(s), (
        f"title_len={title_len}, cves={len(doc.cves)}, entities={len(doc.entities)}"
    )


def _analyst_confidence(r) -> tuple[int, str]:
    doc = r.normalized
    if doc.techniques:
        avg = sum(_CONFIDENCE_WEIGHT[t.confidence] for t in doc.techniques) / len(doc.techniques)
        base = avg * 60
    else:
        avg = None
        base = 35
    base += 20 if any(e.status == "enriched" for e in r.enrichments) else 0
    base += 20 if (doc.source_url and doc.source_name) else 10 if doc.source_url else 0
    return _clamp(base), (
        f"technique_confidence_avg={'n/a' if avg is None else round(avg, 2)}, "
        f"enriched={any(e.status == 'enriched' for e in r.enrichments)}, "
        f"corroboration={'strong' if doc.source_url and doc.source_name else 'weak'}"
    )


def _report_structure(r) -> tuple[int, str]:
    """% of `_RECOMMENDED_SECTIONS` actually present, by name. Neutral
    default (50) when `raw_sections` isn't populated — the automated
    pipeline's output isn't Markdown-sectioned the same way, so "no
    section list" isn't evidence of poor structure, just a different
    shape this check can't read."""
    sections = getattr(r, "raw_sections", None)
    if not sections:
        return 50, "no section list available (not a sectioned report) — neutral score"
    names_upper = [str(n).upper() for n in sections.keys()]
    present = sum(1 for want in _RECOMMENDED_SECTIONS if any(want.upper() in n for n in names_upper))
    total = len(_RECOMMENDED_SECTIONS)
    s = round(100 * present / total)
    return _clamp(s), f"{present}/{total} recommended structural sections present"


def _defensive_guidance(r) -> tuple[int, str]:
    """% of `_DEFENSIVE_SECTIONS` present — containment/eradication/
    recovery/hardening/patch-prioritization guidance, not just detection."""
    sections = getattr(r, "raw_sections", None)
    if not sections:
        return 50, "no section list available — neutral score"
    names_upper = [str(n).upper() for n in sections.keys()]
    present = sum(1 for want in _DEFENSIVE_SECTIONS if any(want.upper() in n for n in names_upper))
    total = len(_DEFENSIVE_SECTIONS)
    s = round(100 * present / total)
    return _clamp(s), f"{present}/{total} defensive-guidance sections present"


def _analyst_usability(r) -> tuple[int, str]:
    """Citability (References), transparency (Confidence Assessment),
    structured data (tables) over wall-of-text, and a sane section count —
    proxies for "can an analyst actually use this quickly," not a
    readability-score algorithm."""
    sections = getattr(r, "raw_sections", None)
    if not sections:
        return 50, "no section list available — neutral score"
    names_upper = [str(n).upper() for n in sections.keys()]
    has_refs = any("REFERENCE" in n for n in names_upper)
    has_confidence = any("CONFIDENCE" in n for n in names_upper)
    table_sections = sum(1 for body in sections.values() if "|---" in body or "| ---" in body)
    section_count = len(sections)
    reasonable_length = 8 <= section_count <= 40
    s = 0
    s += 25 if has_refs else 0
    s += 20 if has_confidence else 0
    s += min(35, table_sections * 10)
    s += 20 if reasonable_length else 5
    return _clamp(s), (
        f"references={has_refs}, confidence_section={has_confidence}, "
        f"tables={table_sections}, sections={section_count}"
    )


def _visualizations(r) -> tuple[int, str]:
    """Tables and images actually present in the rendered content — the
    only two "visualization" types this platform's reports use today."""
    sections = getattr(r, "raw_sections", None)
    if not sections:
        return 40, "no section list available — neutral-low score (nothing to check)"
    full_text = "\n".join(sections.values())
    table_count = full_text.count("|---") + full_text.count("| ---")
    image_count = len(re.findall(r"!\[[^\]]*\]\([^)]+\)", full_text))
    s = min(70, table_count * 12) + min(30, image_count * 30)
    return _clamp(s), f"tables={table_count}, images={image_count}"


def _technical_accuracy(r) -> tuple[int, str]:
    """A structural-cleanliness PROXY, not a true accuracy verifier — this
    platform has no ground-truth oracle to check a claim's correctness
    against. What quality.py's gate *can* actually check is measurable:
    valid CVE/ATT&CK ID formats, non-fabricated required fields,
    well-formed embedded detection rules. Scored as the inverse of gate-
    finding severity/density rather than duplicating `gate_passed` (already
    a separate, hard eligibility factor in `score()`) — this dimension adds
    granularity *within* passing reports instead of restating pass/fail."""
    gate = getattr(r, "gate", None)
    if gate is None:
        return 70, "no gate result available — neutral-leaning score (structural checks not run)"
    findings = list(getattr(gate, "findings", []) or [])
    blocks = sum(1 for f in findings if getattr(f, "severity", "") == "block")
    warns = sum(1 for f in findings if getattr(f, "severity", "") == "warn")
    s = 100 - (blocks * 25) - (warns * 8)
    return _clamp(s), f"gate findings: {blocks} block, {warns} warn"


# --------------------------------------------------------------------------
# composite
# --------------------------------------------------------------------------

def score(result, threshold: int = DEFAULT_THRESHOLD,
          gate: GateResult | None = None) -> IntelligenceScore:
    """Score a ``PipelineResult`` across fourteen dimensions and decide
    eligibility.

    ``gate`` defaults to ``result.gate``; a blocking gate finding makes the
    report ineligible regardless of score (correctness before commercial value).
    """
    dims: dict[str, int] = {}
    why: dict[str, str] = {}

    dims["evidence_quality"], why["evidence_quality"] = _evidence_quality(result)
    dims["original_analysis"], why["original_analysis"] = _original_analysis(result)
    dims["detection_value"], why["detection_value"] = _detection_value(result)
    dims["soc_value"], why["soc_value"] = _soc_value(result, dims["detection_value"])
    dims["dfir_value"], why["dfir_value"] = _dfir_value(result)
    dims["executive_value"], why["executive_value"] = _executive_value(result)
    dims["commercial_value"], why["commercial_value"] = _commercial_value(result)
    dims["analyst_confidence"], why["analyst_confidence"] = _analyst_confidence(result)
    dims["seo_value"], why["seo_value"] = _seo_value(result)
    dims["technical_accuracy"], why["technical_accuracy"] = _technical_accuracy(result)
    dims["defensive_guidance"], why["defensive_guidance"] = _defensive_guidance(result)
    dims["analyst_usability"], why["analyst_usability"] = _analyst_usability(result)
    dims["report_structure"], why["report_structure"] = _report_structure(result)
    dims["visualizations"], why["visualizations"] = _visualizations(result)

    overall = _clamp(sum(dims[k] * w for k, w in WEIGHTS.items()))

    effective_gate = gate if gate is not None else getattr(result, "gate", None)
    gate_passed = True if effective_gate is None else effective_gate.passed

    eligible = overall >= threshold and gate_passed
    tier = _tier(overall, dims["detection_value"], eligible)

    return IntelligenceScore(
        dimensions=dims, rationale=why, overall=overall,
        threshold=threshold, gate_passed=gate_passed,
        eligible=eligible, tier=tier,
    )


def _tier(overall: int, detection_value: int, eligible: bool) -> str:
    if not eligible:
        return "BLOCKED"
    if overall >= 82 and detection_value >= 60:
        return "ENTERPRISE"
    if overall >= 70:
        return "PRO"
    return "FREE"
