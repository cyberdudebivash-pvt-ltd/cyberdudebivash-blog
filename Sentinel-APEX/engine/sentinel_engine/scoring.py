"""Intelligence Scoring Engine — objective, deterministic publication scoring.

This is the analytical gate the whole pipeline funnels through. Every report
is scored across ten dimensions computed **only** from artifacts the engine
already produced (evidence, technique mappings, enrichments, correlation,
derived detections) — no new claims, no model calls, fully reproducible. A
report is publication-eligible only if it clears the threshold AND carries no
blocking quality-gate finding.

The score also drives commercial tiering (FREE / PRO / ENTERPRISE): the same
evidence effort is routed to the audience its analytical value justifies.

Design notes
------------
- Every sub-score is an integer 0–100 with a one-line, auditable rationale.
- Weights are explicit and sum to 1.0 (see ``WEIGHTS``).
- Scoring is a pure function of the ``PipelineResult`` — it never fabricates
  or re-derives; it measures what the evidence layer supports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .models import Confidence, GateResult, IOCType

# Overall-score weighting. Explicit and summing to 1.0 so the composite is
# transparent and tunable.
WEIGHTS: dict[str, float] = {
    "evidence_quality": 0.22,
    "original_analysis": 0.18,
    "detection_value": 0.15,
    "soc_value": 0.10,
    "dfir_value": 0.06,
    "executive_value": 0.10,
    "commercial_value": 0.08,
    "analyst_confidence": 0.06,
    "seo_value": 0.05,
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


def _detection_value(r) -> tuple[int, str]:
    formats = sum(len(a.formats()) for a in r.detections)
    s = formats * 10 + len(r.suricata_rules) * 5
    return _clamp(s), (
        f"detection_formats={formats}, suricata_rules={len(r.suricata_rules)}"
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


# --------------------------------------------------------------------------
# composite
# --------------------------------------------------------------------------

def score(result, threshold: int = DEFAULT_THRESHOLD,
          gate: GateResult | None = None) -> IntelligenceScore:
    """Score a ``PipelineResult`` across ten dimensions and decide eligibility.

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
