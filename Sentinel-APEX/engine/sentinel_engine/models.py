"""Core data model for the Sentinel APEX Intelligence Engine.

Every artifact that flows through the pipeline is one of these types.
The model enforces the platform's first-class constraint: facts and
assessments are separate, and every assessment carries a confidence label.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class IOCType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    REGISTRY_KEY = "registry_key"


@dataclass(frozen=True)
class IOC:
    """A single indicator, always stored refanged (live form) internally.

    Rendering for publication must go through ``ioc_extractor.defang``.
    """

    value: str
    type: IOCType
    context: str = ""  # short evidence excerpt the IOC was extracted from

    def key(self) -> tuple:
        return (self.type.value, self.value.lower())


@dataclass(frozen=True)
class TechniqueMapping:
    """A MITRE ATT&CK technique tied to the exact evidence that supports it."""

    technique_id: str
    name: str
    tactic: str
    evidence: str  # the phrase in the source text that triggered the mapping
    confidence: Confidence = Confidence.MEDIUM


@dataclass(frozen=True)
class Entity:
    """A named entity for the knowledge graph (actor, malware, vendor...)."""

    name: str
    type: str  # threat_actor | malware | tool | vendor | product | sector | country
    context: str = ""


@dataclass
class SourceDocument:
    """Raw inbound material before normalization."""

    raw_text: str
    source_url: str = ""
    source_name: str = ""
    title: str = ""
    published: str = ""  # ISO-8601 when known, empty when not


@dataclass
class NormalizedDoc:
    """The evidence layer: only what was extracted from the source, nothing added."""

    title: str
    text: str
    source_url: str = ""
    source_name: str = ""
    published: str = ""
    iocs: list[IOC] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    techniques: list[TechniqueMapping] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)

    def to_dict(self) -> dict:
        return json.loads(json.dumps(asdict(self), default=str))


@dataclass
class CVEEnrichment:
    """Enrichment for one CVE. Fields stay ``None`` unless a live source
    returned them — the engine never fabricates scores or metadata."""

    cve_id: str
    status: str = "unavailable"  # "enriched" | "unavailable"
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_listed: Optional[bool] = None  # None = KEV catalog not reachable
    sources: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class GateFinding:
    gate: str
    severity: str  # "block" | "warn"
    message: str


@dataclass
class GateResult:
    findings: list[GateFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(f.severity == "block" for f in self.findings)

    @property
    def blocks(self) -> list[GateFinding]:
        return [f for f in self.findings if f.severity == "block"]

    @property
    def warnings(self) -> list[GateFinding]:
        return [f for f in self.findings if f.severity == "warn"]

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "blocks": [asdict(f) for f in self.blocks],
            "warnings": [asdict(f) for f in self.warnings],
        }
