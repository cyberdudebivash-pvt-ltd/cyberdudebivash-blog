"""Threat-type schema isolation (ReportX Section 5) + the ransomware
evidence model (Section 6) + the CVE/KEV specialist model (Section 7).

The isolation rule (Section 5): a premium renderer must never use a
foreign threat-type field unless the event has an explicit linked object.
Concretely — a ``RansomwareVictimClaim`` has no ``cvss_score: float``
field a template could accidentally populate; the only way a CVE ever
attaches to a ransomware claim is through ``linked_vulnerabilities``,
each entry a full, independent ``LinkedVulnerability`` record. The
top-level applicability markers (``cisa_kev_state`` etc.) stay
``NOT_APPLICABLE`` until that link exists — see the class docstrings for
why this is a real dataclass field and not just a rendering convention.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from .claim_model import EpistemicState, TemporalPrecision


class ThreatType(str, Enum):
    RANSOMWARE_VICTIM_CLAIM = "RANSOMWARE_VICTIM_CLAIM"
    CVE = "CVE"
    CISA_KEV = "CISA_KEV"
    # Extensible interfaces only, per Section 5 -- no dedicated field sets
    # built out this pass; ThreatProduct subclasses may be added later
    # without touching RANSOMWARE_VICTIM_CLAIM/CVE/CISA_KEV.
    MALWARE = "MALWARE"
    APT_CAMPAIGN = "APT_CAMPAIGN"
    BREACH = "BREACH"
    PHISHING = "PHISHING"
    STRATEGIC_ASSESSMENT = "STRATEGIC_ASSESSMENT"


# ============================================================
# Shared "vulnerability link" — the ONLY channel through which
# vulnerability data may reach a non-CVE schema.
# ============================================================

@dataclass
class LinkedVulnerability:
    """A full, independent CVE record attached to a non-CVE threat product
    (e.g. a ransomware claim where an attributed initial-access CVE is
    established by evidence). This is a real ``CVERecord`` reference — the
    parent schema never re-derives or copies fields out of it into its own
    flat namespace."""

    cve_record: "CVERecord"
    attribution_claim_id: str  # the Claim that establishes THIS vuln caused THIS incident
    attribution_status: EpistemicState = EpistemicState.NOT_ASSESSED

    def to_dict(self) -> dict:
        return {
            "cve_record": self.cve_record.to_dict(),
            "attribution_claim_id": self.attribution_claim_id,
            "attribution_status": self.attribution_status.value,
        }


@dataclass
class ThreatProduct:
    """Base marker every isolated schema inherits. Carries only what is
    genuinely cross-cutting (a stable product id and its declared type) —
    everything threat-type-specific lives on the subclass, never here."""

    product_id: str
    threat_type: ThreatType
    linked_vulnerabilities: list[LinkedVulnerability] = field(default_factory=list)

    def has_linked_vulnerability(self) -> bool:
        return bool(self.linked_vulnerabilities)


# ============================================================
# Section 6 — Ransomware evidence model, 3 explicit layers
# ============================================================

@dataclass
class VictimObservation:
    """Layer A — victim-specific observations for THIS incident only."""

    group_named_by_source: Optional[str] = None
    victim_name: Optional[str] = None
    victim_domain: Optional[str] = None
    country: Optional[str] = None
    sector: Optional[str] = None
    claim_date: Optional[str] = None
    claim_temporal_precision: TemporalPrecision = TemporalPrecision.UNKNOWN
    leak_site_claim_status: EpistemicState = EpistemicState.NOT_ASSESSED
    claimed_data_description: Optional[str] = None
    sample_proof_status: EpistemicState = EpistemicState.NOT_ASSESSED
    independent_confirmation: EpistemicState = EpistemicState.NOT_ASSESSED
    victim_acknowledgement: EpistemicState = EpistemicState.NOT_ASSESSED
    regulator_disclosure: EpistemicState = EpistemicState.NOT_ASSESSED
    # claim_ids, not raw values -- every one of these must trace back to
    # the EvidenceGraph via a Claim with its own source_refs.
    source_claim_ids: list[str] = field(default_factory=list)
    observed_incident_ioc_claim_ids: list[str] = field(default_factory=list)
    observed_incident_ttp_claim_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["claim_temporal_precision"] = self.claim_temporal_precision.value
        d["leak_site_claim_status"] = self.leak_site_claim_status.value
        d["sample_proof_status"] = self.sample_proof_status.value
        d["independent_confirmation"] = self.independent_confirmation.value
        d["victim_acknowledgement"] = self.victim_acknowledgement.value
        d["regulator_disclosure"] = self.regulator_disclosure.value
        return d


@dataclass
class ActorHistoricalContext:
    """Layer B — what is known about the actor IN GENERAL. Every field is
    claim-id-backed, not free text, so the claim-support matrix (Section 9)
    can verify actor-context assertions have their own evidence
    independent of the victim-observation layer (Section 19's explicit
    requirement: 'Historical Qilin behavior is not evidence that the
    behavior occurred at Spoonful of Comfort')."""

    actor_aliases: list[str] = field(default_factory=list)
    raas_model_claim_ids: list[str] = field(default_factory=list)
    historical_ttp_claim_ids: list[str] = field(default_factory=list)
    historical_tooling_claim_ids: list[str] = field(default_factory=list)
    initial_access_history_claim_ids: list[str] = field(default_factory=list)
    infrastructure_claim_ids: list[str] = field(default_factory=list)
    affiliate_behavior_claim_ids: list[str] = field(default_factory=list)
    victimology_claim_ids: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    geographies: list[str] = field(default_factory=list)
    campaign_history_claim_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GenericReadiness:
    """Layer C — generic ransomware defensive guidance. Always rendered
    with an explicit, unremovable label so it can never be presented as
    incident-specific evidence (Section 6's closing requirement)."""

    LABEL = "GENERIC_DEFENSIVE_READINESS"

    immutable_backups: str = ""
    identity_hardening: str = ""
    segmentation: str = ""
    mass_encryption_detection: str = ""
    recovery_inhibition_coverage: str = ""
    ir_preparation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["label"] = self.LABEL
        return d


@dataclass
class RansomwareVictimClaim(ThreatProduct):
    """Section 5's isolation requirement made concrete: the four
    vulnerability-shaped fields below exist so a renderer that expects them
    (for uniform "does this product have a KEV state" checks) always finds
    a value, but that value is ``NOT_APPLICABLE`` unless
    ``linked_vulnerabilities`` is genuinely populated — enforced by
    ``__post_init__``, not left to renderer discipline."""

    threat_type: ThreatType = field(default=ThreatType.RANSOMWARE_VICTIM_CLAIM, init=False)
    victim_observation: VictimObservation = field(default_factory=VictimObservation)
    actor_context: ActorHistoricalContext = field(default_factory=ActorHistoricalContext)
    generic_readiness: GenericReadiness = field(default_factory=GenericReadiness)

    # Vulnerability-shaped applicability markers -- NOT_APPLICABLE unless
    # linked_vulnerabilities is non-empty. These are the exact four fields
    # Section 5 names: CISA_KEV, CVSS, PATCH, EXPLOIT_CVE_STATUS.
    cisa_kev_state: EpistemicState = EpistemicState.NOT_APPLICABLE
    cvss_state: EpistemicState = EpistemicState.NOT_APPLICABLE
    patch_state: EpistemicState = EpistemicState.NOT_APPLICABLE
    exploit_cve_status: EpistemicState = EpistemicState.NOT_APPLICABLE

    def __post_init__(self):
        # Contamination guard: no matter what the caller passed, if there
        # is no linked vulnerability these MUST be NOT_APPLICABLE.
        if not self.has_linked_vulnerability():
            self.cisa_kev_state = EpistemicState.NOT_APPLICABLE
            self.cvss_state = EpistemicState.NOT_APPLICABLE
            self.patch_state = EpistemicState.NOT_APPLICABLE
            self.exploit_cve_status = EpistemicState.NOT_APPLICABLE

    def to_dict(self) -> dict:
        return {
            "product_id": self.product_id,
            "threat_type": self.threat_type.value,
            "victim_observation": self.victim_observation.to_dict(),
            "actor_context": self.actor_context.to_dict(),
            "generic_readiness": self.generic_readiness.to_dict(),
            "cisa_kev_state": self.cisa_kev_state.value,
            "cvss_state": self.cvss_state.value,
            "patch_state": self.patch_state.value,
            "exploit_cve_status": self.exploit_cve_status.value,
            "linked_vulnerabilities": [lv.to_dict() for lv in self.linked_vulnerabilities],
        }


# ============================================================
# Section 7 — CVE / KEV specialist model
# ============================================================

@dataclass
class CVERecord(ThreatProduct):
    """Only fields authoritative sources actually establish are populated;
    everything else stays at its explicit unestablished default (``None``
    or ``NOT_ASSESSED``) — Section 7's closing instruction: 'Do not
    manufacture fields that authoritative sources do not establish.'"""

    threat_type: ThreatType = field(default=ThreatType.CVE, init=False)

    cve_id: str = ""
    cna_or_vendor: Optional[str] = None
    product: Optional[str] = None
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    cwe: Optional[str] = None
    cvss_v31: Optional[float] = None
    cvss_v31_vector: Optional[str] = None
    cvss_v4: Optional[float] = None
    cvss_v4_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_state: EpistemicState = EpistemicState.NOT_ASSESSED
    kev_date: Optional[str] = None
    kev_remediation_deadline: Optional[str] = None
    root_cause: Optional[str] = None
    exploit_prerequisites: list[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    exploit_chain_claim_ids: list[str] = field(default_factory=list)
    poc_status: EpistemicState = EpistemicState.NOT_ASSESSED
    weaponization_status: EpistemicState = EpistemicState.NOT_ASSESSED
    confirmed_exploitation_status: EpistemicState = EpistemicState.NOT_ASSESSED
    observed_exploitation_source_claim_ids: list[str] = field(default_factory=list)
    internet_exposure_claim_id: Optional[str] = None
    patch_advisory_timeline_claim_ids: list[str] = field(default_factory=list)
    mitigation_claim_ids: list[str] = field(default_factory=list)
    compensating_control_claim_ids: list[str] = field(default_factory=list)
    telemetry_notes: Optional[str] = None
    detection_claim_ids: list[str] = field(default_factory=list)
    hunting_claim_ids: list[str] = field(default_factory=list)
    attack_technique_ids: list[str] = field(default_factory=list)
    reference_source_ids: list[str] = field(default_factory=list)

    # Ransomware-shaped fields this schema must NEVER carry (reciprocal
    # isolation test target — see test_threat_schema_isolation.py). Their
    # absence here IS the enforcement; this comment exists only so a future
    # editor sees the deliberate omission before "fixing" it.
    # victim_name / leak_site_claim_status / actor_context / etc. do not
    # exist on CVERecord by design.

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat_type"] = self.threat_type.value
        d["kev_state"] = self.kev_state.value
        d["poc_status"] = self.poc_status.value
        d["weaponization_status"] = self.weaponization_status.value
        d["confirmed_exploitation_status"] = self.confirmed_exploitation_status.value
        d["linked_vulnerabilities"] = [lv.to_dict() for lv in self.linked_vulnerabilities]
        return d


@dataclass
class CISAKEVRecord(ThreatProduct):
    """A CISA Known Exploited Vulnerabilities catalog entry, kept distinct
    from CVERecord because a KEV listing is itself a claim (CISA's) about a
    CVE, not the CVE's own technical record — collapsing the two would
    make "when did CISA list this" indistinguishable from "when was this
    disclosed", a temporal-integrity risk Section 4 is designed to avoid."""

    threat_type: ThreatType = field(default=ThreatType.CISA_KEV, init=False)

    cve_id: str = ""
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    date_added_precision: TemporalPrecision = TemporalPrecision.UNKNOWN
    required_action: Optional[str] = None
    due_date: Optional[str] = None
    known_ransomware_campaign_use: EpistemicState = EpistemicState.NOT_ASSESSED
    notes: Optional[str] = None
    reference_source_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat_type"] = self.threat_type.value
        d["date_added_precision"] = self.date_added_precision.value
        d["known_ransomware_campaign_use"] = self.known_ransomware_campaign_use.value
        d["linked_vulnerabilities"] = [lv.to_dict() for lv in self.linked_vulnerabilities]
        return d
