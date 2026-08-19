"""
CYBERDUDEBIVASH® SENTINEL APEX — Premium Report Contract (Phase A/C)

Formalizes the 24-section premium intelligence product standard as a
canonical schema, reconciled against what this pipeline's renderer
(report_renderer.py) actually implements today -- not an aspirational
restatement of the spec. Mirrors the reconciliation method already
established in this repository for an earlier, similarly-shaped request
(Sentinel-APEX/eios/sentinel-intelligence-standard.md:296-329, "Cross-
reference to an external 25-part taxonomy request"): every requested
section is checked item-by-item against what exists, not assumed new.

Two independent questions per section, per report:
  1. APPLICABILITY -- is this section even relevant to this report family?
     (MANDATORY / OPTIONAL / NOT_APPLICABLE, from _FAMILY_APPLICABILITY)
  2. STATE -- given relevance, what did THIS article actually resolve to?
     (SectionState, from evaluate_section_states())

A section this pipeline has no analytical capability to populate honestly
resolves to WITHHELD_INSUFFICIENT_EVIDENCE, never a blank or generic
heading -- the same discipline already enforced for Detection Engineering
in report_renderer.py's _detection_package().
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .content_discovery import DiscoveredArticle
    from .report_integrity import ReportContext


class SectionState(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    WITHHELD_INSUFFICIENT_EVIDENCE = "WITHHELD_INSUFFICIENT_EVIDENCE"
    HOLD_FOR_ENRICHMENT = "HOLD_FOR_ENRICHMENT"


class Applicability(str, Enum):
    MANDATORY = "MANDATORY"
    OPTIONAL = "OPTIONAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# The 24 canonical sections, in the founder mandate's own order. Keys are
# stable identifiers used by _FAMILY_APPLICABILITY and evaluate_section_states
# -- never renamed without updating both, since they are the join key.
SECTION_1_EXECUTIVE_RISK_COMMAND_CENTER = "executive_risk_command_center"
SECTION_2_EXECUTIVE_SUMMARY = "executive_summary"
SECTION_3_KEY_JUDGEMENTS = "key_judgements"
SECTION_4_INTELLIGENCE_REQUIREMENTS = "intelligence_requirements"
SECTION_5_VERIFIED_FACTS = "verified_facts"
SECTION_6_EVIDENCE_SOURCE_ASSESSMENT = "evidence_source_assessment"
SECTION_7_TECHNICAL_ANALYSIS = "technical_analysis"
SECTION_8_EXPLOITATION_INCIDENT_ASSESSMENT = "exploitation_incident_assessment"
SECTION_9_EXPOSURE_ASSET_RELEVANCE = "exposure_asset_relevance"
SECTION_10_ATTACK_PATH = "attack_path"
SECTION_11_ATTACK_MAPPING = "attack_mapping"
SECTION_12_ACTOR_CAMPAIGN_CONTEXT = "actor_campaign_context"
SECTION_13_HISTORICAL_CORRELATION = "historical_correlation"
SECTION_14_THREAT_HUNTING = "threat_hunting"
SECTION_15_DETECTION_ENGINEERING = "detection_engineering"
SECTION_16_INDICATORS_OBSERVABLES = "indicators_observables"
SECTION_17_BUSINESS_IMPACT = "business_impact"
SECTION_18_SECTOR_GEOGRAPHIC_IMPACT = "sector_geographic_impact"
SECTION_19_ROLE_DECISION_MATRIX = "role_decision_matrix"
SECTION_20_TIMEBOUND_ACTIONS = "timebound_actions"
SECTION_21_INTELLIGENCE_GAPS = "intelligence_gaps"
SECTION_22_FORECAST_OUTLOOK = "forecast_outlook"
SECTION_23_REFERENCES_EVIDENCE_LEDGER = "references_evidence_ledger"
SECTION_24_PROVENANCE_CERTIFICATION = "provenance_certification"

ALL_SECTIONS = (
    SECTION_1_EXECUTIVE_RISK_COMMAND_CENTER,
    SECTION_2_EXECUTIVE_SUMMARY,
    SECTION_3_KEY_JUDGEMENTS,
    SECTION_4_INTELLIGENCE_REQUIREMENTS,
    SECTION_5_VERIFIED_FACTS,
    SECTION_6_EVIDENCE_SOURCE_ASSESSMENT,
    SECTION_7_TECHNICAL_ANALYSIS,
    SECTION_8_EXPLOITATION_INCIDENT_ASSESSMENT,
    SECTION_9_EXPOSURE_ASSET_RELEVANCE,
    SECTION_10_ATTACK_PATH,
    SECTION_11_ATTACK_MAPPING,
    SECTION_12_ACTOR_CAMPAIGN_CONTEXT,
    SECTION_13_HISTORICAL_CORRELATION,
    SECTION_14_THREAT_HUNTING,
    SECTION_15_DETECTION_ENGINEERING,
    SECTION_16_INDICATORS_OBSERVABLES,
    SECTION_17_BUSINESS_IMPACT,
    SECTION_18_SECTOR_GEOGRAPHIC_IMPACT,
    SECTION_19_ROLE_DECISION_MATRIX,
    SECTION_20_TIMEBOUND_ACTIONS,
    SECTION_21_INTELLIGENCE_GAPS,
    SECTION_22_FORECAST_OUTLOOK,
    SECTION_23_REFERENCES_EVIDENCE_LEDGER,
    SECTION_24_PROVENANCE_CERTIFICATION,
)

# Sections this pipeline's renderer (report_renderer.py) already
# implements with real, evidence-backed content today, mapped to their
# actual current section name -- reconciliation, not aspiration.
_IMPLEMENTED_TODAY = {
    SECTION_2_EXECUTIVE_SUMMARY: "Executive Summary",
    SECTION_5_VERIFIED_FACTS: "Verified Facts",
    SECTION_7_TECHNICAL_ANALYSIS: "Technical Analysis",
    SECTION_9_EXPOSURE_ASSET_RELEVANCE: "Exposure and Remediation Decisions",
    SECTION_15_DETECTION_ENGINEERING: "Detection Engineering",
    SECTION_19_ROLE_DECISION_MATRIX: "Role-Based Decisions",
    SECTION_23_REFERENCES_EVIDENCE_LEDGER: "Source Evidence Extract / References",
    SECTION_24_PROVENANCE_CERTIFICATION: "Provenance and Certification",
}

# Section 1 (Executive Risk Command Center), Section 6 (Evidence & Source
# Assessment), and Section 8 (Exploitation/Incident Assessment) exist under
# different names/shapes (authority_transformer.py's risk dashboard tiles;
# "Threat Classification and Evidence Status" + "Source Reliability &
# Corroboration"; the same "Threat Classification" section's own
# "Exploitation:" line + KEV cross-check) -- tracked separately since
# they aren't produced by report_renderer.py's _section()-based helpers.
_IMPLEMENTED_ELSEWHERE = frozenset({
    SECTION_1_EXECUTIVE_RISK_COMMAND_CENTER,
    SECTION_6_EVIDENCE_SOURCE_ASSESSMENT,
    SECTION_8_EXPLOITATION_INCIDENT_ASSESSMENT,
})

# Sections with a real, non-fabricated structured SIGNAL today, but not
# the full narrative/object model the founder mandate describes:
#   11 (ATT&CK Mapping) -- report_renderer.py's _attack_mapping() emits a
#       single prose line per mapping ("Initial Access -> Exploit Public-
#       Facing Application (T1190), conditional on...") with a condition
#       expressed in words, not the {tactic, technique_id, technique,
#       evidence, rationale, confidence, STATUS} structured object Section
#       11 specifies.
#   12 (Actor/Campaign Context) -- threat_feeds.py/content_discovery.py
#       carry real ransomware_group/sector/country as structured fields
#       (Phase 1 slice), but no aliases/historical-operations/motivations/
#       victimology narrative exists anywhere.
#   13 (Historical Correlation) -- internal_linker.py's _classify_relation()
#       (Phase 1 slice) gives a real, typed list of related reports, not
#       yet the correlative PROSE ("why this matters relative to history").
#   18 (Sector & Geographic Impact) -- the same ransomware_sector/country
#       fields are real facts, but no impact-differentiation narrative
#       ("why this sector specifically") exists.
# Section 13 alone was a true blanket case when this comment was first
# written: the classification mechanism (internal_linker._classify_relation())
# is real and runs unconditionally for every article, but confirming
# whether THIS article actually matched something requires the live state
# file, which this function does not have access to (by design --
# report_contract.py stays dependency-light, no coupling to
# internal_linker.py or the filesystem). PARTIAL_EVIDENCE here means "the
# capability is real," not "a match was confirmed."
#
# RX-P1F: Section 21 (Intelligence Gaps) joined this set once
# pipeline_composer.compose_report() started computing a real
# intelligence_gaps list unconditionally for every article (Round 2) --
# today always exactly one honest, non-fabricated gap ("independent
# corroboration not assessed"), not yet a rich per-article analysis. Same
# reasoning as Section 13: the mechanism is real and article-independent,
# so this is a static architectural characterization, not a per-article
# check of key_judgements/authority_transformer.py's actual output.
_PARTIAL_SIGNAL_ONLY = frozenset({
    SECTION_13_HISTORICAL_CORRELATION,
    SECTION_21_INTELLIGENCE_GAPS,
})

# Key Judgements (Section 3) is resolved dynamically below, from a real
# key_judgement_count -- see key_judgements.py (RX-P1F). Every remaining
# section (Intelligence Requirements, Attack Path, Threat Hunting as a
# distinct hypothesis section, Indicators & Observables, Business Impact,
# Time-bound Actions split by horizon, Forecast & Outlook) still has no
# implementation anywhere in this pipeline -- resolves to WITHHELD_
# INSUFFICIENT_EVIDENCE for every article, honestly, not silently rendered
# blank.

# Per-family applicability -- MANDATORY sections a genuinely premium report
# in that family must resolve to something better than WITHHELD before it
# can honestly claim PREMIUM_LONG_FORM; OPTIONAL sections add value when
# resolvable but don't gate the tier; NOT_APPLICABLE sections should never
# even be attempted (Section 8's "Never invent an intrusion chain" for a
# ransomware claim is exactly this: Attack Path is NOT_APPLICABLE there,
# not merely unresolved).
_FAMILY_APPLICABILITY: dict = {
    "cve_advisory": {
        SECTION_1_EXECUTIVE_RISK_COMMAND_CENTER: Applicability.MANDATORY,
        SECTION_2_EXECUTIVE_SUMMARY: Applicability.MANDATORY,
        SECTION_3_KEY_JUDGEMENTS: Applicability.MANDATORY,
        SECTION_4_INTELLIGENCE_REQUIREMENTS: Applicability.OPTIONAL,
        SECTION_5_VERIFIED_FACTS: Applicability.MANDATORY,
        SECTION_6_EVIDENCE_SOURCE_ASSESSMENT: Applicability.MANDATORY,
        SECTION_7_TECHNICAL_ANALYSIS: Applicability.MANDATORY,
        SECTION_8_EXPLOITATION_INCIDENT_ASSESSMENT: Applicability.MANDATORY,
        SECTION_9_EXPOSURE_ASSET_RELEVANCE: Applicability.MANDATORY,
        SECTION_10_ATTACK_PATH: Applicability.OPTIONAL,
        SECTION_11_ATTACK_MAPPING: Applicability.OPTIONAL,
        SECTION_12_ACTOR_CAMPAIGN_CONTEXT: Applicability.NOT_APPLICABLE,
        SECTION_13_HISTORICAL_CORRELATION: Applicability.MANDATORY,
        SECTION_14_THREAT_HUNTING: Applicability.OPTIONAL,
        SECTION_15_DETECTION_ENGINEERING: Applicability.MANDATORY,
        SECTION_16_INDICATORS_OBSERVABLES: Applicability.OPTIONAL,
        SECTION_17_BUSINESS_IMPACT: Applicability.OPTIONAL,
        SECTION_18_SECTOR_GEOGRAPHIC_IMPACT: Applicability.OPTIONAL,
        SECTION_19_ROLE_DECISION_MATRIX: Applicability.MANDATORY,
        SECTION_20_TIMEBOUND_ACTIONS: Applicability.OPTIONAL,
        SECTION_21_INTELLIGENCE_GAPS: Applicability.MANDATORY,
        SECTION_22_FORECAST_OUTLOOK: Applicability.NOT_APPLICABLE,
        SECTION_23_REFERENCES_EVIDENCE_LEDGER: Applicability.MANDATORY,
        SECTION_24_PROVENANCE_CERTIFICATION: Applicability.MANDATORY,
    },
    "ransomware_claim": {
        SECTION_1_EXECUTIVE_RISK_COMMAND_CENTER: Applicability.MANDATORY,
        SECTION_2_EXECUTIVE_SUMMARY: Applicability.MANDATORY,
        SECTION_3_KEY_JUDGEMENTS: Applicability.MANDATORY,
        SECTION_4_INTELLIGENCE_REQUIREMENTS: Applicability.OPTIONAL,
        SECTION_5_VERIFIED_FACTS: Applicability.MANDATORY,
        SECTION_6_EVIDENCE_SOURCE_ASSESSMENT: Applicability.MANDATORY,
        SECTION_7_TECHNICAL_ANALYSIS: Applicability.NOT_APPLICABLE,
        SECTION_8_EXPLOITATION_INCIDENT_ASSESSMENT: Applicability.MANDATORY,
        SECTION_9_EXPOSURE_ASSET_RELEVANCE: Applicability.NOT_APPLICABLE,
        # Founder mandate, Section 8/Phase B, verbatim: "Do not invent an
        # intrusion chain" for a ransomware claim -- NOT_APPLICABLE, not
        # merely unresolved, is the correct state, always.
        SECTION_10_ATTACK_PATH: Applicability.NOT_APPLICABLE,
        SECTION_11_ATTACK_MAPPING: Applicability.NOT_APPLICABLE,
        SECTION_12_ACTOR_CAMPAIGN_CONTEXT: Applicability.MANDATORY,
        SECTION_13_HISTORICAL_CORRELATION: Applicability.MANDATORY,
        SECTION_14_THREAT_HUNTING: Applicability.OPTIONAL,
        SECTION_15_DETECTION_ENGINEERING: Applicability.OPTIONAL,
        SECTION_16_INDICATORS_OBSERVABLES: Applicability.OPTIONAL,
        SECTION_17_BUSINESS_IMPACT: Applicability.MANDATORY,
        SECTION_18_SECTOR_GEOGRAPHIC_IMPACT: Applicability.MANDATORY,
        SECTION_19_ROLE_DECISION_MATRIX: Applicability.MANDATORY,
        SECTION_20_TIMEBOUND_ACTIONS: Applicability.OPTIONAL,
        SECTION_21_INTELLIGENCE_GAPS: Applicability.MANDATORY,
        SECTION_22_FORECAST_OUTLOOK: Applicability.OPTIONAL,
        SECTION_23_REFERENCES_EVIDENCE_LEDGER: Applicability.MANDATORY,
        SECTION_24_PROVENANCE_CERTIFICATION: Applicability.MANDATORY,
    },
}
# cisa_kev/cisa_advisory reuse cve_advisory's matrix (same technical shape;
# KEV adds a federal-mandate urgency signal but not a different section
# set). breach_notice/ai_security/general_intelligence intentionally have
# no entry yet -- see evaluate_section_states()'s fallback below; adding a
# family-specific matrix without first confirming what evidence those
# families actually carry would be guessing, not reconciling.
_FAMILY_APPLICABILITY["cisa_kev"] = _FAMILY_APPLICABILITY["cve_advisory"]
_FAMILY_APPLICABILITY["cisa_advisory"] = _FAMILY_APPLICABILITY["cve_advisory"]


@dataclass(frozen=True)
class SectionResolution:
    section: str
    applicability: Applicability
    state: SectionState


def get_applicability(family: str, section: str) -> Applicability:
    """OPTIONAL is the safe default for a family with no matrix entry yet
    (breach_notice/ai_security/general_intelligence) or a section left
    unlisted within a matrix -- never MANDATORY (would falsely gate
    families not yet analyzed) and never NOT_APPLICABLE (would silently
    hide a section that might genuinely apply once that family gets its
    own reconciled matrix)."""
    return _FAMILY_APPLICABILITY.get(family, {}).get(section, Applicability.OPTIONAL)


# threat_feeds.py's real fallback for an unnamed ransomware actor -- not a
# genuine identity. Duplicated here (not imported from internal_linker.py)
# to keep this module dependency-light; both copies exist for the same
# adversarial-testing reason and must be kept in sync if the source
# fallback string ever changes.
_PLACEHOLDER_ACTOR_NAMES = frozenset({"Unknown Group"})

# report_renderer.py's real DetectionPackage.status values (_detection_
# package()) -- passed in by the caller rather than recomputed here, since
# report_renderer.py already computes it once per render and this module
# stays dependency-light (no import of report_renderer.py, avoiding any
# future circular-import risk between the two).
_DETECTION_STATUS_REAL_CONTENT = frozenset({"syntax_validated_experimental", "telemetry_specification_only"})


def evaluate_section_states(
    article: "DiscoveredArticle", context: "ReportContext", detection_status: str = "",
    key_judgement_count: int = 0,
) -> list[SectionResolution]:
    """Resolve all 24 sections for one article. Never fabricates a state:
    a section with no implementation anywhere in this pipeline always
    resolves to WITHHELD_INSUFFICIENT_EVIDENCE, regardless of applicability
    -- MANDATORY-but-withheld is exactly the signal analytical_depth_gate.py
    uses to keep a report out of PREMIUM_LONG_FORM honestly.

    ``detection_status`` is report_renderer.py's already-computed
    DetectionPackage.status for this article (pass "" if unavailable --
    treated conservatively as withheld, never assumed successful).

    ``key_judgement_count`` (RX-P1F) is the number of judgements
    key_judgements.generate_key_judgements() produced AND
    validate_key_judgements() actually accepted for this article -- never
    the raw count an LLM returned. Default 0 preserves every existing
    caller's behavior (always WITHHELD) exactly."""
    resolutions = []
    for section in ALL_SECTIONS:
        applicability = get_applicability(context.family, section)
        if applicability == Applicability.NOT_APPLICABLE:
            state = SectionState.NOT_APPLICABLE
        elif section == SECTION_3_KEY_JUDGEMENTS:
            state = SectionState.COMPLETE if key_judgement_count > 0 else SectionState.WITHHELD_INSUFFICIENT_EVIDENCE
        elif section in _IMPLEMENTED_TODAY or section in _IMPLEMENTED_ELSEWHERE:
            state = _resolve_implemented_section(article, context, section, detection_status)
        elif section in _PARTIAL_SIGNAL_ONLY:
            state = SectionState.PARTIAL_EVIDENCE
        elif section == SECTION_11_ATTACK_MAPPING:
            state = _resolve_attack_mapping(detection_status)
        elif section == SECTION_12_ACTOR_CAMPAIGN_CONTEXT:
            state = _resolve_actor_context(article)
        elif section == SECTION_18_SECTOR_GEOGRAPHIC_IMPACT:
            state = _resolve_sector_impact(article)
        else:
            state = SectionState.WITHHELD_INSUFFICIENT_EVIDENCE
        resolutions.append(SectionResolution(section=section, applicability=applicability, state=state))
    return resolutions


def _resolve_implemented_section(
    article: "DiscoveredArticle", context: "ReportContext", section: str, detection_status: str,
) -> SectionState:
    """Sections with a real renderer today can still be PARTIAL_EVIDENCE
    or fully withheld per-article -- e.g. Verified Facts is COMPLETE for a
    CVE with a full CVSS vector, but PARTIAL_EVIDENCE for one (like the
    real CVE-2026-60698 sample this session) that carries no CWE at all in
    its source record; Detection Engineering is COMPLETE only when
    detection_status shows real, evidence-gated content actually rendered,
    never merely because the capability to render it exists."""
    if section == SECTION_5_VERIFIED_FACTS and context.family in {"cve_advisory", "cisa_kev", "cisa_advisory"}:
        if not article.cwe_ids and article.cvss_vector:
            return SectionState.PARTIAL_EVIDENCE
    if section == SECTION_9_EXPOSURE_ASSET_RELEVANCE and context.family in {"cve_advisory", "cisa_kev", "cisa_advisory"}:
        if not article.affected_vendor and not article.affected_product:
            return SectionState.PARTIAL_EVIDENCE
    if section == SECTION_15_DETECTION_ENGINEERING:
        if detection_status == "syntax_validated_experimental":
            return SectionState.COMPLETE
        if detection_status == "telemetry_specification_only":
            return SectionState.PARTIAL_EVIDENCE
        if detection_status == "not_applicable":
            return SectionState.NOT_APPLICABLE
        return SectionState.WITHHELD_INSUFFICIENT_EVIDENCE
    return SectionState.COMPLETE


def _resolve_attack_mapping(detection_status: str) -> SectionState:
    """report_renderer.py's MITRE mapping line is generated by the same
    evidence-conditioned branch as the Sigma/KQL detection templates for
    the same vulnerability classes -- real content only when that gate
    actually cleared, never assumed."""
    if detection_status in _DETECTION_STATUS_REAL_CONTENT:
        return SectionState.PARTIAL_EVIDENCE
    return SectionState.WITHHELD_INSUFFICIENT_EVIDENCE


def _resolve_actor_context(article: "DiscoveredArticle") -> SectionState:
    group = (article.ransomware_group or "").strip()
    if group and group not in _PLACEHOLDER_ACTOR_NAMES:
        return SectionState.PARTIAL_EVIDENCE
    return SectionState.WITHHELD_INSUFFICIENT_EVIDENCE


def _resolve_sector_impact(article: "DiscoveredArticle") -> SectionState:
    if article.ransomware_sector or article.ransomware_country:
        return SectionState.PARTIAL_EVIDENCE
    return SectionState.WITHHELD_INSUFFICIENT_EVIDENCE
