"""RX-P1I: structured, evidence-anchored MITRE ATT&CK mapping objects.

The first-class replacement for ``report_renderer.DetectionPackage.
attack_mappings`` -- a tuple of hardcoded prose sentences with no
machine-readable status, confidence, or evidence linkage at all. This
module adds exactly that structure on top of two already-real, already-
tested primitives (Reuse Before Build, not a second mapping engine):

- ``attack_mapper.map_techniques()`` -- the negation-aware, evidence-
  anchored text-to-technique mapper, unchanged.
- The per-article ``EvidenceGraph`` REPORTX already builds -- claim_refs/
  evidence_refs/source_refs point at real, existing graph entries, never
  fabricated ones.

Status semantics (mandate-defined, not invented here):
  OBSERVED     = behavior directly supported by the READER's OWN
                 telemetry. This pipeline never has that -- it only ever
                 sees third-party-reported source text (a CVE advisory, a
                 leak-site claim, a vendor writeup), never a customer's
                 live environment. OBSERVED is therefore structurally
                 unreachable here by design, not merely unimplemented --
                 see ``_apply_semantic_gate()``. The enum member exists
                 for schema completeness and a future real telemetry
                 integration, the same "real in the model, honestly
                 unreachable today" pattern already established by
                 ``analytical_depth_gate.py``'s PREMIUM_CUSTOMER tier.
  ASSESSED     = a defensible analytical inference: an explicit technique
                 ID cited by name in the source text, or a HIGH-confidence
                 unambiguous phrase match (``attack_mapper.Confidence.
                 HIGH``).
  CONDITIONAL  = valid only if a specific deployment/exploitation
                 condition holds -- every vulnerability-class-driven
                 mapping in ``report_renderer._detection_package()`` is
                 already honestly phrased this way in prose ("conditional
                 on...", "only if..."); a MEDIUM-confidence text-phrase
                 match gets the same status for the same reason.
  NOT_SUPPORTED = a candidate mapping rejected by the semantic gate.
                 Never returned by ``build_attack_mappings()`` -- an
                 invalid mapping is filtered out during construction
                 (mirrors ``map_techniques()``'s own silent-exclusion
                 discipline for negated matches), not included with a
                 disclaimer, since a customer-visible "NOT_SUPPORTED"
                 badge is confusing content, not honest content.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from automation.report_integrity import _source_text  # noqa: E402
from automation.report_contract import Applicability, SECTION_11_ATTACK_MAPPING, get_applicability  # noqa: E402

from ..attack_mapper import KNOWN_TECHNIQUES, is_valid_technique_id, map_techniques, tactics_for
from ..models import Confidence
from .claim_model import EvidenceGraph


class AttackMappingStatus(str, Enum):
    OBSERVED = "OBSERVED"
    ASSESSED = "ASSESSED"
    CONDITIONAL = "CONDITIONAL"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class AttackValidationStatus(str, Enum):
    VALID = "VALID"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class AttackMapping:
    attack_mapping_id: str
    technique_id: str
    technique_name: str
    tactics: tuple[str, ...]
    status: AttackMappingStatus
    claim_refs: tuple[str, ...] = field(default_factory=tuple)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    source_refs: tuple[str, ...] = field(default_factory=tuple)
    behavioral_basis: str = ""
    reasoning: str = ""
    confidence: str = Confidence.MEDIUM.value
    limitations: tuple[str, ...] = field(default_factory=tuple)
    validation_status: AttackValidationStatus = AttackValidationStatus.VALID

    def to_dict(self) -> dict:
        return {
            "attack_mapping_id": self.attack_mapping_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactics": list(self.tactics),
            "status": self.status.value,
            "claim_refs": list(self.claim_refs),
            "evidence_refs": list(self.evidence_refs),
            "source_refs": list(self.source_refs),
            "behavioral_basis": self.behavioral_basis,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
            "validation_status": self.validation_status.value,
        }


_CONDITIONAL_LIMITATION = (
    "Conditional on the deployment/exploitation scenario described in the source record; "
    "not confirmed by telemetry."
)
_TEXT_MATCH_LIMITATION = (
    "Derived from source-text phrase matching, not independently confirmed or observed in "
    "any environment."
)

# discovery_bridge.py's own claim_id/evidence_id/source_id convention
# (evidence_id == f"e-{claim_id}", the universal PRIMARY_SOURCE_ID) --
# referenced here, not re-derived, so this stays a single source of truth.
_PRIMARY_SOURCE_ID = "src-primary"
_CVE_CLAIM_IDS = ("c-cve-id", "c-exploitation-status")


def _refs_for_cve_mapping(graph: EvidenceGraph) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    claim_refs = tuple(cid for cid in _CVE_CLAIM_IDS if cid in graph.claims)
    evidence_refs = tuple(f"e-{cid}" for cid in claim_refs if f"e-{cid}" in graph.evidence)
    source_refs = (_PRIMARY_SOURCE_ID,) if _PRIMARY_SOURCE_ID in graph.sources else ()
    return claim_refs, evidence_refs, source_refs


def _refs_for_summary_mapping(graph: EvidenceGraph) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    claim_refs = ("c-summary",) if "c-summary" in graph.claims else ()
    evidence_refs = ("e-c-summary",) if "e-c-summary" in graph.evidence else ()
    source_refs = (_PRIMARY_SOURCE_ID,) if _PRIMARY_SOURCE_ID in graph.sources else ()
    return claim_refs, evidence_refs, source_refs


def _apply_semantic_gate(candidates: list[AttackMapping]) -> list[AttackMapping]:
    """Mandate Section 5: technique exists, name/tactic match the curated
    registry, a behavioral basis exists, at least one real evidence/claim/
    source reference exists, and OBSERVED is structurally disallowed (this
    pipeline never has customer telemetry to justify it). A candidate that
    fails any check is dropped entirely -- never returned as a
    NOT_SUPPORTED entry, since customer-visible "NOT_SUPPORTED" badges are
    confusing content, not honest content (see module docstring)."""
    validated = []
    for m in candidates:
        if not is_valid_technique_id(m.technique_id):
            continue
        if KNOWN_TECHNIQUES[m.technique_id][0] != m.technique_name:
            continue
        if KNOWN_TECHNIQUES[m.technique_id][1] not in m.tactics:
            continue
        if not m.behavioral_basis:
            continue
        if not (m.claim_refs or m.evidence_refs or m.source_refs):
            continue
        if m.status == AttackMappingStatus.OBSERVED:
            continue
        validated.append(m)
    return validated


def build_attack_mappings(article, context, graph: EvidenceGraph, package) -> list[AttackMapping]:
    """Two real evidence sources, merged (a technique already covered by
    the first is never duplicated by the second):

    1. ``package.attack_mappings`` -- report_renderer.py's existing,
       vulnerability-class-conditioned prose sentences. Each already-cited
       technique_id becomes a structured CONDITIONAL mapping, with the
       existing prose itself as the honest ``reasoning`` (real text
       already written for this exact purpose, not fabricated).
    2. ``map_techniques()`` run over this article's own full source text
       -- surfaces additional real technique signal the single-mapping-
       per-vulnerability-class system can never catch (e.g. a CVE article
       that also describes C2 exfiltration in prose). HIGH-confidence
       matches (explicit technique-ID citation or an unambiguous phrase)
       become ASSESSED; everything else stays CONDITIONAL.

    Every candidate passes through ``_apply_semantic_gate()`` before
    being returned -- an invalid candidate never reaches the caller.

    ``ransomware_claim`` (and any future family whose own
    ``_FAMILY_APPLICABILITY`` entry marks Section 11 NOT_APPLICABLE)
    short-circuits to an empty list before either evidence source runs.
    This is not a new rule: ``report_contract.py`` already declares
    Section 11 NOT_APPLICABLE for that family, the same "never invent an
    intrusion chain for a third-party leak-site claim" discipline already
    applied to Sections 7/9/10. ``package.attack_mappings`` is already
    empty for that family by construction
    (``report_renderer._detection_package()``'s own ransomware_claim
    branch never sets it), but ``map_techniques()`` run over raw source
    text has no such family-awareness -- a richer claim's text (e.g.
    explicitly describing encryption or exfiltration) could otherwise
    produce real, evidence-anchored mappings that still bypass the
    family's own declared policy. Checked here, once, rather than trusting
    every future caller to remember it independently.
    """
    if get_applicability(context.family, SECTION_11_ATTACK_MAPPING) == Applicability.NOT_APPLICABLE:
        return []

    from ..attack_mapper import extract_technique_ids

    candidates: dict[str, AttackMapping] = {}

    for prose in getattr(package, "attack_mappings", ()):
        for tid in extract_technique_ids(prose):
            if tid in candidates or not is_valid_technique_id(tid):
                continue
            name, _ = KNOWN_TECHNIQUES[tid]
            claim_refs, evidence_refs, source_refs = _refs_for_cve_mapping(graph)
            candidates[tid] = AttackMapping(
                attack_mapping_id=f"{context.report_id}-attack-{tid}",
                technique_id=tid, technique_name=name, tactics=tactics_for(tid),
                status=AttackMappingStatus.CONDITIONAL,
                claim_refs=claim_refs, evidence_refs=evidence_refs, source_refs=source_refs,
                behavioral_basis=f"Vulnerability-class-conditioned mapping for {getattr(context, 'vulnerability_class', '') or 'this record'}.",
                reasoning=prose,
                confidence=Confidence.MEDIUM.value,
                limitations=(_CONDITIONAL_LIMITATION,),
            )

    text = _source_text(article)
    for tm in map_techniques(text):
        if tm.technique_id in candidates:
            continue
        status = AttackMappingStatus.ASSESSED if tm.confidence == Confidence.HIGH else AttackMappingStatus.CONDITIONAL
        claim_refs, evidence_refs, source_refs = _refs_for_summary_mapping(graph)
        candidates[tm.technique_id] = AttackMapping(
            attack_mapping_id=f"{context.report_id}-attack-{tm.technique_id}",
            technique_id=tm.technique_id, technique_name=tm.name, tactics=tactics_for(tm.technique_id),
            status=status,
            claim_refs=claim_refs, evidence_refs=evidence_refs, source_refs=source_refs,
            behavioral_basis=tm.evidence,
            reasoning=f'Source text evidence: "{tm.evidence}"',
            confidence=tm.confidence.value,
            limitations=(_TEXT_MATCH_LIMITATION,),
        )

    return sorted(_apply_semantic_gate(list(candidates.values())), key=lambda m: m.technique_id)
