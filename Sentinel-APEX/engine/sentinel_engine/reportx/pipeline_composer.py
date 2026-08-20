"""The live-pipeline composer: turns one ``DiscoveredArticle`` into a real,
evidence-graph-backed, commercial-readiness-gated report -- the piece
``REPORTX-INTELLIGENCE-FACTORY-ARCHITECTURE.md`` designed and
``discovery_bridge.py`` half-built. This module is the other half: it
reuses ``automation.report_renderer.render_evidence_report()`` (the real,
evidence-first HTML core, "RX-STABILIZATION-1" in that module's own
history) UNCHANGED for the base narrative, and adds exactly two new
sections on top using that same module's own styling primitives
(``_section``/``_panel``/``_bullets``) -- never a second, competing visual
system.

The point of this module is not to write new analytical prose from
scratch (``report_renderer.py`` already does that honestly, per
vulnerability class). The point is to make the result *gate-checkable*:
build the real ``EvidenceGraph`` alongside the HTML, run it through
``commercial_readiness.py``'s unmodified 23-control matrix scoped to the
tier the evidence actually supports (``tier_downgrade.py``, reused from
the P0 release-certification work), and report an achieved tier a caller
can trust -- rather than a fixed template nobody re-validates per report.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

# See discovery_bridge.py's identical bootstrap for why this is needed:
# automation/ lives at the repo root, not under Sentinel-APEX/engine/.
_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from automation.report_integrity import ReportContext, build_report_context  # noqa: E402
from automation.report_renderer import (  # noqa: E402
    DetectionPackage,
    _bullets,
    _detection_package,
    _esc,
    _panel,
    _section,
)

from .analytic_scaffolding import IntelligenceGap
from .claim_model import CorroborationState, EvidenceGraph
from .commercial_readiness import ControlResult, ReportBundle, evaluate_commercial_readiness
from .contradiction_engine import Contradiction, find_all_contradictions
from .detection_validation import DetectionRule, DetectionValidationState
from .discovery_bridge import build_evidence_graph, build_threat_product
from .entity_resolution import CanonicalEntity, resolve_canonical_entities
from .intelligence_validation import IntelligenceScorecard, evaluate_intelligence_validation
from .executive_products import (
    RoleAudience,
    RoleDecision,
    information_credibility,
    overall_analytical_confidence,
    render_role_decisions,
    role_display_label,
    source_reliability_grade,
    two_axis_reliability,
    worst_corroboration_state,
)
from .human_review import CertificationState
from .product_depth import DepthAssessment
from .tier_downgrade import DowngradeResult, determine_achieved_tier

from sentinel_engine.attack_mapper import extract_technique_ids  # noqa: E402

_STATUS_TO_VALIDATION_STATE = {
    "syntax_validated_experimental": DetectionValidationState.SYNTAX_VALIDATED,
}


def _detection_rules(report_id: str, package: DetectionPackage) -> list[DetectionRule]:
    """One ``DetectionRule`` per format the (single, shared) evidence basis
    actually supports -- ``DetectionPackage.status`` governs both formats
    identically, since Sigma and KQL are two renderings of the same
    evidence-conditioned decision, not two independent judgments. A
    withheld package still yields exactly one rule (as before), so
    ``commercial_readiness.py``'s detection_evidence_discipline control
    (which requires at least one rule to evaluate) keeps working unchanged."""
    validation_state = _STATUS_TO_VALIDATION_STATE.get(package.status, DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE)
    # COMMERCIAL-QUALITY-2026-08-18: package.attack_mappings entries are
    # full descriptive sentences ("Defense Evasion -> Valid Accounts
    # (T1078), only if authentication/session abuse is observed."), not
    # bare technique IDs -- DetectionRule.technique_id must hold the ID
    # alone (it's serialized as a structured field by bundle_io.py and read
    # as one by intelligence_validation.py's own scorer, which already had
    # to work around this exact shape via the same extract_technique_ids()
    # reused here rather than storing the raw sentence and pushing the
    # parsing burden onto every consumer).
    _ids = extract_technique_ids(package.attack_mappings[0]) if package.attack_mappings else []
    technique_id = _ids[0] if _ids else ""
    formats = [("sigma", package.sigma_yaml), ("kql", package.kql)]
    rules = [
        DetectionRule(
            rule_id=f"{report_id}-detection-{fmt}", technique_id=technique_id,
            format=fmt, validation_state=validation_state, body=body, evidence_gap_rationale=package.rationale,
        )
        for fmt, body in formats if body
    ]
    if rules:
        return rules
    return [DetectionRule(
        rule_id=f"{report_id}-detection", technique_id=technique_id,
        format="none", validation_state=validation_state, body="", evidence_gap_rationale=package.rationale,
    )]


# discovery_bridge.py's own claim_id naming convention (the only place that
# convention is defined) mapped to contradiction_engine.py's canonical
# dimension vocabulary -- kept here, not duplicated into either module, so
# there is exactly one place this join can drift. A claim_id absent from
# this graph (e.g. a family that never builds "c-kev-listed") is simply
# absent from the resulting tags, never a KeyError.
_DIMENSION_BY_CLAIM_ID: dict[str, str] = {
    "c-exploitation-status": "exploitation_state",
    "c-kev-listed": "kev_state",
    "c-patch-status": "patch_state",
    "c-actor-attribution": "actor_identity",
    "c-victim-claim": "victim_confirmation",
}


def _dimension_tags_for(graph: EvidenceGraph) -> dict[str, list[str]]:
    """Groups this graph's claims by contradiction_engine.py's dimension
    vocabulary. Today's discovery_bridge.py only ever builds one claim per
    dimension per article (single-source construction; a later independent
    match upgrades an existing claim's corroboration_state rather than
    adding a competing one -- see _apply_independent_corroboration()'s own
    docstring), so find_dimension_contradictions() cannot yet find a real
    conflict from this alone. Wired unconditionally anyway (Section 6's own
    discipline: a real, tested mechanism must not sit disconnected) so it
    engages automatically the moment a future increment merges a second,
    independently-sourced claim into the same dimension, without a second
    wiring pass."""
    tags: dict[str, list[str]] = {}
    for claim_id, dimension in _DIMENSION_BY_CLAIM_ID.items():
        if claim_id in graph.claims:
            tags.setdefault(dimension, []).append(claim_id)
    return tags


_VULNERABILITY_MANAGER_FAMILIES = ("cve_advisory", "cisa_advisory", "cisa_kev")


def _lean_role_decisions(article, context: ReportContext, threat_product) -> list[RoleDecision]:
    """A deliberately SHORT role list for FLASH-tier volume content --
    the full 10-role treatment (``REPORTX-INTELLIGENCE-FACTORY-BENCHMARK.md``)
    is reserved for premium dossiers with the evidence depth to ground all
    10. Padding every routine alert with 10 roles it has no real basis for
    would itself be the padding defect this factory exists to remove.

    Vulnerability Manager guidance requires a real patch/exploitation
    dimension to be relevant -- gated to the families
    ``context.exploitation_status``/``context.patch_label`` are actually
    meaningful for (Section 10's evidence-scoping discipline applied to
    role routing, not just to claims). Before this gate, every family --
    including phishing/PhaaS and third-party ransomware-campaign reporting
    with no patch or exploitation dimension at all -- got a bare "Track
    against {family} intake..." Vulnerability Manager decision regardless
    (verified live against a real published JWR PhaaS report,
    family=general_intelligence, which had no CVE/patch evidence anywhere in
    its bundle). ``ransomware_claim`` was also removed from this list
    (COMMERCIAL-QUALITY-2026-08-18 finding, independently verified against
    the live-fetched CVE-2026-75105 report and this module's own then-empty
    ``evidence_claim_ids`` for that family, which had already signalled the
    decision wasn't really evidence-backed): an unverified leak-site victim
    claim has no CVE, no patch, and no exploitation-status dimension either
    -- it is not a vulnerability-management concern at all. The IR Manager
    decision below already covers this family with real, evidence-scoped
    guidance; it does not also need a Vulnerability Manager decision with
    nothing to track against."""
    decisions: list[RoleDecision] = []
    if context.family in _VULNERABILITY_MANAGER_FAMILIES:
        # exploitation_label/patch_label (report_integrity._exploitation()/
        # _patch()) are standalone display phrases -- several of them (e.g.
        # "Not confirmed by available evidence; not in verified KEV
        # snapshot") were never written to grammatically complete a
        # mid-sentence clause like "severity commensurate with {X}.", which
        # produced broken English (independently verified live against the
        # published CVE-2026-75105 report, and separately flagged in the
        # same terms by an external review -- COMMERCIAL-QUALITY-2026-08-18).
        # Presenting each status as its own colon-introduced clause is
        # grammatically correct for every current and future value, rather
        # than special-casing individual label strings.
        decisions.append(RoleDecision(
            role=RoleAudience.VULNERABILITY_MANAGER,
            decision=f"Track against {context.family_label.lower()} intake. "
                     f"Exploitation status: {context.exploitation_label}. Patch status: {context.patch_label}.",
            rationale="Prioritization reflects this record's own exploitation/patch evidence, not a fixed severity template.",
            evidence_claim_ids=("c-exploitation-status", "c-patch-status"),
        ))
    if context.family in ("cve_advisory", "cisa_advisory", "cisa_kev"):
        decisions.append(RoleDecision(
            role=RoleAudience.SOC_MANAGER,
            decision="Review the detection guidance below before enabling any blocking action on it.",
            rationale="Detection maturity for this record is stated explicitly, not assumed production-ready.",
            evidence_claim_ids=("c-summary",),
        ))
    if context.family == "ransomware_claim":
        decisions.append(RoleDecision(
            role=RoleAudience.IR_MANAGER,
            decision="Treat as a validation task (confirm internally), not an activation trigger, absent "
                      "independent corroboration.",
            rationale="The victim claim is a single, third-party leak-site source (c-victim-claim, REPORTED "
                       "not CONFIRMED) -- Section 10's high-impact-claim-type discipline applies.",
            evidence_claim_ids=("c-victim-claim",),
        ))
    # RX-P1H: these four families previously got no role decision at all --
    # confirmed live (test_pipeline_composer.py's
    # TestRoleRoutingDoesNotMisapplyVulnerabilityManagement class) that an
    # empty list correctly omits the whole Role-Based Decisions section
    # rather than rendering it empty, but omission is not a substitute for a
    # real decision when this family's own evidence supports one. Each of
    # the four below reuses an existing RoleAudience value (no new role
    # invented) and is deliberately unconditional -- same "SHORT list, but
    # never zero for a family with real evidence to route" reasoning as the
    # three families above -- so that report_contract.py's new MANDATORY
    # Section 19 for these families (RX-P1H) is never a trap: the section is
    # always genuinely populated, not merely claimed applicable.
    if context.family == "ai_security":
        decisions.append(RoleDecision(
            role=RoleAudience.CISO_CIO,
            decision="Confirm whether the cited AI system, model, or capability exists in approved or shadow use "
                      "before treating this as a governance action item.",
            rationale="AI security findings are a governance and control-mapping concern at this evidence depth, "
                       "not yet a confirmed technical defect.",
            evidence_claim_ids=("c-summary",),
        ))
    if context.family == "breach_notice":
        decisions.append(RoleDecision(
            role=RoleAudience.LEGAL_COMPLIANCE_PRIVACY,
            decision="Assess whether this public breach record involves the organization's own data, customers, or "
                      "vendors before any notification or regulatory determination.",
            rationale="A public breach record is a disclosure to review, not a confirmed organizational incident on "
                       "its own (c-summary only -- no scope evidence has been independently established).",
            evidence_claim_ids=("c-summary",),
        ))
    if context.family == "threat_actor":
        decisions.append(RoleDecision(
            role=RoleAudience.THREAT_HUNTER,
            decision="Cross-reference the described actor's infrastructure and TTPs against internal telemetry "
                      "before treating this record as relevant to the environment.",
            rationale="Actor attribution and TTPs are as reported by the cited source; this pipeline does not "
                       "independently corroborate them.",
            evidence_claim_ids=("c-summary",),
        ))
    if context.family == "ransomware_reporting":
        decisions.append(RoleDecision(
            role=RoleAudience.SOC_MANAGER,
            decision="Review detection and backup-immutability coverage against the ransomware tradecraft "
                      "described, independent of any specific victim claim.",
            rationale="This record reports ransomware activity or trends generally, not a claim against a named "
                       "victim -- see the Ransomware Claim Intelligence family for that distinct evidence type.",
            evidence_claim_ids=("c-summary",),
        ))
    return decisions


@dataclass(frozen=True)
class ComposedReport:
    report_id: str
    context: ReportContext
    html: str
    bundle: ReportBundle
    control_results: list[ControlResult]
    downgrade: DowngradeResult
    # COMMERCIAL-QUALITY-2026-08-18: the 20-dimension, weighted commercial-
    # readiness scorecard (Intelligence Validation Framework, PR #90) --
    # already built, already tested against 5 real canary exports, and
    # already calibrated (ValidationThresholds' per-dimension overrides).
    # Computed unconditionally from the same bundle/control_results this
    # function already builds, at zero extra evidence cost. Exposed here as
    # real, observable data first (report_id, overall_score, coverage,
    # publication_eligible, blocking_reasons) -- NOT yet wired into the hard
    # publication gate. Elevating it to a gate is a separate, deliberate
    # calibration decision (does today's live pipeline actually clear the
    # existing 75-point threshold consistently, the same question PR #90
    # answered empirically for the 5 canaries before setting it) that must
    # be made from live evidence, not assumed here.
    scorecard: IntelligenceScorecard
    # RX-P1D-WIRE: contradiction_engine.py's own two real, tested checkers
    # (dimension-level: same-claim-dimension EpistemicStates that can never
    # both be true; text-pattern: the task's own three motivating rendered-
    # prose examples), run unconditionally against this exact graph/html --
    # not a new checker, not a new schema. Empty today for every real
    # article (see _dimension_tags_for()'s docstring for why the dimension
    # layer specifically cannot yet fire); the text-pattern layer is
    # already live against whatever this function's own real rendered html
    # contains. A non-empty list here is a real, material finding, not
    # noise -- see validate_publication()'s new hard gate on it.
    contradictions: list[Contradiction] = field(default_factory=list)
    # RX-P1E-WIRE: the 3-axis confidence model (source reliability /
    # information credibility / overall analytical confidence), already
    # rendered as prose in html above, exposed here as structured data for
    # the first time. See analytical_confidence's construction above for
    # why these stay 3 distinct fields rather than one blended score.
    analytical_confidence: dict = field(default_factory=dict)
    # RX-P1G-WIRE: canonical entities resolved from this article's own
    # structured fields (CVE ID, ransomware group/sector/country) and the
    # existing curated entities.py lexicon -- never from LLM-generated
    # content, never fuzzy/alias-merged across distinct raw name strings
    # (see entity_resolution.py's module docstring for why). Computed
    # unconditionally, at zero extra evidence cost (reuses the graph this
    # function already built), for every article regardless of tier or
    # content_source.
    canonical_entities: list[CanonicalEntity] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.control_results if r.status == "PASS")

    @property
    def total_count(self) -> int:
        return len(self.control_results)


def compose_report(
    article, config, requested_tier: CertificationState = CertificationState.FLASH_READY,
    include_provenance: bool = True,
) -> ComposedReport:
    """``include_provenance=False`` produces a body-content fragment (no
    Provenance and Certification section) for callers -- namely
    ``authority_transformer._composer_enhance()`` -- that append their own
    single canonical provenance section afterward and would otherwise get it
    twice. Standalone/direct callers get the default ``True``, matching
    ``render_evidence_report()``'s own default, so ``ComposedReport.html``
    stays a complete, self-contained artifact unless a caller opts out."""
    context = build_report_context(article)
    graph = build_evidence_graph(article, context, state_file=getattr(config, "state_file", None))
    canonical_entities = list(resolve_canonical_entities(article, graph))
    threat_product = build_threat_product(article, context)
    package = _detection_package(article, context)

    from automation.report_renderer import render_evidence_report
    base = render_evidence_report(article, config, include_provenance=include_provenance)

    role_decisions = _lean_role_decisions(article, context, threat_product)
    # An empty-but-titled section (heading with nothing under it) reads as
    # broken, not honest -- omit the section entirely when this record's
    # family has no grounded role guidance at all, matching
    # executive_products.render_role_decisions()'s own "if not decisions:
    # return ''" convention for the same situation.
    role_html = "" if not role_decisions else _section(
        "Role-Based Decisions",
        _bullets([f"<strong>{role_display_label(d.role)}:</strong> {_esc(d.decision)} "
                  f"<span style=\"color:#64748b\">&mdash; {_esc(d.rationale)}</span>" for d in role_decisions],
                 "#00d4ff"),
        "#00d4ff",
    )

    source = next(iter(graph.sources.values()))
    # COMMERCIAL-QUALITY-2026-08-18: real, independent 2-axis Admiralty
    # grading -- Source Reliability (the publisher) separate from
    # Information Credibility (this record's own corroboration standing,
    # already computed by EvidenceGraph.recompute_corroboration(), read
    # here rather than re-derived) -- instead of one blended "A/B —
    # Reliable" line, and an honest corroboration statement that reflects
    # the actually-computed state rather than always asserting "not been
    # assessed" regardless of it.
    corroboration_state = worst_corroboration_state(
        c.corroboration_state for c in graph.claims.values() if source.source_id in c.source_refs
    )
    reliability_lines = "<br>".join(
        _esc(line) for line in two_axis_reliability(source.reliability, corroboration_state).split("\n")
    )
    # RX-P1E-WIRE: the same 3 real, independently-computed axes the prose
    # line above already renders, as structured data -- two_axis_reliability()
    # itself only returns a formatted string, so these 3 pure functions
    # (unchanged, already imported into this module) are called a second
    # time here at zero real cost. Mandate Section 11's own requirement:
    # "do not use one report-wide cosmetic label" -- this exposes the 3
    # distinct axes (source reliability / information credibility /
    # analytical confidence) as 3 distinct structured fields, not a single
    # blended score.
    credibility_number, credibility_label = information_credibility(corroboration_state)
    analytical_confidence = {
        "source_reliability_grade": source_reliability_grade(source.reliability),
        "information_credibility_number": credibility_number,
        "information_credibility_label": credibility_label,
        "corroboration_state": corroboration_state.value,
        "overall_confidence": overall_analytical_confidence(source.reliability, credibility_number),
    }
    corroboration_note = {
        CorroborationState.MULTI_SOURCE_INDEPENDENT:
            "This record is corroborated by independent sources (see the evidence ledger).",
        CorroborationState.MULTI_SOURCE_DEPENDENT:
            "Multiple outlets report this, but they trace to a shared, non-independent origin (see the "
            "evidence ledger) -- treated as a single-source claim, not independent confirmation.",
        CorroborationState.SINGLE_SOURCE:
            "Reported by a single identified source; an independent second source has not been found "
            "(see the evidence ledger).",
        CorroborationState.UNCORROBORATED:
            "Whether an independent second source corroborates this record has not been assessed (see the "
            "evidence ledger). This report does not wait on that assessment to publish, and does not "
            "overstate certainty in the meantime.",
    }[corroboration_state]
    reliability_html = _section(
        "Source Reliability & Corroboration",
        _panel(
            f'<p style="margin:0 0 8px"><strong>{_esc(source.publisher)}</strong></p>'
            f'<p style="margin:0 0 8px;font-family:monospace;font-size:12px;line-height:1.7">{reliability_lines}</p>'
            f'<p style="margin:0;color:#94a3b8">{corroboration_note}</p>',
        ),
        "#64748b",
    )

    html = base.html + role_html + reliability_html

    contradictions = find_all_contradictions(graph, dimension_tags=_dimension_tags_for(graph), full_text=html)

    intelligence_gaps = [
        IntelligenceGap(
            description="Whether an independent second source corroborates this record has not been assessed.",
            category="KNOWN_UNKNOWN",
            what_would_confirm_or_refute="A second, independent source reporting the same underlying fact.",
        ),
    ]
    # RX-P1H: this list was identical for every family regardless of its
    # actual evidence shape -- the one universal gap above stays true for
    # every family (corroboration is genuinely unassessed everywhere), but
    # each of these four families has its own, additional real gap that the
    # universal one does not capture. Additive only: no existing family's
    # gap list changes.
    _FAMILY_SPECIFIC_GAPS = {
        "ai_security": IntelligenceGap(
            description="Whether the cited AI system, model, or capability is in use within the reader's "
                         "environment has not been independently verified.",
            category="KNOWN_UNKNOWN",
            what_would_confirm_or_refute="A confirmed model/vendor inventory match against approved or shadow AI usage records.",
        ),
        "breach_notice": IntelligenceGap(
            description="The actual scope of data exposure (records, individuals, or data categories affected) "
                         "has not been independently confirmed beyond the public disclosure record.",
            category="KNOWN_UNKNOWN",
            what_would_confirm_or_refute="A verified breach notification or regulatory filing detailing confirmed scope.",
        ),
        "threat_actor": IntelligenceGap(
            description="Whether the described actor, infrastructure, or TTPs are currently active against the "
                         "reader's own sector or region has not been assessed.",
            category="KNOWN_UNKNOWN",
            what_would_confirm_or_refute="A matching indicator or TTP observed in the reader's own telemetry.",
        ),
        "ransomware_reporting": IntelligenceGap(
            description="This record describes ransomware activity or trends generally; no specific victim "
                         "organization in the reader's environment has been claimed or assessed.",
            category="KNOWN_UNKNOWN",
            what_would_confirm_or_refute="A specific, named victim claim or internal indicator matching the reported activity.",
        ),
    }
    if context.family in _FAMILY_SPECIFIC_GAPS:
        intelligence_gaps.append(_FAMILY_SPECIFIC_GAPS[context.family])

    material_claims = [c for c in graph.claims.values() if c.has_evidence()]
    bundle = ReportBundle(
        report_id=context.report_id, graph=graph, rendered_text=html,
        detection_rules=_detection_rules(context.report_id, package),
        threat_products=[threat_product] if threat_product else [],
        intelligence_gaps=intelligence_gaps,
        review=None, is_premium_tier=(requested_tier in (
            CertificationState.PREMIUM_READY_PENDING_HUMAN, CertificationState.PREMIUM_CERTIFIED,
            CertificationState.PREMIUM_AUTOMATED_CERTIFIED,
        )),
        depth_assessment=DepthAssessment(
            rendered_word_count=len(html.split()), material_claim_count=len(material_claims),
            distinct_evidence_backed_sections=html.count("data-section="),
        ),
    )
    control_results = evaluate_commercial_readiness(bundle)
    downgrade = determine_achieved_tier(control_results, requested_tier=requested_tier)
    scorecard = evaluate_intelligence_validation(bundle, control_results)

    return ComposedReport(
        report_id=context.report_id, context=context, html=html, bundle=bundle,
        control_results=control_results, downgrade=downgrade, scorecard=scorecard,
        contradictions=contradictions, analytical_confidence=analytical_confidence,
        canonical_entities=canonical_entities,
    )
