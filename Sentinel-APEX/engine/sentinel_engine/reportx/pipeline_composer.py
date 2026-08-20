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

import re
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
from .attack_mapping import AttackMapping, build_attack_mappings
from .claim_model import CorroborationState, EvidenceGraph
from .commercial_readiness import ControlResult, ReportBundle, evaluate_commercial_readiness
from .contradiction_engine import Contradiction, find_all_contradictions
from .detection_validation import DetectionRule, DetectionValidationState
from .discovery_bridge import build_evidence_graph, build_threat_product
from .entity_resolution import CanonicalEntity, resolve_canonical_entities
from .forecast import Forecast, WithheldForecast
from .intelligence_validation import IntelligenceScorecard, SupplementalEvidence, evaluate_intelligence_validation
from .executive_products import (
    HuntHypothesis,
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
from sentinel_engine.models import Confidence  # noqa: E402

# RX-P1I: previously only 1 of report_renderer.DetectionPackage's 4 real
# status strings was mapped -- the other 3 all fell through to the same
# WITHHELD_INSUFFICIENT_EVIDENCE default, conflating "this format has no
# threat-specific telemetry at all" (not_applicable) and "a telemetry plan
# exists but no rule was attempted" (telemetry_specification_only) with a
# genuine evidentiary shortfall. detection_validation.py's own
# NOT_APPLICABLE/TELEMETRY_SPECIFICATION states (added alongside this fix)
# now let every real status map to its own honest state.
_STATUS_TO_VALIDATION_STATE = {
    "syntax_validated_experimental": DetectionValidationState.SYNTAX_VALIDATED,
    "not_applicable": DetectionValidationState.NOT_APPLICABLE,
    "telemetry_specification_only": DetectionValidationState.TELEMETRY_SPECIFICATION,
    "withheld_insufficient_evidence": DetectionValidationState.WITHHELD_INSUFFICIENT_EVIDENCE,
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

# RX-P1J: exact-string regression guard for the specific bare-generic
# defects the mandate names and this pipeline already fixed once
# (COMMERCIAL-QUALITY-2026-08-18 removed a bare "Track against {family}
# intake..." with nothing evidence-specific appended -- see
# _lean_role_decisions()'s own docstring). Every current decision's text
# carries real, evidence-specific content beyond these lead-ins, so this
# never trims real output today; it exists so a future family branch can't
# silently reintroduce the exact defect already found and removed.
_GENERIC_DECISION_PHRASES = frozenset({"monitor this threat", "track against intake"})

# This pipeline has no jurisdiction/regulation evidence model in the
# role-decision path (regulatory.py's real Section 14 engine is a separate,
# unwired capability -- see _validate_role_decisions()'s docstring), so a
# specific numeric deadline or an asserted legal/regulatory obligation
# reaching a RoleDecision today can only be fabricated, never evidenced.
_ROLE_DEADLINE_PATTERN = re.compile(r"\b\d+[\s-]?(?:hour|day|week)s?\b", re.IGNORECASE)
_ROLE_REGULATORY_PATTERN = re.compile(
    r"\b(?:must notify|legally required|regulatory (?:filing|obligation|deadline)|"
    r"required by (?:law|regulation)|GDPR|NIS2|DORA|HIPAA)\b", re.IGNORECASE,
)


def _validate_role_decisions(decisions: list[RoleDecision]) -> list[RoleDecision]:
    """Mandate Section 7/11 hard-fail gate, mirroring attack_mapping.
    _apply_semantic_gate()'s "drop, never downgrade" discipline: a
    RoleDecision that fails any check here is dropped entirely rather than
    published with a fabricated or unsupported basis.

    Promotional/placeholder language is already caught downstream once
    rendered (report_integrity.validate_publication()'s
    _UNSUPPORTED_COMMERCIAL_PATTERNS/_PLACEHOLDER_PATTERNS, which run
    against the full rendered HTML -- including role-decision content once
    RX-P1J wires it through authority_transformer.py the same way
    hunt_hypotheses/attack_mappings already are). This gate instead catches
    defects only visible at the structured-object level, before rendering:
    a malformed role, no stated decision, no evidence basis, an exact
    regression of a known bare-generic decision, a duplicate role+decision
    pair within one report, and a deadline/regulatory claim this pipeline
    cannot support today."""
    validated: list[RoleDecision] = []
    seen: set[tuple] = set()
    for d in decisions:
        if not isinstance(d.role, RoleAudience):
            continue
        text = (d.decision or "").strip()
        if not text:
            continue
        if text.rstrip(".").lower() in _GENERIC_DECISION_PHRASES:
            continue
        if not d.evidence_claim_ids:
            continue
        if d.deadline_or_trigger and _ROLE_DEADLINE_PATTERN.search(d.deadline_or_trigger):
            continue
        if _ROLE_REGULATORY_PATTERN.search(f"{d.decision} {d.rationale} {d.escalation_condition}"):
            continue
        key = (d.role, d.decision)
        if key in seen:
            continue
        seen.add(key)
        validated.append(d)
    return validated


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
            limitations="Reflects only this record's own reported exploitation and patch status; does not confirm "
                        "whether the affected component is deployed in any specific environment.",
        ))
    if context.family in ("cve_advisory", "cisa_advisory", "cisa_kev"):
        decisions.append(RoleDecision(
            role=RoleAudience.SOC_MANAGER,
            decision="Review the detection guidance below before enabling any blocking action on it.",
            rationale="Detection maturity for this record is stated explicitly, not assumed production-ready.",
            evidence_claim_ids=("c-summary",),
            limitations="Detection guidance is evidence-scoped to this record; does not confirm the described "
                        "technique has been observed in any specific environment.",
        ))
    if context.family == "ransomware_claim":
        decisions.append(RoleDecision(
            role=RoleAudience.IR_MANAGER,
            decision="Treat as a validation task (confirm internally), not an activation trigger, absent "
                      "independent corroboration.",
            rationale="The victim claim is a single, third-party leak-site source (c-victim-claim, REPORTED "
                       "not CONFIRMED) -- Section 10's high-impact-claim-type discipline applies.",
            evidence_claim_ids=("c-victim-claim",),
            escalation_condition="Independent corroboration of the victim claim is found.",
            limitations="Based on a single, third-party leak-site claim only; does not confirm the claim is "
                        "accurate or that any specific organization has been compromised.",
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
            limitations="Based on this record's own summary only; does not confirm the cited AI system, model, "
                        "or capability is in use within any specific environment.",
        ))
    if context.family == "breach_notice":
        decisions.append(RoleDecision(
            role=RoleAudience.LEGAL_COMPLIANCE_PRIVACY,
            decision="Assess whether this public breach record involves the organization's own data, customers, or "
                      "vendors before any notification or regulatory determination.",
            rationale="A public breach record is a disclosure to review, not a confirmed organizational incident on "
                       "its own (c-summary only -- no scope evidence has been independently established).",
            evidence_claim_ids=("c-summary",),
            limitations="Based on a public disclosure record only; does not confirm organizational, customer, or "
                        "vendor data involvement, and is not itself a regulatory or legal determination.",
        ))
    if context.family == "threat_actor":
        decisions.append(RoleDecision(
            role=RoleAudience.THREAT_HUNTER,
            decision="Cross-reference the described actor's infrastructure and TTPs against internal telemetry "
                      "before treating this record as relevant to the environment.",
            rationale="Actor attribution and TTPs are as reported by the cited source; this pipeline does not "
                       "independently corroborate them.",
            evidence_claim_ids=("c-summary",),
            limitations="Actor attribution and TTPs are as reported by the cited source only; this pipeline does "
                        "not independently corroborate them or confirm relevance to any specific environment.",
        ))
    if context.family == "ransomware_reporting":
        decisions.append(RoleDecision(
            role=RoleAudience.SOC_MANAGER,
            decision="Review detection and backup-immutability coverage against the ransomware tradecraft "
                      "described, independent of any specific victim claim.",
            rationale="This record reports ransomware activity or trends generally, not a claim against a named "
                       "victim -- see the Ransomware Claim Intelligence family for that distinct evidence type.",
            evidence_claim_ids=("c-summary",),
            limitations="Describes ransomware activity or trends generally; does not confirm any specific named "
                        "victim or environment-specific relevance.",
        ))
    return _validate_role_decisions(decisions)


def _cve_hunt_hypotheses(article, context: ReportContext, package: DetectionPackage) -> list[HuntHypothesis]:
    """RX-P1I, mandate Section 15: "CVE: exposure + exploitation hypothesis."
    Scoped to cve_advisory only this round -- proves the wiring pattern with
    one real, well-evidenced family (Reuse Before Build: required_telemetry
    reuses report_renderer._detection_package()'s own already-computed,
    vulnerability-class-conditioned telemetry guidance verbatim, rather than
    re-deriving a second copy) instead of a rushed multi-family rollout.
    cisa_kev's retrospective-exploitation hunt (mandate Section 15) is real,
    separate follow-up work, not attempted here.

    Deliberately generated unconditionally for every cve_advisory article,
    not gated on vulnerability_class: package.telemetry is real and
    non-empty even in the final, generic fallback branch of
    _detection_package() ("Confirm affected assets and versions, then
    collect..."), so there is always a genuine, non-fabricated exposure-
    plus-exploitation question to ask -- the hypothesis itself, not a
    pipeline-level gate, is what stays honest about "no evidence yet" via
    its own negative_indicators/limitations text: this never asserts
    compromise occurred, only what evidence WOULD indicate it did."""
    if context.family != "cve_advisory":
        return []
    subject = article.affected_product or article.affected_vendor or article.cve_id or "the affected component"
    return [HuntHypothesis(
        hypothesis_id=f"hunt-{context.report_id}-exposure",
        statement=f"If {subject} is deployed and reachable as described by {context.report_id}'s evidence "
                   f"(CVE: {article.cve_id or 'not supplied'}), telemetry consistent with the vulnerability "
                   f"class below may show attempted or successful exploitation.",
        required_telemetry=package.telemetry,
        pivot_opportunities=(
            "Pivot on the affected component's inventoried version/build identifier, where available.",
            "Pivot on network paths and identities with reachability to the affected component.",
        ),
        expected_observations=(
            "Requests, processes, or events consistent with the vulnerability class described in this "
            "report's Technical Analysis, occurring after the CVE's public disclosure date and targeting "
            "the specific affected component.",
        ),
        negative_indicators=(
            "No matching telemetry for the affected component across the retrospective lookback window.",
            "The affected component is confirmed not deployed, or not reachable as this CVE describes.",
        ),
        false_positive_considerations=(
            "Legitimate administrative, diagnostic, or scanning activity against the same component can "
            "resemble exploitation attempts; corroborate with authentication context and known-good change "
            "records before escalating.",
        ),
        validation_steps=(
            "Confirm the affected component is deployed and reach the specific affected version/build.",
            "Query the required telemetry sources above for the retrospective lookback window.",
            "Manually review any matches for legitimacy before escalation.",
        ),
        success_criteria="A specific, timestamped, corroborated telemetry match consistent with the "
                          "vulnerability class, tied to the confirmed affected component.",
        evidence_claim_ids=("c-cve-id", "c-exploitation-status"),
        escalation_criteria="Escalate to incident response only when a validated telemetry match is "
                             "corroborated by at least one additional independent signal (e.g. an "
                             "authentication anomaly or unexpected process lineage) -- a single matching "
                             "log line alone is not sufficient grounds for escalation.",
        limitations="Derived from the vulnerability class alone; does not confirm the affected component is "
                    "actually deployed in the reader's environment, nor that matching telemetry represents "
                    "genuine exploitation rather than benign activity.",
    )]


def _cve_forecast(article, context: ReportContext) -> Forecast | WithheldForecast:
    """RX-P1K, mandate Section 22: ``forecast.py``'s ``Forecast``/
    ``WithheldForecast`` (Section 16 of the founder mandate) were real,
    tested, and certified but never imported by this live pipeline at
    all -- Section 22 (Forecast/Outlook) has been permanently WITHHELD for
    every article regardless of family since this contract was first
    written. Scoped to ``cve_advisory``/``cisa_kev``/``cisa_advisory`` only
    this round (the same "prove the wiring pattern on the family with the
    strongest real evidence first" discipline already used for
    ``_cve_hunt_hypotheses()``, RX-P1I) -- proves the wiring end to end
    with one real, well-evidenced condition rather than a rushed
    multi-family rollout that risks the generic "threat activity is
    expected to continue" filler the mandate explicitly bans.

    The only real, structural forecasting signal this pipeline has for a
    CVE today is the CISA KEV catalog listing itself
    (``discovery_bridge.py`` only ever constructs the ``c-kev-listed``
    claim when ``article.kev_listed is True``): a federal, evidence-based
    confirmation of active exploitation is a genuine basis to forecast
    continued exploitation activity until remediation. A CVE with no KEV
    listing has no comparable real activity signal in this pipeline's
    evidence model -- forecasting one would be exactly the "assigned HIGH
    CONFIDENCE solely because a template says so" defect ``forecast.py``'s
    own module docstring names, so that case is an explicit, reasoned
    ``WithheldForecast``, never a guessed judgment."""
    if context.family not in _VULNERABILITY_MANAGER_FAMILIES:
        return WithheldForecast(
            topic="Exploitation trajectory",
            reason="Forecast generation is scoped to CVE-shaped families with a KEV-catalog signal; "
                   f"no such capability exists yet for family={context.family!r}.",
        )
    if article.kev_listed is True:
        return Forecast(
            judgment="Exploitation activity against this vulnerability is likely to continue while affected "
                     "systems remain unremediated, consistent with its confirmed CISA KEV listing.",
            time_horizon="Until affected systems are remediated or mitigated",
            supporting_observation_claim_ids=("c-kev-listed",),
            assumptions=("The vulnerability class and affected component described in this record remain "
                         "accurate for as-yet-unremediated deployments.",),
            confidence=Confidence.MEDIUM.value,
            confidence_rationale="Based on confirmed CISA KEV listing (a federal, evidence-based confirmation "
                                  "of active exploitation); does not predict the rate, targeting, or duration of "
                                  "continued activity beyond the fact that exploitation is already occurring.",
            indicators_to_watch=("Removal from the KEV catalog", "A confirmed vendor/telemetry signal of "
                                  "majority patch adoption across affected deployments"),
            what_would_change_assessment=("Removal from the KEV catalog", "Confirmed majority patch adoption "
                                           "across affected deployments"),
        )
    return WithheldForecast(
        topic="Exploitation trajectory",
        reason="No confirmed exploitation signal (e.g. a CISA KEV listing) exists for this vulnerability to "
               "forecast future activity from; forecasting a trajectory with no observed activity baseline "
               "would be speculative, not evidence-based.",
    )


def _render_forecast_html(forecast: Forecast | WithheldForecast) -> str:
    """Only a real, adequately-supported Forecast renders customer-visible
    content -- a WithheldForecast's reason is exposed structurally (see
    ComposedReport.forecasts / the output dict) but not as its own prose
    block, matching every other WITHHELD section's own "silent omission,
    not a placeholder" convention already established throughout this
    pipeline (Sections 4/10/16/17/20)."""
    if not isinstance(forecast, Forecast) or not forecast.is_adequately_supported():
        return ""
    rows = (
        f'<p style="margin:0 0 8px"><strong>Judgment:</strong> {_esc(forecast.judgment)}</p>'
        f'<p style="margin:0 0 8px"><strong>Time horizon:</strong> {_esc(forecast.time_horizon)}</p>'
        f'<p style="margin:0 0 8px"><strong>Confidence:</strong> {_esc(forecast.confidence)} '
        f'&mdash; {_esc(forecast.confidence_rationale)}</p>'
    )
    if forecast.assumptions:
        rows += _bullets(["<strong>Assumption:</strong> " + _esc(a) for a in forecast.assumptions], "#eab308")
    if forecast.what_would_change_assessment:
        rows += _bullets(
            ["<strong>Would change this assessment:</strong> " + _esc(w) for w in forecast.what_would_change_assessment],
            "#eab308",
        )
    return _section("Forecast / Outlook", _panel(rows, "#eab308"), "#eab308")


def _render_attack_mappings_html(mappings: list[AttackMapping]) -> str:
    """RX-P1I: the structured counterpart to report_renderer._attack_section()
    -- that function already renders package.attack_mappings' prose
    sentences unconditionally (unchanged, still real, still tested). This
    is additive: the same underlying evidence, now also surfaced with an
    explicit status/confidence/limitations a caller can act on
    programmatically, not just read as prose. Empty list renders nothing,
    matching every other optional section's own convention in this
    function."""
    if not mappings:
        return ""
    rows = []
    for m in mappings:
        rows.append(_panel(
            f'<p style="margin:0 0 6px"><strong>{_esc(m.technique_id)} &mdash; {_esc(m.technique_name)}</strong> '
            f'<span style="color:#94a3b8">({_esc(", ".join(m.tactics))})</span></p>'
            f'<p style="margin:0 0 6px;font-family:monospace;font-size:11px;color:#a855f7">'
            f'STATUS: {_esc(m.status.value)} &middot; CONFIDENCE: {_esc(m.confidence)}</p>'
            f'<p style="margin:0 0 6px">{_esc(m.reasoning)}</p>'
            + ("".join(f'<p style="margin:0;color:#64748b;font-size:12px">Limitation: {_esc(lim)}</p>' for lim in m.limitations)),
            "#a855f7",
        ))
    return _section("Structured ATT&CK Assessment", "".join(rows), "#a855f7")


def _render_intelligence_gaps_html(gaps: list[IntelligenceGap]) -> str:
    """RX-P1K: report_contract.py's Section 21 (Intelligence Gaps) has
    resolved PARTIAL_EVIDENCE unconditionally since RX-P1F, on the
    documented basis that a real, family-conditioned gap list is always
    computed (see the ``intelligence_gaps`` construction above) -- but that
    list was never rendered into the published HTML on ANY content path,
    including this composer's own. The mechanism being real was never the
    same claim as the reader ever seeing it; this closes that gap (no pun
    intended). Empty list renders nothing, matching every other optional
    section's own convention in this function -- though in practice this
    list is never empty (the universal corroboration gap above is
    unconditional)."""
    if not gaps:
        return ""
    items = []
    for g in gaps:
        line = f'<strong>{_esc(g.category.replace("_", " ").title())}:</strong> {_esc(g.description)}'
        if g.what_would_confirm_or_refute:
            line += (f'<br><span style="color:#64748b">Would be resolved by: '
                     f'{_esc(g.what_would_confirm_or_refute)}</span>')
        items.append(line)
    return _section("Intelligence Gaps", _bullets(items, "#f59e0b"), "#f59e0b")


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
    # RX-P1I-WIRE: real, evidence-grounded hunt hypotheses (cve_advisory
    # only this round -- see _cve_hunt_hypotheses()). Empty for every other
    # family, matching canonical_entities' own "always present, sometimes
    # empty" convention rather than a family-conditioned Optional.
    hunt_hypotheses: list[HuntHypothesis] = field(default_factory=list)
    # RX-P1I-WIRE (structured ATT&CK): first-class replacement for reading
    # DetectionPackage.attack_mappings' prose tuple directly -- every entry
    # here already passed build_attack_mappings()'s semantic gate (real
    # technique, real tactic, real behavioral basis, real evidence/claim/
    # source references, OBSERVED structurally excluded). Computed
    # unconditionally for every article/family, at zero extra evidence
    # cost (reuses the graph and detection package this function already
    # built), same "always present, sometimes empty" convention as
    # canonical_entities/hunt_hypotheses above.
    attack_mappings: list[AttackMapping] = field(default_factory=list)
    # RX-P1J-WIRE: real, family-conditioned role decisions (see
    # _lean_role_decisions()/_validate_role_decisions() above) -- every
    # entry already passed the structural hard-fail gate (real role, real
    # decision, real evidence basis, no duplicates, no unsupported
    # deadline/regulatory claim). Same "always present, sometimes empty"
    # convention as hunt_hypotheses/attack_mappings/canonical_entities
    # above, so report_contract.py's Section 19 can finally distinguish a
    # genuinely-measured-empty report from a caller that never measured at
    # all (see evaluate_section_states()'s role_decision_count parameter).
    role_decisions: list[RoleDecision] = field(default_factory=list)
    # RX-P1K-WIRE: report_contract.py Section 6 (Evidence & Source
    # Assessment) has claimed unconditional COMPLETE since this contract
    # was first written, on the (correct, for THIS module) assumption that
    # real reliability/corroboration data always exists once compose_report()
    # succeeds -- true here, but the rendered HTML backing that claim
    # (``reliability_html`` below, in this function) was never exposed on
    # this dataclass at all, so authority_transformer.py had no way to
    # render it on the LLM-authored or legacy-template content paths (only
    # ``reportx_composer`` ever saw it, baked into ``html`` directly).
    # Exposed here as the pre-built HTML string, not re-derived structured
    # data, since exactly one place ever needs to construct it (unlike
    # hunt_hypotheses/attack_mappings/role_decisions, which are lists
    # rendered per-item on multiple paths with their own dict shape).
    reliability_html: str = ""
    # RX-P1K-WIRE: real, evidence-grounded Forecast/WithheldForecast
    # entries (see _cve_forecast() above) -- forecast.py's dataclasses
    # existed, were tested, and certified, but were never imported by this
    # live pipeline at all before this round (Section 22 was permanently
    # WITHHELD for every article regardless of family). Same "always
    # present, sometimes empty" convention as hunt_hypotheses/
    # attack_mappings/role_decisions above.
    forecasts: list = field(default_factory=list)

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
    attack_mappings = build_attack_mappings(article, context, graph, package)

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
                  f"<span style=\"color:#64748b\">&mdash; {_esc(d.rationale)}</span>"
                  + (f"<br><span style=\"color:#64748b\">Escalate when: {_esc(d.escalation_condition)}</span>"
                     if d.escalation_condition else "")
                  + (f"<br><span style=\"color:#64748b\">Limitations: {_esc(d.limitations)}</span>"
                     if d.limitations else "")
                  for d in role_decisions],
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

    # RX-P1I: real, evidence-grounded hunt hypotheses -- previously
    # executive_products.HuntHypothesis/render_hunt_package() existed and
    # were tested but never called from this live pipeline (Section 14,
    # Threat Hunting, was permanently WITHHELD_INSUFFICIENT_EVIDENCE for
    # every article regardless of family). Scoped to cve_advisory only this
    # round -- see _cve_hunt_hypotheses()'s own docstring for why.
    hunt_hypotheses = _cve_hunt_hypotheses(article, context, package)
    hunt_html = "" if not hunt_hypotheses else "".join(
        _section(
            f"Threat Hunting — {h.hypothesis_id}",
            _panel(f'<p style="margin:0"><strong>Hypothesis:</strong> {_esc(h.statement)}</p>')
            + _bullets(["<strong>Required telemetry:</strong> " + _esc(t) for t in h.required_telemetry]
                       + ["<strong>Pivot:</strong> " + _esc(p) for p in h.pivot_opportunities]
                       + ["<strong>Expected if true:</strong> " + _esc(e) for e in h.expected_observations]
                       + ["<strong>Negative indicator:</strong> " + _esc(n) for n in h.negative_indicators]
                       + ["<strong>False-positive risk:</strong> " + _esc(f) for f in h.false_positive_considerations],
                       "#a855f7")
            + _panel(
                f'<p style="margin:0 0 8px"><strong>Success criteria:</strong> {_esc(h.success_criteria)}</p>'
                f'<p style="margin:0 0 8px"><strong>Escalation criteria:</strong> {_esc(h.escalation_criteria)}</p>'
                f'<p style="margin:0 0 8px"><strong>Confidence:</strong> {_esc(h.confidence.value)} &mdash; '
                f'<strong>Maturity:</strong> {_esc(h.maturity)} (not independently confirmed by execution '
                f'against real telemetry)</p>'
                f'<p style="margin:0"><strong>Limitations:</strong> {_esc(h.limitations)}</p>'
            ),
            "#a855f7",
        )
        for h in hunt_hypotheses
    )

    attack_html = _render_attack_mappings_html(attack_mappings)

    # RX-P1K: real, evidence-grounded forecast -- cve_advisory/cisa_kev/
    # cisa_advisory only this round, see _cve_forecast()'s own docstring
    # for why. "always present, sometimes withheld" convention: a
    # WithheldForecast is a real, explained outcome, not an absence --
    # forecasts always holds exactly one entry for these three families,
    # zero for every other family today.
    forecasts = [_cve_forecast(article, context)] if context.family in _VULNERABILITY_MANAGER_FAMILIES else []
    forecast_html = _render_forecast_html(forecasts[0]) if forecasts else ""

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

    gaps_html = _render_intelligence_gaps_html(intelligence_gaps)

    html = base.html + role_html + reliability_html + hunt_html + attack_html + forecast_html + gaps_html

    # Computed against the now-complete html (including the gaps section
    # just appended above) -- find_all_contradictions() scans full_text for
    # its 3 text-pattern checks, so this must run after every section that
    # could contain a contradictory statement has been assembled, not
    # before.
    contradictions = find_all_contradictions(graph, dimension_tags=_dimension_tags_for(graph), full_text=html)

    material_claims = [c for c in graph.claims.values() if c.has_evidence()]
    bundle = ReportBundle(
        report_id=context.report_id, graph=graph, rendered_text=html,
        detection_rules=_detection_rules(context.report_id, package),
        threat_products=[threat_product] if threat_product else [],
        intelligence_gaps=intelligence_gaps, forecasts=forecasts,
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
    # RX-P1I: threads the real hunt_hypotheses computed above into the
    # scorecard's Threat Hunting Guidance dimension for the first time --
    # previously this call never passed a `supplemental` argument at all,
    # so that dimension always reported "No hunt hypotheses supplied."
    # RX-P1N: role_decisions (computed above, real and gate-passed since
    # RX-P1J) was never added here even after the role-decision system was
    # built -- Executive Decision Support and Business Context always
    # reported "No ... role decisions supplied" for every report, including
    # ones that genuinely have CEO/Board-, CISO/CIO-, or business-facing
    # decisions. This scorecard does not gate live publication (see
    # ComposedReport.scorecard's own docstring -- deliberately observability-
    # only, pending a separate calibration decision), but its accuracy still
    # matters: that future calibration decision must be made from real
    # coverage, not artificially low coverage caused by a wiring gap.
    scorecard = evaluate_intelligence_validation(
        bundle, control_results,
        supplemental=SupplementalEvidence(
            hunt_hypotheses=tuple(hunt_hypotheses), role_decisions=tuple(role_decisions),
        ),
    )

    return ComposedReport(
        report_id=context.report_id, context=context, html=html, bundle=bundle,
        control_results=control_results, downgrade=downgrade, scorecard=scorecard,
        contradictions=contradictions, analytical_confidence=analytical_confidence,
        canonical_entities=canonical_entities, hunt_hypotheses=hunt_hypotheses,
        attack_mappings=attack_mappings, role_decisions=role_decisions,
        reliability_html=reliability_html, forecasts=forecasts,
    )
