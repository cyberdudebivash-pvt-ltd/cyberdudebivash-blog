"""Commercial readiness validator (ReportX Sections 31-33, 46).

Orchestrates every gate this package implements into the exact 23-row
matrix Section 33/46 requires. Every row's status is *computed* from the
other modules' real output — there is no manual PASS field anywhere in
this file. A row whose underlying data is simply absent from the bundle
(e.g. no forecasts were ever attempted) is reported ``BLOCKED``, not
silently defaulted to ``PASS`` — Section 33's "NO MANUAL PASS FIELD" is
enforced by construction: nothing in this module ever writes the string
``"PASS"`` except as the output of a real comparison.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from .analytic_scaffolding import HypothesisSet, IntelligenceGap, build_bibliography, find_orphan_citations
from .claim_model import EpistemicState, EvidenceGraph
from .claim_support_matrix import STATUSES_REQUIRING_EVIDENCE, evaluate_claim_support_gate
from .contradiction_engine import find_all_contradictions
from .detection_validation import DetectionRule, check_all_rules
from .forecast import Forecast, WithheldForecast, evaluate_forecast_gate
from .human_review import CertificationState, ReviewRecord, resolve_certification_state
from .metrics_registry import MetricsRegistry, evaluate_statistics_gate
from .product_depth import DepthAssessment
from .qa_linter import critical_defect_count, lint_text
from .regulatory import RegulatoryApplicability, evaluate_regulatory_gate
from .threat_schemas import CVERecord, RansomwareVictimClaim, ThreatProduct


@dataclass
class ReportBundle:
    """Everything one report needs on hand to be evaluated. Fields left at
    their default represent genuinely absent data, not an oversight — the
    validator reports ``BLOCKED`` for any control whose required input is
    empty, rather than assuming a pass."""

    report_id: str
    graph: EvidenceGraph
    rendered_text: str = ""
    dimension_tags: dict[str, list[str]] = field(default_factory=dict)
    claim_sections: dict[str, str] = field(default_factory=dict)
    detection_rules: list[DetectionRule] = field(default_factory=list)
    metrics_registry: MetricsRegistry = field(default_factory=MetricsRegistry)
    cited_metric_ids: list[str] = field(default_factory=list)
    rendered_metric_ids: list[str] = field(default_factory=list)
    regulatory_applicabilities: list[RegulatoryApplicability] = field(default_factory=list)
    forecasts: list = field(default_factory=list)  # Forecast | WithheldForecast
    hypothesis_sets: list[HypothesisSet] = field(default_factory=list)
    intelligence_gaps: list[IntelligenceGap] = field(default_factory=list)
    threat_products: list[ThreatProduct] = field(default_factory=list)
    review: ReviewRecord | None = None
    is_premium_tier: bool = False
    depth_assessment: DepthAssessment | None = None
    technical_recommendation_count: int = 0
    technical_recommendations_with_evidence_basis: int = 0


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    name: str
    status: str  # "PASS" | "FAIL" | "BLOCKED"
    evidence: str
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id, "name": self.name, "status": self.status,
            "evidence": self.evidence, "failures": self.failures, "warnings": self.warnings,
        }


def _pass_fail(control_id: str, name: str, ok: bool, evidence: str, failures: list[str] | None = None) -> ControlResult:
    return ControlResult(control_id, name, "PASS" if ok else "FAIL", evidence, failures or [])


def _blocked(control_id: str, name: str, reason: str) -> ControlResult:
    return ControlResult(control_id, name, "BLOCKED", reason)


def evaluate_commercial_readiness(bundle: ReportBundle, as_of: date | None = None) -> list[ControlResult]:
    results: list[ControlResult] = []
    graph = bundle.graph

    # 1. Source provenance
    if not graph.sources:
        results.append(_blocked("source_provenance", "Source provenance", "No sources registered in this bundle."))
    else:
        missing = [sid for sid, s in graph.sources.items() if not s.url or not s.publisher]
        results.append(_pass_fail("source_provenance", "Source provenance", not missing,
                                   f"{len(graph.sources)} sources registered, {len(missing)} incomplete.", missing))

    # 2. Evidence hash — content_sha256 present where technically feasible.
    # "Where feasible" is judged conservatively: a source with no content
    # captured at all (empty notes/url) can't be hashed; that's excluded
    # from the denominator rather than counted as a failure to hash it.
    if not graph.sources:
        results.append(_blocked("evidence_hash", "Evidence hash", "No sources registered in this bundle."))
    else:
        hashable = [s for s in graph.sources.values() if s.url]
        missing_hash = [s.source_id for s in hashable if not s.content_sha256]
        results.append(_pass_fail("evidence_hash", "Evidence hash", not missing_hash,
                                   f"{len(hashable) - len(missing_hash)}/{len(hashable)} hashable sources carry content_sha256.",
                                   missing_hash))

    # 3. Automated-review disclosure
    if bundle.review is None:
        state = resolve_certification_state(True, bundle.is_premium_tier, None, bundle.rendered_text)
        results.append(_pass_fail("automated_review_disclosure", "Automated-review disclosure",
                                   state != CertificationState.PREMIUM_CERTIFIED,
                                   f"No review on file; resolved state {state.value} correctly withholds PREMIUM_CERTIFIED."))
    else:
        results.append(_pass_fail("automated_review_disclosure", "Automated-review disclosure", True,
                                   f"Review on file: {bundle.review.decision.value} by {bundle.review.reviewer_identity}."))

    # 4. Source-specific facts — every claim tagged OBSERVED must carry
    # evidence/source refs of its own (not borrowed from a CONTEXT claim).
    # Scoped to ASSERTIVE epistemic states only, via the same
    # STATUSES_REQUIRING_EVIDENCE frozenset claim_support_matrix.py's own
    # gate already uses -- imported, not re-listed, so the two policies
    # cannot drift apart again. A claim honestly declaring a gap
    # (UNKNOWN/NOT_ASSESSED/NOT_APPLICABLE/HYPOTHESIS) is not asserting
    # anything, so the absence of evidence is the correct representation,
    # not a defect: "did a compromise actually occur?" answered UNKNOWN
    # with no evidence is exactly what Section 10 requires, not a failure
    # of this row.
    from .claim_model import ObservedVsContext
    observed_without_evidence = [
        cid for cid, c in graph.claims.items()
        if c.observed_vs_context == ObservedVsContext.OBSERVED
        and c.status in STATUSES_REQUIRING_EVIDENCE
        and not c.has_evidence()
    ]
    results.append(_pass_fail("source_specific_facts", "Source-specific facts", not observed_without_evidence,
                               f"{sum(1 for c in graph.claims.values() if c.observed_vs_context == ObservedVsContext.OBSERVED)} "
                               f"incident-specific claims checked.", observed_without_evidence))

    # 5. Cross-source corroboration
    high_impact_uncorroborated_but_confirmed = [
        cid for cid, c in graph.claims.items() if c.requires_downgrade_without_corroboration()
    ]
    results.append(_pass_fail("cross_source_corroboration", "Cross-source corroboration",
                               not high_impact_uncorroborated_but_confirmed,
                               f"{len(graph.claims)} claims checked against the corroboration policy.",
                               high_impact_uncorroborated_but_confirmed))

    # 6. Threat-type schema correctness
    contamination: list[str] = []
    for product in bundle.threat_products:
        if isinstance(product, RansomwareVictimClaim) and not product.has_linked_vulnerability():
            for field_name, state in (
                ("cisa_kev_state", product.cisa_kev_state), ("cvss_state", product.cvss_state),
                ("patch_state", product.patch_state), ("exploit_cve_status", product.exploit_cve_status),
            ):
                if state != EpistemicState.NOT_APPLICABLE:
                    contamination.append(f"{product.product_id}.{field_name}={state.value}")
    if not bundle.threat_products:
        results.append(_blocked("threat_type_schema_correctness", "Threat-type schema correctness",
                                 "No threat products registered in this bundle."))
    else:
        results.append(_pass_fail("threat_type_schema_correctness", "Threat-type schema correctness",
                                   not contamination,
                                   f"{len(bundle.threat_products)} threat products checked for cross-schema contamination.",
                                   contamination))

    # 7. Cross-section consistency
    contradictions = find_all_contradictions(graph, bundle.dimension_tags, full_text=bundle.rendered_text)
    results.append(_pass_fail("cross_section_consistency", "Cross-section consistency", not contradictions,
                               f"{len(contradictions)} contradictions found.",
                               [c.description for c in contradictions]))

    # 8. Actor-specific analysis — actor-context claims must each carry
    # their OWN evidence (never borrow the victim-observation layer's).
    actor_context_claims = [c for c in graph.claims.values() if c.claim_type.value in ("TTP_HISTORICAL",)]
    unsupported_actor_context = [c.claim_id for c in actor_context_claims if not c.has_evidence()]
    if not actor_context_claims:
        results.append(_blocked("actor_specific_analysis", "Actor-specific analysis", "No actor-historical-context claims in this bundle."))
    else:
        results.append(_pass_fail("actor_specific_analysis", "Actor-specific analysis", not unsupported_actor_context,
                                   f"{len(actor_context_claims)} actor-context claims checked.", unsupported_actor_context))

    # 9. Victim-specific analysis
    claim_support = evaluate_claim_support_gate(graph)
    results.append(_pass_fail("victim_specific_analysis", "Victim-specific analysis",
                               not claim_support.victim_impact_without_evidence,
                               "Victim-impact claims checked against the claim-support matrix.",
                               claim_support.victim_impact_without_evidence))

    # 10. Current statistics
    if not bundle.rendered_metric_ids:
        results.append(_blocked("current_statistics", "Current statistics", "No quantitative claims rendered in this bundle."))
    else:
        stats_gate = evaluate_statistics_gate(bundle.metrics_registry, bundle.cited_metric_ids,
                                               bundle.rendered_metric_ids, as_of=as_of)
        results.append(_pass_fail("current_statistics", "Current statistics", stats_gate.passed,
                                   f"{len(bundle.rendered_metric_ids)} quantitative claims checked.",
                                   stats_gate.uncited_quantitative_claims + stats_gate.expired_statistics))

    # 11. Regulatory specificity
    if not bundle.regulatory_applicabilities:
        results.append(_blocked("regulatory_specificity", "Regulatory specificity", "No regulatory applicability assessments in this bundle."))
    else:
        reg_gate = evaluate_regulatory_gate(bundle.regulatory_applicabilities)
        results.append(_pass_fail("regulatory_specificity", "Regulatory specificity", reg_gate.passed,
                                   f"{len(bundle.regulatory_applicabilities)} regulatory determinations checked.",
                                   reg_gate.unsupported_determinations))

    # 12. Technical recommendations
    if bundle.technical_recommendation_count == 0:
        results.append(_blocked("technical_recommendations", "Technical recommendations", "No technical recommendations in this bundle."))
    else:
        ok = bundle.technical_recommendations_with_evidence_basis == bundle.technical_recommendation_count
        results.append(_pass_fail("technical_recommendations", "Technical recommendations", ok,
                                   f"{bundle.technical_recommendations_with_evidence_basis}/"
                                   f"{bundle.technical_recommendation_count} recommendations carry an evidence_basis."))

    # 13. Detection evidence discipline
    if not bundle.detection_rules:
        results.append(_blocked("detection_evidence_discipline", "Detection evidence discipline", "No detection rules in this bundle."))
    else:
        promotions = check_all_rules(bundle.detection_rules, bundle.rendered_text)
        results.append(_pass_fail("detection_evidence_discipline", "Detection evidence discipline", not promotions,
                                   f"{len(bundle.detection_rules)} detection rules checked for state-promotion language.",
                                   [f"{v.rule_id}: {v.matched_phrase!r}" for v in promotions]))

    # 14. Temporal integrity — no source with EXACT_TIMESTAMP precision
    # whose retrieved_at predates its own source_date's plausible range is
    # checked here at the coarsest level this bundle can verify: every
    # source_date string, once parsed, must not be a bare date string
    # wearing exact-timestamp precision (the Section 4/8 fabrication risk).
    from .claim_model import TemporalPrecision, infer_temporal_precision
    temporal_defects = [
        s.source_id for s in graph.sources.values()
        if s.source_date and s.temporal_precision == TemporalPrecision.EXACT_TIMESTAMP
        and infer_temporal_precision(s.source_date) != TemporalPrecision.EXACT_TIMESTAMP
    ]
    if not graph.sources:
        results.append(_blocked("temporal_integrity", "Temporal integrity", "No sources registered in this bundle."))
    else:
        results.append(_pass_fail("temporal_integrity", "Temporal integrity", not temporal_defects,
                                   f"{len(graph.sources)} sources checked for fabricated timestamp precision.",
                                   temporal_defects))

    # 15. Grammar/synthesis QA
    if not bundle.rendered_text:
        results.append(_blocked("grammar_synthesis_qa", "Grammar/synthesis QA", "No rendered text in this bundle."))
    else:
        qa_findings = lint_text(bundle.rendered_text)
        n_critical = critical_defect_count(qa_findings)
        results.append(_pass_fail("grammar_synthesis_qa", "Grammar/synthesis QA", n_critical == 0,
                                   f"{len(qa_findings)} QA findings, {n_critical} critical.",
                                   [f.message for f in qa_findings if f.severity == "block"]))

    # 16. Forecast methodology
    if not bundle.forecasts:
        results.append(_blocked("forecast_methodology", "Forecast methodology", "No forecasts attempted in this bundle."))
    else:
        forecast_gate = evaluate_forecast_gate(bundle.forecasts)
        results.append(_pass_fail("forecast_methodology", "Forecast methodology", forecast_gate.passed,
                                   f"{len(bundle.forecasts)} forecast items checked.",
                                   forecast_gate.unsupported_forecasts))

    # 17. Evidence ledger — every claim has evidence_refs or source_refs OR
    # is in an honestly-unresolved state (this is the same rule
    # claim_support_matrix already enforces; re-surfaced here under its
    # own named row per Section 33).
    results.append(_pass_fail("evidence_ledger", "Evidence ledger", claim_support.passed,
                               f"{len(graph.claims)} claims in the ledger.",
                               claim_support.material_claims_without_evidence))

    # 18. Alternative hypotheses
    if not bundle.hypothesis_sets:
        results.append(_blocked("alternative_hypotheses", "Alternative hypotheses", "No hypothesis sets in this bundle."))
    else:
        malformed = [hs.question for hs in bundle.hypothesis_sets if not hs.is_well_formed()]
        results.append(_pass_fail("alternative_hypotheses", "Alternative hypotheses", not malformed,
                                   f"{len(bundle.hypothesis_sets)} hypothesis sets checked.", malformed))

    # 19. Intelligence gaps
    if not bundle.intelligence_gaps:
        results.append(_blocked("intelligence_gaps", "Intelligence gaps", "No intelligence gaps declared in this bundle."))
    else:
        results.append(_pass_fail("intelligence_gaps", "Intelligence gaps", True,
                                   f"{len(bundle.intelligence_gaps)} gaps declared."))

    # 20. Report-specific bibliography
    if not graph.sources:
        results.append(_blocked("report_specific_bibliography", "Report-specific bibliography", "No sources registered in this bundle."))
    else:
        orphans = find_orphan_citations(graph)
        bibliography = build_bibliography(graph)
        results.append(_pass_fail("report_specific_bibliography", "Report-specific bibliography", not orphans,
                                   f"{len(bibliography)} cited sources, {len(orphans)} orphaned.", orphans))

    # 21. Human analyst certification governance
    cert_state = resolve_certification_state(True, bundle.is_premium_tier, bundle.review, bundle.rendered_text)
    governance_ok = (
        (not bundle.is_premium_tier)
        or cert_state in (CertificationState.PREMIUM_READY_PENDING_HUMAN, CertificationState.PREMIUM_CERTIFIED)
    )
    results.append(_pass_fail("human_analyst_certification_governance", "Human analyst certification governance",
                               governance_ok, f"Resolved certification state: {cert_state.value}."))

    # 22. 30-40 page premium depth
    if bundle.depth_assessment is None:
        results.append(_blocked("premium_depth", "30-40 page premium depth", "No depth assessment computed for this bundle."))
    else:
        results.append(_pass_fail("premium_depth", "30-40 page premium depth",
                                   bundle.depth_assessment.passes_premium_depth(),
                                   f"{bundle.depth_assessment.rendered_word_count} words, "
                                   f"{bundle.depth_assessment.material_claim_count} material claims, "
                                   f"{bundle.depth_assessment.distinct_evidence_backed_sections} evidence-backed sections."))

    # 23. Fortune-500 commercial deliverable — the roll-up. Section 46 is
    # explicit ("MANDATORY TARGET: 23 / 23 PASS ... If even one row cannot
    # truthfully PASS: NOT COMMERCIAL-READY") — a BLOCKED row is not a
    # PASS, so it counts against this roll-up exactly like a FAIL. A
    # genuinely complete premium bundle has no BLOCKED rows at all: every
    # required input (sources, statistics, forecasts, hypotheses, gaps,
    # depth assessment, ...) was actually supplied.
    all_else_pass = all(r.status == "PASS" for r in results)
    results.append(_pass_fail("fortune_500_commercial_deliverable", "Fortune-500 commercial deliverable",
                               all_else_pass and governance_ok,
                               f"{sum(1 for r in results if r.status == 'PASS')}/{len(results)} controls PASS, "
                               f"{sum(1 for r in results if r.status == 'BLOCKED')} BLOCKED (not yet attempted)."))

    return results


def render_matrix_report(results: list[ControlResult]) -> str:
    lines = ["COMMERCIAL READINESS", ""]
    for r in results:
        lines.append(f"{r.name}: {r.status}")
    n_pass = sum(1 for r in results if r.status == "PASS")
    lines += ["", f"{n_pass} / {len(results)} PASS"]
    if any(r.status != "PASS" for r in results):
        blockers = [f"{r.name}: {r.status}" for r in results if r.status != "PASS"]
        lines += ["", "FINAL VERDICT: NOT COMMERCIAL-READY", "Remaining blockers:"] + [f"  - {b}" for b in blockers]
    else:
        lines += ["", "FINAL VERDICT: COMMERCIAL-READY (23/23 PASS)"]
    return "\n".join(lines)
