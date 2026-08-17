"""JSON (de)serialization for ``ReportBundle`` (Section 31's CLI interface).

A deliberately small, explicit schema — every field maps 1:1 to a
constructor argument on the underlying dataclasses. No implicit defaults
beyond what those dataclasses themselves already declare, so a JSON bundle
that omits a section produces the exact same ``BLOCKED`` behavior as
constructing the bundle directly in Python.
"""

from __future__ import annotations

import json
from datetime import date

from .analytic_scaffolding import Hypothesis, HypothesisSet, IntelligenceGap
from .claim_model import Claim, ClaimType, CorroborationState, EpistemicState, EvidenceGraph, EvidenceRecord, ObservedVsContext, Reliability, SourceRecord, SourceRole, SourceType, TemporalPrecision
from .commercial_readiness import ReportBundle, evaluate_commercial_readiness, render_matrix_report
from .detection_validation import DetectionRule, DetectionValidationState
from .forecast import Forecast, WithheldForecast
from .human_review import ReviewDecision, ReviewRecord
from .metrics_registry import ExternalMetric, MetricsRegistry
from .product_depth import DepthAssessment
from .regulatory import ApplicabilityState, RegulatoryApplicability


def _enum(cls, value, default=None):
    if value is None:
        return default
    return cls(value)


def bundle_from_dict(d: dict) -> ReportBundle:
    graph = EvidenceGraph()
    for s in d.get("sources", []):
        graph.add_source(SourceRecord(
            source_id=s["source_id"], url=s.get("url", ""), publisher=s.get("publisher", ""),
            source_type=_enum(SourceType, s.get("source_type"), SourceType.OTHER),
            source_role=_enum(SourceRole, s.get("source_role"), SourceRole.PRIMARY_EVENT_SOURCE),
            retrieved_at=s.get("retrieved_at", ""), source_date=s.get("source_date"),
            temporal_precision=_enum(TemporalPrecision, s.get("temporal_precision"), TemporalPrecision.UNKNOWN),
            content_sha256=s.get("content_sha256"),
            reliability=_enum(Reliability, s.get("reliability"), Reliability.UNKNOWN),
            independence_group=s.get("independence_group", ""),
            accessibility=s.get("accessibility", "PUBLIC"), notes=s.get("notes", ""),
        ))
    for e in d.get("evidence", []):
        graph.add_evidence(EvidenceRecord(evidence_id=e["evidence_id"], source_id=e["source_id"],
                                           excerpt=e.get("excerpt", ""), locator=e.get("locator", "")))
    for c in d.get("claims", []):
        claim = Claim(
            claim_id=c["claim_id"], claim_type=ClaimType(c["claim_type"]), text=c.get("text", ""),
            scope=c.get("scope", ""), status=_enum(EpistemicState, c.get("status"), EpistemicState.NOT_ASSESSED),
            evidence_refs=c.get("evidence_refs", []), source_refs=c.get("source_refs", []),
            observed_vs_context=_enum(ObservedVsContext, c.get("observed_vs_context"), ObservedVsContext.NOT_SET),
            temporal_scope=c.get("temporal_scope"), applicability=c.get("applicability", ""),
            analyst_notes=c.get("analyst_notes", ""),
        )
        graph.add_claim(claim)
        graph.recompute_corroboration(claim.claim_id)

    metrics_registry = MetricsRegistry()
    for m in d.get("metrics", []):
        metrics_registry.register(ExternalMetric(
            metric_id=m["metric_id"], name=m.get("name", ""), value=m.get("value", 0.0),
            unit=m.get("unit", ""), scope=m.get("scope", ""), source=m.get("source", ""),
            source_url=m.get("source_url", ""), publication_year=m.get("publication_year", 0),
            retrieved_at=m.get("retrieved_at", ""), valid_until=m.get("valid_until"),
            review_after=m.get("review_after"), sample_scope=m.get("sample_scope", ""),
            notes=m.get("notes", ""),
        ))

    detection_rules = [
        DetectionRule(rule_id=r["rule_id"], technique_id=r.get("technique_id", ""), format=r.get("format", ""),
                      validation_state=_enum(DetectionValidationState, r.get("validation_state"), DetectionValidationState.DRAFT),
                      body=r.get("body", ""))
        for r in d.get("detection_rules", [])
    ]

    regulatory = [
        RegulatoryApplicability(
            jurisdiction=r.get("jurisdiction", ""), victim_geography=r.get("victim_geography"),
            operations_geography=r.get("operations_geography"), data_subject_geography=r.get("data_subject_geography"),
            sector=r.get("sector"), entity_classification=r.get("entity_classification"),
            incident_facts_claim_ids=tuple(r.get("incident_facts_claim_ids", [])),
            regulation=r["regulation"], applicability_state=ApplicabilityState(r["applicability_state"]),
            basis=r.get("basis", ""), confidence=r.get("confidence", ""),
        )
        for r in d.get("regulatory_applicabilities", [])
    ]

    forecasts = []
    for f in d.get("forecasts", []):
        if f.get("withheld"):
            forecasts.append(WithheldForecast(topic=f["topic"], reason=f.get("reason", "")))
        else:
            forecasts.append(Forecast(
                judgment=f["judgment"], time_horizon=f.get("time_horizon", ""),
                supporting_observation_claim_ids=tuple(f.get("supporting_observation_claim_ids", [])),
                confidence=f.get("confidence", ""), confidence_rationale=f.get("confidence_rationale", ""),
            ))

    hypothesis_sets = [
        HypothesisSet(question=hs["question"], hypotheses=tuple(
            Hypothesis(h["hypothesis_id"], h["label"], h["statement"],
                       supporting_evidence_claim_ids=tuple(h.get("supporting_evidence_claim_ids", [])),
                       contradicting_evidence_claim_ids=tuple(h.get("contradicting_evidence_claim_ids", [])),
                       confidence=h.get("confidence", ""), collection_requirement=h.get("collection_requirement", ""))
            for h in hs.get("hypotheses", [])
        ))
        for hs in d.get("hypothesis_sets", [])
    ]

    intelligence_gaps = [
        IntelligenceGap(description=g["description"], category=g.get("category", "KNOWN_UNKNOWN"),
                        what_would_confirm_or_refute=g.get("what_would_confirm_or_refute", ""))
        for g in d.get("intelligence_gaps", [])
    ]

    review = None
    r = d.get("review")
    if r:
        review = ReviewRecord(
            report_id=r["report_id"], artifact_sha256=r["artifact_sha256"],
            reviewer_identity=r["reviewer_identity"], review_timestamp=r["review_timestamp"],
            decision=ReviewDecision(r["decision"]), review_version=r.get("review_version", 1),
            notes=r.get("notes", ""), is_test_only_fixture=r.get("is_test_only_fixture", False),
        )

    depth = None
    da = d.get("depth_assessment")
    if da:
        depth = DepthAssessment(
            rendered_word_count=da.get("rendered_word_count", 0),
            material_claim_count=da.get("material_claim_count", 0),
            distinct_evidence_backed_sections=da.get("distinct_evidence_backed_sections", 0),
        )

    return ReportBundle(
        report_id=d["report_id"], graph=graph, rendered_text=d.get("rendered_text", ""),
        dimension_tags=d.get("dimension_tags", {}), claim_sections=d.get("claim_sections", {}),
        detection_rules=detection_rules, metrics_registry=metrics_registry,
        cited_metric_ids=d.get("cited_metric_ids", []), rendered_metric_ids=d.get("rendered_metric_ids", []),
        regulatory_applicabilities=regulatory, forecasts=forecasts, hypothesis_sets=hypothesis_sets,
        intelligence_gaps=intelligence_gaps, review=review, is_premium_tier=d.get("is_premium_tier", False),
        depth_assessment=depth,
        technical_recommendation_count=d.get("technical_recommendation_count", 0),
        technical_recommendations_with_evidence_basis=d.get("technical_recommendations_with_evidence_basis", 0),
    )


def run_gate_on_file(path: str, as_of: date | None = None) -> tuple[str, str]:
    """Returns (markdown_report, json_report) for CLI use."""
    with open(path, encoding="utf-8") as fh:
        bundle = bundle_from_dict(json.load(fh))
    results = evaluate_commercial_readiness(bundle, as_of=as_of)
    markdown = render_matrix_report(results)
    as_json = json.dumps([r.to_dict() for r in results], indent=2)
    return markdown, as_json
