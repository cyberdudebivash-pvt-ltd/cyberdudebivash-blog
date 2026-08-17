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

from .analytic_scaffolding import Hypothesis, HypothesisSet, IntelligenceGap, NotApplicableHypothesisSet
from .claim_model import Claim, ClaimType, CorroborationState, EpistemicState, EvidenceGraph, EvidenceRecord, ObservedVsContext, Reliability, SourceRecord, SourceRole, SourceType, TemporalPrecision
from .commercial_readiness import ReportBundle, evaluate_commercial_readiness, render_matrix_report
from .detection_validation import DetectionRule, DetectionValidationState
from .forecast import Forecast, WithheldForecast
from .human_review import ReviewDecision, ReviewRecord
from .metrics_registry import ExternalMetric, MetricsRegistry
from .product_depth import DepthAssessment
from .regulatory import ApplicabilityState, RegulatoryApplicability
from .threat_schemas import (
    ActorHistoricalContext,
    CISAKEVRecord,
    CVERecord,
    GenericReadiness,
    LinkedVulnerability,
    RansomwareVictimClaim,
    ThreatProduct,
    VictimObservation,
)


def _enum(cls, value, default=None):
    if value is None:
        return default
    return cls(value)


# ============================================================
# threat_products (de)serialization -- closes the gap noted in
# REPORTX-ROLLOUT-RUNBOOK.md Phase 3: the golden fixtures (all
# RansomwareVictimClaim) originally had to be constructed directly in
# Python because this JSON schema didn't round-trip the threat-type-
# isolated layer at all. CVERecord/CISAKEVRecord are included for
# completeness -- ThreatProduct's own to_dict()/to_dict-shaped output is
# reused unchanged on the way OUT; these are only needed for the way IN,
# since none of those classes have a from_dict of their own.
# ============================================================

def _victim_observation_from_dict(d: dict) -> VictimObservation:
    return VictimObservation(
        group_named_by_source=d.get("group_named_by_source"), victim_name=d.get("victim_name"),
        victim_domain=d.get("victim_domain"), country=d.get("country"), sector=d.get("sector"),
        claim_date=d.get("claim_date"),
        claim_temporal_precision=_enum(TemporalPrecision, d.get("claim_temporal_precision"), TemporalPrecision.UNKNOWN),
        leak_site_claim_status=_enum(EpistemicState, d.get("leak_site_claim_status"), EpistemicState.NOT_ASSESSED),
        claimed_data_description=d.get("claimed_data_description"),
        sample_proof_status=_enum(EpistemicState, d.get("sample_proof_status"), EpistemicState.NOT_ASSESSED),
        independent_confirmation=_enum(EpistemicState, d.get("independent_confirmation"), EpistemicState.NOT_ASSESSED),
        victim_acknowledgement=_enum(EpistemicState, d.get("victim_acknowledgement"), EpistemicState.NOT_ASSESSED),
        regulator_disclosure=_enum(EpistemicState, d.get("regulator_disclosure"), EpistemicState.NOT_ASSESSED),
        source_claim_ids=d.get("source_claim_ids", []),
        observed_incident_ioc_claim_ids=d.get("observed_incident_ioc_claim_ids", []),
        observed_incident_ttp_claim_ids=d.get("observed_incident_ttp_claim_ids", []),
    )


def _actor_context_from_dict(d: dict) -> ActorHistoricalContext:
    return ActorHistoricalContext(
        actor_aliases=d.get("actor_aliases", []), raas_model_claim_ids=d.get("raas_model_claim_ids", []),
        historical_ttp_claim_ids=d.get("historical_ttp_claim_ids", []),
        historical_tooling_claim_ids=d.get("historical_tooling_claim_ids", []),
        initial_access_history_claim_ids=d.get("initial_access_history_claim_ids", []),
        infrastructure_claim_ids=d.get("infrastructure_claim_ids", []),
        affiliate_behavior_claim_ids=d.get("affiliate_behavior_claim_ids", []),
        victimology_claim_ids=d.get("victimology_claim_ids", []),
        sectors=d.get("sectors", []), geographies=d.get("geographies", []),
        campaign_history_claim_ids=d.get("campaign_history_claim_ids", []),
    )


def _generic_readiness_from_dict(d: dict) -> GenericReadiness:
    return GenericReadiness(
        immutable_backups=d.get("immutable_backups", ""), identity_hardening=d.get("identity_hardening", ""),
        segmentation=d.get("segmentation", ""), mass_encryption_detection=d.get("mass_encryption_detection", ""),
        recovery_inhibition_coverage=d.get("recovery_inhibition_coverage", ""),
        ir_preparation=d.get("ir_preparation", ""),
    )


def _cve_record_from_dict(d: dict) -> CVERecord:
    record = CVERecord(
        product_id=d["product_id"],
        cve_id=d.get("cve_id", ""), cna_or_vendor=d.get("cna_or_vendor"), product=d.get("product"),
        affected_versions=d.get("affected_versions", []), fixed_versions=d.get("fixed_versions", []),
        cwe=d.get("cwe"), cvss_v31=d.get("cvss_v31"), cvss_v31_vector=d.get("cvss_v31_vector"),
        cvss_v4=d.get("cvss_v4"), cvss_v4_vector=d.get("cvss_v4_vector"), epss_score=d.get("epss_score"),
        epss_percentile=d.get("epss_percentile"),
        kev_state=_enum(EpistemicState, d.get("kev_state"), EpistemicState.NOT_ASSESSED),
        kev_date=d.get("kev_date"), kev_remediation_deadline=d.get("kev_remediation_deadline"),
        root_cause=d.get("root_cause"), exploit_prerequisites=d.get("exploit_prerequisites", []),
        attack_vector=d.get("attack_vector"), privileges_required=d.get("privileges_required"),
        user_interaction=d.get("user_interaction"), exploit_chain_claim_ids=d.get("exploit_chain_claim_ids", []),
        poc_status=_enum(EpistemicState, d.get("poc_status"), EpistemicState.NOT_ASSESSED),
        weaponization_status=_enum(EpistemicState, d.get("weaponization_status"), EpistemicState.NOT_ASSESSED),
        confirmed_exploitation_status=_enum(EpistemicState, d.get("confirmed_exploitation_status"), EpistemicState.NOT_ASSESSED),
        observed_exploitation_source_claim_ids=d.get("observed_exploitation_source_claim_ids", []),
        internet_exposure_claim_id=d.get("internet_exposure_claim_id"),
        patch_advisory_timeline_claim_ids=d.get("patch_advisory_timeline_claim_ids", []),
        mitigation_claim_ids=d.get("mitigation_claim_ids", []),
        compensating_control_claim_ids=d.get("compensating_control_claim_ids", []),
        telemetry_notes=d.get("telemetry_notes"), detection_claim_ids=d.get("detection_claim_ids", []),
        hunting_claim_ids=d.get("hunting_claim_ids", []), attack_technique_ids=d.get("attack_technique_ids", []),
        reference_source_ids=d.get("reference_source_ids", []),
    )
    return record


def _cisa_kev_record_from_dict(d: dict) -> CISAKEVRecord:
    return CISAKEVRecord(
        product_id=d["product_id"],
        cve_id=d.get("cve_id", ""), vendor_project=d.get("vendor_project"), product=d.get("product"),
        vulnerability_name=d.get("vulnerability_name"), date_added=d.get("date_added"),
        date_added_precision=_enum(TemporalPrecision, d.get("date_added_precision"), TemporalPrecision.UNKNOWN),
        required_action=d.get("required_action"), due_date=d.get("due_date"),
        known_ransomware_campaign_use=_enum(EpistemicState, d.get("known_ransomware_campaign_use"), EpistemicState.NOT_ASSESSED),
        notes=d.get("notes"), reference_source_ids=d.get("reference_source_ids", []),
    )


def _linked_vulnerability_from_dict(d: dict) -> LinkedVulnerability:
    return LinkedVulnerability(
        cve_record=_cve_record_from_dict(d["cve_record"]), attribution_claim_id=d["attribution_claim_id"],
        attribution_status=_enum(EpistemicState, d.get("attribution_status"), EpistemicState.NOT_ASSESSED),
    )


def _threat_product_from_dict(d: dict) -> ThreatProduct:
    threat_type = d.get("threat_type")
    linked_vulnerabilities = [_linked_vulnerability_from_dict(lv) for lv in d.get("linked_vulnerabilities", [])]
    if threat_type == "RANSOMWARE_VICTIM_CLAIM":
        return RansomwareVictimClaim(
            product_id=d["product_id"], linked_vulnerabilities=linked_vulnerabilities,
            victim_observation=_victim_observation_from_dict(d.get("victim_observation", {})),
            actor_context=_actor_context_from_dict(d.get("actor_context", {})),
            generic_readiness=_generic_readiness_from_dict(d.get("generic_readiness", {})),
            cisa_kev_state=_enum(EpistemicState, d.get("cisa_kev_state"), EpistemicState.NOT_APPLICABLE),
            cvss_state=_enum(EpistemicState, d.get("cvss_state"), EpistemicState.NOT_APPLICABLE),
            patch_state=_enum(EpistemicState, d.get("patch_state"), EpistemicState.NOT_APPLICABLE),
            exploit_cve_status=_enum(EpistemicState, d.get("exploit_cve_status"), EpistemicState.NOT_APPLICABLE),
        )
    if threat_type == "CVE":
        record = _cve_record_from_dict(d)
        record.linked_vulnerabilities = linked_vulnerabilities
        return record
    if threat_type == "CISA_KEV":
        record = _cisa_kev_record_from_dict(d)
        record.linked_vulnerabilities = linked_vulnerabilities
        return record
    raise ValueError(f"Unknown or unsupported threat_type {threat_type!r} in threat_products entry {d.get('product_id')!r}")


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
            etag=s.get("etag"), last_modified=s.get("last_modified"),
            excerpt_fingerprint_sha256=s.get("excerpt_fingerprint_sha256"),
            fingerprint_fallback_reason=s.get("fingerprint_fallback_reason"),
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
                      body=r.get("body", ""), evidence_gap_rationale=r.get("evidence_gap_rationale", ""))
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

    hypothesis_sets = []
    for hs in d.get("hypothesis_sets", []):
        if hs.get("applicable") is False:
            hypothesis_sets.append(NotApplicableHypothesisSet(question=hs["question"], rationale=hs.get("rationale", "")))
        else:
            hypothesis_sets.append(HypothesisSet(question=hs["question"], hypotheses=tuple(
                Hypothesis(h["hypothesis_id"], h["label"], h["statement"],
                           supporting_evidence_claim_ids=tuple(h.get("supporting_evidence_claim_ids", [])),
                           contradicting_evidence_claim_ids=tuple(h.get("contradicting_evidence_claim_ids", [])),
                           confidence=h.get("confidence", ""), collection_requirement=h.get("collection_requirement", ""))
                for h in hs.get("hypotheses", [])
            )))

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
            reviewer_role=r.get("reviewer_role", ""), gate_snapshot_sha256=r.get("gate_snapshot_sha256", ""),
        )

    depth = None
    da = d.get("depth_assessment")
    if da:
        depth = DepthAssessment(
            rendered_word_count=da.get("rendered_word_count", 0),
            material_claim_count=da.get("material_claim_count", 0),
            distinct_evidence_backed_sections=da.get("distinct_evidence_backed_sections", 0),
        )

    threat_products = [_threat_product_from_dict(tp) for tp in d.get("threat_products", [])]

    return ReportBundle(
        report_id=d["report_id"], graph=graph, rendered_text=d.get("rendered_text", ""),
        dimension_tags=d.get("dimension_tags", {}), claim_sections=d.get("claim_sections", {}),
        detection_rules=detection_rules, metrics_registry=metrics_registry,
        cited_metric_ids=d.get("cited_metric_ids", []), rendered_metric_ids=d.get("rendered_metric_ids", []),
        regulatory_applicabilities=regulatory, forecasts=forecasts, hypothesis_sets=hypothesis_sets,
        intelligence_gaps=intelligence_gaps, threat_products=threat_products, review=review,
        is_premium_tier=d.get("is_premium_tier", False), depth_assessment=depth,
        technical_recommendation_count=d.get("technical_recommendation_count", 0),
        technical_recommendations_with_evidence_basis=d.get("technical_recommendations_with_evidence_basis", 0),
    )


# ============================================================
# Export direction (Python -> JSON), for ReportX Rollout Runbook Phase 3:
# System 5 (JS) consumes this JSON rather than re-deriving any of it.
# Reuses every dataclass's own to_dict() unchanged where one already
# exists; only DetectionRule and HypothesisSet needed a small local
# helper here, since neither owns a to_dict() itself.
# ============================================================

def _detection_rule_to_dict(rule: DetectionRule) -> dict:
    return {
        "rule_id": rule.rule_id, "technique_id": rule.technique_id, "format": rule.format,
        "validation_state": rule.validation_state.value, "body": rule.body,
    }


def _hypothesis_set_to_dict(hs) -> dict:
    if isinstance(hs, NotApplicableHypothesisSet):
        return hs.to_dict()
    return {"question": hs.question, "applicable": True, "hypotheses": [h.to_dict() for h in hs.hypotheses]}


def _forecast_to_dict(f) -> dict:
    if isinstance(f, WithheldForecast):
        return {"withheld": True, "topic": f.topic, "reason": f.reason}
    return {"withheld": False, **f.to_dict()}


def bundle_to_dict(bundle: ReportBundle) -> dict:
    """The inverse of bundle_from_dict(). Every field maps 1:1 back onto
    the JSON schema that function reads, so a bundle exported here and
    re-loaded via bundle_from_dict() round-trips losslessly for every
    field a golden fixture in this repo actually populates."""
    graph_dict = bundle.graph.to_dict()
    return {
        "report_id": bundle.report_id,
        "is_premium_tier": bundle.is_premium_tier,
        # bundle_from_dict() reads sources/evidence/claims as top-level LIST
        # fields (matching the existing hand-written JSON fixtures); graph.to_dict()
        # itself returns id-keyed dicts for O(1) lookup within the engine, so the
        # values are unwrapped into lists here to match the input schema exactly.
        "sources": list(graph_dict["sources"].values()),
        "evidence": list(graph_dict["evidence"].values()),
        "claims": list(graph_dict["claims"].values()),
        "rendered_text": bundle.rendered_text,
        "dimension_tags": bundle.dimension_tags,
        "claim_sections": bundle.claim_sections,
        "detection_rules": [_detection_rule_to_dict(r) for r in bundle.detection_rules],
        "metrics": [m.to_dict() for m in bundle.metrics_registry._metrics.values()],
        "cited_metric_ids": bundle.cited_metric_ids,
        "rendered_metric_ids": bundle.rendered_metric_ids,
        "regulatory_applicabilities": [r.to_dict() for r in bundle.regulatory_applicabilities],
        "forecasts": [_forecast_to_dict(f) for f in bundle.forecasts],
        "hypothesis_sets": [_hypothesis_set_to_dict(hs) for hs in bundle.hypothesis_sets],
        "intelligence_gaps": [g.to_dict() for g in bundle.intelligence_gaps],
        "threat_products": [tp.to_dict() for tp in bundle.threat_products],
        "review": bundle.review.to_dict() if bundle.review else None,
        "depth_assessment": bundle.depth_assessment.to_dict() if bundle.depth_assessment else None,
        "technical_recommendation_count": bundle.technical_recommendation_count,
        "technical_recommendations_with_evidence_basis": bundle.technical_recommendations_with_evidence_basis,
    }


def export_report_json(bundle: ReportBundle, as_of: date | None = None) -> dict:
    """The single self-contained artifact System 5's JS adapter reads:
    the raw validated bundle PLUS the already-computed 23-control gate
    result. System 5 reads control_results; it never recomputes them."""
    results = evaluate_commercial_readiness(bundle, as_of=as_of)
    n_pass = sum(1 for r in results if r.status == "PASS")
    return {
        "bundle": bundle_to_dict(bundle),
        "commercial_readiness": {
            "controls": [r.to_dict() for r in results],
            "pass_count": n_pass,
            "total_count": len(results),
            "verdict": "COMMERCIAL-READY" if n_pass == len(results) else "NOT COMMERCIAL-READY",
        },
    }


def run_gate_on_file(path: str, as_of: date | None = None) -> tuple[str, str]:
    """Returns (markdown_report, json_report) for CLI use."""
    with open(path, encoding="utf-8") as fh:
        bundle = bundle_from_dict(json.load(fh))
    results = evaluate_commercial_readiness(bundle, as_of=as_of)
    markdown = render_matrix_report(results)
    as_json = json.dumps([r.to_dict() for r in results], indent=2)
    return markdown, as_json
