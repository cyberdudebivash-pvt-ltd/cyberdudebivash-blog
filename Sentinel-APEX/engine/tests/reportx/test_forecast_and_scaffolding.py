from sentinel_engine.reportx.analytic_scaffolding import (
    BibliographyEntry,
    Hypothesis,
    HypothesisSet,
    IntelligenceGap,
    build_bibliography,
    derive_ransomware_gaps,
    find_orphan_citations,
)
from sentinel_engine.reportx.claim_model import (
    Claim,
    ClaimType,
    EpistemicState,
    EvidenceGraph,
    SourceRecord,
    SourceRole,
    SourceType,
)
from sentinel_engine.reportx.forecast import Forecast, WithheldForecast, evaluate_forecast_gate
from sentinel_engine.reportx.threat_schemas import VictimObservation


class TestForecastGate:
    def test_forecast_with_observations_and_rationale_is_supported(self):
        f = Forecast(
            judgment="Campaign likely continues targeting the same sector.",
            time_horizon="30 days",
            supporting_observation_claim_ids=("c1", "c2"),
            confidence="MEDIUM",
            confidence_rationale="Based on 2 corroborated prior campaign observations in the same sector.",
        )
        assert f.is_adequately_supported()

    def test_forecast_with_confidence_but_no_observations_is_unsupported(self):
        # The exact defect Section 16 names: confidence assigned "because
        # the template says so", nothing behind it.
        f = Forecast(
            judgment="Campaign continuation (HIGH CONFIDENCE)",
            time_horizon="30 days",
            supporting_observation_claim_ids=(),
            confidence="HIGH",
            confidence_rationale="",
        )
        assert not f.is_adequately_supported()
        result = evaluate_forecast_gate([f])
        assert not result.passed
        assert f.judgment in result.unsupported_forecasts

    def test_withheld_forecast_never_fails_the_gate(self):
        w = WithheldForecast(topic="6-month campaign trajectory", reason="Insufficient historical baseline.")
        result = evaluate_forecast_gate([w])
        assert result.passed


class TestAlternativeHypotheses:
    def test_well_formed_set_requires_at_least_two_with_evidence(self):
        hs = HypothesisSet(
            question="Does the leak-site claim represent genuine compromise?",
            hypotheses=(
                Hypothesis("h1", "H1", "Genuine compromise.", supporting_evidence_claim_ids=("c1",)),
                Hypothesis("h2", "H2", "Recycled/mislabeled claim.", contradicting_evidence_claim_ids=("c2",)),
            ),
        )
        assert hs.is_well_formed()

    def test_single_hypothesis_not_well_formed(self):
        hs = HypothesisSet(
            question="x",
            hypotheses=(Hypothesis("h1", "H1", "x", supporting_evidence_claim_ids=("c1",)),),
        )
        assert not hs.is_well_formed()

    def test_hypothesis_with_no_evidence_either_side_not_well_formed(self):
        hs = HypothesisSet(
            question="x",
            hypotheses=(
                Hypothesis("h1", "H1", "x", supporting_evidence_claim_ids=("c1",)),
                Hypothesis("h2", "H2", "y"),  # no evidence at all
            ),
        )
        assert not hs.is_well_formed()


class TestIntelligenceGaps:
    def test_derive_ransomware_gaps_flags_missing_acknowledgement(self):
        vo = VictimObservation(victim_acknowledgement=EpistemicState.NOT_ASSESSED)
        gaps = derive_ransomware_gaps(vo)
        assert any("acknowledgement" in g.description.lower() for g in gaps)

    def test_derive_ransomware_gaps_flags_missing_iocs(self):
        vo = VictimObservation(observed_incident_ioc_claim_ids=[])
        gaps = derive_ransomware_gaps(vo)
        assert any("IOC" in g.description for g in gaps)

    def test_fully_evidenced_victim_observation_produces_fewer_gaps(self):
        vo = VictimObservation(
            victim_acknowledgement=EpistemicState.CONFIRMED,
            observed_incident_ioc_claim_ids=["c1"],
            sample_proof_status=EpistemicState.CONFIRMED,
            independent_confirmation=EpistemicState.CORROBORATED,
            observed_incident_ttp_claim_ids=["c2"],
        )
        gaps = derive_ransomware_gaps(vo)
        assert gaps == []


class TestBibliography:
    def _graph(self):
        graph = EvidenceGraph()
        graph.add_source(SourceRecord(
            source_id="s1", url="https://example.com", publisher="Example",
            source_type=SourceType.JOURNALISM, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
            retrieved_at="2026-08-18T00:00:00Z",
        ))
        graph.add_source(SourceRecord(
            source_id="s2", url="https://unused.example.com", publisher="Unused",
            source_type=SourceType.OTHER, source_role=SourceRole.CORROBORATION,
            retrieved_at="2026-08-18T00:00:00Z",
        ))
        return graph

    def test_bibliography_includes_only_cited_sources(self):
        graph = self._graph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x", source_refs=["s1"]))
        entries = build_bibliography(graph)
        assert [e.source_id for e in entries] == ["s1"]

    def test_orphan_citation_detected_for_unused_source(self):
        graph = self._graph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x", source_refs=["s1"]))
        orphans = find_orphan_citations(graph)
        assert orphans == ["s2"]

    def test_no_orphans_when_every_source_is_cited(self):
        graph = self._graph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x", source_refs=["s1", "s2"]))
        assert find_orphan_citations(graph) == []
