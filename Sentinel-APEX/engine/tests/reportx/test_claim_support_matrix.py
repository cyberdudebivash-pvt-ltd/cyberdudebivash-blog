from sentinel_engine.reportx.claim_model import Claim, ClaimType, EpistemicState, EvidenceGraph, SourceRecord, SourceRole, SourceType
from sentinel_engine.reportx.claim_support_matrix import (
    build_claim_support_matrix,
    evaluate_claim_support_gate,
    render_matrix_markdown,
)


def _graph_with_source():
    graph = EvidenceGraph()
    graph.add_source(SourceRecord(
        source_id="s1", url="https://example.com", publisher="Example",
        source_type=SourceType.JOURNALISM, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-18T00:00:00Z",
    ))
    return graph


class TestGateCatchesUnsupportedMaterialClaims:
    def test_confirmed_claim_with_no_evidence_flagged_material(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x", status=EpistemicState.CONFIRMED))
        result = evaluate_claim_support_gate(graph)
        assert "c1" in result.material_claims_without_evidence
        assert not result.passed

    def test_claim_with_source_ref_passes(self):
        graph = _graph_with_source()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x",
                               status=EpistemicState.REPORTED, source_refs=["s1"]))
        result = evaluate_claim_support_gate(graph)
        assert result.material_claims_without_evidence == []
        assert result.passed

    def test_not_assessed_claim_never_flagged_even_without_evidence(self):
        # An honest gap declaration is not a defect.
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.DATA_THEFT, text="unknown",
                               status=EpistemicState.NOT_ASSESSED))
        result = evaluate_claim_support_gate(graph)
        assert result.material_claims_without_evidence == []
        assert result.passed

    def test_hypothesis_claim_never_flagged(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.ACTOR_ATTRIBUTION, text="maybe",
                               status=EpistemicState.HYPOTHESIS))
        result = evaluate_claim_support_gate(graph)
        assert result.material_claims_without_evidence == []

    def test_generic_guidance_never_counted_as_material(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.GENERIC_GUIDANCE, text="use MFA",
                               status=EpistemicState.CONFIRMED))
        result = evaluate_claim_support_gate(graph)
        assert result.material_claims_without_evidence == []


class TestSpecificHighRiskCategories:
    def test_statistic_without_citation_flagged_in_its_own_bucket(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.STATISTIC, text="avg cost $X",
                               status=EpistemicState.REPORTED))
        result = evaluate_claim_support_gate(graph)
        assert result.quantitative_claims_without_citation == ["c1"]

    def test_actor_attribution_without_evidence_flagged(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.ACTOR_ATTRIBUTION, text="Qilin",
                               status=EpistemicState.ASSESSED))
        result = evaluate_claim_support_gate(graph)
        assert result.actor_attribution_without_evidence == ["c1"]

    def test_victim_impact_without_evidence_flagged(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.BUSINESS_IMPACT, text="halted ops",
                               status=EpistemicState.REPORTED))
        result = evaluate_claim_support_gate(graph)
        assert result.victim_impact_without_evidence == ["c1"]

    def test_observed_ttp_without_evidence_flagged(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.TTP_OBSERVED, text="T1486 used",
                               status=EpistemicState.REPORTED))
        result = evaluate_claim_support_gate(graph)
        assert result.observed_ttp_without_evidence == ["c1"]

    def test_fully_supported_report_passes_every_bucket(self):
        graph = _graph_with_source()
        for i, ctype in enumerate([ClaimType.STATISTIC, ClaimType.ACTOR_ATTRIBUTION,
                                    ClaimType.BUSINESS_IMPACT, ClaimType.TTP_OBSERVED]):
            graph.add_claim(Claim(claim_id=f"c{i}", claim_type=ctype, text="x",
                                   status=EpistemicState.REPORTED, source_refs=["s1"]))
        result = evaluate_claim_support_gate(graph)
        assert result.passed


class TestMatrixRendering:
    def test_matrix_rows_stable_order(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="b", claim_type=ClaimType.STATISTIC, text="x"))
        graph.add_claim(Claim(claim_id="a", claim_type=ClaimType.STATISTIC, text="y"))
        rows = build_claim_support_matrix(graph)
        assert [r.claim_id for r in rows] == ["a", "b"]

    def test_section_label_falls_back_to_unspecified(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="a", claim_type=ClaimType.STATISTIC, text="x"))
        rows = build_claim_support_matrix(graph)
        assert rows[0].section == "UNSPECIFIED"

    def test_section_label_respects_mapping(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="a", claim_type=ClaimType.STATISTIC, text="x"))
        rows = build_claim_support_matrix(graph, claim_sections={"a": "Business Impact"})
        assert rows[0].section == "Business Impact"

    def test_render_markdown_produces_a_table(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="a", claim_type=ClaimType.STATISTIC, text="x"))
        rows = build_claim_support_matrix(graph)
        md = render_matrix_markdown(rows)
        assert md.startswith("| Claim |")
        assert "| a |" in md
