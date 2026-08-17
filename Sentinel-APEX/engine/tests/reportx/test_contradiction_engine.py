from sentinel_engine.reportx.claim_model import Claim, ClaimType, EpistemicState, EvidenceGraph
from sentinel_engine.reportx.contradiction_engine import (
    find_all_contradictions,
    find_dimension_contradictions,
    find_text_contradictions,
)


class TestTextContradictions:
    """The task's own three motivating examples, as regression tests."""

    def test_no_ttps_vs_attribution_based_on_ttps_flagged(self):
        text = (
            "Assessment: no validated actor-specific TTPs were identified in this incident.\n"
            "...\n"
            "Actor attribution is based on TTPs from the source reporting."
        )
        findings = find_text_contradictions(text)
        assert any("TTPs" in f.description for f in findings)

    def test_withheld_detection_vs_push_immediately_flagged(self):
        text = (
            "DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE\n"
            "...\n"
            "MSSP guidance: push actor detection rules covering T1486 immediately."
        )
        findings = find_text_contradictions(text)
        assert any("WITHHELD_INSUFFICIENT_EVIDENCE" in f.description for f in findings)

    def test_experimental_vs_production_validated_detection_flagged(self):
        text = (
            "The Sigma rule is currently experimental detection, pending telemetry validation.\n"
            "...\n"
            "This is a production-validated detection ready for SOC deployment."
        )
        findings = find_text_contradictions(text)
        assert any("experimental" in f.description for f in findings)

    def test_no_contradiction_when_only_one_side_present(self):
        text = "DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE. No further guidance issued yet."
        assert find_text_contradictions(text) == []

    def test_clean_consistent_text_has_zero_contradictions(self):
        text = (
            "DETECTION STATUS: SYNTAX_VALIDATED. Detection is experimental and "
            "has not yet been validated against production telemetry; do not "
            "push to production SIEM until telemetry validation completes."
        )
        assert find_text_contradictions(text) == []


class TestDimensionContradictions:
    def _graph_with_two_claims(self, status_a, status_b):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="a", claim_type=ClaimType.VULNERABILITY_FACT, text="x", status=status_a))
        graph.add_claim(Claim(claim_id="b", claim_type=ClaimType.VULNERABILITY_FACT, text="y", status=status_b))
        return graph

    def test_confirmed_vs_not_applicable_same_dimension_flagged(self):
        graph = self._graph_with_two_claims(EpistemicState.CONFIRMED, EpistemicState.NOT_APPLICABLE)
        findings = find_dimension_contradictions(graph, {"kev_state": ["a", "b"]})
        assert len(findings) == 1
        assert findings[0].dimension == "kev_state"
        assert {findings[0].claim_id_a, findings[0].claim_id_b} == {"a", "b"}

    def test_confirmed_vs_reported_same_dimension_not_flagged(self):
        # REPORTED is a weaker claim, not a directly opposed one -- this is
        # normal evidentiary variance, not a contradiction.
        graph = self._graph_with_two_claims(EpistemicState.CONFIRMED, EpistemicState.REPORTED)
        assert find_dimension_contradictions(graph, {"kev_state": ["a", "b"]}) == []

    def test_disputed_state_never_self_flagged(self):
        # DISPUTED is the correct representation of a genuine source-level
        # conflict -- the checker must not double-flag it as an engine defect.
        graph = self._graph_with_two_claims(EpistemicState.DISPUTED, EpistemicState.DISPUTED)
        assert find_dimension_contradictions(graph, {"actor_identity": ["a", "b"]}) == []

    def test_claims_in_different_dimensions_never_compared(self):
        graph = self._graph_with_two_claims(EpistemicState.CONFIRMED, EpistemicState.NOT_APPLICABLE)
        findings = find_dimension_contradictions(graph, {"kev_state": ["a"], "patch_state": ["b"]})
        assert findings == []


def test_find_all_contradictions_combines_both_layers():
    graph = EvidenceGraph()
    graph.add_claim(Claim(claim_id="a", claim_type=ClaimType.VULNERABILITY_FACT, text="x", status=EpistemicState.CONFIRMED))
    graph.add_claim(Claim(claim_id="b", claim_type=ClaimType.VULNERABILITY_FACT, text="y", status=EpistemicState.NOT_APPLICABLE))
    text = "DETECTION STATUS: WITHHELD_INSUFFICIENT_EVIDENCE ... push actor detection rules immediately"
    findings = find_all_contradictions(graph, {"kev_state": ["a", "b"]}, full_text=text)
    dims = {f.dimension for f in findings}
    assert "kev_state" in dims
    assert "text-pattern" in dims
    assert len(findings) == 2
