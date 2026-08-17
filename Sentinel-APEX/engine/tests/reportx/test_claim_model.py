import pytest

from sentinel_engine.models import Confidence
from sentinel_engine.reportx.claim_model import (
    Claim,
    ClaimType,
    CorroborationState,
    EpistemicState,
    EvidenceGraph,
    EvidenceRecord,
    ObservedVsContext,
    Reliability,
    SourceRecord,
    SourceRole,
    SourceType,
    TemporalPrecision,
    infer_temporal_precision,
)


def _source(source_id="s1", **kw):
    defaults = dict(
        url="https://example.com/a",
        publisher="Example Publisher",
        source_type=SourceType.JOURNALISM,
        source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-18T12:00:00Z",
    )
    defaults.update(kw)
    return SourceRecord(source_id=source_id, **defaults)


class TestTemporalPrecision:
    def test_date_only_not_upgraded_to_exact_timestamp(self):
        # Section 4's explicit example: a source date of "2026-08-18" must
        # never be represented as a fabricated midnight timestamp.
        assert infer_temporal_precision("2026-08-18") == TemporalPrecision.DATE_ONLY

    def test_exact_timestamp_detected(self):
        assert infer_temporal_precision("2026-08-18T14:30:00Z") == TemporalPrecision.EXACT_TIMESTAMP

    def test_month_only_detected(self):
        assert infer_temporal_precision("2026-08") == TemporalPrecision.MONTH_ONLY

    def test_year_only_detected(self):
        assert infer_temporal_precision("2026") == TemporalPrecision.YEAR_ONLY

    def test_none_is_unknown(self):
        assert infer_temporal_precision(None) == TemporalPrecision.UNKNOWN
        assert infer_temporal_precision("") == TemporalPrecision.UNKNOWN

    def test_garbage_is_unknown_not_fabricated(self):
        assert infer_temporal_precision("sometime last week") == TemporalPrecision.UNKNOWN

    def test_source_record_auto_classifies_from_source_date(self):
        src = _source(source_date="2026-08-18")
        assert src.temporal_precision == TemporalPrecision.DATE_ONLY

    def test_source_record_respects_explicit_precision_override(self):
        # Caller explicitly says UNKNOWN even though the string looks like a
        # date -- e.g. the date came from a different field with different
        # semantics. __post_init__ must not clobber an explicit non-default.
        src = _source(source_date="2026-08-18", temporal_precision=TemporalPrecision.EXACT_TIMESTAMP)
        assert src.temporal_precision == TemporalPrecision.EXACT_TIMESTAMP


class TestEvidenceGraphIntegrity:
    def test_evidence_must_reference_known_source(self):
        graph = EvidenceGraph()
        with pytest.raises(ValueError, match="unknown source_id"):
            graph.add_evidence(EvidenceRecord(evidence_id="e1", source_id="nonexistent", excerpt="x"))

    def test_claim_must_reference_known_evidence(self):
        graph = EvidenceGraph()
        graph.add_source(_source())
        with pytest.raises(ValueError, match="unknown evidence_id"):
            graph.add_claim(Claim(
                claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x",
                evidence_refs=["nonexistent"],
            ))

    def test_claim_must_reference_known_source(self):
        graph = EvidenceGraph()
        with pytest.raises(ValueError, match="unknown source_id"):
            graph.add_claim(Claim(
                claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x",
                source_refs=["nonexistent"],
            ))

    def test_valid_graph_round_trip(self):
        graph = EvidenceGraph()
        graph.add_source(_source())
        graph.add_evidence(EvidenceRecord(evidence_id="e1", source_id="s1", excerpt="quote"))
        claim = graph.add_claim(Claim(
            claim_id="c1", claim_type=ClaimType.VICTIM_IDENTITY, text="x",
            evidence_refs=["e1"], source_refs=["s1"],
        ))
        assert graph.claims["c1"] is claim
        d = graph.to_dict()
        assert d["claims"]["c1"]["claim_type"] == "VICTIM_IDENTITY"


class TestCorroborationComputation:
    def test_no_sources_is_uncorroborated(self):
        graph = EvidenceGraph()
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.GENERIC_GUIDANCE, text="x"))
        assert graph.recompute_corroboration("c1") == CorroborationState.UNCORROBORATED

    def test_one_source_is_single_source(self):
        graph = EvidenceGraph()
        graph.add_source(_source("s1"))
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.EXPLOITATION, text="x", source_refs=["s1"]))
        assert graph.recompute_corroboration("c1") == CorroborationState.SINGLE_SOURCE

    def test_two_independent_sources_is_multi_independent(self):
        graph = EvidenceGraph()
        graph.add_source(_source("s1", independence_group="pub-a"))
        graph.add_source(_source("s2", independence_group="pub-b"))
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.EXPLOITATION, text="x", source_refs=["s1", "s2"]))
        state = graph.recompute_corroboration("c1")
        assert state == CorroborationState.MULTI_SOURCE_INDEPENDENT
        assert graph.claims["c1"].source_independence is True

    def test_two_sources_same_independence_group_is_dependent_not_independent(self):
        # Section 10: a syndicated wire story republished by 3 outlets is
        # still ONE source's claim, not three independent confirmations.
        graph = EvidenceGraph()
        graph.add_source(_source("s1", independence_group="wire-service-x"))
        graph.add_source(_source("s2", independence_group="wire-service-x"))
        graph.add_claim(Claim(claim_id="c1", claim_type=ClaimType.EXPLOITATION, text="x", source_refs=["s1", "s2"]))
        state = graph.recompute_corroboration("c1")
        assert state == CorroborationState.MULTI_SOURCE_DEPENDENT
        assert graph.claims["c1"].source_independence is False


class TestHighImpactCorroborationPolicy:
    def test_exploitation_claim_single_source_cannot_stand_as_confirmed(self):
        claim = Claim(
            claim_id="c1", claim_type=ClaimType.EXPLOITATION, text="x",
            status=EpistemicState.CONFIRMED, corroboration_state=CorroborationState.SINGLE_SOURCE,
        )
        assert claim.requires_downgrade_without_corroboration() is True

    def test_exploitation_claim_reported_is_fine_single_source(self):
        claim = Claim(
            claim_id="c1", claim_type=ClaimType.EXPLOITATION, text="x",
            status=EpistemicState.REPORTED, corroboration_state=CorroborationState.SINGLE_SOURCE,
        )
        assert claim.requires_downgrade_without_corroboration() is False

    def test_generic_guidance_never_needs_downgrade(self):
        # Not a high-impact claim type -- the corroboration policy doesn't
        # apply to it at all.
        claim = Claim(
            claim_id="c1", claim_type=ClaimType.GENERIC_GUIDANCE, text="x",
            status=EpistemicState.CONFIRMED, corroboration_state=CorroborationState.SINGLE_SOURCE,
        )
        assert claim.requires_downgrade_without_corroboration() is False

    def test_multi_source_independent_high_impact_confirmed_is_fine(self):
        claim = Claim(
            claim_id="c1", claim_type=ClaimType.ACTOR_ATTRIBUTION, text="x",
            status=EpistemicState.CORROBORATED, corroboration_state=CorroborationState.MULTI_SOURCE_INDEPENDENT,
        )
        assert claim.requires_downgrade_without_corroboration() is False


class TestClaimHelpers:
    def test_has_evidence_true_with_evidence_refs(self):
        assert Claim(claim_id="c1", claim_type=ClaimType.STATISTIC, text="x", evidence_refs=["e1"]).has_evidence()

    def test_has_evidence_false_when_empty(self):
        assert not Claim(claim_id="c1", claim_type=ClaimType.STATISTIC, text="x").has_evidence()

    def test_observed_vs_context_defaults_not_set(self):
        # A claim that never explicitly declares OBSERVED vs CONTEXT should
        # be visibly "not decided yet", not silently defaulted to either.
        claim = Claim(claim_id="c1", claim_type=ClaimType.TTP_HISTORICAL, text="x")
        assert claim.observed_vs_context == ObservedVsContext.NOT_SET


def test_unknown_and_not_applicable_are_distinct_values():
    # Section 3's explicit prohibition: "Do NOT overload UNKNOWN to mean
    # NOT_APPLICABLE."
    assert EpistemicState.UNKNOWN != EpistemicState.NOT_APPLICABLE
    assert EpistemicState.UNKNOWN.value != EpistemicState.NOT_APPLICABLE.value
