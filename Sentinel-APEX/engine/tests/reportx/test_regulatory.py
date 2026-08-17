import pytest

from sentinel_engine.reportx.regulatory import (
    ApplicabilityState,
    RegulatoryApplicability,
    evaluate_regulatory_gate,
    not_assessed,
)


class TestBasisRequirement:
    def test_positive_state_without_basis_raises(self):
        with pytest.raises(ValueError, match="without a stated basis"):
            RegulatoryApplicability(
                jurisdiction="EU", victim_geography="Germany", operations_geography="Germany",
                data_subject_geography="Germany", sector="Healthcare", entity_classification="Controller",
                incident_facts_claim_ids=("c1",), regulation="GDPR",
                applicability_state=ApplicabilityState.LIKELY, basis="",
            )

    def test_not_assessed_never_requires_a_basis(self):
        ra = not_assessed("NIS2", reason="")
        assert ra.applicability_state == ApplicabilityState.NOT_ASSESSED

    def test_positive_state_with_basis_constructs_fine(self):
        ra = RegulatoryApplicability(
            jurisdiction="EU", victim_geography="Germany", operations_geography="Germany",
            data_subject_geography="Germany", sector="Healthcare", entity_classification="Controller",
            incident_facts_claim_ids=("c1",), regulation="GDPR",
            applicability_state=ApplicabilityState.LIKELY,
            basis="Victim is an EU-based healthcare data controller with a confirmed data-theft claim.",
        )
        assert ra.applicability_state == ApplicabilityState.LIKELY


class TestNeverImpliesLegalConclusionFromUncertainty:
    def test_not_assessed_helper_never_asserts_applicability(self):
        ra = not_assessed("HIPAA", reason="Victim sector not established by any source.")
        assert ra.applicability_state == ApplicabilityState.NOT_ASSESSED
        gate = evaluate_regulatory_gate([ra])
        assert gate.passed


class TestGateRequiresLinkedFacts:
    def test_positive_determination_with_no_incident_facts_is_unsupported(self):
        ra = RegulatoryApplicability(
            jurisdiction="US", victim_geography="California", operations_geography="California",
            data_subject_geography="California", sector="Retail", entity_classification="Business",
            incident_facts_claim_ids=(),  # no linked facts, even though basis text was written
            regulation="CCPA", applicability_state=ApplicabilityState.POTENTIAL,
            basis="Retail sector generally triggers CCPA.",
        )
        gate = evaluate_regulatory_gate([ra])
        assert "CCPA" in gate.unsupported_determinations
        assert not gate.passed

    def test_positive_determination_with_linked_facts_passes(self):
        ra = RegulatoryApplicability(
            jurisdiction="US", victim_geography="California", operations_geography="California",
            data_subject_geography="California", sector="Retail", entity_classification="Business",
            incident_facts_claim_ids=("c-data-theft-1",),
            regulation="CCPA", applicability_state=ApplicabilityState.LIKELY,
            basis="Confirmed data theft of CA resident records from a CA-operating retailer.",
        )
        gate = evaluate_regulatory_gate([ra])
        assert gate.passed

    def test_not_applicable_never_flagged_even_without_facts(self):
        ra = RegulatoryApplicability(
            jurisdiction="", victim_geography=None, operations_geography=None,
            data_subject_geography=None, sector=None, entity_classification=None,
            incident_facts_claim_ids=(), regulation="GDPR",
            applicability_state=ApplicabilityState.NOT_APPLICABLE,
            basis="Victim operates and holds data exclusively in the US with no EU nexus.",
        )
        gate = evaluate_regulatory_gate([ra])
        assert gate.passed
