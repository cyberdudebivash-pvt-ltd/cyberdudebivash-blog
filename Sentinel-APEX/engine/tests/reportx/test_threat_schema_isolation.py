"""Section 5 acceptance tests: 0 vulnerability-only fields leak into
ordinary ransomware claims, and 0 ransomware-only assumptions leak into
CVE reports."""

import dataclasses

from sentinel_engine.reportx.claim_model import EpistemicState
from sentinel_engine.reportx.threat_schemas import (
    CISAKEVRecord,
    CVERecord,
    GenericReadiness,
    LinkedVulnerability,
    RansomwareVictimClaim,
    ThreatType,
)


def _bare_cve_record(cve_id="CVE-2099-0001") -> CVERecord:
    return CVERecord(product_id="cve-test-1", cve_id=cve_id)


class TestRansomwareHasNoUnlinkedVulnerabilityData:
    def test_no_unattributed_ransomware_claim_carries_cvss_score_field(self):
        # The schema itself has no float cvss_score field at all -- only
        # cvss_state (an EpistemicState), which __post_init__ pins to
        # NOT_APPLICABLE absent a link. Assert both halves of that.
        field_names = {f.name for f in dataclasses.fields(RansomwareVictimClaim)}
        assert "cvss_score" not in field_names
        assert "cvss_state" in field_names

    def test_bare_ransomware_claim_defaults_all_four_markers_not_applicable(self):
        claim = RansomwareVictimClaim(product_id="rw-1")
        assert claim.cisa_kev_state == EpistemicState.NOT_APPLICABLE
        assert claim.cvss_state == EpistemicState.NOT_APPLICABLE
        assert claim.patch_state == EpistemicState.NOT_APPLICABLE
        assert claim.exploit_cve_status == EpistemicState.NOT_APPLICABLE

    def test_cannot_smuggle_positive_state_without_a_real_linked_vulnerability(self):
        # Even if a caller tries to directly construct with a non-NOT_APPLICABLE
        # state but no linked_vulnerabilities, __post_init__ must correct it.
        claim = RansomwareVictimClaim(
            product_id="rw-2",
            cisa_kev_state=EpistemicState.CONFIRMED,
            cvss_state=EpistemicState.CONFIRMED,
        )
        assert claim.cisa_kev_state == EpistemicState.NOT_APPLICABLE
        assert claim.cvss_state == EpistemicState.NOT_APPLICABLE

    def test_linking_a_real_vulnerability_is_the_only_way_markers_may_move(self):
        cve = _bare_cve_record()
        link = LinkedVulnerability(cve_record=cve, attribution_claim_id="claim-attr-1",
                                    attribution_status=EpistemicState.CORROBORATED)
        claim = RansomwareVictimClaim(
            product_id="rw-3",
            linked_vulnerabilities=[link],
            cisa_kev_state=EpistemicState.REPORTED,
        )
        # Now that a real link exists, the caller's explicit state is
        # respected -- __post_init__ only forces NOT_APPLICABLE when there
        # is NO link, it never overrides a genuinely-linked claim.
        assert claim.cisa_kev_state == EpistemicState.REPORTED
        assert claim.has_linked_vulnerability()
        assert claim.linked_vulnerabilities[0].cve_record.cve_id == "CVE-2099-0001"

    def test_ransomware_schema_has_no_top_level_vulnerability_technical_fields(self):
        # None of CVERecord's technical vocabulary (cwe, epss_score,
        # attack_vector, poc_status, ...) exists directly on
        # RansomwareVictimClaim -- it can only arrive via a real
        # LinkedVulnerability -> CVERecord.
        ransomware_fields = {f.name for f in dataclasses.fields(RansomwareVictimClaim)}
        cve_only_fields = {"cwe", "epss_score", "attack_vector", "poc_status",
                            "weaponization_status", "affected_versions", "fixed_versions"}
        assert ransomware_fields.isdisjoint(cve_only_fields)


class TestCVEHasNoRansomwareAssumptions:
    def test_cve_record_has_no_victim_fields(self):
        cve_fields = {f.name for f in dataclasses.fields(CVERecord)}
        ransomware_only_fields = {
            "victim_name", "victim_domain", "leak_site_claim_status",
            "sample_proof_status", "ransom_amount", "victim_acknowledgement",
            "actor_context", "generic_readiness", "raas_model_claim_ids",
        }
        assert cve_fields.isdisjoint(ransomware_only_fields)

    def test_cve_record_threat_type_is_fixed(self):
        record = _bare_cve_record()
        assert record.threat_type == ThreatType.CVE

    def test_cve_record_defaults_have_no_fabricated_positive_values(self):
        record = _bare_cve_record()
        assert record.kev_state == EpistemicState.NOT_ASSESSED
        assert record.cvss_v31 is None
        assert record.epss_score is None
        assert record.confirmed_exploitation_status == EpistemicState.NOT_ASSESSED

    def test_kev_record_is_distinct_type_from_cve_record(self):
        # A KEV listing is CISA's own claim about a CVE, not the CVE's
        # technical record -- collapsing them would blur "when disclosed"
        # vs "when CISA listed it" (a temporal-integrity risk).
        kev = CISAKEVRecord(product_id="kev-1", cve_id="CVE-2099-0001")
        assert kev.threat_type == ThreatType.CISA_KEV
        cve_fields = {f.name for f in dataclasses.fields(CVERecord)}
        kev_only_fields = {"date_added", "required_action", "due_date",
                            "known_ransomware_campaign_use"}
        # These KEV-specific fields must not appear directly on CVERecord --
        # a CVE can be KEV-listed only via a real CISAKEVRecord reference
        # (not modeled as a direct link this pass; flagged for a follow-up
        # if a CVE-to-KEV cross-reference becomes a concrete requirement).
        assert cve_fields.isdisjoint(kev_only_fields)


class TestGenericReadinessAlwaysLabeled:
    def test_generic_readiness_to_dict_always_carries_its_label(self):
        gr = GenericReadiness(immutable_backups="Maintain 3-2-1 backups")
        d = gr.to_dict()
        assert d["label"] == "GENERIC_DEFENSIVE_READINESS"

    def test_label_is_a_class_constant_not_settable_to_something_misleading(self):
        # There is no constructor parameter for `label` at all -- a caller
        # cannot instantiate a GenericReadiness that claims to be
        # incident-specific.
        field_names = {f.name for f in dataclasses.fields(GenericReadiness)}
        assert "label" not in field_names
        assert GenericReadiness.LABEL == "GENERIC_DEFENSIVE_READINESS"
