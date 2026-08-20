"""Tests for sentinel_engine.reportx.attack_mapping -- the structured,
evidence-anchored ATT&CK mapping object (RX-P1I, Phase 1I remainder).

Every fixture goes through the real, unmocked lower-level pieces
(build_report_context, build_evidence_graph, _detection_package) rather
than a synthetic EvidenceGraph, so these tests exercise the actual wiring
build_attack_mappings() depends on, not an idealized stand-in for it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from automation.content_discovery import DiscoveredArticle
from automation.report_integrity import build_report_context
from automation.report_renderer import _detection_package

from sentinel_engine.reportx.attack_mapping import (
    AttackMapping,
    AttackMappingStatus,
    AttackValidationStatus,
    _apply_semantic_gate,
    build_attack_mappings,
)
from sentinel_engine.reportx.discovery_bridge import build_evidence_graph


def _cve_article(**overrides) -> DiscoveredArticle:
    defaults = dict(
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-11111",
        title="CVE-2026-11111 test vulnerability",
        summary="A SQL injection vulnerability in the login form allows authentication bypass.",
        published_at="2026-08-20T00:00:00Z", content_hash="attackmap1",
        labels=["Vulnerabilities"], source="nvd", cve_id="CVE-2026-11111",
        cvss_score=8.2, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", cwe_ids=["CWE-89"],
        kev_listed=False,
    )
    defaults.update(overrides)
    return DiscoveredArticle(**defaults)


def _mappings_for(article: DiscoveredArticle) -> list[AttackMapping]:
    context = build_report_context(article)
    graph = build_evidence_graph(article, context)
    package = _detection_package(article, context)
    return build_attack_mappings(article, context, graph, package)


class TestRealVulnerabilityClassMappingBecomesConditional:
    def test_sql_injection_cve_yields_a_conditional_technique_id_mapping(self):
        mappings = _mappings_for(_cve_article())
        assert any(m.technique_id == "T1190" for m in mappings)
        t1190 = next(m for m in mappings if m.technique_id == "T1190")
        assert t1190.status == AttackMappingStatus.CONDITIONAL
        assert t1190.behavioral_basis
        assert t1190.reasoning
        assert t1190.claim_refs or t1190.evidence_refs or t1190.source_refs

    def test_cve_claim_refs_point_at_real_cve_claims(self):
        mappings = _mappings_for(_cve_article())
        t1190 = next(m for m in mappings if m.technique_id == "T1190")
        assert "c-cve-id" in t1190.claim_refs or "c-exploitation-status" in t1190.claim_refs


class TestTextEvidenceMappingSurfacesBeyondTheSingleVulnerabilityClassBranch:
    """The vulnerability-class branch only ever yields ONE technique --
    map_techniques() run over the full article text can surface real
    additional signal the narrow branch never catches."""

    def test_explicit_technique_id_citation_becomes_assessed(self):
        # T1057 (Process Discovery) has no phrase-lexicon pattern in
        # attack_mapper.py at all -- the ONLY way map_techniques() can
        # surface it is the explicit-citation path, so this isolates that
        # path cleanly (a technique phrase-matched AND cited explicitly
        # keeps its phrase-match confidence -- attack_mapper.py's own,
        # pre-existing "first match wins" behavior, not something to
        # re-verify here).
        article = _cve_article(
            summary="A SQL injection vulnerability allows authentication bypass. The attacker chain "
                     "documented in this report matches MITRE technique T1057.",
        )
        mappings = _mappings_for(article)
        t1057 = next((m for m in mappings if m.technique_id == "T1057"), None)
        assert t1057 is not None
        assert t1057.status == AttackMappingStatus.ASSESSED
        assert t1057.confidence == "HIGH"

    def test_high_confidence_phrase_match_becomes_assessed(self):
        article = _cve_article(
            summary="A SQL injection vulnerability allows authentication bypass. Post-exploitation, "
                     "the actor used mimikatz to dump credentials from LSASS memory.",
        )
        mappings = _mappings_for(article)
        t1003 = next((m for m in mappings if m.technique_id == "T1003.001"), None)
        assert t1003 is not None
        assert t1003.status == AttackMappingStatus.ASSESSED

    def test_medium_confidence_phrase_match_stays_conditional(self):
        article = _cve_article(
            summary="A SQL injection vulnerability allows authentication bypass, potentially enabling "
                     "lateral movement across the network.",
        )
        mappings = _mappings_for(article)
        t1021 = next((m for m in mappings if m.technique_id == "T1021"), None)
        assert t1021 is not None
        assert t1021.status == AttackMappingStatus.CONDITIONAL

    def test_a_technique_already_covered_by_the_vulnerability_class_branch_is_never_duplicated(self):
        mappings = _mappings_for(_cve_article())
        ids = [m.technique_id for m in mappings]
        assert len(ids) == len(set(ids))


class TestAdversarialNegationHandling:
    def test_negated_phrase_never_produces_a_mapping(self):
        article = _cve_article(
            summary="A SQL injection vulnerability allows authentication bypass. There is no evidence "
                     "the actor has deployed ransomware or encrypted any files.",
        )
        mappings = _mappings_for(article)
        assert not any(m.technique_id == "T1486" for m in mappings)

    def test_negated_explicit_technique_citation_never_produces_a_mapping(self):
        article = _cve_article(
            summary="A SQL injection vulnerability allows authentication bypass. T1486 (ransomware "
                     "impact) was considered and rejected as a possible outcome of this vulnerability.",
        )
        mappings = _mappings_for(article)
        assert not any(m.technique_id == "T1486" for m in mappings)


class TestMultiTacticSupport:
    """Mandate Section 4: real ATT&CK legitimately assigns T1053/T1053.005
    to Execution, Persistence, AND Privilege Escalation -- must not be
    hardcoded to a single tactic."""

    def test_t1053_005_carries_all_three_real_tactics(self):
        article = _cve_article(
            summary="A SQL injection vulnerability allows authentication bypass. The actor then "
                     "established persistence using scheduled tasks.",
        )
        mappings = _mappings_for(article)
        t1053 = next((m for m in mappings if m.technique_id == "T1053.005"), None)
        assert t1053 is not None
        assert set(t1053.tactics) == {"execution", "persistence", "privilege-escalation"}

    def test_a_single_tactic_technique_still_carries_exactly_one(self):
        mappings = _mappings_for(_cve_article())
        t1190 = next(m for m in mappings if m.technique_id == "T1190")
        assert t1190.tactics == ("initial-access",)


class TestSemanticGateRejectsInvalidCandidates:
    """Mandate Section 5: constructs deliberately-invalid AttackMapping
    candidates directly (bypassing build_attack_mappings()'s own
    construction) to prove _apply_semantic_gate() itself rejects each
    defect class, independent of whether the real construction path
    happens to ever produce one."""

    def _valid_mapping(self, **overrides) -> AttackMapping:
        defaults = dict(
            attack_mapping_id="test-1", technique_id="T1190", technique_name="Exploit Public-Facing Application",
            tactics=("initial-access",), status=AttackMappingStatus.CONDITIONAL,
            claim_refs=("c-summary",), behavioral_basis="test basis", reasoning="test reasoning",
        )
        defaults.update(overrides)
        return AttackMapping(**defaults)

    def test_unknown_technique_id_is_rejected(self):
        bad = self._valid_mapping(technique_id="T9999", technique_name="Not A Real Technique")
        assert _apply_semantic_gate([bad]) == []

    def test_technique_name_mismatch_is_rejected(self):
        bad = self._valid_mapping(technique_name="Wrong Name Entirely")
        assert _apply_semantic_gate([bad]) == []

    def test_tactic_not_in_registry_is_rejected(self):
        bad = self._valid_mapping(tactics=("made-up-tactic",))
        assert _apply_semantic_gate([bad]) == []

    def test_a_real_primary_tactic_plus_a_fabricated_extra_tactic_is_rejected(self):
        # Regression: the gate used to check "is the canonical primary
        # tactic present somewhere in m.tactics", which a candidate could
        # satisfy while also carrying an invented tactic alongside the real
        # one -- e.g. ("initial-access", "invented-tactic") for T1190 has
        # its real primary tactic present, so the old check wrongly passed
        # it. The gate must require exact equality with tactics_for(), not
        # mere membership.
        bad = self._valid_mapping(tactics=("initial-access", "invented-tactic"))
        assert _apply_semantic_gate([bad]) == []

    def test_missing_a_required_tactic_is_rejected(self):
        # T1053/T1053.005 legitimately carry 3 tactics -- a candidate
        # claiming only 1 of them is incomplete, not merely different.
        bad = self._valid_mapping(
            technique_id="T1053.005", technique_name="Scheduled Task", tactics=("persistence",),
        )
        assert _apply_semantic_gate([bad]) == []

    def test_reordered_tactics_for_a_multi_tactic_technique_is_rejected(self):
        # The check is tuple equality (==), which is order-sensitive --
        # tactics_for() always returns one canonical order and every real
        # candidate is constructed directly from it (never hand-ordered),
        # so a reordered tuple can only be a tampered or hand-built one;
        # rejecting it (not just a different element set) is intentional.
        from sentinel_engine.attack_mapper import tactics_for
        canonical = tactics_for("T1053.005")
        reordered = tuple(reversed(canonical))
        assert reordered != canonical  # sanity: T1053.005 has >1 tactic, so this really differs
        bad = self._valid_mapping(technique_id="T1053.005", technique_name="Scheduled Task", tactics=reordered)
        assert _apply_semantic_gate([bad]) == []

    def test_empty_behavioral_basis_is_rejected(self):
        bad = self._valid_mapping(behavioral_basis="")
        assert _apply_semantic_gate([bad]) == []

    def test_no_evidence_claim_or_source_refs_is_rejected(self):
        bad = self._valid_mapping(claim_refs=(), evidence_refs=(), source_refs=())
        assert _apply_semantic_gate([bad]) == []

    def test_observed_status_is_always_rejected(self):
        # This pipeline never has customer telemetry -- OBSERVED is
        # structurally disallowed regardless of how well-evidenced the
        # rest of the candidate is.
        bad = self._valid_mapping(status=AttackMappingStatus.OBSERVED)
        assert _apply_semantic_gate([bad]) == []

    def test_a_genuinely_valid_candidate_survives_the_gate(self):
        good = self._valid_mapping()
        result = _apply_semantic_gate([good])
        assert result == [good]
        assert result[0].validation_status == AttackValidationStatus.VALID


class TestRansomwareClaimNeverGetsAttackMappingsRegardlessOfTextEvidence:
    """Real-data review defect (mandate Section 20): report_contract.py
    already declares Section 11 NOT_APPLICABLE for ransomware_claim -- the
    same "never invent an intrusion chain for a third-party leak-site
    claim" discipline already applied to Attack Path/Technical Analysis.
    package.attack_mappings is already empty for this family by
    construction, but map_techniques() over raw text has no such
    family-awareness on its own; without the explicit family gate in
    build_attack_mappings(), a richer claim's text could produce real,
    evidence-anchored mappings that still bypass the family's declared
    policy."""

    def test_rich_encryption_and_exfiltration_language_still_yields_zero_mappings(self):
        article = DiscoveredArticle(
            url="https://www.ransomware.live/id/rich-claim", title="Group Claims Rich Corp",
            summary="qilin has listed Rich Corp as a new victim on its leak site. The group claims to "
                     "have encrypted all servers and exfiltrated 500GB of data before deploying ransomware.",
            published_at="2026-08-20T00:00:00Z", content_hash="richclaim1",
            labels=["Ransomware"], source="ransomware_intel",
        )
        context = build_report_context(article)
        assert context.family == "ransomware_claim"
        graph = build_evidence_graph(article, context)
        package = _detection_package(article, context)
        mappings = build_attack_mappings(article, context, graph, package)
        assert mappings == []


class TestBuildAttackMappingsNeverReturnsCweOnlyReasoning:
    """Mandate Section 4/5: 'CWE-only reasoning is prohibited.' Structural
    proof, not a runtime check -- build_attack_mappings() never reads
    article.cwe_ids at all, so no mapping's reasoning can ever originate
    from a bare CWE-to-technique inference."""

    def test_no_mapping_reasoning_mentions_cwe(self):
        article = _cve_article(cwe_ids=["CWE-89", "CWE-79"])
        mappings = _mappings_for(article)
        assert mappings
        assert not any("cwe" in m.reasoning.lower() for m in mappings)
