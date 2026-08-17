"""Golden fixture: Qilin / Mulino Padano ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://ransomware.live/id/TXVsaW5vIFBhZGFub0BxaWxpbg==
    (leak-site tracker; exact discovery timestamp, country IT, sector,
    a leak screenshot, and a separate infostealer-exposure signal: 7
    compromised users / 6 external attack-surface exposures)
  - https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)
    (actor-historical context -- the SAME source and the SAME
    already-verified facts used in the Qilin/Spoonful of Comfort fixture:
    Trend Micro's August 2022 first detection, Group-IB's March 2023
    affiliate-panel infiltration finding an 80-85% affiliate revenue
    share, the Go-to-Rust tooling rewrite by December 2022, and the
    2023-onward sector/geography spread. Legitimate reuse of the same
    actor across two different incidents -- Section 19's rule is that
    actor-historical claims must not be treated as evidence for a
    SPECIFIC incident, not that the same true fact about the actor must
    be re-researched from scratch for every victim.)

No second independent source with distinct victim-specific detail was
located for this claim (unlike the Panzer/SAGASTA fixture) -- represented
honestly as SINGLE_SOURCE, the same posture as the original Qilin/Spoonful
of Comfort fixture. AFTER-only, same rationale as the other ransomware
fixtures: BEFORE/AFTER defect-catalog demonstration already lives in the
CVE-2025-62593 pair.
"""

from __future__ import annotations

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
)
from sentinel_engine.reportx.commercial_readiness import ReportBundle
from sentinel_engine.reportx.threat_schemas import ActorHistoricalContext, GenericReadiness, RansomwareVictimClaim, VictimObservation


def build_graph() -> EvidenceGraph:
    graph = EvidenceGraph()

    graph.add_source(SourceRecord(
        source_id="s-ransomwarelive-mp", url="https://ransomware.live/id/TXVsaW5vIFBhZGFub0BxaWxpbg==",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T15:59:00Z",
        reliability=Reliability.MODERATE, independence_group="qilin-mulino-padano-leak-post",
        notes="Indexes Qilin's own Tor leak-site post directly; displays a leak screenshot; "
              "victim website listed as www.mulinopadano.it; separately carries an infostealer/"
              "attack-surface signal (7 compromised users, 6 external exposures) not attributed "
              "to a specific breach vector. Site disclaimer: indexes only publicly visible "
              "attacker claims, does not host stolen content.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-wikipedia-qilin-mp", url="https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)",
        publisher="Wikipedia", source_type=SourceType.OTHER, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", reliability=Reliability.MODERATE,
        independence_group="wikipedia-qilin",
        notes="Same source and facts already verified for the Qilin/Spoonful of Comfort fixture "
              "this session: Trend Micro (August 2022 first detection as 'Agenda'), Group-IB "
              "(March 2023 affiliate-panel infiltration, 80-85% affiliate revenue share).",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-mp", source_id="s-ransomwarelive-mp",
        excerpt="Mulino Padano listed on Qilin's leak site, discovered 2026-08-16 15:59 UTC, "
                "est. attack date 2026-08-16; country IT; agriculture/food-production sector; "
                "leak screenshot displayed; no specific data description beyond a generic "
                "compromise claim. Separately: infostealer/attack-surface signal -- 7 "
                "compromised users, 6 external exposures.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-infostealer-signal-mp", source_id="s-ransomwarelive-mp",
        excerpt="7 compromised users and 6 external attack-surface exposures detected (source "
                "does not attribute these to the incident's initial-access vector).",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-raas-model-mp", source_id="s-wikipedia-qilin-mp",
        excerpt="Group-IB's March 2023 infiltration of Qilin's affiliate panel found affiliates "
                "earn approximately 80-85% of each ransom payment.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-tooling-history-mp", source_id="s-wikipedia-qilin-mp",
        excerpt="First detected by Trend Micro August 2022 as 'Agenda', written in Go, code "
                "resembling Black Basta/BlackMatter/REvil; rewritten in Rust by December 2022.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-sector-history-mp", source_id="s-wikipedia-qilin-mp",
        excerpt="Since 2023, victims span energy/manufacturing, government/public sector, "
                "healthcare, charity/business, and other sectors across Asia, Europe, and "
                "North America; documented data theft ranging from 178 GB to over 1 TB.",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim-mp", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself Qilin listed 'Mulino Padano' on its extortion leak site "
                 "on 2026-08-16.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-mp"],
            source_refs=["s-ransomwarelive-mp"], observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes "
                          "the claim was made, not that compromise/encryption/theft occurred.",
        ),
        Claim(
            claim_id="c-compromise-occurred-mp", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at Mulino Padano.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, regulator filing, or "
                          "data sample was located. Represented as UNKNOWN, not guessed.",
        ),
        Claim(
            claim_id="c-infostealer-exposure-mp", claim_type=ClaimType.TTP_OBSERVED,
            text="ransomware.live's aggregated telemetry indicates 7 compromised user credentials "
                 "and 6 external attack-surface exposures associated with Mulino Padano.",
            status=EpistemicState.REPORTED, evidence_refs=["e-infostealer-signal-mp"],
            source_refs=["s-ransomwarelive-mp"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="A distinct signal from the leak-site claim itself; not established as "
                          "the incident's initial-access vector -- no source connects the two.",
        ),
        Claim(
            claim_id="c-victim-ack-mp", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-mp"],
            source_refs=["s-ransomwarelive-mp"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-raas-model-mp", claim_type=ClaimType.TTP_HISTORICAL,
            text="Qilin operates a ransomware-as-a-service affiliate model in which affiliates "
                 "retain approximately 80-85% of each ransom payment (per Group-IB's March 2023 "
                 "affiliate-panel infiltration).",
            status=EpistemicState.REPORTED, evidence_refs=["e-raas-model-mp"],
            source_refs=["s-wikipedia-qilin-mp"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
        Claim(
            claim_id="c-tooling-history-mp", claim_type=ClaimType.TTP_HISTORICAL,
            text="Qilin's ransomware payload (originally 'Agenda', first detected August 2022, "
                 "written in Go) was rewritten in Rust by December 2022.",
            status=EpistemicState.REPORTED, evidence_refs=["e-tooling-history-mp"],
            source_refs=["s-wikipedia-qilin-mp"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
        Claim(
            claim_id="c-sector-history-mp", claim_type=ClaimType.TTP_HISTORICAL,
            text="Since 2023, Qilin-attributed victims span energy/manufacturing, government, "
                 "healthcare, and charity/business sectors across Asia, Europe, and North America, "
                 "with documented exfiltration volumes from 178 GB to over 1 TB in various cases.",
            status=EpistemicState.REPORTED, evidence_refs=["e-sector-history-mp"],
            source_refs=["s-wikipedia-qilin-mp"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="Qilin",
        victim_name="Mulino Padano",
        victim_domain="www.mulinopadano.it",
        country="Italy",
        sector="Agriculture / food production (flour milling)",
        claim_date="2026-08-16T15:59:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # ransomware.live gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Not specified by the source beyond a generic compromise claim; "
                                  "no data category, volume, or sample described.",
        sample_proof_status=EpistemicState.REPORTED,  # a leak screenshot is displayed; not independently authenticated
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-mp", "c-victim-ack-mp"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-infostealer-exposure-mp"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=["Agenda"],
        raas_model_claim_ids=["c-raas-model-mp"],
        historical_ttp_claim_ids=["c-sector-history-mp"],
        historical_tooling_claim_ids=["c-tooling-history-mp"],
        sectors=["Energy/Manufacturing", "Government/Public Sector", "Healthcare", "Charity/Business"],
        geographies=["Asia", "Europe", "North America"],
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Enforce MFA on all remote-access and privileged accounts; monitor for "
                            "exposed external attack-surface assets and compromised credentials.",
        segmentation="Segment networks to limit lateral movement from an initial foothold.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption activity.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="qilin-mulino-padano-2026-08-16",
        victim_observation=victim_observation,
        actor_context=actor_context,
        generic_readiness=generic_readiness,
        # No linked_vulnerabilities -- no CVE/exploit was claimed or found
        # for this incident; the four markers stay NOT_APPLICABLE by
        # construction (RansomwareVictimClaim.__post_init__).
    )


def build_bundle() -> ReportBundle:
    graph = build_graph()
    claim = build_ransomware_victim_claim()

    rendered_text = (
        "## Executive Summary\n\n"
        "On 2026-08-16, a group identifying itself as Qilin listed 'Mulino Padano' on its Tor "
        "extortion leak site. This is a single-source claim; no independent confirmation, victim "
        "statement, regulator filing, or data sample has been located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 15:59 UTC. Country: Italy. Sector: agriculture / food "
        "production. The claim does not specify what data, if any, was taken beyond a generic "
        "compromise assertion; a leak screenshot was displayed but not independently "
        "authenticated. Separately, aggregated telemetry indicates 7 compromised user "
        "credentials and 6 external attack-surface exposures associated with the victim, though "
        "no source connects these to the claimed incident's initial-access vector. Whether a "
        "compromise actually occurred is UNKNOWN on current evidence -- this report does not "
        "assert it did.\n\n"
        "## Actor Historical Context (Qilin, general -- not incident-specific)\n\n"
        "Qilin (originally 'Agenda') was first detected in August 2022; a Group-IB affiliate-panel "
        "infiltration in March 2023 found affiliates retain approximately 80-85% of each ransom "
        "payment. The ransomware payload was rewritten from Go to Rust by December 2022. Since "
        "2023, Qilin-attributed victims span energy/manufacturing, government, healthcare, and "
        "charity/business sectors across Asia, Europe, and North America. None of this historical "
        "context is evidence of what happened, if anything, at Mulino Padano specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, MFA, attack-surface and "
        "credential-exposure monitoring, network segmentation, mass-encryption detection, "
        "shadow-copy-deletion monitoring, and a tested IR plan -- is provided as general "
        "hardening, not as evidence any specific technique was used against this victim.\n"
    )

    return ReportBundle(
        report_id="qilin-mulino-padano-2026-08-16",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
