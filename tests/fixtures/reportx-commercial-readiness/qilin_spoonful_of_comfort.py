"""Golden fixture: Qilin / Spoonful of Comfort ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-18) against:
  - https://www.hendryadrian.com/ransom-spoonful-of-comfort-aug-2026/
    (leak-site claim aggregator; exact claim timestamp, sector, disclaimer
    that the claim is unconfirmed)
  - https://www.redpacketsecurity.com/qilin-ransomware-victim-spoonful-of-comfort/
    (same claim, cross-checked; blocked by 403 to automated fetch, cited
    for its WebSearch summary only, not directly quoted)
  - https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)
    (actor-historical context: launch date, RaaS affiliate split per
    Group-IB's March 2023 infiltration, tooling evolution, sector/
    geography history)

Provides an AFTER-only fixture (no BEFORE defect reconstruction for this
case -- CVE-2025-62593's BEFORE/AFTER pair already demonstrates the
validator catching the named defect classes; this fixture's job is to
prove the ransomware three-layer model and single-source corroboration
policy against a REAL leak-site claim, not to re-demonstrate QA-linter
mechanics).
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
        source_id="s-hendryadrian", url="https://www.hendryadrian.com/ransom-spoonful-of-comfort-aug-2026/",
        publisher="hendryadrian.com (ransomware leak-site aggregator)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-18T00:00:00Z", source_date="2026-08-16T18:56:20Z",
        reliability=Reliability.MODERATE, independence_group="qilin-leak-site-claim",
        notes="Aggregates the Qilin group's own Tor leak-site post; page's own disclaimer: "
              "\"This post is based on public claims made by the ransomware group 'qilin'. "
              "I cannot confirm the accuracy of the information.\"",
    ))
    graph.add_source(SourceRecord(
        source_id="s-wikipedia-qilin", url="https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)",
        publisher="Wikipedia", source_type=SourceType.OTHER, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-18T00:00:00Z", reliability=Reliability.MODERATE,
        independence_group="wikipedia-qilin",
        notes="Tertiary source citing Trend Micro (August 2022 first detection) and Group-IB "
              "(March 2023 affiliate-panel infiltration, 80-85% affiliate revenue share).",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post", source_id="s-hendryadrian",
        excerpt="Spoonful of Comfort listed on Qilin's leak site 2026-08-16 18:56:20 UTC; "
                "hospitality sector, United States; claim describes 'unauthorized access and "
                "disruption of operations' with no specific data described; no victim acknowledgement.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-raas-model", source_id="s-wikipedia-qilin",
        excerpt="Group-IB's March 2023 infiltration of Qilin's affiliate panel found affiliates "
                "earn approximately 80-85% of each ransom payment.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-tooling-history", source_id="s-wikipedia-qilin",
        excerpt="First detected by Trend Micro August 2022 as 'Agenda', written in Go, code "
                "resembling Black Basta/BlackMatter/REvil; rewritten in Rust by December 2022.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-sector-history", source_id="s-wikipedia-qilin",
        excerpt="Since 2023, victims span energy/manufacturing, government/public sector, "
                "healthcare, charity/business, and other sectors across Asia, Europe, and "
                "North America; documented data theft ranging from 178 GB to over 1 TB.",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself Qilin listed 'Spoonful of Comfort' on its extortion leak site on 2026-08-16.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post"], source_refs=["s-hendryadrian"],
            observed_vs_context=ObservedVsContext.OBSERVED, corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes the "
                          "claim was made, not that compromise/encryption/theft actually occurred.",
        ),
        Claim(
            claim_id="c-compromise-occurred", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at Spoonful of Comfort.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, regulator filing, or "
                          "data sample was located. The leak-site claim alone does not establish "
                          "this (Section 10) -- explicitly represented as UNKNOWN, not guessed.",
        ),
        Claim(
            claim_id="c-victim-ack", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post"], source_refs=["s-hendryadrian"],
            observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-raas-model", claim_type=ClaimType.TTP_HISTORICAL,
            text="Qilin operates a ransomware-as-a-service affiliate model in which affiliates "
                 "retain approximately 80-85% of each ransom payment (per Group-IB's March 2023 "
                 "affiliate-panel infiltration).",
            status=EpistemicState.REPORTED, evidence_refs=["e-raas-model"], source_refs=["s-wikipedia-qilin"],
            observed_vs_context=ObservedVsContext.CONTEXT,
        ),
        Claim(
            claim_id="c-tooling-history", claim_type=ClaimType.TTP_HISTORICAL,
            text="Qilin's ransomware payload (originally 'Agenda', first detected August 2022, "
                 "written in Go) was rewritten in Rust by December 2022.",
            status=EpistemicState.REPORTED, evidence_refs=["e-tooling-history"], source_refs=["s-wikipedia-qilin"],
            observed_vs_context=ObservedVsContext.CONTEXT,
        ),
        Claim(
            claim_id="c-sector-history", claim_type=ClaimType.TTP_HISTORICAL,
            text="Since 2023, Qilin-attributed victims span energy/manufacturing, government, "
                 "healthcare, and charity/business sectors across Asia, Europe, and North America, "
                 "with documented exfiltration volumes from 178 GB to over 1 TB in various cases.",
            status=EpistemicState.REPORTED, evidence_refs=["e-sector-history"], source_refs=["s-wikipedia-qilin"],
            observed_vs_context=ObservedVsContext.CONTEXT,
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)
    # recompute_corroboration would flip c-leak-site-claim to SINGLE_SOURCE
    # automatically from its one source_ref -- already set explicitly above
    # for clarity; both agree, confirmed by construction.

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="Qilin",
        victim_name="Spoonful of Comfort",
        victim_domain=None,  # not stated by the source
        country="United States",
        sector="Hospitality (per aggregator categorization)",
        claim_date="2026-08-16T18:56:20Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # genuinely supported -- the source gives an exact UTC timestamp
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Not specified by the source beyond 'unauthorized access and disruption of operations'.",
        sample_proof_status=EpistemicState.UNKNOWN,  # sources disagree on whether even an image was posted; no data sample described by either
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim", "c-victim-ack"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=[],  # none located -- no incident-specific TTP evidence, only actor-historical context below
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=["Agenda"],
        raas_model_claim_ids=["c-raas-model"],
        historical_ttp_claim_ids=["c-sector-history"],
        historical_tooling_claim_ids=["c-tooling-history"],
        sectors=["Energy/Manufacturing", "Government/Public Sector", "Healthcare", "Charity/Business"],
        geographies=["Asia", "Europe", "North America"],
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Enforce MFA on all remote-access and privileged accounts.",
        segmentation="Segment networks to limit lateral movement from an initial foothold.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption activity.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="qilin-spoonful-of-comfort-2026-08-16",
        victim_observation=victim_observation,
        actor_context=actor_context,
        generic_readiness=generic_readiness,
        # No linked_vulnerabilities -- no CVE/exploit was claimed or found
        # for this incident, so the four markers stay NOT_APPLICABLE by
        # construction (RansomwareVictimClaim.__post_init__).
    )


def build_bundle() -> ReportBundle:
    graph = build_graph()
    claim = build_ransomware_victim_claim()

    rendered_text = (
        "## Executive Summary\n\n"
        "On 2026-08-16, a group identifying itself as Qilin listed 'Spoonful of Comfort' on its "
        "Tor extortion leak site. This is a single-source claim; no independent confirmation, "
        "victim statement, regulator filing, or data sample has been located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 18:56:20 UTC. Sector: hospitality (per aggregator). "
        "Country: United States. The claim describes 'unauthorized access and disruption of "
        "operations' without specifying what data, if any, was taken. No proof sample was "
        "reviewed. Whether a compromise actually occurred is UNKNOWN on current evidence -- "
        "this report does not assert it did.\n\n"
        "## Actor Historical Context (Qilin, general -- not incident-specific)\n\n"
        "Qilin (originally 'Agenda') was first detected in August 2022; a Group-IB affiliate-panel "
        "infiltration in March 2023 found affiliates retain approximately 80-85% of each ransom "
        "payment. The ransomware payload was rewritten from Go to Rust by December 2022. Since "
        "2023, Qilin-attributed victims span energy/manufacturing, government, healthcare, and "
        "charity/business sectors across Asia, Europe, and North America. None of this historical "
        "context is evidence of what happened, if anything, at Spoonful of Comfort specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, MFA, network segmentation, "
        "mass-encryption detection, shadow-copy-deletion monitoring, and a tested IR plan -- is "
        "provided as general hardening, not as evidence any specific technique was used against "
        "this victim.\n"
    )

    return ReportBundle(
        report_id="qilin-spoonful-of-comfort-2026-08-16",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
