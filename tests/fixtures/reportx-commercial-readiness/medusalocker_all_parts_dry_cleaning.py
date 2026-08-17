"""Golden fixture: MedusaLocker / All Parts Dry Cleaning ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://ransomware.live/id/QWxsIFBhcnRzIERyeSBDbGVhbmluZ0BtZWR1c2Fsb2NrZXI=
    (leak-site tracker; exact discovery timestamp, domain, sector,
    country GB, a leak screenshot, and a HudsonRock infostealer/
    attack-surface signal: 2 compromised employees, 1 external
    attack-surface exposure)
  - MedusaLocker actor-historical context reuses the SAME already-verified
    facts from the Twal Family IT Lab fixture (cybersecuritydive.com's
    reporting on the 2022 CISA/FBI/Treasury/FinCEN joint advisory) --
    legitimate reuse of the same true facts about the same actor, not
    re-fabricated.

No second independent source with distinct victim-specific detail was
located (a search for hendryadrian.com/RedPacket Security/recentbreaches.com
coverage returned no fetchable page beyond ransomware.live itself) --
represented honestly as SINGLE_SOURCE. AFTER-only, same rationale as the
other ransomware fixtures.
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
        source_id="s-ransomwarelive-apdc", url="https://ransomware.live/id/QWxsIFBhcnRzIERyeSBDbGVhbmluZ0BtZWR1c2Fsb2NrZXI=",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T15:21:00Z",
        reliability=Reliability.MODERATE, independence_group="medusalocker-all-parts-dry-cleaning-leak-post",
        notes="Indexes MedusaLocker's own Tor leak-site post directly; victim domain "
              "allpartsdrycleaning.co.uk; sector classified 'Retail & E-Commerce' (described as "
              "'Dry cleaning & laundry'); leak screenshot referenced; HudsonRock infostealer "
              "signal: 2 compromised employees, 0 compromised users, 0 third-party employee "
              "credentials, 1 external attack-surface exposure. Site disclaimer: 'Ransomware.live "
              "does not engage in the acquisition, exfiltration, downloading, possession, "
              "hosting, access, consultation, redistribution, or disclosure of unlawfully "
              "obtained data.'",
    ))
    graph.add_source(SourceRecord(
        source_id="s-cybersecuritydive-medusalocker-apdc", url="https://www.cybersecuritydive.com/news/fbi-cisa-medusalocker-ransomware/626483/",
        publisher="Cybersecurity Dive", source_type=SourceType.JOURNALISM, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2022-07-01",
        reliability=Reliability.MODERATE, independence_group="cybersecuritydive-medusalocker-2022",
        notes="Same source already verified for the Twal Family IT Lab fixture this session: "
              "reports on the CISA/FBI/Treasury/FinCEN joint advisory (AA22-181A, "
              "2022-06-29/30) -- active since late 2019, RDP brute-force/phishing initial "
              "access, 55-60% affiliate/developer ransom split, healthcare heavily impacted "
              "during COVID-19.",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-apdc", source_id="s-ransomwarelive-apdc",
        excerpt="All Parts Dry Cleaning listed by MedusaLocker, discovered 2026-08-16 15:21 UTC, "
                "est. attack date 2026-08-16; domain allpartsdrycleaning.co.uk; country GB; "
                "dry cleaning & laundry sector; leak screenshot referenced; no data-category or "
                "volume figure stated.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-infostealer-signal-apdc", source_id="s-ransomwarelive-apdc",
        excerpt="HudsonRock intelligence: 2 compromised employees, 0 compromised users, 0 "
                "third-party employee credentials, 1 external attack-surface exposure. Not "
                "attributed to the incident's initial-access vector by the source.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-medusalocker-advisory-apdc", source_id="s-cybersecuritydive-medusalocker-apdc",
        excerpt="MedusaLocker active since late 2019; initial access via RDP brute force and "
                "phishing/spam campaigns; RaaS split -- affiliates typically receive 55-60% of "
                "ransom proceeds, developer receives the remainder; healthcare sector "
                "particularly impacted during the COVID-19 pandemic (joint CISA/FBI/Treasury/"
                "FinCEN advisory, 2022-06-29/30).",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim-apdc", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself MedusaLocker listed 'All Parts Dry Cleaning' on its "
                 "extortion leak site on 2026-08-16.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-apdc"],
            source_refs=["s-ransomwarelive-apdc"], observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes "
                          "the claim was made, not that compromise/encryption/theft occurred.",
        ),
        Claim(
            claim_id="c-compromise-occurred-apdc", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at All Parts Dry Cleaning.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, or regulator filing "
                          "was located. Represented as UNKNOWN, not guessed.",
        ),
        Claim(
            claim_id="c-infostealer-exposure-apdc", claim_type=ClaimType.TTP_OBSERVED,
            text="Aggregated telemetry indicates 2 compromised employee endpoints and 1 external "
                 "attack-surface exposure associated with All Parts Dry Cleaning; 0 compromised "
                 "end-user or third-party credentials were reported.",
            status=EpistemicState.REPORTED, evidence_refs=["e-infostealer-signal-apdc"],
            source_refs=["s-ransomwarelive-apdc"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="A distinct signal from the leak-site claim itself; not established as "
                          "the incident's initial-access vector -- no source connects the two.",
        ),
        Claim(
            claim_id="c-victim-ack-apdc", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-apdc"],
            source_refs=["s-ransomwarelive-apdc"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-medusalocker-history-apdc", claim_type=ClaimType.TTP_HISTORICAL,
            text="MedusaLocker has been active since late 2019, primarily gains initial access "
                 "via RDP brute-force and phishing/spam campaigns, and operates a RaaS model in "
                 "which affiliates typically retain 55-60% of ransom proceeds. Per a joint "
                 "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30), the healthcare sector was "
                 "particularly impacted during the COVID-19 pandemic.",
            status=EpistemicState.REPORTED, evidence_refs=["e-medusalocker-advisory-apdc"],
            source_refs=["s-cybersecuritydive-medusalocker-apdc"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="MedusaLocker",
        victim_name="All Parts Dry Cleaning",
        victim_domain="allpartsdrycleaning.co.uk",
        country="United Kingdom",
        sector="Dry cleaning and laundry services",
        claim_date="2026-08-16T15:21:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # ransomware.live gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Not specified by the source beyond a generic compromise claim; "
                                  "no data category, volume, or sample described.",
        sample_proof_status=EpistemicState.REPORTED,  # a leak screenshot is referenced; not independently authenticated
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-apdc", "c-victim-ack-apdc"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-infostealer-exposure-apdc"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],
        raas_model_claim_ids=["c-medusalocker-history-apdc"],
        historical_ttp_claim_ids=["c-medusalocker-history-apdc"],
        historical_tooling_claim_ids=[],
        sectors=["Healthcare (historically, per 2022 CISA advisory)"],
        geographies=[],  # not specified by the source located this session
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Disable or restrict internet-facing RDP; enforce MFA on all "
                            "remote-access and privileged accounts; monitor for exposed external "
                            "attack-surface assets and infostealer-compromised endpoints.",
        segmentation="Segment networks to limit lateral movement from an initial foothold.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption activity.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="medusalocker-all-parts-dry-cleaning-2026-08-16",
        victim_observation=victim_observation,
        actor_context=actor_context,
        generic_readiness=generic_readiness,
        # No linked_vulnerabilities -- MedusaLocker's documented initial-access
        # vector is RDP brute force/phishing, not a specific CVE; the four
        # markers stay NOT_APPLICABLE by construction.
    )


def build_bundle() -> ReportBundle:
    graph = build_graph()
    claim = build_ransomware_victim_claim()

    rendered_text = (
        "## Executive Summary\n\n"
        "On 2026-08-16, a group identifying itself as MedusaLocker listed 'All Parts Dry "
        "Cleaning' (allpartsdrycleaning.co.uk) on its Tor extortion leak site. This is a "
        "single-source claim; no independent confirmation, victim statement, regulator filing, "
        "or data sample has been located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 15:21 UTC. Country: United Kingdom. Sector: dry cleaning and "
        "laundry services. The claim does not specify what data, if any, was taken beyond a "
        "generic compromise assertion; a leak screenshot was referenced but not independently "
        "authenticated. Separately, aggregated telemetry indicates 2 compromised employee "
        "endpoints and 1 external attack-surface exposure, with 0 compromised end-user or "
        "third-party credentials reported; no source connects these to the claimed incident's "
        "initial-access vector. Whether a compromise actually occurred is UNKNOWN on current "
        "evidence -- this report does not assert it did.\n\n"
        "## Actor Historical Context (MedusaLocker, general -- not incident-specific)\n\n"
        "MedusaLocker has been active since late 2019, primarily gains initial access via RDP "
        "brute-force attacks and phishing/spam campaigns, and operates a ransomware-as-a-service "
        "model in which affiliates typically retain 55-60% of ransom proceeds. A joint "
        "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30) found the healthcare sector was "
        "particularly impacted during the COVID-19 pandemic. None of this historical context is "
        "evidence of what happened, if anything, at All Parts Dry Cleaning specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, disabling or restricting "
        "internet-facing RDP, MFA, attack-surface and credential-exposure monitoring, network "
        "segmentation, mass-encryption detection, shadow-copy-deletion monitoring, and a tested "
        "IR plan -- is provided as general hardening, not as evidence any specific technique was "
        "used against this victim.\n"
    )

    return ReportBundle(
        report_id="medusalocker-all-parts-dry-cleaning-2026-08-16",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
