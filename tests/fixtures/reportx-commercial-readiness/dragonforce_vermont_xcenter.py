"""Golden fixture: DragonForce / Vermont XCenter ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://www.ransomware.live/id/VmVybW9udCBYQ2VudGVyQGRyYWdvbmZvcmNl
    (leak-site tracker; exact discovery timestamp, domain, country BR,
    HudsonRock infostealer signal -- notably larger than any prior
    fixture in this set: 2 compromised employees, 48 compromised users,
    9 third-party credentials exposed, 18 external attack-surface
    exposures -- plus passive-DNS infrastructure fingerprinting: MX/TXT
    records show Microsoft 365 email and a Zendesk integration)
  - https://vermont.com.br
    (the victim's own current site -- independently confirms it is a
    contact-center/BPO company, "Operating for almost three decades",
    self-described services; a genuine VICTIM_STATEMENT-tier source
    distinct from the leak-site tracker)
  - https://www.group-ib.com/blog/dragonforce-ransomware/
    (actor-historical context: discovered August 2023, affiliate program
    launched 2024-06-26 offering "80% of your revenue (we only take
    20%)" quoted directly from the group; two Windows variants -- a
    LockBit 3.0 fork and a modified Conti-based build; SystemBC/Cobalt
    Strike/Mimikatz tooling; Aug 2023-Aug 2024 stats: 82 victims, 52.4%
    US, top sectors Manufacturing/Real Estate/Transportation)

  redpacketsecurity.com's own write-up returned HTTP 403 to direct fetch
  this session (consistent with the same block seen on the Qilin/Spoonful
  of Comfort fixture) and is not used as a source here.

AFTER-only, same rationale as the other ransomware fixtures.
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
        source_id="s-ransomwarelive-vxc", url="https://www.ransomware.live/id/VmVybW9udCBYQ2VudGVyQGRyYWdvbmZvcmNl",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-17T09:24:00Z",
        reliability=Reliability.MODERATE, independence_group="dragonforce-vermont-xcenter-leak-post",
        notes="Indexes DragonForce's own Tor leak-site post; domain vermont.com.br; country BR; "
              "no data-volume figure stated; HudsonRock infostealer signal: 2 compromised "
              "employees, 48 compromised users, 9 third-party employee credentials exposed, 18 "
              "external attack-surface exposures. Passive-DNS infrastructure fingerprinting "
              "(MX/TXT records): Microsoft 365 email, Zendesk integration.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-vermont-own-site", url="https://vermont.com.br",
        publisher="Vermont XCenter (the company's own site)",
        source_type=SourceType.VICTIM_STATEMENT, source_role=SourceRole.CORROBORATION,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="vermont-own-site",
        notes="Company's own self-description: an omnichannel contact-center/BPO operation, "
              "'operating for almost three decades'; services span customer service, "
              "telesales, technical support/help desk, CRM implementation (Salesforce, HubSpot, "
              "Monday.com), and healthcare-specific patient-relationship support.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-groupib-dragonforce", url="https://www.group-ib.com/blog/dragonforce-ransomware/",
        publisher="Group-IB", source_type=SourceType.CTI_VENDOR_RESEARCH, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.MODERATE, independence_group="groupib-dragonforce-profile",
        notes="Discovered August 2023; public affiliate-program launch 2024-06-26 offering "
              "'80% of your revenue (we only take 20%)' (quoted directly from the group); two "
              "Windows variants -- a LockBit 3.0 fork and a modified Conti-based build (BYOVD, "
              "scheduled-task persistence); SystemBC/Cobalt Strike/Mimikatz tooling; "
              "double-extortion. Aug 2023-Aug 2024: 82 victims, 52.4% US (43 attacks), top "
              "sectors Manufacturing (14.6%), Real Estate (13.4%), Transportation (12.2%); other "
              "significant targets UK (12.2%), Australia (6%).",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-vxc", source_id="s-ransomwarelive-vxc",
        excerpt="Vermont XCenter listed by DragonForce, discovered 2026-08-17 09:24 UTC, est. "
                "attack date 2026-08-17; domain vermont.com.br; country BR; no data-volume "
                "figure stated.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-infostealer-signal-vxc", source_id="s-ransomwarelive-vxc",
        excerpt="HudsonRock: 2 compromised employees, 48 compromised users, 9 third-party "
                "employee credentials exposed, 18 external attack-surface exposures. Not "
                "attributed to the incident's initial-access vector by the source.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-infra-fingerprint-vxc", source_id="s-ransomwarelive-vxc",
        excerpt="Passive DNS (MX/TXT records) shows Microsoft 365 email and a Zendesk "
                "integration in use -- infrastructure fingerprinting, not evidence of how "
                "access was obtained.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-vermont-self-description", source_id="s-vermont-own-site",
        excerpt="'An Omnichannel Contact Center made your way. Operating for almost three "
                "decades, with robust infrastructure to serve diverse customer service and "
                "sales operations.' Services include SAC/call-center/contact-center/"
                "telemarketing, telesales, technical support/help desk, collections, CRM "
                "implementation, and healthcare-specific patient-relationship support.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-dragonforce-profile", source_id="s-groupib-dragonforce",
        excerpt="DragonForce discovered August 2023; affiliate program launched 2024-06-26 "
                "offering affiliates 80% of revenue; LockBit 3.0 fork and modified "
                "Conti-based variant; SystemBC/Cobalt Strike/Mimikatz; double extortion. "
                "Aug 2023-Aug 2024: 82 victims, 52.4% US, top sectors Manufacturing/Real "
                "Estate/Transportation.",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim-vxc", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself DragonForce listed 'Vermont XCenter' on its extortion "
                 "leak site on 2026-08-17.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-vxc"],
            source_refs=["s-ransomwarelive-vxc"], observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes "
                          "the claim was made, not that compromise/encryption/theft occurred.",
        ),
        Claim(
            claim_id="c-victim-business-description", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Vermont XCenter is an omnichannel contact-center / business-process-outsourcing "
                 "company operating for almost three decades, per its own site.",
            status=EpistemicState.CONFIRMED, evidence_refs=["e-vermont-self-description"],
            source_refs=["s-vermont-own-site"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="CONFIRMED because this is the entity's own self-description, "
                          "independent of the leak-site tracker's classification (which left "
                          "'sector' unpopulated in its own structured fields).",
        ),
        Claim(
            claim_id="c-compromise-occurred-vxc", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at Vermont XCenter.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, or regulator filing "
                          "was located. Represented as UNKNOWN, not guessed.",
        ),
        Claim(
            claim_id="c-infostealer-exposure-vxc", claim_type=ClaimType.TTP_OBSERVED,
            text="Aggregated telemetry indicates 2 compromised employee endpoints, 48 "
                 "compromised end-user credentials, 9 exposed third-party employee credentials, "
                 "and 18 external attack-surface exposures associated with Vermont XCenter.",
            status=EpistemicState.REPORTED, evidence_refs=["e-infostealer-signal-vxc"],
            source_refs=["s-ransomwarelive-vxc"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="A distinct signal from the leak-site claim itself; not established as "
                          "the incident's initial-access vector -- no source connects the two, "
                          "despite the notably larger scale of this exposure signal compared to "
                          "other fixtures in this set.",
        ),
        Claim(
            claim_id="c-infra-fingerprint-vxc", claim_type=ClaimType.TTP_OBSERVED,
            text="Passive DNS records (MX/TXT) show Vermont XCenter uses Microsoft 365 for email "
                 "and has a Zendesk integration.",
            status=EpistemicState.REPORTED, evidence_refs=["e-infra-fingerprint-vxc"],
            source_refs=["s-ransomwarelive-vxc"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="Infrastructure fingerprinting only -- not evidence of the incident's "
                          "initial-access vector.",
        ),
        Claim(
            claim_id="c-victim-ack-vxc", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-vxc"],
            source_refs=["s-ransomwarelive-vxc"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-dragonforce-history", claim_type=ClaimType.TTP_HISTORICAL,
            text="DragonForce was discovered in August 2023 and launched a public affiliate "
                 "program on 2024-06-26 offering affiliates 80% of ransom revenue. It operates "
                 "two Windows ransomware variants -- a LockBit 3.0 fork and a modified "
                 "Conti-based build -- alongside SystemBC, Cobalt Strike, and Mimikatz tooling, "
                 "and uses double extortion. Between August 2023 and August 2024, Group-IB "
                 "documented 82 victims, 52.4% in the United States, with Manufacturing, Real "
                 "Estate, and Transportation as the top-targeted sectors.",
            status=EpistemicState.REPORTED, evidence_refs=["e-dragonforce-profile"],
            source_refs=["s-groupib-dragonforce"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="DragonForce",
        victim_name="Vermont XCenter",
        victim_domain="vermont.com.br",
        country="Brazil",
        sector="Contact center / business process outsourcing (BPO)",
        claim_date="2026-08-17T09:24:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # ransomware.live gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Not specified by the source beyond a generic compromise claim; "
                                  "no data category, volume, or sample described.",
        sample_proof_status=EpistemicState.NOT_ASSESSED,  # no screenshot or proof artifact was described by the source located this session
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-vxc", "c-victim-business-description", "c-victim-ack-vxc"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-infostealer-exposure-vxc", "c-infra-fingerprint-vxc"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],
        raas_model_claim_ids=["c-dragonforce-history"],
        historical_ttp_claim_ids=["c-dragonforce-history"],
        historical_tooling_claim_ids=["c-dragonforce-history"],
        sectors=["Manufacturing", "Real Estate", "Transportation"],
        geographies=["United States", "United Kingdom", "Australia"],
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Enforce MFA on all remote-access and privileged accounts; monitor for "
                            "exposed third-party and end-user credentials in infostealer logs.",
        segmentation="Segment networks to limit lateral movement from an initial foothold.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption "
                                   "activity and known tooling (Cobalt Strike, SystemBC, Mimikatz).",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="dragonforce-vermont-xcenter-2026-08-17",
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
        "On 2026-08-17, a group identifying itself as DragonForce listed 'Vermont XCenter' "
        "(vermont.com.br) on its Tor extortion leak site. This is a single-source claim; no "
        "independent confirmation, victim statement, regulator filing, or data sample has been "
        "located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-17 09:24 UTC. Country: Brazil. Per the company's own site, Vermont "
        "XCenter is an omnichannel contact-center / BPO operation active for almost three "
        "decades. The leak-site post does not specify what data, if any, was taken, and no proof "
        "sample was described. Separately, aggregated telemetry indicates a notably larger "
        "exposure signal than other cases in this set -- 2 compromised employee endpoints, 48 "
        "compromised end-user credentials, 9 exposed third-party employee credentials, and 18 "
        "external attack-surface exposures -- alongside passive-DNS infrastructure "
        "fingerprinting showing Microsoft 365 email and a Zendesk integration in use. None of "
        "this is attributed to the incident's initial-access vector by any source. Whether a "
        "compromise actually occurred is UNKNOWN on current evidence -- this report does not "
        "assert it did.\n\n"
        "## Actor Historical Context (DragonForce, general -- not incident-specific)\n\n"
        "DragonForce was discovered in August 2023 and launched a public affiliate program on "
        "2024-06-26 offering affiliates 80% of ransom revenue. It operates two Windows "
        "ransomware variants -- a LockBit 3.0 fork and a modified Conti-based build -- alongside "
        "SystemBC, Cobalt Strike, and Mimikatz tooling, and uses double extortion. Between August "
        "2023 and August 2024, Group-IB documented 82 victims, 52.4% in the United States, with "
        "Manufacturing, Real Estate, and Transportation as the top-targeted sectors. None of this "
        "historical context is evidence of what happened, if anything, at Vermont XCenter "
        "specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, MFA, credential-exposure "
        "monitoring, network segmentation, behavioral detection for known tooling, "
        "shadow-copy-deletion monitoring, and a tested IR plan -- is provided as general "
        "hardening, not as evidence any specific technique was used against this victim.\n"
    )

    return ReportBundle(
        report_id="dragonforce-vermont-xcenter-2026-08-17",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
