"""Golden fixture: MedusaLocker / Twal Family IT Lab ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://www.hendryadrian.com/ransom-twal-family-it-lab-aug-2026/
    (leak-site claim aggregator; exact claim timestamp, technical claim
    details -- VMware vSphere and Active Directory ("twalfamily.com"
    domain) disruption -- and the standard "cannot confirm accuracy"
    disclaimer)
  - https://ransomware.live/id/VHdhbCBGYW1pbHkgSVQgTGFiQG1lZHVzYWxvY2tlcg==
    (same underlying MedusaLocker leak-site post; notably states the
    tracker had "previously misidentified [this victim] as Forces/
    forces.gc.ca" before correcting the record to a personal IT home
    lab -- a genuine, sourced example of why an initial leak-site
    attribution must not be trusted at face value)
  - https://www.cybersecuritydive.com/news/fbi-cisa-medusalocker-ransomware/626483/
    (actor-historical context: CISA/FBI/Treasury/FinCEN's June 2022 joint
    advisory on MedusaLocker -- active since late 2019, RDP brute-force
    and phishing initial access, 55-60% affiliate/developer ransom split,
    healthcare sector heavily targeted during COVID-19. CISA's own
    advisory page (aa22-181a) returned HTTP 403 to direct fetch this
    session and the two advisory PDFs fetched did not decode to readable
    text -- cited via this secondary reporting outlet, not pretended to
    be a direct CISA read.)

PRIVACY SCOPING NOTE: the leak-site claim as publicly indexed names a
specific individual and a residential address (this was a personal home
lab, not a company). This fixture deliberately excludes the individual's
name, employer, and street address -- none of that is needed to exercise
the ransomware evidence schema, and republishing it here would amplify a
private person's doxxing rather than serve any analytic purpose. Only the
self-chosen entity label ("Twal Family IT Lab"), its self-chosen AD domain
(already public and functionally equivalent to a company using its own
domain as an identifier), country-level geography, and the ransomware
group's technical claims are retained -- the same category and
granularity of information used in every other fixture in this set.

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

    # Both leak-site trackers report identical specifics (same timestamp,
    # same claim) -- they are downstream syndications of the SAME
    # MedusaLocker Tor post, not independent observations of it. Sharing
    # one independence_group makes recompute_corroboration() correctly
    # yield MULTI_SOURCE_DEPENDENT rather than overstating this as
    # MULTI_SOURCE_INDEPENDENT.
    graph.add_source(SourceRecord(
        source_id="s-hendryadrian-twal", url="https://www.hendryadrian.com/ransom-twal-family-it-lab-aug-2026/",
        publisher="hendryadrian.com (ransomware leak-site aggregator)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T15:21:57Z",
        reliability=Reliability.MODERATE, independence_group="medusalocker-twal-leak-site-post",
        notes="Aggregates MedusaLocker's own Tor leak-site post; page's own disclaimer: "
              "\"This post is based on public claims made by the ransomware group "
              "'medusalocker'. I cannot confirm the accuracy of the information.\" Technical "
              "claim: VMware vSphere and Active Directory (twalfamily.com domain, multiple AD "
              "domains) disrupted.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-ransomwarelive-twal", url="https://ransomware.live/id/VHdhbCBGYW1pbHkgSVQgTGFiQG1lZHVzYWxvY2tlcg==",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.CORROBORATION,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T15:21:00Z",
        reliability=Reliability.MODERATE, independence_group="medusalocker-twal-leak-site-post",
        notes="Same underlying leak-site post as hendryadrian.com. Notable self-correction: the "
              "platform states this victim was 'previously misidentified as Forces/forces.gc.ca' "
              "before being corrected to a personal IT home lab -- direct evidence that an "
              "initial leak-site victim attribution can be wrong and must not be trusted at "
              "face value.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-cybersecuritydive-medusalocker", url="https://www.cybersecuritydive.com/news/fbi-cisa-medusalocker-ransomware/626483/",
        publisher="Cybersecurity Dive", source_type=SourceType.JOURNALISM, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2022-07-01",
        reliability=Reliability.MODERATE, independence_group="cybersecuritydive-medusalocker-2022",
        notes="Reports on the CISA/FBI/Treasury/FinCEN joint advisory (AA22-181A, published "
              "2022-06-29/30). CISA's own advisory page returned HTTP 403 to direct fetch this "
              "session; two advisory PDF mirrors fetched did not decode to readable text. Cited "
              "via this secondary reporting outlet, not a direct CISA read.",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-twal-1", source_id="s-hendryadrian-twal",
        excerpt="Twal Family IT Lab listed on MedusaLocker's leak site 2026-08-16 15:21:57 UTC; "
                "personal home-lab environment; VMware vSphere and Active Directory "
                "(twalfamily.com domain, multiple AD domains) disruption claimed; screenshot "
                "posted, no further corroborating evidence detailed.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-twal-2", source_id="s-ransomwarelive-twal",
        excerpt="Twal Family IT Lab listed by MedusaLocker 2026-08-16 15:21 UTC; sector "
                "classified as personal IT home lab; location Canada; entry notes the victim "
                "was 'previously misidentified as Forces/forces.gc.ca' before correction.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-misattribution-correction", source_id="s-ransomwarelive-twal",
        excerpt="'Previously misidentified as Forces/forces.gc.ca' -- the tracker's own record "
                "of correcting an initial (wrong) government-entity attribution to the actual "
                "personal home-lab target.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-medusalocker-advisory", source_id="s-cybersecuritydive-medusalocker",
        excerpt="MedusaLocker active since late 2019 (per CyberReason, as cited); initial access "
                "via RDP brute force and phishing/spam campaigns; RaaS split -- affiliates "
                "typically receive 55-60% of ransom proceeds, developer receives the remainder; "
                "healthcare sector particularly impacted during the COVID-19 pandemic; advisory "
                "issued jointly by CISA, FBI, Treasury, and FinCEN, 2022-06-29/30.",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim-twal", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself MedusaLocker listed 'Twal Family IT Lab' (a personal IT "
                 "home-lab environment, not a company) on its extortion leak site on 2026-08-16.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-twal-1", "e-claim-post-twal-2"],
            source_refs=["s-hendryadrian-twal", "s-ransomwarelive-twal"],
            observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.MULTI_SOURCE_DEPENDENT,
            analyst_notes="Two trackers report this, but both syndicate the SAME underlying "
                          "MedusaLocker Tor post (same independence_group) -- correctly "
                          "MULTI_SOURCE_DEPENDENT, not MULTI_SOURCE_INDEPENDENT. Per Section 10 "
                          "this still does not establish compromise/encryption/theft occurred.",
        ),
        Claim(
            claim_id="c-misattribution-correction", claim_type=ClaimType.VICTIM_IDENTITY,
            text="ransomware.live's own record shows this victim entry was previously "
                 "misidentified as 'Forces/forces.gc.ca' (a Canadian government entity) before "
                 "being corrected to the actual personal home-lab target.",
            status=EpistemicState.CONFIRMED, evidence_refs=["e-misattribution-correction"],
            source_refs=["s-ransomwarelive-twal"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="CONFIRMED because this is the tracker's own documented correction of "
                          "its own record, not a claim about the incident itself -- a concrete, "
                          "sourced example of why an initial leak-site attribution must be "
                          "verified before being reported as fact.",
        ),
        Claim(
            claim_id="c-compromise-occurred-twal", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at Twal Family IT Lab.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, or regulator filing "
                          "was located (and would not be expected for a personal home lab). "
                          "Represented as UNKNOWN, not guessed.",
        ),
        Claim(
            claim_id="c-technical-disruption-claim", claim_type=ClaimType.TTP_OBSERVED,
            text="The leak-site post claims disruption of VMware vSphere virtualization "
                 "infrastructure and multiple Active Directory domains (twalfamily.com).",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-twal-1"],
            source_refs=["s-hendryadrian-twal"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="A claim about WHAT was allegedly disrupted, not independent proof "
                          "that disruption occurred -- same single-tracker-post provenance as "
                          "the leak-site claim itself.",
        ),
        Claim(
            claim_id="c-victim-ack-twal", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-twal-1"],
            source_refs=["s-hendryadrian-twal"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-medusalocker-history", claim_type=ClaimType.TTP_HISTORICAL,
            text="MedusaLocker has been active since late 2019, primarily gains initial access "
                 "via RDP brute-force and phishing/spam campaigns, and operates a RaaS model in "
                 "which affiliates typically retain 55-60% of ransom proceeds. Per a joint "
                 "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30), the healthcare sector was "
                 "particularly impacted during the COVID-19 pandemic.",
            status=EpistemicState.REPORTED, evidence_refs=["e-medusalocker-advisory"],
            source_refs=["s-cybersecuritydive-medusalocker"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="MedusaLocker",
        victim_name="Twal Family IT Lab",
        victim_domain="twalfamily.com",
        country="Canada",
        sector="Personal / individual home-lab infrastructure (not a commercial or governmental entity)",
        claim_date="2026-08-16T15:21:57Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # hendryadrian gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="VMware vSphere and multiple Active Directory domains "
                                  "(twalfamily.com) claimed disrupted; no specific data category, "
                                  "volume, or sample described.",
        sample_proof_status=EpistemicState.REPORTED,  # a screenshot was posted; not independently authenticated
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-twal", "c-misattribution-correction", "c-victim-ack-twal"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-technical-disruption-claim"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],
        raas_model_claim_ids=["c-medusalocker-history"],
        historical_ttp_claim_ids=["c-medusalocker-history"],
        historical_tooling_claim_ids=[],  # no payload/tooling-family analysis located this session
        sectors=["Healthcare (historically, per 2022 CISA advisory)"],
        geographies=[],  # not specified by the source located this session
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Disable or restrict internet-facing RDP; enforce MFA on all "
                            "remote-access and privileged accounts.",
        segmentation="Segment networks (including hypervisor management interfaces) to limit "
                     "lateral movement from an initial foothold.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption activity.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="medusalocker-twal-family-it-lab-2026-08-16",
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
        "On 2026-08-16, a group identifying itself as MedusaLocker listed 'Twal Family IT Lab' "
        "-- a personal IT home-lab environment, not a company -- on its Tor extortion leak site. "
        "Two trackers report the same underlying post; no independent confirmation, victim "
        "statement, or data sample has been located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 15:21:57 UTC. Country: Canada. The leak-site post claims "
        "disruption of VMware vSphere virtualization infrastructure and multiple Active "
        "Directory domains (twalfamily.com). Notably, one tracker's own record shows this entry "
        "was previously misidentified as a Canadian government entity ('Forces/forces.gc.ca') "
        "before being corrected to the actual personal home-lab target -- a concrete example of "
        "why an initial leak-site attribution must be verified, not assumed. Whether a "
        "compromise actually occurred is UNKNOWN on current evidence -- this report does not "
        "assert it did.\n\n"
        "## Actor Historical Context (MedusaLocker, general -- not incident-specific)\n\n"
        "MedusaLocker has been active since late 2019, primarily gains initial access via RDP "
        "brute-force attacks and phishing/spam campaigns, and operates a ransomware-as-a-service "
        "model in which affiliates typically retain 55-60% of ransom proceeds. A joint "
        "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30) found the healthcare sector was "
        "particularly impacted during the COVID-19 pandemic. None of this historical context is "
        "evidence of what happened, if anything, at Twal Family IT Lab specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, disabling or restricting "
        "internet-facing RDP, MFA, hypervisor-management-plane segmentation, mass-encryption "
        "detection, shadow-copy-deletion monitoring, and a tested IR plan -- is provided as "
        "general hardening, not as evidence any specific technique was used against this victim.\n"
    )

    return ReportBundle(
        report_id="medusalocker-twal-family-it-lab-2026-08-16",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
