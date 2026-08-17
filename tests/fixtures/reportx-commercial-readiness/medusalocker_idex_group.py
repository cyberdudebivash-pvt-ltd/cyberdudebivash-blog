"""Golden fixture: MedusaLocker / Idex Group ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://ransomware.live/id/SWRleCBHcm91cEBtZWR1c2Fsb2NrZXI=
    (leak-site tracker; exact discovery timestamp, domain idex-group.com,
    country DE, sector Technology, claim of '30 emails extracted', DNS/
    WHOIS fingerprinting signal)
  - MedusaLocker actor-historical context reuses the SAME already-verified
    facts from the Twal Family IT Lab and All Parts Dry Cleaning fixtures
    (cybersecuritydive.com's reporting on the 2022 CISA/FBI/Treasury/
    FinCEN joint advisory).

NAME-COLLISION CAUTION (the load-bearing finding of this fixture's
research): a search for the victim's own business description turned up
"IDEX Corporation" (idexcorp.com) -- a large, publicly traded, S&P
500-member industrial company headquartered in Northbrook, Illinois, with
~9,000 employees. This is a DIFFERENT ENTITY from the leak-site victim
"Idex Group" (idex-group.com). idex-group.com itself returned HTTP 503 to
direct fetch this session, so no independent business description for the
actual victim was obtainable. This fixture deliberately leaves the
victim's business description NOT_ASSESSED rather than borrowing IDEX
Corporation's public profile -- doing so would misrepresent a small/
mid-size victim as a Fortune-500-adjacent company, exactly the class of
fabrication-by-similar-name error Section 37 exists to prevent.

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
        source_id="s-ransomwarelive-idex", url="https://ransomware.live/id/SWRleCBHcm91cEBtZWR1c2Fsb2NrZXI=",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T15:20:00Z",
        reliability=Reliability.MODERATE, independence_group="medusalocker-idex-group-leak-post",
        notes="Indexes MedusaLocker's own Tor leak-site post; domain idex-group.com; country DE; "
              "sector classified 'Technology'; claim describes '30 emails extracted'; leak "
              "screenshot referenced; DNS records show Mail Exchange and SPF configuration, no "
              "well-known cloud/SaaS service detected, WHOIS abuse contact listed "
              "(abuseinternet.gmo).",
    ))
    graph.add_source(SourceRecord(
        source_id="s-cybersecuritydive-medusalocker-idex", url="https://www.cybersecuritydive.com/news/fbi-cisa-medusalocker-ransomware/626483/",
        publisher="Cybersecurity Dive", source_type=SourceType.JOURNALISM, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2022-07-01",
        reliability=Reliability.MODERATE, independence_group="cybersecuritydive-medusalocker-2022",
        notes="Same source already verified for the Twal Family IT Lab and All Parts Dry "
              "Cleaning fixtures this session: reports on the CISA/FBI/Treasury/FinCEN joint "
              "advisory (AA22-181A, 2022-06-29/30) -- active since late 2019, RDP brute-force/"
              "phishing initial access, 55-60% affiliate/developer ransom split, healthcare "
              "heavily impacted during COVID-19.",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-idex", source_id="s-ransomwarelive-idex",
        excerpt="Idex Group listed by MedusaLocker, discovered 2026-08-16 15:20 UTC, est. attack "
                "date 2026-08-16; domain idex-group.com; country DE; sector Technology; claim "
                "describes '30 emails extracted'.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-infra-fingerprint-idex", source_id="s-ransomwarelive-idex",
        excerpt="DNS records show Mail Exchange and SPF configuration; no well-known cloud/SaaS "
                "service detected; WHOIS abuse contact listed (abuseinternet.gmo). "
                "Infrastructure fingerprinting only, not evidence of the initial-access vector.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-medusalocker-advisory-idex", source_id="s-cybersecuritydive-medusalocker-idex",
        excerpt="MedusaLocker active since late 2019; initial access via RDP brute force and "
                "phishing/spam campaigns; RaaS split -- affiliates typically receive 55-60% of "
                "ransom proceeds, developer receives the remainder; healthcare sector "
                "particularly impacted during the COVID-19 pandemic (joint CISA/FBI/Treasury/"
                "FinCEN advisory, 2022-06-29/30).",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim-idex", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself MedusaLocker listed 'Idex Group' (idex-group.com) on "
                 "its extortion leak site on 2026-08-16, claiming 30 emails were extracted.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-idex"],
            source_refs=["s-ransomwarelive-idex"], observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes "
                          "the claim was made, not that 30 emails (or any data) were actually "
                          "extracted.",
        ),
        Claim(
            claim_id="c-not-idex-corporation", claim_type=ClaimType.VICTIM_IDENTITY,
            text="'Idex Group' (idex-group.com), the leak-site victim, is NOT the same entity as "
                 "'IDEX Corporation' (idexcorp.com), a large publicly traded (S&P 500) US "
                 "industrial company with a German subsidiary presence. No source located this "
                 "session connects the two.",
            status=EpistemicState.ASSESSED, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="Recorded as an explicit disambiguation, not a positive fact about "
                          "either entity -- a WebSearch for the victim's business description "
                          "surfaced IDEX Corporation prominently due to name similarity. "
                          "idex-group.com itself returned HTTP 503 this session, so no "
                          "independent business description for the ACTUAL victim was obtained; "
                          "none is fabricated here from the unrelated, larger company's profile.",
        ),
        Claim(
            claim_id="c-compromise-occurred-idex", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at Idex Group.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, or regulator filing "
                          "was located. Represented as UNKNOWN, not guessed.",
        ),
        Claim(
            claim_id="c-infra-fingerprint-idex", claim_type=ClaimType.TTP_OBSERVED,
            text="Passive DNS records show Idex Group's domain has Mail Exchange and SPF "
                 "configuration, with no well-known cloud/SaaS service detected.",
            status=EpistemicState.REPORTED, evidence_refs=["e-infra-fingerprint-idex"],
            source_refs=["s-ransomwarelive-idex"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="Infrastructure fingerprinting only -- not evidence of the incident's "
                          "initial-access vector.",
        ),
        Claim(
            claim_id="c-victim-ack-idex", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-idex"],
            source_refs=["s-ransomwarelive-idex"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-medusalocker-history-idex", claim_type=ClaimType.TTP_HISTORICAL,
            text="MedusaLocker has been active since late 2019, primarily gains initial access "
                 "via RDP brute-force and phishing/spam campaigns, and operates a RaaS model in "
                 "which affiliates typically retain 55-60% of ransom proceeds. Per a joint "
                 "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30), the healthcare sector was "
                 "particularly impacted during the COVID-19 pandemic.",
            status=EpistemicState.REPORTED, evidence_refs=["e-medusalocker-advisory-idex"],
            source_refs=["s-cybersecuritydive-medusalocker-idex"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="MedusaLocker",
        victim_name="Idex Group",
        victim_domain="idex-group.com",
        country="Germany",
        sector="Technology (per tracker classification; no independent business description "
               "was obtainable -- idex-group.com returned HTTP 503 this session)",
        claim_date="2026-08-16T15:20:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # ransomware.live gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="'30 emails extracted' per the leak-site post; no further "
                                  "category, sensitivity, or content description given.",
        sample_proof_status=EpistemicState.REPORTED,  # a leak screenshot is referenced; not independently authenticated
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-idex", "c-not-idex-corporation", "c-victim-ack-idex"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-infra-fingerprint-idex"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],
        raas_model_claim_ids=["c-medusalocker-history-idex"],
        historical_ttp_claim_ids=["c-medusalocker-history-idex"],
        historical_tooling_claim_ids=[],
        sectors=["Healthcare (historically, per 2022 CISA advisory)"],
        geographies=[],  # not specified by the source located this session
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Disable or restrict internet-facing RDP; enforce MFA on all "
                            "remote-access and privileged accounts.",
        segmentation="Segment networks to limit lateral movement from an initial foothold.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption activity.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="medusalocker-idex-group-2026-08-16",
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
        "On 2026-08-16, a group identifying itself as MedusaLocker listed 'Idex Group' "
        "(idex-group.com) on its Tor extortion leak site, claiming 30 emails were extracted. "
        "This is a single-source claim; no independent confirmation, victim statement, "
        "regulator filing, or data sample has been located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 15:20 UTC. Country: Germany. Sector: Technology (per tracker "
        "classification only -- idex-group.com itself was unreachable this session, so no "
        "independent business description was obtained). This victim is NOT IDEX Corporation "
        "(idexcorp.com), the unrelated, much larger, publicly traded US industrial company that "
        "surfaces prominently in a name search; no source connects the two, and none of IDEX "
        "Corporation's public profile is used to describe this victim. Passive DNS shows Mail "
        "Exchange and SPF records with no well-known cloud/SaaS service detected; this is "
        "infrastructure fingerprinting only, not evidence of the initial-access vector. Whether "
        "a compromise actually occurred is UNKNOWN on current evidence -- this report does not "
        "assert it did.\n\n"
        "## Actor Historical Context (MedusaLocker, general -- not incident-specific)\n\n"
        "MedusaLocker has been active since late 2019, primarily gains initial access via RDP "
        "brute-force attacks and phishing/spam campaigns, and operates a ransomware-as-a-service "
        "model in which affiliates typically retain 55-60% of ransom proceeds. A joint "
        "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30) found the healthcare sector was "
        "particularly impacted during the COVID-19 pandemic. None of this historical context is "
        "evidence of what happened, if anything, at Idex Group specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, disabling or restricting "
        "internet-facing RDP, MFA, network segmentation, mass-encryption detection, "
        "shadow-copy-deletion monitoring, and a tested IR plan -- is provided as general "
        "hardening, not as evidence any specific technique was used against this victim.\n"
    )

    return ReportBundle(
        report_id="medusalocker-idex-group-2026-08-16",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
