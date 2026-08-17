"""Golden fixture: MedusaLocker / Bija Industrie ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://www.ransomware.live/id/QmlqYSBJbmR1c3RyaWVAbWVkdXNhbG9ja2Vy
    (leak-site tracker; exact discovery timestamp, domain
    bija-industrie.com, country FR, sector Manufacturing, claim of '693
    emails extracted', a detected Mailinblack cloud/SaaS email-security
    service, DNS/WHOIS fingerprinting)
  - https://bija-industrie.com
    (the victim's own current site -- independently confirms it is a
    French aerospace/industrial tooling manufacturer with 20+ years of
    aerospace experience serving civil AND MILITARY aviation programs;
    a genuine VICTIM_STATEMENT-tier source, refining the tracker's
    generic 'Manufacturing' classification with the entity's own,
    more specific description)
  - MedusaLocker actor-historical context reuses the SAME already-verified
    facts from the Twal Family IT Lab, All Parts Dry Cleaning, and Idex
    Group fixtures (cybersecuritydive.com's reporting on the 2022
    CISA/FBI/Treasury/FinCEN joint advisory).

No second independent leak-site-specific source was located
(redpacketsecurity.com's write-up was not fetched directly, consistent
with the HTTP 403 seen on other fixtures in this set; cyberattaque.org
had no indexed page for this specific victim) -- represented honestly as
SINGLE_SOURCE for the leak-site claim itself.

The military-aviation detail from the victim's own site is retained
because it is directly self-stated by the entity (not inferred or
guessed) and is analytically relevant (defense-industrial-base exposure
context) -- but no claim in this fixture asserts that any specific data,
military or otherwise, was actually exfiltrated; the leak-site claim
itself only states an email count, and whether any compromise occurred
at all remains UNKNOWN per the same discipline as every other fixture
in this set.

AFTER-only, same rationale as the other ransomware fixtures. This is the
10th and final golden fixture for ReportX Section 34/42's named
acceptance-case set.
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
        source_id="s-ransomwarelive-bija", url="https://www.ransomware.live/id/QmlqYSBJbmR1c3RyaWVAbWVkdXNhbG9ja2Vy",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T15:20:00Z",
        reliability=Reliability.MODERATE, independence_group="medusalocker-bija-industrie-leak-post",
        notes="Indexes MedusaLocker's own Tor leak-site post; domain bija-industrie.com; country "
              "FR; sector classified 'Manufacturing'; claim describes '693 emails extracted'; "
              "leak screenshot referenced; Mailinblack (email-security SaaS) detected via cloud/"
              "SaaS fingerprinting; DNS (MX, TXT, WHOIS emails) documented.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-bija-own-site", url="https://bija-industrie.com",
        publisher="BIJA Industrie (the company's own site)",
        source_type=SourceType.VICTIM_STATEMENT, source_role=SourceRole.CORROBORATION,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="bija-own-site",
        notes="Company's own self-description: design, manufacture, and distribution of "
              "specialized tools for aerospace and industrial sectors; 20+ years of aerospace "
              "experience; serves civil AND military aviation programs; three brands (BIJA "
              "Industrie, MMI, MRO Integral Solutions).",
    ))
    graph.add_source(SourceRecord(
        source_id="s-cybersecuritydive-medusalocker-bija", url="https://www.cybersecuritydive.com/news/fbi-cisa-medusalocker-ransomware/626483/",
        publisher="Cybersecurity Dive", source_type=SourceType.JOURNALISM, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2022-07-01",
        reliability=Reliability.MODERATE, independence_group="cybersecuritydive-medusalocker-2022",
        notes="Same source already verified for the Twal Family IT Lab, All Parts Dry Cleaning, "
              "and Idex Group fixtures this session: reports on the CISA/FBI/Treasury/FinCEN "
              "joint advisory (AA22-181A, 2022-06-29/30) -- active since late 2019, RDP "
              "brute-force/phishing initial access, 55-60% affiliate/developer ransom split, "
              "healthcare heavily impacted during COVID-19.",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-bija", source_id="s-ransomwarelive-bija",
        excerpt="Bija Industrie listed by MedusaLocker, discovered 2026-08-16 15:20 UTC, est. "
                "attack date 2026-08-16; domain bija-industrie.com; country FR; sector "
                "Manufacturing; claim describes '693 emails extracted'.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-infra-fingerprint-bija", source_id="s-ransomwarelive-bija",
        excerpt="Mailinblack (email-security SaaS) detected; DNS (MX, TXT, WHOIS emails) "
                "documented. Infrastructure fingerprinting only, not evidence of the "
                "initial-access vector.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-bija-self-description", source_id="s-bija-own-site",
        excerpt="'conception, la fabrication et la distribution d'outils et d'outillages "
                "specifiques pour les secteurs aeronautiques et industriels' (design, "
                "manufacturing, and distribution of specialized tools for aerospace and "
                "industrial sectors); 20+ years of aerospace experience; serves civil and "
                "military aviation programs; three brands (BIJA Industrie, MMI, MRO Integral "
                "Solutions).",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-medusalocker-advisory-bija", source_id="s-cybersecuritydive-medusalocker-bija",
        excerpt="MedusaLocker active since late 2019; initial access via RDP brute force and "
                "phishing/spam campaigns; RaaS split -- affiliates typically receive 55-60% of "
                "ransom proceeds, developer receives the remainder; healthcare sector "
                "particularly impacted during the COVID-19 pandemic (joint CISA/FBI/Treasury/"
                "FinCEN advisory, 2022-06-29/30).",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim-bija", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself MedusaLocker listed 'Bija Industrie' (bija-industrie.com) "
                 "on its extortion leak site on 2026-08-16, claiming 693 emails were extracted.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-bija"],
            source_refs=["s-ransomwarelive-bija"], observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes "
                          "the claim was made, not that 693 emails (or any data) were actually "
                          "extracted.",
        ),
        Claim(
            claim_id="c-victim-business-description-bija", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Bija Industrie is a French manufacturer of specialized tooling for the "
                 "aerospace and industrial sectors, with 20+ years of aerospace experience "
                 "serving both civil and military aviation programs, per its own site.",
            status=EpistemicState.CONFIRMED, evidence_refs=["e-bija-self-description"],
            source_refs=["s-bija-own-site"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="CONFIRMED because this is the entity's own self-description, refining "
                          "the tracker's generic 'Manufacturing' classification. Recorded for "
                          "defense-industrial-base context only -- no claim in this fixture "
                          "asserts that military-program-specific or any other specific data "
                          "was actually exfiltrated; the leak-site claim itself states only an "
                          "email count.",
        ),
        Claim(
            claim_id="c-compromise-occurred-bija", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at Bija Industrie.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, or regulator filing "
                          "was located. Represented as UNKNOWN, not guessed -- including for the "
                          "aerospace/military-adjacent context noted above.",
        ),
        Claim(
            claim_id="c-infra-fingerprint-bija", claim_type=ClaimType.TTP_OBSERVED,
            text="Passive fingerprinting shows Bija Industrie uses Mailinblack for email "
                 "security, with DNS (MX/TXT/WHOIS) records documented.",
            status=EpistemicState.REPORTED, evidence_refs=["e-infra-fingerprint-bija"],
            source_refs=["s-ransomwarelive-bija"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="Infrastructure fingerprinting only -- not evidence of the incident's "
                          "initial-access vector.",
        ),
        Claim(
            claim_id="c-victim-ack-bija", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-bija"],
            source_refs=["s-ransomwarelive-bija"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-medusalocker-history-bija", claim_type=ClaimType.TTP_HISTORICAL,
            text="MedusaLocker has been active since late 2019, primarily gains initial access "
                 "via RDP brute-force and phishing/spam campaigns, and operates a RaaS model in "
                 "which affiliates typically retain 55-60% of ransom proceeds. Per a joint "
                 "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30), the healthcare sector was "
                 "particularly impacted during the COVID-19 pandemic.",
            status=EpistemicState.REPORTED, evidence_refs=["e-medusalocker-advisory-bija"],
            source_refs=["s-cybersecuritydive-medusalocker-bija"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="MedusaLocker",
        victim_name="Bija Industrie",
        victim_domain="bija-industrie.com",
        country="France",
        sector="Manufacturing -- specialized aerospace and industrial tooling (per the victim's "
               "own site; serves civil and military aviation programs)",
        claim_date="2026-08-16T15:20:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # ransomware.live gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="'693 emails extracted' per the leak-site post; no further "
                                  "category, sensitivity, or content description given.",
        sample_proof_status=EpistemicState.REPORTED,  # a leak screenshot is referenced; not independently authenticated
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-bija", "c-victim-business-description-bija", "c-victim-ack-bija"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-infra-fingerprint-bija"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],
        raas_model_claim_ids=["c-medusalocker-history-bija"],
        historical_ttp_claim_ids=["c-medusalocker-history-bija"],
        historical_tooling_claim_ids=[],
        sectors=["Healthcare (historically, per 2022 CISA advisory)"],
        geographies=[],  # not specified by the source located this session
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Disable or restrict internet-facing RDP; enforce MFA on all "
                            "remote-access and privileged accounts.",
        segmentation="Segment networks to limit lateral movement from an initial foothold; "
                     "consider heightened scrutiny given exposure to defense-industrial-base "
                     "supply-chain risk.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption activity.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="medusalocker-bija-industrie-2026-08-16",
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
        "On 2026-08-16, a group identifying itself as MedusaLocker listed 'Bija Industrie' "
        "(bija-industrie.com) on its Tor extortion leak site, claiming 693 emails were "
        "extracted. This is a single-source claim; no independent confirmation, victim "
        "statement, regulator filing, or data sample has been located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 15:20 UTC. Country: France. Per the company's own site, Bija "
        "Industrie manufactures specialized tooling for the aerospace and industrial sectors, "
        "with over 20 years of aerospace experience serving both civil and military aviation "
        "programs. This context is recorded for defense-industrial-base relevance only -- the "
        "leak-site claim itself describes only an email count, and whether any compromise "
        "actually occurred, military-program-related or otherwise, is UNKNOWN on current "
        "evidence; this report does not assert it did. Separately, passive fingerprinting shows "
        "the organization uses Mailinblack for email security, with standard DNS records "
        "documented; this is infrastructure fingerprinting only, not evidence of the "
        "initial-access vector.\n\n"
        "## Actor Historical Context (MedusaLocker, general -- not incident-specific)\n\n"
        "MedusaLocker has been active since late 2019, primarily gains initial access via RDP "
        "brute-force attacks and phishing/spam campaigns, and operates a ransomware-as-a-service "
        "model in which affiliates typically retain 55-60% of ransom proceeds. A joint "
        "CISA/FBI/Treasury/FinCEN advisory (2022-06-29/30) found the healthcare sector was "
        "particularly impacted during the COVID-19 pandemic. None of this historical context is "
        "evidence of what happened, if anything, at Bija Industrie specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, disabling or restricting "
        "internet-facing RDP, MFA, network segmentation, mass-encryption detection, "
        "shadow-copy-deletion monitoring, and a tested IR plan -- is provided as general "
        "hardening, not as evidence any specific technique was used against this victim.\n"
    )

    return ReportBundle(
        report_id="medusalocker-bija-industrie-2026-08-16",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
