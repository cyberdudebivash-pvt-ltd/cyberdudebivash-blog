"""Golden fixture: Panzer / SAGASTA s.r.o. ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://www.ransomware.live/id/U0FHQVNUQSBzcm9AUGFuemVy
    (leak-site tracker; exact discovery timestamp, country, "46GB" claim,
    a leak screenshot, and a separate HudsonRock infostealer-credential
    signal)
  - https://www.galaxywarden.com/blog/breach/sagasta-sro-panzer-2026-08
    (independent write-up of the same leak-site post; describes the
    claimed data as "internal documents and at least one password field"
    -- a DIFFERENT specific than ransomware.live's "46GB", explicitly kept
    as two separately-sourced, non-contradicting claims rather than
    merged into one over-confident figure; states plainly that SAGASTA
    "has not publicly confirmed any breach or data theft")
  - https://securityarsenal.com/blog/panzer-ransomware-gang-2-new-victims-posted-...
    (actor-historical context: affiliate-recruitment operation, victim
    selection pattern, two other named 2026-08 victims; explicitly does
    NOT state a revenue split or full platform list, so those are left
    NOT_ASSESSED here rather than borrowed from an unverifiable source)
  - https://x.com/DarkWebInformer/status/2085040081098690995
    (WebFetch returned HTTP 402 -- blocked to direct automated fetch.
    Registered as a source with accessibility="BLOCKED_DIRECT_FETCH" and
    reliability=LOW; used ONLY for the narrow, search-engine-indexed claim
    that the group announced an affiliate recruitment program, and is
    NOT used to corroborate anything securityarsenal.com does not itself
    state -- Section 37's "an unfetchable source must not be silently
    upgraded to full reliability" applied here at the source level.)

AFTER-only fixture (same rationale as the Qilin fixture): the BEFORE/AFTER
defect-catalog demonstration already lives in the CVE-2025-62593 pair.
This fixture's job is to exercise the ransomware three-layer model against
a second REAL leak-site claim with a genuinely different shape -- a
brand-new, thinly-documented threat actor and two sources that disagree on
claimed-data specifics without being in direct epistemic conflict.
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
        source_id="s-ransomwarelive", url="https://www.ransomware.live/id/U0FHQVNUQSBzcm9AUGFuemVy",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T17:52:00Z",
        reliability=Reliability.MODERATE, independence_group="panzer-leak-site-post",
        notes="Indexes Panzer's own Tor leak-site post directly; displays a leak screenshot; "
              "explicit site disclaimer that it indexes only publicly visible attacker claims "
              "and does not access or distribute stolen content. Also carries a separate "
              "HudsonRock infostealer signal: 1 third-party employee credential compromised.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-galaxywarden", url="https://www.galaxywarden.com/blog/breach/sagasta-sro-panzer-2026-08",
        publisher="GalaxyWarden", source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.CORROBORATION,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16",
        reliability=Reliability.MODERATE, independence_group="galaxywarden-analysis",
        notes="Independent write-up of the same Panzer leak-site post; describes the claimed "
              "data differently (\"internal documents and at least one password field\", no "
              "volume figure) than ransomware.live's \"46GB\" -- explicitly states the listing "
              "\"establishes only that an accusation has been made, not that a breach occurred\" "
              "and that SAGASTA \"has not publicly confirmed any breach or data theft\".",
    ))
    graph.add_source(SourceRecord(
        source_id="s-securityarsenal", url="https://securityarsenal.com/blog/panzer-ransomware-gang-2-new-victims-posted-energy-and-media-targeting-analysis-detection-rules-and-ir-playbook",
        publisher="Security Arsenal", source_type=SourceType.CTI_VENDOR_RESEARCH, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-09",
        reliability=Reliability.MODERATE, independence_group="securityarsenal-panzer-analysis",
        notes="Own dark-web collection infrastructure; 2 Panzer victim postings observed "
              "2026-08-08 through 2026-08-09 (Siam Oil Product, Thailand, energy; Daily Trust, "
              "Nigeria, media); assesses Panzer 'deliberately selects organizations large enough "
              "to pay seven-figure demands' and scans globally rather than regionally. Does NOT "
              "state an affiliate revenue split or a full supported-platform list.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-darkwebinformer", url="https://x.com/DarkWebInformer/status/2085040081098690995",
        publisher="Dark Web Informer (X/Twitter)", source_type=SourceType.SECURITY_RESEARCHER,
        source_role=SourceRole.ACTOR_CONTEXT, retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.LOW, independence_group="darkwebinformer-x-post",
        accessibility="BLOCKED_DIRECT_FETCH_402",
        notes="WebFetch returned HTTP 402 for this URL -- not independently verified by direct "
              "fetch this session, only by a search-engine-indexed snippet. Used only for the "
              "narrow claim that Panzer announced an affiliate-recruitment program; NOT used to "
              "back any specific (revenue split, platform list) the indexed snippet was "
              "inconsistent about across separate queries.",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-live", source_id="s-ransomwarelive",
        excerpt="SAGASTA sro listed by Panzer 2026-08-16 17:52 UTC; country CZ; design/engineering "
                "sector; claim describes '46GB' of exfiltrated data; leak screenshot displayed; "
                "site notes this is 'an emerging group ... treat with caution until independently "
                "verified'. Separately: 1 third-party employee credential compromised per HudsonRock.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-galaxywarden", source_id="s-galaxywarden",
        excerpt="SAGASTA sro (design and engineering firm specializing in railway, road, bridge, "
                "and water management construction) listed by Panzer; claim describes 'a variety "
                "of internal documents and at least one password field'; no data-volume figure "
                "given; 'SAGASTA has not publicly confirmed any breach or data theft as of this "
                "writing'.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-infostealer-signal", source_id="s-ransomwarelive",
        excerpt="HudsonRock intelligence: 1 third-party employee credential compromised "
                "(infostealer-log signal, not confirmed as the incident's initial-access vector).",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-actor-recruitment", source_id="s-securityarsenal",
        excerpt="Panzer gang confirmed 2 new victim postings 2026-08-08 through 2026-08-09 "
                "(Siam Oil Product, Thailand, energy/utilities; Daily Trust, Nigeria, media); "
                "assessment: 'deliberately selects organizations large enough to pay seven-figure "
                "demands'; scans globally for vulnerable edge appliances rather than focusing "
                "regionally.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-actor-recruitment-x", source_id="s-darkwebinformer",
        excerpt="Search-engine-indexed snippet: 'Panzer ransomware operation launches affiliate "
                "recruitment program ... recruiting penetration testers and other affiliates, "
                "offering access to [a management platform]' (full post text not independently "
                "verified -- direct fetch blocked, HTTP 402).",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself Panzer listed 'SAGASTA sro' on its extortion leak site "
                 "on 2026-08-16, claiming approximately 46GB of exfiltrated data.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-live"], source_refs=["s-ransomwarelive"],
            observed_vs_context=ObservedVsContext.OBSERVED, corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim (the data-volume specific, '46GB', is "
                          "stated only by ransomware.live) per Section 10 policy -- establishes "
                          "the claim was made, not that a 46GB exfiltration actually occurred.",
        ),
        Claim(
            claim_id="c-leak-site-claim-contents", claim_type=ClaimType.VICTIM_IDENTITY,
            text="GalaxyWarden's independent write-up of the same leak-site post describes the "
                 "claimed data as 'internal documents and at least one password field', without "
                 "stating a volume figure.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-galaxywarden"],
            source_refs=["s-galaxywarden"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="Kept as a SEPARATE claim from c-leak-site-claim rather than merged: "
                          "the two sources describe the same underlying leak-site post with "
                          "different specificity, not a directly opposed fact -- not a "
                          "contradiction under Section 11's dimension-consistency test, which "
                          "flags directly opposed EpistemicState values, not differing detail.",
        ),
        Claim(
            claim_id="c-compromise-occurred", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at SAGASTA s.r.o.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, or regulator filing "
                          "was located; GalaxyWarden explicitly states SAGASTA has not confirmed "
                          "a breach. Represented as UNKNOWN, not inferred from the leak claim.",
        ),
        Claim(
            claim_id="c-infostealer-credential", claim_type=ClaimType.TTP_OBSERVED,
            text="HudsonRock infostealer-log data indicates one third-party employee credential "
                 "associated with SAGASTA sro was compromised.",
            status=EpistemicState.REPORTED, evidence_refs=["e-infostealer-signal"],
            source_refs=["s-ransomwarelive"], observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="A distinct signal from the leak-site claim itself; not established as "
                          "the incident's initial-access vector -- no source connects the two.",
        ),
        Claim(
            claim_id="c-victim-ack", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-galaxywarden"],
            source_refs=["s-galaxywarden"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-actor-recruitment", claim_type=ClaimType.TTP_HISTORICAL,
            text="Panzer is a newly observed ransomware operation running an affiliate "
                 "recruitment program; early confirmed victims (2026-08-08 to 2026-08-09) span "
                 "energy/utilities (Thailand) and media (Nigeria); the group appears to select "
                 "targets able to pay seven-figure ransom demands and scans globally rather than "
                 "focusing on one region.",
            status=EpistemicState.REPORTED, evidence_refs=["e-actor-recruitment"],
            source_refs=["s-securityarsenal"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
        Claim(
            claim_id="c-actor-affiliate-announcement", claim_type=ClaimType.TTP_HISTORICAL,
            text="Panzer publicly announced an affiliate recruitment program advertising a "
                 "management platform to prospective affiliates.",
            status=EpistemicState.REPORTED, evidence_refs=["e-actor-recruitment-x"],
            source_refs=["s-darkwebinformer"], observed_vs_context=ObservedVsContext.CONTEXT,
            analyst_notes="Sourced to a search-engine-indexed snippet only; the primary post was "
                          "not independently fetchable this session (HTTP 402). Deliberately kept "
                          "narrow -- does not assert a revenue split or platform list, since no "
                          "independently-fetched source in this graph states either.",
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="Panzer",
        victim_name="SAGASTA s.r.o.",
        victim_domain=None,  # not stated by any source
        country="Czech Republic",
        sector="Design and engineering (railway, road, bridge, and water-management construction)",
        claim_date="2026-08-16T17:52:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # ransomware.live gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Two sources describe this differently: ransomware.live states "
                                  "'46GB' of exfiltrated data; GalaxyWarden states 'internal "
                                  "documents and at least one password field' with no volume "
                                  "figure. Neither has been independently verified.",
        sample_proof_status=EpistemicState.REPORTED,  # ransomware.live displays a leak screenshot; not independently authenticated
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim", "c-leak-site-claim-contents", "c-victim-ack"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-infostealer-credential"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],  # no alias reported by any source located this session
        raas_model_claim_ids=[],  # revenue split NOT independently confirmed -- deliberately empty, not guessed
        historical_ttp_claim_ids=["c-actor-recruitment"],
        historical_tooling_claim_ids=[],  # no tooling/malware-family analysis located this session
        affiliate_behavior_claim_ids=["c-actor-affiliate-announcement"],
        sectors=["Energy/Utilities", "Media", "Design/Engineering"],
        geographies=["Southeast Asia", "West Africa", "Europe"],
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures.",
        identity_hardening="Enforce MFA on all remote-access and privileged accounts; monitor for "
                            "credentials appearing in infostealer-log marketplaces.",
        segmentation="Segment networks to limit lateral movement from an initial foothold.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption activity.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion and backup-service tampering (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks.",
    )

    return RansomwareVictimClaim(
        product_id="panzer-sagasta-sro-2026-08-16",
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
        "On 2026-08-16, a newly observed group identifying itself as Panzer listed 'SAGASTA "
        "s.r.o.' on its Tor extortion leak site. This is a single-source-per-detail claim: two "
        "independent write-ups of the same post describe the claimed data differently, and "
        "neither has been independently verified.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 17:52 UTC. Country: Czech Republic. Sector: design and "
        "engineering. ransomware.live's write-up states '46GB' of exfiltrated data and displays "
        "a leak screenshot; GalaxyWarden's independent write-up of the same post instead "
        "describes 'internal documents and at least one password field' with no volume figure. "
        "Whether a compromise actually occurred is UNKNOWN on current evidence -- this report "
        "does not assert it did. Separately, HudsonRock infostealer-log data shows one "
        "third-party employee credential associated with SAGASTA was compromised; no source "
        "connects this to the leak-site claim's initial-access vector.\n\n"
        "## Actor Historical Context (Panzer, general -- not incident-specific)\n\n"
        "Panzer is a newly observed ransomware operation running a public affiliate-recruitment "
        "program. Security Arsenal's own dark-web collection observed two other Panzer victim "
        "postings within a 48-hour window in early August 2026 -- Siam Oil Product (energy, "
        "Thailand) and Daily Trust (media, Nigeria) -- and assesses that Panzer selects targets "
        "able to pay seven-figure ransom demands, scanning globally rather than focusing on one "
        "region. Panzer's affiliate revenue split and full supported-platform list have not been "
        "independently confirmed and are not stated here. None of this historical context is "
        "evidence of what happened, if anything, at SAGASTA specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, MFA, infostealer-credential "
        "monitoring, network segmentation, mass-encryption detection, shadow-copy-deletion "
        "monitoring, and a tested IR plan -- is provided as general hardening, not as evidence "
        "any specific technique was used against this victim.\n"
    )

    return ReportBundle(
        report_id="panzer-sagasta-sro-2026-08-16",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
