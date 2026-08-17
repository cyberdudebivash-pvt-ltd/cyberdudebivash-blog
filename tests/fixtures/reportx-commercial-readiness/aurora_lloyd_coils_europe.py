"""Golden fixture: Aurora / Lloyd Coils Europe ransomware leak-site claim.

Built from real research retrieved this session (WebSearch + WebFetch,
2026-08-17) against:
  - https://ransomware.live/id/TGxveWQgQ29pbHMgRXVyb3BlQGF1cm9yYQ==
    (leak-site tracker; exact discovery timestamp, sector, country field
    GB, a leak screenshot; HudsonRock infostealer metrics are literally
    redacted with em-dashes on the page -- represented here as
    NOT_ASSESSED, not fabricated)
  - https://www.archilovers.com/teams/621723/lloyd-coils-europe-s-r-o.html
    (independent manufacturer-directory listing: HQ address "Vrazska 143,
    15300 Radotin, Czech Rep.")
  - https://4coilstech.eu/
    (the company's OWN current site -- confirms the identical Radotin,
    Czech Republic address and references a "LEEL Coils Europe" /
    portal.leelcoils.eu rebrand, i.e. the leak-site claim uses a company
    name that has since changed. Two independently-fetched, non-syndicating
    sources agreeing on the same fact -- the first genuinely
    MULTI_SOURCE_INDEPENDENT claim in this fixture set.)
  - https://www.ransomware.live/group/aurora
    (Aurora group operational profile: 31 documented victims, first
    victim 2026-04-17, most recent activity 2026-08-17, sector/country
    distribution, and the page's own characterization: "a ransomware
    group associated with a multi-purpose Go-based malware distributed
    by multiple criminal teams from mid-2022, also sold as an
    infostealer/botnet under the same name")

NAMING-COLLISION CAUTION: a search-indexed (not independently fetched --
X/Twitter, blocked) post from Red Piranha states that "Aurora" is ALSO
used in public reporting for an unrelated, older 2018 "Aurora/OneKeyLocker/
Zorro" ransomware family. This fixture does NOT attribute any 2018-era
history to the group that claimed Lloyd Coils Europe -- every
actor-historical claim here is scoped strictly to what ransomware.live's
own 2026 group page states, exactly the same caution already applied to
the Medusa/MedusaLocker name collision in the Twal Family IT Lab fixture.

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
        source_id="s-ransomwarelive-lce", url="https://ransomware.live/id/TGxveWQgQ29pbHMgRXVyb3BlQGF1cm9yYQ==",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-17T09:52:00Z",
        reliability=Reliability.MODERATE, independence_group="aurora-lloyd-coils-europe-leak-post",
        notes="Indexes Aurora's own Tor leak-site post; sector 'Manufacturing'; country field "
              "'GB'; leak screenshot referenced; HudsonRock infostealer metrics shown as "
              "em-dash-redacted placeholders on the page (no numbers actually stated). Site "
              "disclaimer: indexes only publicly visible attacker claims, does not host stolen "
              "content.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-archilovers-lce", url="https://www.archilovers.com/teams/621723/lloyd-coils-europe-s-r-o.html",
        publisher="Archilovers (manufacturer directory)", source_type=SourceType.OTHER,
        source_role=SourceRole.CORROBORATION, retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.MODERATE, independence_group="archilovers-directory",
        notes="Manufacturer-directory profile page; HQ address 'Vrazska 143, 15300 Radotin, "
              "Czech Rep.'",
    ))
    graph.add_source(SourceRecord(
        source_id="s-4coilstech-lce", url="https://4coilstech.eu/",
        publisher="4 Coils Tech s.r.o. (the company's own current site)",
        source_type=SourceType.VICTIM_STATEMENT, source_role=SourceRole.CORROBORATION,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="4coilstech-own-site",
        notes="The company's own current website; confirms HQ 'Vrazska 143, 153 00 Prague 5 - "
              "Radotin, Czech Republic' (same address as Archilovers, independently); "
              "references a 'LEEL Coils Europe' rebrand and a customer portal at "
              "portal.leelcoils.eu -- the leak-site claim uses the company's FORMER name.",
    ))
    graph.add_source(SourceRecord(
        source_id="s-ransomwarelive-aurora-group", url="https://www.ransomware.live/group/aurora",
        publisher="ransomware.live (group profile)", source_type=SourceType.LEAK_SITE_AGGREGATOR,
        source_role=SourceRole.ACTOR_CONTEXT, retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-17",
        reliability=Reliability.MODERATE, independence_group="ransomwarelive-aurora-group-profile",
        notes="Aurora group profile page (distinct URL from the victim-specific page): 31 "
              "documented victims; first victim est. 2026-04-17, most recent activity "
              "2026-08-17; top sectors Manufacturing (11), Professional Services (6), Retail & "
              "E-Commerce (4); top countries United States (9), Germany (6), Netherlands (3); "
              "page's own characterization: 'a ransomware group associated with a multi-purpose "
              "Go-based malware distributed by multiple criminal teams from mid-2022, also sold "
              "as an infostealer/botnet under the same name'.",
    ))

    graph.add_evidence(EvidenceRecord(
        evidence_id="e-claim-post-lce", source_id="s-ransomwarelive-lce",
        excerpt="Lloyd Coils Europe listed by Aurora, discovered 2026-08-17 09:52 UTC, est. "
                "attack date 2026-08-17; sector Manufacturing; country GB; leak screenshot "
                "referenced; HudsonRock infostealer metrics redacted (em-dashes, no numbers "
                "stated).",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-hq-archilovers", source_id="s-archilovers-lce",
        excerpt="Lloyd Coils Europe s.r.o. headquarters: Vrazska 143, 15300 Radotin, Czech Rep.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-hq-4coilstech", source_id="s-4coilstech-lce",
        excerpt="Company's own site: 'Vrazska 143, 153 00 Prague 5 - Radotin, Czech Republic'; "
                "references 'LEEL Coils Europe' branding and a customer portal at "
                "portal.leelcoils.eu.",
    ))
    graph.add_evidence(EvidenceRecord(
        evidence_id="e-aurora-group-profile", source_id="s-ransomwarelive-aurora-group",
        excerpt="31 documented Aurora victims; activity 2026-04-17 through 2026-08-17; top "
                "sectors Manufacturing/Professional Services/Retail & E-Commerce; top countries "
                "US/Germany/Netherlands; described as linked to a multi-purpose Go-based "
                "malware distributed by multiple criminal teams since mid-2022, also sold as an "
                "infostealer/botnet under the same name.",
    ))

    claims = [
        Claim(
            claim_id="c-leak-site-claim-lce", claim_type=ClaimType.VICTIM_IDENTITY,
            text="A group calling itself Aurora listed 'Lloyd Coils Europe' on its extortion "
                 "leak site on 2026-08-17.",
            status=EpistemicState.REPORTED, evidence_refs=["e-claim-post-lce"],
            source_refs=["s-ransomwarelive-lce"], observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.SINGLE_SOURCE,
            analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes "
                          "the claim was made, not that compromise/encryption/theft occurred.",
        ),
        Claim(
            claim_id="c-hq-context-lce", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Lloyd Coils Europe s.r.o. is headquartered in Radotin, near Prague, Czech "
                 "Republic, and has since rebranded to 'LEEL Coils Europe' -- the leak-site "
                 "claim uses the company's former name.",
            status=EpistemicState.CONFIRMED, evidence_refs=["e-hq-archilovers", "e-hq-4coilstech"],
            source_refs=["s-archilovers-lce", "s-4coilstech-lce"],
            observed_vs_context=ObservedVsContext.OBSERVED,
            corroboration_state=CorroborationState.MULTI_SOURCE_INDEPENDENT,
            analyst_notes="Two independently-fetched, non-syndicating sources (a manufacturer "
                          "directory and the company's own current site) state the identical "
                          "address independently -- CONFIRMED, and genuinely "
                          "MULTI_SOURCE_INDEPENDENT (different independence_group each). "
                          "ransomware.live's own 'GB' country field is NOT overwritten by this "
                          "claim -- it may refer specifically to a UK-registered entity within "
                          "the same corporate family; both facts are recorded rather than one "
                          "silently replacing the other.",
        ),
        Claim(
            claim_id="c-compromise-occurred-lce", claim_type=ClaimType.DATA_THEFT,
            text="Whether an actual compromise or data theft occurred at Lloyd Coils Europe.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.OBSERVED,
            analyst_notes="No independent confirmation, victim statement, or regulator filing "
                          "was located. Represented as UNKNOWN, not guessed.",
        ),
        Claim(
            claim_id="c-victim-ack-lce", claim_type=ClaimType.VICTIM_IDENTITY,
            text="Victim acknowledgement of the incident.",
            status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-lce"],
            source_refs=["s-ransomwarelive-lce"], observed_vs_context=ObservedVsContext.OBSERVED,
        ),
        Claim(
            claim_id="c-aurora-operational-profile", claim_type=ClaimType.TTP_HISTORICAL,
            text="Aurora's leak site had listed 31 documented victims as of 2026-08-17 (first "
                 "victim est. 2026-04-17), concentrated in Manufacturing, Professional Services, "
                 "and Retail & E-Commerce sectors and in the United States, Germany, and the "
                 "Netherlands. ransomware.live characterizes the group as linked to a "
                 "multi-purpose Go-based malware distributed by multiple criminal teams since "
                 "mid-2022 that is also sold as an infostealer/botnet under the same name.",
            status=EpistemicState.REPORTED, evidence_refs=["e-aurora-group-profile"],
            source_refs=["s-ransomwarelive-aurora-group"], observed_vs_context=ObservedVsContext.CONTEXT,
        ),
        Claim(
            claim_id="c-aurora-naming-ambiguity", claim_type=ClaimType.ACTOR_ATTRIBUTION,
            text="Whether the 2026 Aurora leak-site operation is related to the unrelated, older "
                 "'Aurora/OneKeyLocker/Zorro' ransomware family first reported in 2018.",
            status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
            observed_vs_context=ObservedVsContext.CONTEXT,
            analyst_notes="A search-indexed post raising this distinction could not be "
                          "independently fetched (X/Twitter, blocked) this session. Represented "
                          "as UNKNOWN rather than either asserting or dismissing a lineage "
                          "connection -- no 2018-era TTPs are attributed to this incident.",
        ),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="Aurora",
        victim_name="Lloyd Coils Europe",
        victim_domain=None,  # not stated by the leak-site source; 4coilstech.eu/leelcoils.eu are the CURRENT rebranded entity's domains, not necessarily the entity as named in the claim
        country="United Kingdom",  # per ransomware.live's own field -- see c-hq-context-lce for the parent group's Czech HQ, recorded separately rather than overwriting this
        sector="Manufacturing (heat exchangers / HVAC&R components, per corporate-group sourcing)",
        claim_date="2026-08-17T09:52:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,  # ransomware.live gives an exact UTC time
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Not specified by the source beyond a generic compromise claim; "
                                  "no data category, volume, or sample described.",
        sample_proof_status=EpistemicState.REPORTED,  # a leak screenshot is referenced; not independently authenticated
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-lce", "c-hq-context-lce", "c-victim-ack-lce"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=[],  # infostealer signal was redacted at the source; nothing to cite
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],  # deliberately empty -- see c-aurora-naming-ambiguity
        raas_model_claim_ids=[],  # no affiliate revenue split located this session
        historical_ttp_claim_ids=["c-aurora-operational-profile"],
        historical_tooling_claim_ids=[],  # tooling lineage is exactly what c-aurora-naming-ambiguity leaves UNKNOWN
        sectors=["Manufacturing", "Professional Services", "Retail & E-Commerce"],
        geographies=["United States", "Germany", "Netherlands"],
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
        product_id="aurora-lloyd-coils-europe-2026-08-17",
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
        "On 2026-08-17, a group identifying itself as Aurora listed 'Lloyd Coils Europe' on its "
        "Tor extortion leak site. This is a single-source claim; no independent confirmation, "
        "victim statement, regulator filing, or data sample has been located.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-17 09:52 UTC. ransomware.live's own record lists country as United "
        "Kingdom; two independently-fetched sources (a manufacturer directory and the company's "
        "own current website) confirm the broader corporate group is headquartered in Radotin, "
        "near Prague, Czech Republic, and has since rebranded to 'LEEL Coils Europe' -- the "
        "leak-site claim uses the company's former name. Both facts are recorded rather than one "
        "overwriting the other. HudsonRock infostealer metrics were redacted at the source (no "
        "numbers stated) and are not fabricated here. Whether a compromise actually occurred is "
        "UNKNOWN on current evidence -- this report does not assert it did.\n\n"
        "## Actor Historical Context (Aurora, general -- not incident-specific)\n\n"
        "As of 2026-08-17, Aurora's leak site had listed 31 documented victims since an "
        "estimated first victim on 2026-04-17, concentrated in Manufacturing, Professional "
        "Services, and Retail & E-Commerce sectors, and in the United States, Germany, and the "
        "Netherlands. ransomware.live characterizes the group as linked to a multi-purpose "
        "Go-based malware distributed by multiple criminal teams since mid-2022 that is also "
        "sold as an infostealer/botnet under the same name. Public reporting has also used the "
        "name 'Aurora' for an unrelated, older 2018 ransomware family; whether any lineage "
        "connects the two is UNKNOWN and no 2018-era history is attributed to this incident. "
        "None of this historical context is evidence of what happened, if anything, at Lloyd "
        "Coils Europe specifically.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, MFA, network segmentation, "
        "mass-encryption detection, shadow-copy-deletion monitoring, and a tested IR plan -- is "
        "provided as general hardening, not as evidence any specific technique was used against "
        "this victim.\n"
    )

    return ReportBundle(
        report_id="aurora-lloyd-coils-europe-2026-08-17",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={},
        threat_products=[claim],
        intelligence_gaps=[],  # populated via analytic_scaffolding.derive_ransomware_gaps() in tests
        is_premium_tier=False,
    )
