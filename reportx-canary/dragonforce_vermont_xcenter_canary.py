"""ReportX Phase 4 real premium canary C: DragonForce / Vermont XCenter.

SELECTION RATIONALE (Section 6 of the P0-continuation task mandate: choose
the strongest of DragonForce/Vermont XCenter, Aurora/Lloyd Coils Europe,
Panzer/SAGASTA sro on evidence quality, not ease of forcing 23/23):

  - Aurora/Lloyd Coils Europe carries TWO distinct identity-ambiguity
    problems in its own golden fixture: a victim country/entity discrepancy
    (ransomware.live's own 'GB' field vs. the corporate group's real
    Radotin, Czech Republic HQ) requiring a dedicated non-overwriting
    claim to reconcile, AND an explicitly flagged, unresolved naming
    collision with an unrelated 2018 'Aurora/OneKeyLocker/Zorro'
    ransomware family. Its actor-context is also comparatively thin: one
    source (ransomware.live's own group page), no independent CTI-vendor
    deep-dive.
  - Panzer/SAGASTA sro's own golden fixture states plainly that Panzer is
    "a newly observed ransomware operation" -- no confirmed affiliate
    revenue split, no confirmed tooling/malware-family lineage, no
    multi-year track record. This is the highest-risk choice for reaching
    genuine (non-padded) premium depth: Section 8 of the task mandate is
    explicit that a report unable to reach premium depth honestly must
    not be padded, and a stronger canary should be selected instead.
  - DragonForce/Vermont XCenter has: the richest available actor-context
    (a named Group-IB research team AND a dedicated, current, February
    2026 Blackpoint Cyber threat-profile PDF with a full MITRE ATT&CK
    lifecycle mapping, a real cited CVE-exploitation table, and an
    "Associations" section), genuine independent multi-source
    corroboration (both vendors independently confirm the 80% affiliate
    split and the two-variant LockBit/Conti-fork lineage), a
    substantial, real, and CURRENT 2025-2026 operational evolution
    (RaaS -> "ransomware cartel" -> LockBit partnership -> a paid
    victim-profiling service), zero flagged naming-collision risk for
    the actor's own primary name, and a comparatively large, well-
    documented victim-side infostealer-exposure signal. This is the
    strongest evidence base of the three by every one of the task's
    named criteria except raw claimed-data specificity (where Panzer's
    two-source detail split is marginally richer) -- outweighed here by
    DragonForce's overwhelming advantage in actor-context depth and
    corroboration.

Built from real research retrieved this session (WebSearch + WebFetch +
direct curl, 2026-08-17/18) against FIVE independently retrieved sources,
all fetched as raw bytes via direct HTTP fetch (curl) and checked into
`reportx-canary/raw-sources/`; every source's `content_sha256` is computed
from those exact files at import time -- see
`evidence_integrity.compute_content_sha256`. Every one of this canary's
five sources was fetchable in full -- no excerpt-fingerprint fallback is
used here.

This canary extends (not replaces) the earlier, deliberately modest golden
fixture at
`tests/fixtures/reportx-commercial-readiness/dragonforce_vermont_xcenter.py`
(``is_premium_tier=False``, no detection/forecast/hypothesis/regulatory
content).

Sources:
  - ransomware.live's Vermont XCenter victim page -- the leak-site claim
    itself. Country Brazil (confirmed via the page's own `flags/BR.svg`
    reference). Discovered 2026-08-17 09:24 UTC. No data-volume figure
    stated -- the tracker's own "Description" field is auto-scraped from
    the victim's own site metadata, not a distinct claim about stolen
    data (verified directly against the raw HTML this session). HudsonRock
    infostealer signal: 2 compromised employees, 48 compromised users, 9
    third-party employee credentials, 18 external attack-surface
    exposures. DNS fingerprint: MX to vermont-com-br.mail.protection.
    outlook.com (Microsoft 365), SPF including mail.zendesk.com, no WHOIS
    emails found.
  - vermont.com.br (the victim's own current site, Portuguese) --
    independently confirms, in the company's own words, "Atuando ha quase
    tres decadas" (operating for almost three decades) as an omnichannel
    contact-center/BPO. Also documents a "Vermont Health" service line
    (patient registration, pharmacovigilance support, healthcare-
    professional support) -- retained as real, self-stated context, never
    escalated into an incident-specific data-sensitivity claim.
  - Group-IB, "Inside the Dragon: DragonForce Ransomware Group" (published
    2024-09-25, named analysts) -- discovery August 2023, RaaS/affiliate
    program advertised June 2024 on the RAMP forum, an 80% affiliate
    revenue quote, two Windows variants (a LockBit 3.0-derived build and a
    ContiV3-based build with BYOVD and scheduled-task persistence), and
    SystemBC/Cobalt Strike/Mimikatz tooling.
  - Blackpoint Cyber's "DragonForce Ransomware Threat Profile" PDF
    (published February 2026, 30 pages) -- a full Diamond Model, a real
    cited Known-Exploited-Vulnerabilities table (11 CVEs, 2021-2024,
    including three 2024 SimpleHelp RMM CVEs), a comprehensive MITRE
    ATT&CK lifecycle mapping (initial access through impact), a named
    "Known Tools" table, and an "Associations" section that explicitly
    frames the actor's own most sensitive identity question -- any link
    to the 2023 Malaysian hacktivist collective "DragonForce Malaysia" --
    as unconfirmed ("there is an even chance ... has yet to be
    confirmed"), independently corroborating Group-IB's 80%-split and
    two-variant facts, and documenting the March 2025 "ransomware cartel"
    rebrand, the August 2025 LockBit partnership, and an August 2025
    paid victim-profiling service.
  - ransomware.live's DragonForce group aggregate page -- the tracker's
    own current (2026-08-17) stats: 639 total tracked victims, 65
    countries hit, a 19.0-day average attack-to-claim delay, and 28.2% of
    tracked victims showing infostealer-log domain overlap. Also surfaces
    a genuine, unresolved discrepancy this canary does not silently
    correct in either direction: the tracker's own earliest tracked
    victim has an estimated attack date of 2022-10-20, which PREDATES
    both named vendors' "discovered/first identified August 2023" dating
    -- represented here as an explicit, open temporal gap.

None of the actor-context, TTP, cartel-evolution, or current-scale
material below is evidence of what happened, if anything, at Vermont
XCenter specifically -- every such claim is tagged
``ObservedVsContext.CONTEXT`` and is never merged with the victim
observation layer's ``OBSERVED`` claims. The historical CVE-exploitation
table is actor CAPABILITY only; no source connects any specific CVE to
the Vermont XCenter incident, and this report does not claim one did.
"""

from __future__ import annotations

from pathlib import Path

from sentinel_engine.reportx.analytic_scaffolding import (
    Hypothesis,
    HypothesisSet,
    IntelligenceGap,
    derive_ransomware_gaps,
)
from sentinel_engine.reportx.claim_model import (
    Claim,
    ClaimType,
    Confidence,
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
from sentinel_engine.reportx.detection_validation import DetectionRule, DetectionValidationState
from sentinel_engine.reportx.evidence_integrity import compute_content_sha256
from sentinel_engine.reportx.forecast import Forecast
from sentinel_engine.reportx.metrics_registry import ExternalMetric, MetricsRegistry
from sentinel_engine.reportx.product_depth import DepthAssessment
from sentinel_engine.reportx.regulatory import ApplicabilityState, RegulatoryApplicability, not_assessed
from sentinel_engine.reportx.threat_schemas import ActorHistoricalContext, GenericReadiness, RansomwareVictimClaim, VictimObservation

RAW_SOURCES_DIR = Path(__file__).resolve().parent / "raw-sources"


def _hash_raw(filename: str) -> str:
    """Computes content_sha256 from the actual checked-in raw retrieval --
    never hand-typed, so it can never silently drift from the real file."""
    return compute_content_sha256((RAW_SOURCES_DIR / filename).read_bytes())


def build_graph() -> EvidenceGraph:
    graph = EvidenceGraph()

    ransomwarelive_hash = _hash_raw("vermont-ransomwarelive.html")
    graph.add_source(SourceRecord(
        source_id="s-ransomwarelive-vxc", url="https://www.ransomware.live/id/VmVybW9udCBYQ2VudGVyQGRyYWdvbmZvcmNl",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-17T09:24:00Z",
        reliability=Reliability.MODERATE, independence_group="dragonforce-vermont-leak-post",
        content_sha256=ransomwarelive_hash,
        notes="Indexes DragonForce's own Tor leak-site post; domain vermont.com.br; country BR "
              "(confirmed via flags/BR.svg); sector field 'Not Found' at the tracker itself. The page's "
              "'Description' field auto-scrapes the victim's own site meta-description, not a distinct "
              "claim about stolen data. HudsonRock: 2 compromised employees, 48 compromised users, 9 "
              "third-party employee credentials, 18 external attack-surface exposures. DNS: MX to "
              "vermont-com-br.mail.protection.outlook.com (Microsoft 365), SPF includes mail.zendesk.com, "
              "no WHOIS emails found.",
    ))

    vermont_site_hash = _hash_raw("vermont-com-br.html")
    graph.add_source(SourceRecord(
        source_id="s-vermont-own-site", url="https://vermont.com.br",
        publisher="Vermont XCenter (the company's own site, Portuguese)",
        source_type=SourceType.VICTIM_STATEMENT, source_role=SourceRole.CORROBORATION,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="vermont-own-site",
        content_sha256=vermont_site_hash,
        notes="Company's own self-description: 'Atuando ha quase tres decadas' (operating for almost "
              "three decades), an omnichannel contact-center/BPO. A distinct 'Vermont Health' service "
              "line is documented: patient registration, pharmacovigilance support, healthcare-"
              "professional support.",
    ))

    groupib_hash = _hash_raw("groupib-dragonforce.html")
    graph.add_source(SourceRecord(
        source_id="s-groupib-dragonforce", url="https://www.group-ib.com/blog/dragonforce-ransomware/",
        publisher="Group-IB ('Inside the Dragon: DragonForce Ransomware Group', by named analysts Nikolay "
                   "Kichatov, Sharmine Low, Alexey Kashtanov)",
        source_type=SourceType.CTI_VENDOR_RESEARCH, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2024-09-25",
        reliability=Reliability.MODERATE, independence_group="groupib-dragonforce-profile",
        content_sha256=groupib_hash,
        notes="Discovered August 2023; RaaS affiliate program advertised June 2024 on the RAMP forum, "
              "offering affiliates 80% of ransom revenue; two Windows variants (a LockBit 3.0-derived "
              "build and a ContiV3-based build with BYOVD and scheduled-task persistence); SystemBC/"
              "Cobalt Strike/Mimikatz tooling; double extortion.",
    ))

    blackpoint_hash = _hash_raw("blackpoint-dragonforce.pdf")
    graph.add_source(SourceRecord(
        source_id="s-blackpoint-dragonforce", url="https://blackpointcyber.com/wp-content/uploads/2026/02/DragonForce-1.pdf",
        publisher="Blackpoint Cyber ('DragonForce Ransomware Threat Profile', 30 pages)",
        source_type=SourceType.CTI_VENDOR_RESEARCH, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-02-01",
        reliability=Reliability.MODERATE, independence_group="blackpoint-dragonforce-profile",
        content_sha256=blackpoint_hash,
        notes="Current (Feb 2026) threat profile: Diamond Model, a cited Known-Exploited-Vulnerabilities "
              "table (11 CVEs, 2021-2024), a full MITRE ATT&CK lifecycle mapping, a named Known Tools "
              "table, and an Associations section documenting the March 2025 'ransomware cartel' rebrand, "
              "the August 2025 LockBit partnership, an August 2025 paid victim-profiling service, and "
              "explicit, unresolved uncertainty ('even chance ... has yet to be confirmed') about any link "
              "to the hacktivist group 'DragonForce Malaysia'. Corroborates Group-IB's 80% affiliate-split "
              "and two-variant facts independently.",
    ))

    group_stats_hash = _hash_raw("ransomwarelive-dragonforce-group.html")
    graph.add_source(SourceRecord(
        source_id="s-ransomwarelive-dragonforce-group", url="https://www.ransomware.live/group/dragonforce",
        publisher="ransomware.live (leak-site tracker, group aggregate page)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.STATISTICAL_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-17",
        reliability=Reliability.MODERATE, independence_group="dragonforce-vermont-leak-post",
        content_sha256=group_stats_hash,
        notes="The tracker's own current (2026-08-17) aggregate stats: 639 total tracked victims, first "
              "tracked victim's est. attack date 2022-10-20 (predates named-vendor 'August 2023 "
              "discovery' dating -- an open, unresolved discrepancy, not corrected in either direction "
              "here), discovery date 2023-12-13, 65 countries hit, 19.0-day average attack-to-claim "
              "delay, 28.2% of tracked victims show infostealer-log domain overlap, last-seen 2026-08-17 "
              "(Vermont XCenter is the group's own most recently tracked victim). Same aggregator/tool as "
              "the Vermont-specific claim, hence the SAME independence_group.",
    ))

    # ------------------------------------------------------------------
    # Evidence records
    # ------------------------------------------------------------------
    graph.add_evidence(EvidenceRecord(evidence_id="e-claim-post-vxc", source_id="s-ransomwarelive-vxc",
        excerpt="Vermont XCenter listed by DragonForce, discovered 2026-08-17 09:24 UTC, est. attack date "
                "2026-08-17; domain vermont.com.br; country BR (flags/BR.svg); sector 'Not Found' at the "
                "tracker. No distinct data-volume or category claim -- the 'Description' field is the "
                "victim's own scraped site meta-description."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-infostealer-signal-vxc", source_id="s-ransomwarelive-vxc",
        excerpt="Infostealer activity detected by HudsonRock. Compromised Employees: 2. Compromised "
                "Users: 48. Third Party Employee Credentials: 9. External Attack Surface: 18."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-infra-fingerprint-vxc", source_id="s-ransomwarelive-vxc",
        excerpt="MX Records: vermont-com-br.mail.protection.outlook.com (Microsoft 365). TXT Records: "
                "v=spf1 include:spf.protection.outlook.com include:mail.zendesk.com -all. Cloud/SaaS "
                "Services Detected: Global Sign, Zendesk. WHOIS Emails: No emails found."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-vermont-self-description", source_id="s-vermont-own-site",
        excerpt="'A VERMONT e um Contact Center Omnichannel feito do seu jeito. Atuando ha quase tres "
                "decadas, com infraestrutura robusta para atender as mais diversas operacoes de "
                "atendimento e vendas.' (Vermont is an Omnichannel Contact Center made your way. Operating "
                "for almost three decades, with robust infrastructure serving diverse customer-service and "
                "sales operations.)"))
    graph.add_evidence(EvidenceRecord(evidence_id="e-vermont-health-service-line", source_id="s-vermont-own-site",
        excerpt="'Saude e programa de suporte ao paciente: Gestao de relacionamento, atendimento de "
                "farmacovigilancia, duvidas com atendimento de profissionais de saude. Cadastro de "
                "pacientes, resgate de servicos, atencao a rede credenciada.' (Health and patient-support "
                "program: relationship management, pharmacovigilance support, healthcare-professional "
                "support. Patient registration, service recovery, accredited-network care.)"))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-origin-raas", source_id="s-groupib-dragonforce",
        excerpt="DragonForce is a Ransomware-as-a-Service operation ... Discovered in August 2023, "
                "DragonForce has been targeting companies in critical sectors using a variant of the "
                "leaked LockBit3.0 builder and, more recently, in July 2024, with their own ransomware "
                "variant."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-origin-raas-blackpoint", source_id="s-blackpoint-dragonforce",
        excerpt="DragonForce ransomware was first identified in August 2023. DragonForce ransomware "
                "operated as a private group until June 2024 when the group advertized their affiliate "
                "program on the Russian-language cybercriminal forum, RAMP. The group reportedly offers "
                "80% of a ransom payment to the affiliates."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-variants-groupib", source_id="s-groupib-dragonforce",
        excerpt="DragonForce operates a Ransomware-as-a-Service (RaaS) affiliate program utilizing a "
                "variant of LockBit3.0, and the other, though initially claimed as original, is based on "
                "ContiV3 ... BYOVD, scheduled-task persistence, and expanded encryption customization."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-variants-blackpoint", source_id="s-blackpoint-dragonforce",
        excerpt="DragonForce has two ransomware variants - one based on LockBit Ransomware and another "
                "based on the Conti Ransomware variant. The Conti fork of DragonForce renames files with a "
                "'.dragonforce_encrypted' extension; however, affiliates reportedly have the option to "
                "customize the extension. For each file, the ChaCha8 key and IV is generated by the "
                "CryptGenRandom() function."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-tooling-groupib", source_id="s-groupib-dragonforce",
        excerpt="Group-IB's research also links DragonForce activity to SystemBC, Cobalt Strike, Mimikatz, "
                "and network-reconnaissance tooling used during real intrusions."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-tooling-blackpoint", source_id="s-blackpoint-dragonforce",
        excerpt="Known Tools: PowerShell and WMI (execution); at and schtasks (persistence); SimpleHelp "
                "(legitimate RMM tool abused to maintain persistent access); BadRentdvr2 (vulnerable "
                "driver used for BYOVD, executing kernel-mode routines via ThrottleStop.sys)."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-cartel-evolution", source_id="s-blackpoint-dragonforce",
        excerpt="In March 2025, the group announced their shift to a 'ransomware cartel'. In the "
                "announcement, affiliates were encouraged to continue using DragonForce tools but to "
                "branch out and create their own brand ... In August 2025, DragonForce announced a "
                "partnership with the LockBit operation to create a 'ransomware cartel' [Ransombay: "
                "DragonForce reportedly charges 20% of the ransom payment in exchange for infrastructure, "
                "malware, and ongoing support]. In August 2025, the group reportedly launched a 'data "
                "analysis service' ... offered to affiliates targeting organizations with an annual "
                "revenue of $15 million or more ... The fee for this service reportedly ranges from 0-23% "
                "of ransom payments."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-cve-history", source_id="s-blackpoint-dragonforce",
        excerpt="Known Exploited Vulnerabilities: CVE-2021-44228 (Apache Log4j, CVSS 10); CVE-2023-46805 / "
                "CVE-2024-21887 / CVE-2024-21893 (Ivanti Connect Secure and Policy Secure); CVE-2024-21412 "
                "(Microsoft Windows Internet Shortcut Files, CVSS 8.1); CVE-2024-21762 (FortiOS sslvpnd "
                "out-of-bound write, CVSS 9.8); CVE-2024-40766 (SonicOS improper access control, CVSS 9.8); "
                "CVE-2024-57726 / CVE-2024-57727 / CVE-2024-57728 (SimpleHelp RMM privilege escalation / "
                "path traversal / arbitrary file upload, CVSS 9.9 / 7.5 / 7.2); CVE-2024-55591 (FortiOS "
                "and FortiProxy authentication bypass, CVSS 9.8)."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-attck-lifecycle", source_id="s-blackpoint-dragonforce",
        excerpt="MITRE ATT&CK mappings span the full lifecycle: Initial Access (T1078, T1133, T1189, "
                "T1190, T1566); Persistence (T1053, T1078, T1543, T1547); Privilege Escalation; Defense "
                "Evasion (T1027, T1070, T1112, T1140, T1211, T1218, T1222, T1553, T1562, T1564, T1679); "
                "Credential Access (T1003.001 LSASS Memory, T1003.002 SAM); Discovery (T1012, T1016, "
                "T1018, T1057, T1069, T1082, T1083, T1087, T1135, T1482, T1673); Lateral Movement (T1021 "
                "RDP/SMB, T1210, T1570); Collection (T1005, T1560); Command and Control (T1071, T1090, "
                "T1105, T1219, T1571); Exfiltration (T1041, T1048, T1567); Impact (T1486, T1489, T1490, "
                "T1491, T1529, T1657)."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-malaysia-question", source_id="s-blackpoint-dragonforce",
        excerpt="DragonForce Malaysia: A hacktivist group from Malaysia that announced via their Telegram "
                "in 2023 that they were planning on developing a ransomware operation. Any connection "
                "between the two groups has not been confirmed ... There is an even chance that the "
                "ransomware is related to the hacktivist group ... There is an even chance that another "
                "operation has adopted the name in an effort to evade detection and attribution."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-associations", source_id="s-blackpoint-dragonforce",
        excerpt="Associations: BlackLock/Mamona (linked attacks, possibly part of the cartel); Bjorka (a "
                "forum user linked via a leaked database); Devman (payloads built on DragonForce "
                "infrastructure, also linked to Qilin); LockBit (near-identical builder source code per "
                "Cyble, formal cartel partnership announced August 2025); Qilin (a posted partnership "
                "announcement alongside LockBit); Ransomhub (mixed, contested reports -- ranging from a "
                "cooperative merge to an exit scam); Scattered Spider (observed deploying the DragonForce "
                "variant against Retail-sector targets); tracked by Trend Micro under the name 'Water "
                "Tambanakua'."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-current-scale", source_id="s-ransomwarelive-dragonforce-group",
        excerpt="Victims 639. First Victim (est. attack date) 2022-10-20. Discovery Date 2023-12-13. Last "
                "Seen 2026-08-17. Avg Delay 19.0 days. Infostealer 28.2% victims with domain. Countries "
                "65 hit."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-dragonforce-targeting-profile", source_id="s-blackpoint-dragonforce",
        excerpt="Executive Summary: Most frequently targeted industry: Industrials (Manufacturing). Most "
                "frequently targeted victim HQ region: North America. Diamond Model victim "
                "characteristics: financially-motivated, opportunistic; Industrials (Manufacturing); "
                "North America-focused; $15M+ revenue focus."))

    claims = [
        # ---------------- Victim layer (OBSERVED) ----------------
        Claim(claim_id="c-leak-site-claim-vxc", claim_type=ClaimType.VICTIM_IDENTITY,
              text="A group calling itself DragonForce listed 'Vermont XCenter' (vermont.com.br), a "
                   "Brazil-based organization, on its extortion leak site on 2026-08-17 (09:24 UTC). The "
                   "listing states no data category, volume, or sample beyond the victim's own scraped "
                   "site description.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-claim-post-vxc"], source_refs=["s-ransomwarelive-vxc"],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes the claim "
                            "was made, not that compromise/encryption/theft actually occurred."),
        Claim(claim_id="c-victim-business-description-vxc", claim_type=ClaimType.VICTIM_IDENTITY,
              text="Vermont XCenter is an omnichannel contact-center/business-process-outsourcing company "
                   "operating for almost three decades, with a distinct 'Vermont Health' service line "
                   "covering patient registration and pharmacovigilance support, per its own site.",
              status=EpistemicState.REPORTED, confidence=Confidence.HIGH,
              evidence_refs=["e-vermont-self-description", "e-vermont-health-service-line"],
              source_refs=["s-vermont-own-site"], observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="REPORTED rather than CONFIRMED: VICTIM_IDENTITY is a high-impact claim type "
                            "(Section 10), and this rests on a single source -- the entity's own site is "
                            "credible (HIGH confidence retained) but not independently corroborated. The "
                            "Vermont Health service line is recorded because it is real and self-stated, "
                            "not because any source claims patient or pharmacovigilance data specifically "
                            "was exfiltrated -- no source makes that claim."),
        Claim(claim_id="c-compromise-occurred-vxc", claim_type=ClaimType.DATA_THEFT,
              text="Whether an actual compromise or data theft occurred at Vermont XCenter.",
              status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="No independent confirmation, victim statement, or regulator filing was "
                            "located in any of the five sources reviewed this session. Represented as "
                            "UNKNOWN, not guessed."),
        Claim(claim_id="c-infostealer-exposure-vxc", claim_type=ClaimType.TTP_OBSERVED,
              text="Aggregated telemetry indicates 2 compromised employee endpoints, 48 compromised "
                   "end-user credentials, 9 exposed third-party employee credentials, and 18 external "
                   "attack-surface exposures associated with Vermont XCenter -- a notably larger exposure "
                   "signal than this canary set's other victims.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-infostealer-signal-vxc"], source_refs=["s-ransomwarelive-vxc"],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="Not established as the incident's initial-access vector -- no source "
                            "connects this aggregated exposure signal to the leak-site claim."),
        Claim(claim_id="c-infra-fingerprint-vxc", claim_type=ClaimType.TTP_OBSERVED,
              text="Passive DNS fingerprinting shows Vermont XCenter uses Microsoft 365 for email (via "
                   "Exchange Online Protection) and has a Zendesk integration (via its SPF record); no "
                   "WHOIS abuse-contact email was found for the domain.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-infra-fingerprint-vxc"], source_refs=["s-ransomwarelive-vxc"],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="Infrastructure fingerprinting only -- not evidence of the incident's "
                            "initial-access vector."),
        Claim(claim_id="c-victim-ack-vxc", claim_type=ClaimType.VICTIM_IDENTITY,
              text="Victim acknowledgement of the incident.",
              status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-vxc"],
              source_refs=["s-ransomwarelive-vxc"], observed_vs_context=ObservedVsContext.OBSERVED),

        # ---------------- Actor-historical layer (CONTEXT) ----------------
        Claim(claim_id="c-dragonforce-origin-raas", claim_type=ClaimType.TTP_HISTORICAL,
              text="DragonForce was first identified/discovered in August 2023 and operated privately "
                   "until June 2024, when it advertised a RaaS affiliate program on the Russian-language "
                   "cybercriminal forum RAMP, offering affiliates 80% of ransom revenue -- independently "
                   "reported by both Group-IB and Blackpoint Cyber.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-dragonforce-origin-raas", "e-dragonforce-origin-raas-blackpoint"],
              source_refs=["s-groupib-dragonforce", "s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="MULTI_SOURCE_INDEPENDENT: two named CTI vendors, published roughly 17 months "
                            "apart, independently state the same origin timeline and revenue split."),
        Claim(claim_id="c-dragonforce-variants", claim_type=ClaimType.TTP_HISTORICAL,
              text="DragonForce operates two Windows ransomware variants: one derived from the leaked "
                   "LockBit 3.0 builder, and a second, ContiV3-based build using BYOVD and scheduled-task "
                   "persistence, ChaCha8 encryption keyed via CryptGenRandom(), and a customizable "
                   "'.dragonforce_encrypted' file extension -- independently described by both Group-IB "
                   "and Blackpoint Cyber.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-dragonforce-variants-groupib", "e-dragonforce-variants-blackpoint"],
              source_refs=["s-groupib-dragonforce", "s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="MULTI_SOURCE_INDEPENDENT: the two-variant lineage is confirmed by two "
                            "separately-published vendor analyses, not borrowed from one and repeated."),
        Claim(claim_id="c-dragonforce-tooling", claim_type=ClaimType.TTP_HISTORICAL,
              text="DragonForce intrusions have been linked to SystemBC, Cobalt Strike, and Mimikatz "
                   "(Group-IB), and separately documented using PowerShell/WMI for execution, at/schtasks "
                   "for persistence, SimpleHelp RMM abuse for persistent access, and the BadRentdvr2 "
                   "vulnerable driver for BYOVD privilege escalation (Blackpoint Cyber).",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-dragonforce-tooling-groupib", "e-dragonforce-tooling-blackpoint"],
              source_refs=["s-groupib-dragonforce", "s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-dragonforce-cartel-evolution", claim_type=ClaimType.TTP_HISTORICAL,
              text="In March 2025 DragonForce announced a shift to a 'ransomware cartel' model, "
                   "encouraging affiliates to build their own brands while continuing to use DragonForce "
                   "tools; in August 2025 it announced a formal partnership with LockBit (reportedly "
                   "taking a 20% cut to provide infrastructure, encryptors, and negotiation support); and "
                   "in August 2025 it reportedly launched a paid 'data analysis service' (0-23% of ransom "
                   "proceeds) offered to affiliates targeting organizations with $15M+ annual revenue.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-dragonforce-cartel-evolution"], source_refs=["s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="Single-sourced to Blackpoint Cyber (Feb 2026) -- Group-IB's article predates "
                            "these 2025 developments and does not cover them."),
        Claim(claim_id="c-dragonforce-cve-history", claim_type=ClaimType.TTP_HISTORICAL,
              text="Blackpoint Cyber documents DragonForce actors as having exploited 11 named CVEs "
                   "across 2021-2024, including Apache Log4j (CVE-2021-44228), three Ivanti Connect "
                   "Secure/Policy Secure CVEs, a FortiOS SSL-VPN out-of-bound write (CVE-2024-21762), a "
                   "SonicOS access-control flaw (CVE-2024-40766), three 2024 SimpleHelp RMM CVEs "
                   "(privilege escalation, path traversal, arbitrary file upload), and a FortiOS/"
                   "FortiProxy authentication bypass (CVE-2024-55591).",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-dragonforce-cve-history"], source_refs=["s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="Actor-historical exploitation CAPABILITY only -- no source claims any of "
                            "these specific CVEs was the initial-access vector for Vermont XCenter."),
        Claim(claim_id="c-dragonforce-attck-lifecycle", claim_type=ClaimType.TTP_HISTORICAL,
              text="Blackpoint Cyber's MITRE ATT&CK mapping documents DragonForce's capability across the "
                   "full attack lifecycle -- initial access, persistence, privilege escalation, defense "
                   "evasion, credential access, discovery, lateral movement, collection, command and "
                   "control, exfiltration, and impact (including T1486 encryption, T1489 service stop, "
                   "and T1490 recovery inhibition).",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-dragonforce-attck-lifecycle"], source_refs=["s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-dragonforce-associations", claim_type=ClaimType.TTP_HISTORICAL,
              text="Blackpoint Cyber documents a broader, partly-contested association ecosystem around "
                   "DragonForce: linked attacks from BlackLock/Mamona, a forum-user association (Bjorka), "
                   "Devman payloads built on DragonForce infrastructure, near-identical LockBit 3.0 "
                   "builder source code (per Cyble), a posted Qilin partnership announcement, mixed and "
                   "contested reports about a RansomHub relationship, Scattered Spider observed deploying "
                   "the DragonForce variant against Retail-sector targets, and Trend Micro's independent "
                   "tracking of the same operation under the name 'Water Tambanakua'.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-dragonforce-associations"], source_refs=["s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="REPORTED rather than CONFIRMED: Blackpoint's own language for this section "
                            "is explicitly hedged ('reportedly', 'mixed reports', 'likely') across nearly "
                            "every named association."),
        Claim(claim_id="c-dragonforce-malaysia-question", claim_type=ClaimType.ACTOR_ATTRIBUTION,
              text="Whether DragonForce ransomware is connected to the Malaysian hacktivist group "
                   "'DragonForce Malaysia' (which announced ransomware ambitions via Telegram in 2023), "
                   "versus an unrelated operation having adopted the same name for attribution evasion.",
              status=EpistemicState.UNKNOWN,
              evidence_refs=["e-dragonforce-malaysia-question"], source_refs=["s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="Blackpoint Cyber's own explicit framing: 'even chance' either way, 'has yet "
                            "to be confirmed'. Represented as UNKNOWN with evidence attached -- this is "
                            "evidence THAT the question is open, not evidence resolving it either "
                            "direction (mirrors this fixture set's established Aurora/2018-naming "
                            "discipline, but here the source itself is directly available)."),
        Claim(claim_id="c-dragonforce-targeting-profile", claim_type=ClaimType.TTP_HISTORICAL,
              text="Blackpoint Cyber's Diamond Model characterizes DragonForce's typical victim as "
                   "financially-motivated/opportunistically selected, most frequently in Industrials "
                   "(Manufacturing), most frequently headquartered in North America, with a general focus "
                   "on organizations with $15M+ in annual revenue.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-dragonforce-targeting-profile"], source_refs=["s-blackpoint-dragonforce"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="An aggregate victimology characterization, not a claim about Vermont XCenter "
                            "specifically -- Vermont XCenter is a BPO/contact-center (not Manufacturing) "
                            "headquartered in Brazil (not North America), outside this profile's own "
                            "'most frequently targeted' description."),
        Claim(claim_id="c-dragonforce-current-scale", claim_type=ClaimType.TTP_HISTORICAL,
              text="ransomware.live's own current tracking shows 639 total DragonForce victims across 65 "
                   "countries, with a 19.0-day average delay between estimated attack date and leak-site "
                   "claim, and 28.2% of tracked victims showing infostealer-log domain overlap. The "
                   "tracker's own earliest tracked victim has an estimated attack date of 2022-10-20 -- "
                   "predating both named vendors' 'August 2023' discovery dating by roughly ten months, a "
                   "discrepancy no source reviewed resolves.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-dragonforce-current-scale"], source_refs=["s-ransomwarelive-dragonforce-group"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="REPORTED/MEDIUM, consistent with this aggregator's Reliability.MODERATE tier "
                            "used elsewhere in this report. The 2022-10-20-vs-2023 discrepancy is recorded "
                            "as an open intelligence gap, not silently corrected toward either source."),
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
        sector="Contact center / business process outsourcing (BPO), including a healthcare-adjacent "
               "'Vermont Health' service line (per the victim's own site)",
        claim_date="2026-08-17T09:24:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Not specified by any source beyond a generic compromise claim; no data "
                                  "category, volume, or sample described.",
        sample_proof_status=EpistemicState.NOT_ASSESSED,
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-vxc", "c-victim-business-description-vxc", "c-victim-ack-vxc"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=["c-infostealer-exposure-vxc", "c-infra-fingerprint-vxc"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=["Water Tambanakua (Trend Micro's tracking name)"],
        raas_model_claim_ids=["c-dragonforce-origin-raas", "c-dragonforce-cartel-evolution"],
        historical_ttp_claim_ids=["c-dragonforce-variants", "c-dragonforce-tooling",
                                   "c-dragonforce-attck-lifecycle"],
        historical_tooling_claim_ids=["c-dragonforce-tooling", "c-dragonforce-variants"],
        initial_access_history_claim_ids=["c-dragonforce-cve-history", "c-dragonforce-attck-lifecycle"],
        infrastructure_claim_ids=["c-dragonforce-cve-history"],
        affiliate_behavior_claim_ids=["c-dragonforce-origin-raas", "c-dragonforce-cartel-evolution",
                                       "c-dragonforce-associations"],
        victimology_claim_ids=["c-dragonforce-current-scale", "c-dragonforce-targeting-profile"],
        sectors=["Manufacturing", "Construction & Engineering", "Retail", "Business Services",
                 "Legal Services"],
        geographies=["North America", "Europe"],
        campaign_history_claim_ids=["c-dragonforce-current-scale", "c-dragonforce-cartel-evolution"],
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures -- the "
                           "direct countermeasure to DragonForce's documented T1490 recovery-inhibition "
                           "and T1489 service-stop behavior.",
        identity_hardening="Enforce MFA on all remote-access and privileged accounts; monitor for "
                            "exposed third-party and end-user credentials in infostealer logs; treat any "
                            "unexpected SimpleHelp (or other RMM) installation as a persistence signal.",
        segmentation="Segment networks to limit lateral movement from an initial foothold, given "
                     "DragonForce's documented RDP/SMB-based lateral movement (T1021).",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption "
                                   "activity and for known tooling (Cobalt Strike, SystemBC, Mimikatz).",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion, service-stop events, and "
                                      "backup-service tampering (T1489/T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks, "
                        "including a defined leak-site-monitoring process for unconfirmed extortion "
                        "claims.",
    )

    return RansomwareVictimClaim(
        product_id="dragonforce-vermont-xcenter-premium-canary",
        victim_observation=victim_observation,
        actor_context=actor_context,
        generic_readiness=generic_readiness,
        # No linked_vulnerabilities -- no CVE/exploit was claimed or found for THIS incident specifically
        # (the CVE table above is actor-historical, general capability); the four vulnerability-shaped
        # markers stay NOT_APPLICABLE by construction.
    )


def build_metrics_registry() -> MetricsRegistry:
    registry = MetricsRegistry()
    registry.register(ExternalMetric(
        metric_id="m-dragonforce-total-victims", name="DragonForce total tracked victims",
        value=639, unit="victims", scope="All DragonForce leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/dragonforce",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
        notes="A live, continuously-updated tracker count as of retrieval, not a fixed historical figure.",
    ))
    registry.register(ExternalMetric(
        metric_id="m-dragonforce-countries", name="DragonForce countries hit",
        value=65, unit="countries", scope="All DragonForce leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/dragonforce",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
    ))
    registry.register(ExternalMetric(
        metric_id="m-dragonforce-avg-dwell", name="DragonForce average attack-to-claim delay",
        value=19.0, unit="days", scope="All DragonForce leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/dragonforce",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
    ))
    registry.register(ExternalMetric(
        metric_id="m-dragonforce-infostealer-overlap", name="DragonForce victims with infostealer-log domain overlap",
        value=28.2, unit="percent", scope="All DragonForce leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/dragonforce",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
    ))
    registry.register(ExternalMetric(
        metric_id="m-dragonforce-raas-affiliate-share", name="DragonForce RaaS affiliate revenue share",
        value=80.0, unit="percent",
        scope="DragonForce RaaS ransom-payment split, per Group-IB and Blackpoint Cyber",
        source="Group-IB and Blackpoint Cyber (independently corroborated)",
        source_url="https://www.group-ib.com/blog/dragonforce-ransomware/",
        publication_year=2024, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2027-02-01",
        notes="A point figure (not a range) independently stated by two publishers 17 months apart.",
    ))
    return registry


def build_hypothesis_sets() -> list[HypothesisSet]:
    return [
        HypothesisSet(
            question="Does the 'Vermont XCenter' leak-site listing reflect a genuine, technically "
                      "successful compromise, or could it be an unconfirmed or exaggerated extortion "
                      "claim?",
            hypotheses=(
                Hypothesis(
                    "h1", "H1: Genuine compromise, currently undisclosed",
                    "Consistent with DragonForce's persistent, escalating operating cadence (639 tracked "
                    "victims across 65 countries) and a notably larger infostealer-exposure signal than "
                    "other victims in this canary set, the claim could reflect an actual compromise "
                    "Vermont XCenter has not yet acknowledged publicly.",
                    supporting_evidence_claim_ids=("c-leak-site-claim-vxc", "c-infostealer-exposure-vxc",
                                                    "c-dragonforce-current-scale"),
                    contradicting_evidence_claim_ids=(),
                    confidence="MEDIUM",
                ),
                Hypothesis(
                    "h2", "H2: Unconfirmed or overstated claim",
                    "The claim has not been technically substantiated by any source reviewed -- no proof "
                    "sample, no independent confirmation, and no victim acknowledgement were located, and "
                    "the tracker's own 'Description' field is only the victim's scraped site metadata, "
                    "not a distinct claim of stolen data.",
                    supporting_evidence_claim_ids=("c-compromise-occurred-vxc", "c-victim-ack-vxc"),
                    contradicting_evidence_claim_ids=(),
                    confidence="MEDIUM",
                ),
            ),
        ),
        HypothesisSet(
            question="Is the DragonForce ransomware operation connected to the 2023 Malaysian hacktivist "
                      "collective 'DragonForce Malaysia', or has an unrelated operation adopted the same "
                      "name?",
            hypotheses=(
                Hypothesis(
                    "h1", "H1: Hacktivist-lineage evolution",
                    "DragonForce Malaysia publicly announced, via Telegram in 2023, an intention to start "
                    "a ransomware operation -- a real, dated, on-the-record statement of intent that "
                    "predates the ransomware operation's own August 2023 discovery.",
                    supporting_evidence_claim_ids=("c-dragonforce-malaysia-question",),
                    contradicting_evidence_claim_ids=(),
                    confidence="LOW",
                ),
                Hypothesis(
                    "h2", "H2: Unrelated operation, name reuse for attribution evasion",
                    "Blackpoint Cyber itself explicitly rates this as an even-odds alternative: a "
                    "financially-motivated criminal operation adopting a hacktivist brand's name would "
                    "complicate attribution and could plausibly explain the name overlap without any "
                    "actual organizational continuity.",
                    supporting_evidence_claim_ids=("c-dragonforce-malaysia-question",),
                    contradicting_evidence_claim_ids=(),
                    confidence="LOW",
                ),
            ),
        ),
    ]


def build_intelligence_gaps(victim_observation: VictimObservation) -> list[IntelligenceGap]:
    gaps = derive_ransomware_gaps(victim_observation)
    gaps.append(IntelligenceGap(
        "Whether any of the documented general DragonForce TTPs above (RDP/phishing/vulnerability-based "
        "initial access, BYOVD, SimpleHelp RMM abuse, the ContiV3/LockBit3.0-derived encryptors) were "
        "actually used in this specific incident is not established by any source reviewed -- this is "
        "documented actor CAPABILITY, not incident-specific evidence.",
        "COLLECTION_GAP",
        "Incident-specific forensic artifacts, EDR telemetry, or a confirmed intrusion-vector statement "
        "from Vermont XCenter or an engaged incident-response firm.",
    ))
    gaps.append(IntelligenceGap(
        "The tracker's own earliest tracked DragonForce victim has an estimated attack date "
        "(2022-10-20) that predates both named vendors' 'August 2023 discovery' dating by roughly ten "
        "months -- no source reviewed explains this discrepancy, and it is not resolved here in either "
        "direction.",
        "KNOWN_UNKNOWN",
        "A vendor timeline reconciliation, or confirmation that the tracker's earliest entry reflects a "
        "data-quality issue rather than genuine pre-disclosure activity.",
    ))
    gaps.append(IntelligenceGap(
        "Which specific DragonForce affiliate, or which cartel-partner brand (given the group's "
        "documented 2025 shift toward a multi-brand cartel model), is responsible for this claim is not "
        "established by any source reviewed.",
        "KNOWN_UNKNOWN",
        "CTI vendor attribution research specific to this claim, or law-enforcement/vendor telemetry "
        "tying a specific known affiliate cluster to this incident.",
    ))
    return gaps


def build_regulatory_applicabilities() -> list[RegulatoryApplicability]:
    return [
        not_assessed(
            "LGPD (Brazil -- Lei Geral de Protecao de Dados)",
            reason="Whether any compromise occurred at all is UNKNOWN (c-compromise-occurred-vxc), and no "
                   "source reviewed describes the content or category of any data potentially affected -- "
                   "LGPD notification-obligation applicability cannot be determined from current evidence.",
        ),
        not_assessed(
            "HIPAA / US healthcare business-associate exposure",
            reason="Vermont XCenter's own site documents a 'Vermont Health' service line covering patient "
                   "registration and pharmacovigilance support, but no source reviewed identifies any "
                   "specific US HIPAA-covered-entity client or confirms any patient data was affected -- "
                   "applicability cannot be determined from current evidence.",
        ),
        not_assessed(
            "PCI-DSS",
            reason="Vermont XCenter's contact-center/telesales services plausibly involve payment-card "
                   "data on behalf of retail/e-commerce clients, but no source reviewed describes its "
                   "specific cardholder-data-environment footprint.",
        ),
        RegulatoryApplicability(
            jurisdiction="US/SEC", victim_geography="Brazil", operations_geography="Brazil",
            data_subject_geography=None, sector=None, entity_classification=None,
            incident_facts_claim_ids=("c-leak-site-claim-vxc",), regulation="SEC Cyber Disclosure Rule",
            applicability_state=ApplicabilityState.NOT_APPLICABLE,
            basis="No source reviewed establishes Vermont XCenter as a US public company subject to SEC "
                  "reporting obligations; it is represented in every source reviewed as a private, "
                  "Brazil-based BPO.",
        ),
    ]


def build_forecast() -> Forecast:
    return Forecast(
        judgment="DragonForce-branded and cartel-affiliated ransomware activity will likely continue at "
                 "or above its documented current pace (639 tracked victims across 65 countries, a "
                 "19.0-day average attack-to-claim delay), with continued active exploitation of recently "
                 "disclosed vulnerabilities (the group's own documented pattern of adopting 2024-era CVEs, "
                 "including the SimpleHelp RMM chain, within the same calendar year) and continued "
                 "expansion of its cartel/white-label partnership model (LockBit, and contested reports "
                 "involving RansomHub and Qilin).",
        time_horizon="90 days from 2026-08-17",
        supporting_observation_claim_ids=("c-dragonforce-current-scale", "c-dragonforce-cartel-evolution",
                                           "c-dragonforce-cve-history"),
        historical_baseline_claim_ids=("c-dragonforce-origin-raas",),
        assumptions=(
            "DragonForce's cartel-partner network continues operating at a pace comparable to its "
            "documented 2023-2026 tracked history, with no law-enforcement takedown occurring within the "
            "forecast window.",
        ),
        counter_evidence_claim_ids=(),
        alternative_scenarios=(
            "Law-enforcement action against DragonForce or one of its named cartel partners (LockBit, or "
            "any resolution of the contested RansomHub relationship) disrupts the group's operating "
            "cadence within the forecast window.",
            "The cartel model fragments if affiliate-recruited brands (per the March 2025 announcement's "
            "own encouragement to 'branch out') diverge enough that tracking DragonForce as a single "
            "operation becomes less meaningful.",
        ),
        indicators_to_watch=(
            "New named victims added to DragonForce's leak site at a rate consistent with or exceeding "
            "the tracked pace implied by 639 victims since the group's 2023 RaaS launch",
            "Newly disclosed CVEs in remote-access/RMM software (following the group's documented pattern "
            "of rapid SimpleHelp/Ivanti/FortiOS CVE adoption)",
            "Further named cartel-partnership announcements or law-enforcement action targeting "
            "DragonForce, LockBit, or their shared infrastructure",
        ),
        confidence="MEDIUM",
        confidence_rationale="Supported by a large, multi-year (2022/2023-2026), 639-victim tracked "
                              "operating history, a stable and twice-independently-corroborated RaaS "
                              "economic model, and a documented pattern of rapid adoption of newly "
                              "disclosed CVEs -- tempered by the inherent unpredictability of law-"
                              "enforcement disruption events and by the genuine uncertainty this report's "
                              "own sources document about the cartel model's cohesion (contested RansomHub "
                              "reports, an unresolved DragonForce-Malaysia naming question).",
        what_would_change_assessment=(
            "A confirmed law-enforcement takedown of DragonForce or LockBit's shared cartel "
            "infrastructure, or a published technical report clarifying the RansomHub relationship, would "
            "change this assessment materially.",
        ),
    )


def build_detection_rule() -> DetectionRule:
    """A real, structurally valid Sigma-style detection concept grounded directly in two of
    DragonForce's own documented, quotable indicators (c-dragonforce-tooling) -- marked
    SYNTAX_VALIDATED, not LAB_VALIDATED or PRODUCTION_VALIDATED, since it has not been tested
    against live telemetry this session."""
    body = (
        "title: DragonForce SimpleHelp RMM Persistence and dragonforce_encrypted Ransom Note Pattern\n"
        "id: reportx-canary-dragonforce-simplehelp-persistence\n"
        "status: experimental\n"
        "description: >\n"
        "  Detects two documented DragonForce indicators: unexpected installation\n"
        "  or execution of the legitimate SimpleHelp RMM tool used to maintain\n"
        "  persistent access (per Blackpoint Cyber's Known Tools table), and\n"
        "  files renamed with the '.dragonforce_encrypted' extension used by the\n"
        "  group's ContiV3-based encryptor variant. Neither indicator alone\n"
        "  confirms DragonForce attribution for any specific incident --\n"
        "  SimpleHelp is a legitimate RMM tool with benign uses, and affiliates\n"
        "  reportedly have the option to customize the encrypted-file extension.\n"
        "references:\n"
        "  - https://blackpointcyber.com/wp-content/uploads/2026/02/DragonForce-1.pdf\n"
        "  - https://www.group-ib.com/blog/dragonforce-ransomware/\n"
        "logsource:\n"
        "  category: process_creation\n"
        "  product: windows\n"
        "detection:\n"
        "  selection_simplehelp_new_install:\n"
        "    Image|endswith:\n"
        "      - '\\SimpleHelp.exe'\n"
        "      - '\\Remote.exe'\n"
        "    CommandLine|contains: 'install'\n"
        "  selection_encrypted_extension:\n"
        "    TargetFilename|endswith: '.dragonforce_encrypted'\n"
        "  condition: selection_simplehelp_new_install or selection_encrypted_extension\n"
        "falsepositives:\n"
        "  - Legitimate, IT-authorized SimpleHelp RMM deployments -- verify against a known-good asset "
        "inventory before response\n"
        "  - Affiliates reportedly customize the encrypted-file extension, so absence of "
        "'.dragonforce_encrypted' specifically does not rule out this variant family\n"
        "level: high\n"
    )
    return DetectionRule(
        rule_id="reportx-canary-dragonforce-simplehelp-persistence", technique_id="T1219", format="sigma",
        validation_state=DetectionValidationState.SYNTAX_VALIDATED, body=body,
    )


def _rendered_text(graph: EvidenceGraph, detection_rule: DetectionRule) -> str:
    sources = graph.sources
    evidence = graph.evidence

    def _source_block(source_id: str) -> str:
        s = sources[source_id]
        excerpts = [e.excerpt for e in evidence.values() if e.source_id == source_id]
        lines = [f"### {source_id} — {s.publisher}", "", f"- URL: {s.url}", f"- Type: {s.source_type.value}",
                  f"- Reliability: {s.reliability.value}", f"- Retrieved: {s.retrieved_at}"]
        if s.content_sha256:
            lines.append(f"- content_sha256: `{s.content_sha256}`")
        else:
            lines.append(f"- excerpt_fingerprint_sha256: `{s.excerpt_fingerprint_sha256}` "
                          f"(fallback reason: {s.fingerprint_fallback_reason})")
        lines.append("")
        for ex in excerpts:
            lines.append(f"> {ex}")
            lines.append("")
        return "\n".join(lines)

    sources_appendix = "\n".join(_source_block(sid) for sid in sources)

    return (
        "# DragonForce / 'Vermont XCenter' — Premium Intelligence Canary\n\n"
        "**Classification:** TLP:CLEAR — public leak-site claim and open-source actor intelligence\n\n"
        "## Executive Summary\n\n"
        "On 2026-08-17, a group identifying itself as DragonForce listed 'Vermont XCenter', a "
        "Brazil-based omnichannel contact-center/BPO operating for almost three decades, on its Tor "
        "extortion leak site. This is a single-source claim describing no specific data category, "
        "volume, or sample; no independent confirmation, victim statement, regulator filing, or data "
        "sample has been located. Real, directly-sourced actor context -- drawn from Group-IB's named-"
        "analyst research and a current (February 2026) Blackpoint Cyber threat profile -- shows "
        "DragonForce as one of the most active RaaS operations currently tracked (639 victims across 65 "
        "countries), operating two malware variants derived from the leaked LockBit 3.0 builder and the "
        "Conti codebase, with a documented pattern of rapidly exploiting newly disclosed CVEs and a "
        "significant 2025 evolution into a multi-brand 'ransomware cartel' partnered with LockBit. "
        "Vermont XCenter's own site documents a healthcare-adjacent 'Vermont Health' service line; that "
        "fact is recorded for context only -- no source reviewed describes the content or sensitivity of "
        "any data potentially affected, and this report does not assert any specific data was actually "
        "exfiltrated.\n\n"
        "## Scope and Methodology\n\n"
        "This report synthesizes five independently retrieved sources, all fetched as raw bytes via "
        "direct HTTP fetch with content_sha256 computed programmatically from the checked-in raw files: "
        "the leak-site tracker ransomware.live (both the Vermont-specific victim page and its DragonForce "
        "group aggregate-statistics page), the victim's own site (vermont.com.br, in Portuguese), "
        "Group-IB's named-analyst research (2024-09-25), and Blackpoint Cyber's current 30-page threat "
        "profile (February 2026). Every claim in this report traces to at least one of these five sources "
        "via an explicit evidence_refs/source_refs chain, visible in the Sources & Evidence Ledger "
        "appendix below. Victim-specific observations (this incident only) are kept structurally and "
        "narratively separate from actor-historical context (what is known about DragonForce in general) "
        "throughout. Where the two CTI vendor sources independently corroborate the same fact -- the 80% "
        "affiliate revenue split and the two-variant malware lineage -- this report marks that "
        "corroboration explicitly rather than treating it as single-sourced.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-17 09:24 UTC on DragonForce's Tor leak site. Country: Brazil, confirmed via "
        "the tracker's own country-flag reference. Per the company's own site, Vermont XCenter is an "
        "omnichannel contact-center/BPO operating for almost three decades, with services spanning "
        "customer service, telesales, technical support, CRM implementation, and a distinct 'Vermont "
        "Health' line covering patient registration and pharmacovigilance support. This business-"
        "description context is recorded for completeness only -- the leak-site listing itself states no "
        "data category, volume, or sample; the tracker's 'Description' field is only the victim's own "
        "scraped site metadata, not a separate claim of stolen data, verified directly against the raw "
        "page this session. Whether any compromise actually occurred is UNKNOWN on current evidence; this "
        "report does not assert it did. Separately, aggregated infostealer telemetry indicates a notably "
        "larger exposure signal than other victims in this canary set -- 2 compromised employee "
        "endpoints, 48 compromised end-user credentials, 9 exposed third-party employee credentials, and "
        "18 external attack-surface exposures -- alongside passive-DNS fingerprinting showing Microsoft "
        "365 email and a Zendesk integration. None of this is attributed to the incident's initial-access "
        "vector by any source.\n\n"
        "## Actor Overview: DragonForce (RaaS-to-Cartel Evolution)\n\n"
        "DragonForce was first identified in August 2023 and operated as a private group until June 2024, "
        "when it advertised a RaaS affiliate program on the Russian-language cybercriminal forum RAMP, "
        "offering affiliates 80% of ransom revenue -- a figure independently reported by both Group-IB "
        "and Blackpoint Cyber, published roughly 17 months apart. The group operates two Windows "
        "ransomware variants, also independently confirmed by both vendors: one derived from the leaked "
        "LockBit 3.0 builder, and a ContiV3-based build using BYOVD, scheduled-task persistence, and "
        "ChaCha8 encryption keyed via CryptGenRandom(), with files renamed under a customizable "
        "'.dragonforce_encrypted' extension. DragonForce intrusions have been linked to SystemBC, Cobalt "
        "Strike, and Mimikatz (Group-IB), and separately documented using SimpleHelp RMM abuse for "
        "persistence and the BadRentdvr2 vulnerable driver for BYOVD privilege escalation (Blackpoint "
        "Cyber). In March 2025, the group announced a shift to a 'ransomware cartel' model, encouraging "
        "affiliates to build their own brands while continuing to use DragonForce tooling; in August 2025 "
        "it announced a formal partnership with LockBit (reportedly a 20% cut for infrastructure, "
        "encryptors, and negotiation support), and reportedly launched a paid 'data analysis service' "
        "targeting organizations with $15M+ annual revenue.\n\n"
        "## Historical Vulnerability Exploitation (Generic, Not Incident-Specific)\n\n"
        "Blackpoint Cyber documents DragonForce actors as having exploited 11 named CVEs across "
        "2021-2024: Apache Log4j (CVE-2021-44228, CVSS 10); three Ivanti Connect Secure/Policy Secure "
        "CVEs; a Windows Internet Shortcut Files flaw (CVE-2024-21412); a FortiOS SSL-VPN out-of-bound "
        "write (CVE-2024-21762); a SonicOS access-control flaw (CVE-2024-40766); three 2024 SimpleHelp "
        "RMM CVEs covering privilege escalation, path traversal, and arbitrary file upload; and a FortiOS/"
        "FortiProxy authentication bypass (CVE-2024-55591). This is documented actor CAPABILITY only -- no "
        "source reviewed claims any of these specific CVEs was the initial-access vector for Vermont "
        "XCenter, and this report makes no such claim.\n\n"
        "## Tactics, Techniques, and Procedures (ATT&CK-Mapped)\n\n"
        "Blackpoint Cyber's MITRE ATT&CK mapping documents DragonForce's capability across the full "
        "attack lifecycle: **initial access** (T1078, T1133, T1189, T1190, T1566); **persistence** "
        "(T1053, T1078, T1543, T1547); **defense evasion** (T1027, T1070, T1112, T1140, T1211, T1218, "
        "T1222, T1553, T1562, T1564, T1679); **credential access** (T1003.001 LSASS memory, T1003.002 "
        "SAM); **discovery** (T1012, T1016, T1018, T1057, T1069, T1082, T1083, T1087, T1135, T1482, "
        "T1673); **lateral movement** (T1021 RDP/SMB, T1210, T1570); **collection** (T1005, T1560); "
        "**command and control** (T1071, T1090, T1105, T1219, T1571); **exfiltration** (T1041, T1048, "
        "T1567); and **impact** (T1486 encryption, T1489 service stop, T1490 recovery inhibition, T1491 "
        "defacement, T1529 system shutdown, T1657 financial theft). All of this is documented actor "
        "CAPABILITY -- no TTP specific to the Vermont XCenter incident has been observed by any source "
        "reviewed.\n\n"
        "## Actor Ecosystem: Associations and the DragonForce Malaysia Question\n\n"
        "Blackpoint Cyber documents a broader, partly-contested association ecosystem: linked attacks "
        "from BlackLock/Mamona; a forum-user association (Bjorka); Devman payloads reportedly built on "
        "DragonForce infrastructure; near-identical LockBit 3.0 builder source code (per Cyble); a posted "
        "Qilin partnership announcement; mixed and contested reports about a RansomHub relationship "
        "ranging from a cooperative merge to an exit scam; and Scattered Spider observed deploying the "
        "DragonForce variant against Retail-sector targets. Separately, Trend Micro independently tracks "
        "the same operation under the name 'Water Tambanakua'. The actor's own most sensitive identity "
        "question -- any connection to the Malaysian hacktivist collective 'DragonForce Malaysia', which "
        "announced ransomware ambitions via Telegram in 2023 -- is explicitly framed by Blackpoint Cyber "
        "itself as unresolved: an 'even chance' either way, 'has yet to be confirmed'. This report "
        "represents that question as genuinely UNKNOWN rather than asserting or dismissing a lineage "
        "connection.\n\n"
        "## Current Tracked Scale (2026 Snapshot)\n\n"
        "Blackpoint Cyber's Diamond Model characterizes DragonForce's typical victim as financially-"
        "motivated/opportunistically selected, most frequently in Industrials (Manufacturing) and most "
        "frequently headquartered in North America, generally focused on organizations with $15M+ in "
        "annual revenue -- an aggregate profile Vermont XCenter, a Brazil-based BPO, falls outside of "
        "rather than matches, which this report notes rather than smooths over. "
        "ransomware.live's own current aggregate tracking shows 639 total DragonForce victims across 65 "
        "countries, with a 19.0-day average delay between estimated attack date and leak-site claim, and "
        "28.2% of tracked victims showing a domain-level overlap with known infostealer-malware logs. At "
        "the time of this report, Vermont XCenter is the group's own most recently listed victim. This "
        "report also records an open discrepancy rather than resolving it silently: the tracker's own "
        "earliest tracked victim has an estimated attack date of 2022-10-20, predating both named "
        "vendors' 'August 2023 discovery' dating by roughly ten months -- no source reviewed explains "
        "this gap.\n\n"
        "## Detection\n\n"
        "A Sigma detection concept is provided at SYNTAX_VALIDATED maturity only -- neither lab testing "
        "nor any deployment validation has been performed this session -- targeting two of DragonForce's "
        "own documented, quotable indicators: unexpected SimpleHelp RMM installation activity, and files "
        "renamed with the '.dragonforce_encrypted' extension. A match does not by itself confirm "
        "DragonForce attribution (see the rule's own falsepositives field, including the documented fact "
        "that affiliates can customize the encrypted-file extension). Full rule body:\n\n"
        f"```yaml\n{detection_rule.body}```\n\n"
        "## Hunting\n\n"
        "Given the documented, specific persistence pattern, a defensible hunting hypothesis is to "
        "search endpoint software-inventory and process-creation telemetry for SimpleHelp (or another "
        "unexpected RMM tool) installed outside a known-good IT asset inventory, cross-referenced against "
        "scheduled-task creation events consistent with the group's documented persistence mechanism. "
        "Separately, given the group's documented pattern of rapid adoption of newly disclosed remote-"
        "access-software CVEs (the SimpleHelp chain being the most recent example), hunting teams should "
        "prioritize patch-verification sweeps across internet-facing RMM, VPN, and firewall management "
        "interfaces ahead of narrower endpoint-only hunts. This report does not include incident-specific "
        "IOCs for Vermont XCenter -- none were located by any source reviewed.\n\n"
        "## Forecast\n\n"
        "MEDIUM confidence that DragonForce-branded and cartel-affiliated activity will continue at or "
        "above its documented current pace (639 tracked victims across 65 countries) over the next 90 "
        "days, with continued active exploitation of recently disclosed vulnerabilities and continued "
        "expansion of its cartel/white-label partnership model -- tempered by the inherent "
        "unpredictability of law-enforcement disruption events and by this report's own sources' genuine "
        "uncertainty about the cartel model's cohesion. See the structured forecast record (supporting "
        "observations, assumptions, alternative scenarios, and indicators to watch) in this bundle's "
        "`forecasts` field.\n\n"
        "## Alternative Hypotheses\n\n"
        "Two genuinely open analytic questions are weighed explicitly rather than resolved by assumption. "
        "**First**, whether the leak-site listing reflects a genuine, currently-undisclosed compromise "
        "(**H1**, consistent with DragonForce's persistent operating cadence and a notably larger "
        "infostealer-exposure signal than this canary set's other victims) versus an unconfirmed or "
        "overstated claim (**H2**, consistent with the total absence of a proof sample, independent "
        "confirmation, or victim acknowledgement). **Second**, whether DragonForce ransomware is "
        "connected to the hacktivist collective 'DragonForce Malaysia' (**H1**, a real, dated 2023 "
        "statement of ransomware intent) versus an unrelated operation having adopted the same name for "
        "attribution evasion (**H2**) -- a question this report's own primary vendor source frames as "
        "genuinely even-odds, not one this report resolves.\n\n"
        "## Regulatory Considerations\n\n"
        "LGPD (Brazil) is assessed NOT_ASSESSED: whether any compromise occurred at all is UNKNOWN, and "
        "no source describes the content or category of any data potentially affected. HIPAA/US "
        "healthcare business-associate exposure is assessed NOT_ASSESSED: Vermont XCenter's own site "
        "documents a healthcare-adjacent 'Vermont Health' service line, but no source identifies a "
        "specific US HIPAA-covered-entity client or confirms any patient data was affected. PCI-DSS is "
        "assessed NOT_ASSESSED: the contact-center/telesales business model plausibly involves payment-"
        "card data, but no source describes the specific cardholder-data-environment footprint. The SEC "
        "Cyber Disclosure Rule is assessed NOT_APPLICABLE: no source establishes Vermont XCenter as a US "
        "public company.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, MFA and credential-exposure "
        "monitoring, network segmentation against RDP/SMB-based lateral movement, behavioral detection "
        "for known tooling and mass encryption, shadow-copy/service-stop monitoring, and a tested IR plan "
        "with a defined leak-site-monitoring process -- is provided as general hardening grounded in "
        "DragonForce's own documented attack lifecycle, not as evidence any specific technique was used "
        "against this victim.\n\n"
        "## Intelligence Gaps\n\n"
        "Eight gaps are explicitly unresolved by any source reviewed for this report: victim "
        "acknowledgement is unavailable; no incident-specific IOCs were observed; no proof sample of any "
        "claimed data exists; no independent confirmation of the leak-site claim was located; no "
        "initial-access or incident-specific TTP evidence was found; whether any of DragonForce's "
        "documented general TTPs were used in this specific incident is unestablished; the 2022-10-20-"
        "versus-2023 origin-date discrepancy in the tracker's own dataset is unresolved; and which "
        "specific DragonForce affiliate or cartel-partner brand is responsible for this claim is "
        "unestablished.\n\n"
        "## Technical Recommendations\n\n"
        "1. Maintain a software-inventory baseline for authorized RMM tools and alert on any unexpected "
        "SimpleHelp (or similar) installation -- the direct countermeasure to DragonForce's documented "
        "persistence technique (evidence: c-dragonforce-tooling).\n"
        "2. Prioritize patch-verification sweeps across internet-facing VPN/firewall/RMM management "
        "interfaces, given DragonForce's documented pattern of rapid adoption of newly disclosed CVEs in "
        "exactly this category of software (evidence: c-dragonforce-cve-history).\n"
        "3. Deploy monitoring for DragonForce's specific documented persistence and encryption indicators "
        "via the detection rule above (evidence: c-dragonforce-variants).\n"
        "4. Enforce MFA on all remote-access and privileged accounts and monitor for third-party/end-user "
        "credentials appearing in infostealer-log marketplaces, given the notably large infostealer-"
        "exposure signal observed for this specific victim (evidence: c-infostealer-exposure-vxc).\n\n"
        "## Appendix A: Sources & Evidence Ledger\n\n"
        "Every source registered in this report's evidence graph, its retrieval/integrity metadata, and "
        "every captured excerpt tied to it -- the complete evidentiary basis for every claim above.\n\n"
        f"{sources_appendix}\n"
    )


def build_bundle() -> ReportBundle:
    graph = build_graph()
    ransomware_claim = build_ransomware_victim_claim()
    registry = build_metrics_registry()
    detection_rule = build_detection_rule()
    rendered_text = _rendered_text(graph, detection_rule)
    forecast = build_forecast()
    hypothesis_sets = build_hypothesis_sets()
    gaps = build_intelligence_gaps(ransomware_claim.victim_observation)
    regulatory = build_regulatory_applicabilities()

    # depth assessment computed from the ACTUAL constructed bundle, not hand-guessed -- section count
    # reflects the real '##'-level headings in _rendered_text(), material_claim_count reflects claims that
    # genuinely carry evidence_refs or source_refs.
    section_count = rendered_text.count("\n## ")
    material_claims = [c for c in graph.claims.values() if c.has_evidence()]

    metric_ids = ["m-dragonforce-total-victims", "m-dragonforce-countries", "m-dragonforce-avg-dwell",
                  "m-dragonforce-infostealer-overlap", "m-dragonforce-raas-affiliate-share"]

    return ReportBundle(
        report_id="dragonforce-vermont-xcenter-premium-canary",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={"victim_confirmation": ["c-leak-site-claim-vxc", "c-victim-ack-vxc",
                                                 "c-compromise-occurred-vxc"]},
        detection_rules=[detection_rule],
        metrics_registry=registry,
        cited_metric_ids=metric_ids,
        rendered_metric_ids=metric_ids,
        regulatory_applicabilities=regulatory,
        forecasts=[forecast],
        hypothesis_sets=hypothesis_sets,
        intelligence_gaps=gaps,
        threat_products=[ransomware_claim],
        review=None,  # PREMIUM_READY_PENDING_HUMAN -- no fabricated review; see reportx-review CLI
        is_premium_tier=True,
        depth_assessment=DepthAssessment(
            rendered_word_count=len(rendered_text.split()),
            material_claim_count=len(material_claims),
            distinct_evidence_backed_sections=section_count,
        ),
        technical_recommendation_count=4,
        technical_recommendations_with_evidence_basis=4,
    )
