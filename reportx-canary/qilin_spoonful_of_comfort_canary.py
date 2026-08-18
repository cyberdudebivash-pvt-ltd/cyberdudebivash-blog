"""ReportX Phase 4 real premium canary A: Qilin / Spoonful of Comfort.

Built from real research retrieved this session (WebSearch + WebFetch +
direct curl, 2026-08-17/18) against FIVE independently retrieved sources,
all fetched as raw bytes via direct HTTP fetch (curl) and checked into
`reportx-canary/raw-sources/`; every source's `content_sha256` is computed
from those exact files at import time (never hand-typed) -- see
`evidence_integrity.compute_content_sha256`. Unlike CVE-2025-62593 (Ray),
every one of this canary's five sources was fetchable in full -- no
excerpt-fingerprint fallback is used here.

This canary extends (not replaces) the earlier, deliberately modest
golden fixture at
`tests/fixtures/reportx-commercial-readiness/qilin_spoonful_of_comfort.py`
(``is_premium_tier=False``, no detection/forecast/hypothesis/regulatory
content) -- the victim-observation facts are the same real claim, but this
module adds substantially deeper, independently-sourced actor-context,
TTP, detection, hunting, forecast, and regulatory material on top of it,
built to independently clear the 23-control commercial-readiness matrix
at ``PREMIUM_READY_PENDING_HUMAN``.

Sources:
  - hendryadrian.com (ransomware leak-site aggregator) -- the leak-site
    claim itself. Victim: Spoonful of Comfort. Sector: Hospitality.
    Country: US. Published 2026-08-16T18:56:20.892782+00:00. Explicit
    disclaimer: "I cannot confirm the accuracy of the information."
  - Wikipedia, "Qilin (cybercrime group)" -- tertiary source citing Trend
    Micro (August 2022 first detection as "Agenda") and Group-IB (March
    2023 affiliate-panel infiltration, 80-85% affiliate revenue share),
    plus a real, named, dated 2023-2025 campaign chronology (Thornburi
    Energy Storage Systems, WT Partnership Asia, Yanfen/Stellantis in
    2023; Upper Merion Township, Felda Global Ventures, the Big Issue,
    Skender Construction, and a London-hospitals critical incident in
    2024; Inotiv, Asahi, Academie d'Amiens, and Covenant Health in 2025).
  - MITRE ATT&CK S1242 (Qilin, software page) -- MITRE's own consolidated
    capability profile: RaaS since at least 2022, Go/Rust variants
    targeting Windows/Linux/ESXi, overlaps with Black Basta/REvil/
    BlackCat, majority of victims in US/France/Canada/UK, primarily
    manufacturing/technology/financial-services/healthcare. Real,
    directly-quoted technique entries for encryption, shadow-copy
    deletion, credential dumping, lateral movement, masquerading, defense
    evasion, and initial access are used verbatim below.
  - MITRE ATT&CK G1050 (Water Galura, group page) -- the RaaS operators:
    payload generation, ransom negotiation, and data-leak publication for
    affiliates recruited on Russian cybercrime forums; double-extortion
    model; a Telegram announcement channel (T1585.001); financial
    extortion (T1657).
  - MITRE ATT&CK G1036 (Moonstone Sleet, group page) -- a North
    Korean-linked threat actor (alias Storm-1789) that MITRE records as
    having independently deployed Qilin ransomware, citing a 2025-03-06
    Microsoft Threat Intelligence social-media post as its own source.
    That underlying post was NOT independently retrieved this session --
    represented here as MITRE's own citation, not independently verified,
    and strictly as actor-ECOSYSTEM context (a RaaS brand can have more
    than one kind of operator behind it) -- never as evidence connecting
    Moonstone Sleet, or any other specific actor, to Spoonful of Comfort.

None of the actor-context, TTP, RaaS-model, or campaign-chronology
material below is evidence of what happened, if anything, at Spoonful of
Comfort specifically -- every such claim is tagged
``ObservedVsContext.CONTEXT`` and is never merged with the victim
observation layer's ``OBSERVED`` claims (Section 6's explicit
requirement, restated in this session's own task mandate: "Never upgrade
actor history into incident observation").
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

    hendryadrian_hash = _hash_raw("hendryadrian-spoonful-of-comfort.html")
    graph.add_source(SourceRecord(
        source_id="s-hendryadrian", url="https://www.hendryadrian.com/ransom-spoonful-of-comfort-aug-2026/",
        publisher="hendryadrian.com (ransomware leak-site aggregator)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T18:56:20.892782+00:00",
        reliability=Reliability.MODERATE, independence_group="qilin-leak-site-claim",
        content_sha256=hendryadrian_hash,
        notes="Aggregates the Qilin group's own Tor leak-site post (cited on-page as "
              "http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion/...); page's own "
              "disclaimer: \"This post is based on public claims made by the ransomware group 'qilin'. "
              "I cannot confirm the accuracy of the information.\" Discovered 2026-08-16T18:56:41Z, "
              "published 2026-08-16T18:56:20Z.",
    ))

    wikipedia_hash = _hash_raw("wikipedia-qilin.html")
    graph.add_source(SourceRecord(
        source_id="s-wikipedia-qilin", url="https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)",
        publisher="Wikipedia", source_type=SourceType.OTHER, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.MODERATE, independence_group="wikipedia-qilin",
        content_sha256=wikipedia_hash,
        notes="Tertiary source citing Trend Micro (August 2022 first detection) and Group-IB (March 2023 "
              "affiliate-panel infiltration, 80-85% affiliate revenue share), plus a named, dated 2023-2025 "
              "campaign chronology with per-incident data-volume figures.",
    ))

    s1242_hash = _hash_raw("mitre-attack-s1242-qilin.html")
    graph.add_source(SourceRecord(
        source_id="s-mitre-s1242", url="https://attack.mitre.org/software/S1242/",
        publisher="MITRE ATT&CK", source_type=SourceType.MITRE, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="mitre-attack-s1242",
        content_sha256=s1242_hash,
        notes="MITRE's own consolidated Qilin (S1242) software profile: aliases, platforms, malware-family "
              "overlaps, victim sector/geography aggregate, and the full ATT&CK Enterprise technique table "
              "this canary's TTP claims quote directly.",
    ))

    g1050_hash = _hash_raw("mitre-attack-g1050-water-galura.html")
    graph.add_source(SourceRecord(
        source_id="s-mitre-g1050", url="https://attack.mitre.org/groups/G1050/",
        publisher="MITRE ATT&CK", source_type=SourceType.MITRE, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="mitre-attack-g1050",
        content_sha256=g1050_hash,
        notes="MITRE's Water Galura (G1050, alias GOLD FEATHER) group profile: the operators of the Qilin "
              "RaaS -- payload generation, ransom negotiation, leak-site publication, Russian-forum affiliate "
              "recruitment, double extortion, active since at least 2022.",
    ))

    g1036_hash = _hash_raw("mitre-attack-g1036-moonstone-sleet.html")
    graph.add_source(SourceRecord(
        source_id="s-mitre-g1036", url="https://attack.mitre.org/groups/G1036/",
        publisher="MITRE ATT&CK", source_type=SourceType.MITRE, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="mitre-attack-g1036",
        content_sha256=g1036_hash,
        notes="MITRE's Moonstone Sleet (G1036, alias Storm-1789) group profile: a North Korean-linked actor "
              "MITRE records as having deployed Qilin ransomware, citing a 2025-03-06 Microsoft Threat "
              "Intelligence social-media post -- that underlying post was not independently retrieved this "
              "session.",
    ))

    # ------------------------------------------------------------------
    # Evidence records
    # ------------------------------------------------------------------
    graph.add_evidence(EvidenceRecord(evidence_id="e-claim-post", source_id="s-hendryadrian",
        excerpt="Victim: Spoonful of Comfort. Sector: Hospitality. Country: US. Actor: qilin. "
                "Published: 2026-08-16T18:56:20.892782+00:00. Information: Spoonful of Comfort was targeted "
                "by the Qilin ransomware group in the US. Disclaimer: This post is based on public claims "
                "made by the ransomware group 'qilin'. I cannot confirm the accuracy of the information."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-claim-description", source_id="s-hendryadrian",
        excerpt="Spoonful of Comfort in the US reported a ransomware incident allegedly linked to the qilin "
                "threat actor, resulting in unauthorized access and disruption of operations."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-qilin-overview", source_id="s-mitre-s1242",
        excerpt="Qilin is a ransomware family operated as a ransomware-as-a-service (RaaS) that has been "
                "active since at least 2022. It includes variants written in Go and Rust capable of "
                "targeting Windows, Linux, and VMware ESXi environments. Qilin shares functionality overlaps "
                "with Black Basta, REvil, and BlackCat ransomware. Qilin affiliates have targeted multiple "
                "entities worldwide with the majority of victims in the US, France, Canada, and the UK, "
                "primarily in the manufacturing, technology, financial services, and healthcare sectors."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-tooling-history", source_id="s-wikipedia-qilin",
        excerpt="The group was detected by Trend Micro in August 2022 promoting ransomware called Agenda, "
                "which affiliates could tailor. The software at the time was written in Go and Trend Micro "
                "noted similarity of the source code with Black Basta, Black Matter and REvil families of "
                "malware. In December 2022 the Agenda ransomware was rewritten in Rust."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-raas-affiliate-split", source_id="s-wikipedia-qilin",
        excerpt="Group-IB said they had infiltrated the group in March 2023 and that affiliates earn about "
                "80 to 85% of each ransom payment."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-water-galura-model", source_id="s-mitre-g1050",
        excerpt="Water Galura are the operators of the Qilin Ransomware-as-a-Service (RaaS) who handle "
                "payload generation, ransom negotiations, and the publication of stolen data for Qilin "
                "affiliates recruited on Russian cybercrime forums. Water Galura have been active since at "
                "least 2022 and use a double extortion model where they demand payment for providing "
                "decryption keys and for refraining from publishing the stolen data to their leak site."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-water-galura-telegram", source_id="s-mitre-g1050",
        excerpt="Establish Accounts: Social Media Accounts -- Water Galura operates a news channel on "
                "Telegram to make announcements for the Qilin RaaS."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-water-galura-financial-theft", source_id="s-mitre-g1050",
        excerpt="Financial Theft -- Water Galura has extorted victims for ransomware decryption keys and to "
                "prevent publication of data exfiltrated to their Tor data leak site."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-moonstone-sleet-profile", source_id="s-mitre-g1036",
        excerpt="Moonstone Sleet is a North Korean-linked threat actor executing both financially motivated "
                "attacks and espionage operations. The group previously overlapped significantly with "
                "another North Korean-linked entity, Lazarus Group, but has differentiated its tradecraft "
                "since 2023."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-moonstone-sleet-qilin", source_id="s-mitre-g1036",
        excerpt="Software used: S1242 Qilin -- Moonstone Sleet has deployed Qilin ransomware. [Reference: "
                "Microsoft Threat Intelligence (@MsftSecIntel), 2025-03-06, Microsoft Threat Intelligence on "
                "X. Retrieved by MITRE 2025-09-26.]"))
    graph.add_evidence(EvidenceRecord(evidence_id="e-campaign-2023", source_id="s-wikipedia-qilin",
        excerpt="In 2023, Qilin attacks included the following: Thornburi Energy Storage Systems, a battery "
                "manufacturer in Thailand; construction consultancy WT Partnership Asia; Chinese car parts "
                "manufacturer Yanfen, which affected operations at US car maker Stellantis."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-campaign-2024", source_id="s-wikipedia-qilin",
        excerpt="In 2024, Qilin was named in the following attacks: Upper Merion Township in the United "
                "States, where they claimed to have stolen 500 GB including information on staff and private "
                "contracts; Felda Global Ventures Holdings Berhad in Malaysia; UK-based charity the Big Issue "
                "(550 GB of data stolen including personnel information, contracts and partner data); US "
                "business Skender Construction (651 GB of data stolen impacting 1,067 people including "
                "names, addresses, dates of birth, payment details, passports and potentially health "
                "information); several London hospitals declared a critical incident when a ransomware "
                "attack affected their systems."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-campaign-2025", source_id="s-wikipedia-qilin",
        excerpt="In 2025, Qilin was named in the following attacks: US business Inotiv (178 GB of data "
                "stolen); in October 2025, Qilin claimed responsibility for a ransomware attack on Asahi, a "
                "major Japanese brewery; on October 10, the Qilin group attacked infrastructure in the "
                "Hauts-de-France region targeting the Academie d'Amiens, with more than 1TB of data stolen -- "
                "the largest attack carried out by the Qilin group to date; in June 2025, the Qilin group "
                "claimed responsibility for a data breach on healthcare organization Covenant Health, "
                "reportedly impacting more than 478,000 individuals."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-mitre-tooling-overlap", source_id="s-mitre-s1242",
        excerpt="Qilin shares functionality overlaps with Black Basta, REvil, and BlackCat ransomware."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-ttp-impact", source_id="s-mitre-s1242",
        excerpt="T1486 Data Encrypted for Impact -- Qilin can use AES-256 or ChaCha20 for domain-wide "
                "encryption of victim servers and workstations and RSA-4096 or RSA-2048 to secure generated "
                "encryption keys. T1490 Inhibit System Recovery -- Qilin can execute 'vssadmin.exe delete "
                "shadows /all /quiet' to remove volume shadow copies and can disable High Availability (HA) "
                "and Distributed Resource Scheduler (DRS) in vCenter clusters."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-ttp-credential-lateral", source_id="s-mitre-s1242",
        excerpt="T1003.001 OS Credential Dumping: LSASS Memory -- Qilin can employ an embedded Mimikatz "
                "module to dump LSASS memory. T1570 Lateral Tool Transfer -- Qilin has used PsExec to "
                "distribute a second encryptor, named encryptor_1.exe, across the targeted environment. "
                "T1021.002 Remote Services: SMB/Windows Admin Shares -- Qilin can embed a copy of PsExec "
                "within its payload and place it in the %Temp% directory under a randomly generated "
                "filename. T1021.004 Remote Services: SSH -- Qilin can enable SSH access on ESXi hosts."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-ttp-defense-evasion", source_id="s-mitre-s1242",
        excerpt="T1070.004 Indicator Removal: File Deletion -- Qilin can delete itself from infected hosts "
                "after execution. T1685 Disable or Modify Tools -- Qilin can terminate antivirus-related "
                "processes and services; sub-technique .005 Clear Windows Event Logs -- Qilin has the "
                "ability to clear Windows Event Logs. T1036.004 Masquerading: Masquerade Task or Service -- "
                "Qilin has created a scheduled task named TVInstallRestore to mimic TeamViewer. T1036.005 "
                "Masquerading: Match Legitimate Resource Name or Location -- Qilin has named its payload "
                "file TeamViewer_Host_Setup to disguise itself as a legitimate TeamViewer file."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-ttp-initial-access", source_id="s-mitre-s1242",
        excerpt="T1190 Exploit Public-Facing Application -- Qilin has been delivered through exploitation of "
                "exposed applications and interfaces including Citrix and RDP. T1566.001 Phishing: "
                "Spearphishing Attachment -- Qilin has been delivered to victims through malicious email "
                "attachments. T1566.002 Phishing: Spearphishing Link -- Qilin has been delivered via "
                "malicious links in spearphishing emails."))
    # ------------------------------------------------------------------
    # Claims
    # ------------------------------------------------------------------
    claims = [
        Claim(claim_id="c-leak-site-claim", claim_type=ClaimType.VICTIM_IDENTITY,
              text="A group calling itself Qilin listed 'Spoonful of Comfort' on its Tor extortion leak site "
                   "on 2026-08-16 (18:56:20 UTC), categorizing it as a hospitality-sector victim in the "
                   "United States.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-claim-post"], source_refs=["s-hendryadrian"],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes the claim "
                            "was made, not that compromise/encryption/theft actually occurred. The "
                            "aggregator's own disclaimer ('I cannot confirm the accuracy of the "
                            "information') is preserved verbatim in the evidence excerpt rather than "
                            "smoothed over."),
        Claim(claim_id="c-compromise-occurred", claim_type=ClaimType.DATA_THEFT,
              text="Whether an actual compromise or data theft occurred at Spoonful of Comfort.",
              status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="No independent confirmation, victim statement, regulator filing, or data "
                            "sample was located in any of the five sources reviewed this session. The "
                            "leak-site claim alone does not establish this (Section 10) -- explicitly "
                            "represented as UNKNOWN, not inferred from Qilin's general track record."),
        Claim(claim_id="c-victim-ack", claim_type=ClaimType.VICTIM_IDENTITY,
              text="Victim acknowledgement of the incident.",
              status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post"], source_refs=["s-hendryadrian"],
              observed_vs_context=ObservedVsContext.OBSERVED),

        Claim(claim_id="c-qilin-overview", claim_type=ClaimType.TTP_HISTORICAL,
              text="Qilin is a ransomware-as-a-service (RaaS) family active since at least 2022, with "
                   "variants written in Go and Rust targeting Windows, Linux, and VMware ESXi, and a "
                   "victim base whose documented majority is in the US, France, Canada, and the UK, "
                   "primarily in manufacturing, technology, financial services, and healthcare.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-qilin-overview"], source_refs=["s-mitre-s1242"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="MITRE ATT&CK's own consolidated capability profile -- treated as a primary, "
                            "directly-quoted technical source, consistent with this session's established "
                            "practice for official MITRE technique/software/group pages."),
        Claim(claim_id="c-tooling-history", claim_type=ClaimType.TTP_HISTORICAL,
              text="Qilin's ransomware payload (originally 'Agenda', first detected by Trend Micro in "
                   "August 2022, written in Go and noted at the time to resemble Black Basta/BlackMatter/"
                   "REvil) was rewritten in Rust by December 2022.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-tooling-history"], source_refs=["s-wikipedia-qilin"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-tooling-lineage-current", claim_type=ClaimType.TTP_HISTORICAL,
              text="MITRE's current consolidated assessment records Qilin as sharing functionality overlaps "
                   "with Black Basta, REvil, and BlackCat ransomware -- a similar but not identical family "
                   "list to Trend Micro's 2022 comparison, consistent with a payload that has continued to "
                   "evolve since first detection.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-mitre-tooling-overlap"], source_refs=["s-mitre-s1242"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="Kept SEPARATE from c-tooling-history rather than merged -- two different "
                            "assessments, roughly three years apart, naming an overlapping but not "
                            "identical set of comparison families. Not a contradiction to resolve; both are "
                            "real, independently attributable analyst assessments at different points in "
                            "Qilin's development."),
        Claim(claim_id="c-raas-affiliate-split", claim_type=ClaimType.TTP_HISTORICAL,
              text="Group-IB's March 2023 infiltration of Qilin's affiliate panel found affiliates retain "
                   "approximately 80-85% of each ransom payment.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-raas-affiliate-split"], source_refs=["s-wikipedia-qilin"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-raas-operating-model", claim_type=ClaimType.TTP_HISTORICAL,
              text="Water Galura (MITRE ATT&CK G1050, alias GOLD FEATHER) are the operators of the Qilin "
                   "RaaS, handling payload generation, ransom negotiation, and the publication of stolen "
                   "data for affiliates recruited on Russian cybercrime forums, using a double-extortion "
                   "model, active since at least 2022.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-water-galura-model"], source_refs=["s-mitre-g1050"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-raas-telegram-announcements", claim_type=ClaimType.TTP_HISTORICAL,
              text="Water Galura operates a Telegram news channel to make announcements for the Qilin RaaS.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-water-galura-telegram"], source_refs=["s-mitre-g1050"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-water-galura-financial-theft", claim_type=ClaimType.TTP_HISTORICAL,
              text="Water Galura has extorted victims for ransomware decryption keys and to prevent "
                   "publication of data exfiltrated to their Tor data leak site.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-water-galura-financial-theft"], source_refs=["s-mitre-g1050"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-moonstone-sleet-deployment", claim_type=ClaimType.TTP_HISTORICAL,
              text="MITRE ATT&CK records Moonstone Sleet (G1036, alias Storm-1789), a North Korean-linked "
                   "threat actor, as having independently deployed Qilin ransomware -- citing a 2025-03-06 "
                   "Microsoft Threat Intelligence social-media post as MITRE's own source. That underlying "
                   "post was not independently retrieved this session.",
              status=EpistemicState.REPORTED, confidence=Confidence.LOW,
              evidence_refs=["e-moonstone-sleet-profile", "e-moonstone-sleet-qilin"], source_refs=["s-mitre-g1036"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="REPORTED rather than CONFIRMED: this claim rests on MITRE's own citation of a "
                            "third-party social-media post this session did not independently verify --  "
                            "unlike this canary's other MITRE-sourced TTP claims, which quote MITRE's own "
                            "technical documentation directly. General actor-ECOSYSTEM context only -- not "
                            "evidence connecting Moonstone Sleet, or any actor, to Spoonful of Comfort."),
        Claim(claim_id="c-campaign-chronology-2023", claim_type=ClaimType.TTP_HISTORICAL,
              text="In 2023, Qilin-attributed attacks named in open-source reporting include Thornburi "
                   "Energy Storage Systems (battery manufacturer, Thailand), construction consultancy WT "
                   "Partnership Asia, and Chinese car-parts manufacturer Yanfen (which affected operations "
                   "at US automaker Stellantis).",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-campaign-2023"], source_refs=["s-wikipedia-qilin"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-campaign-chronology-2024", claim_type=ClaimType.TTP_HISTORICAL,
              text="In 2024, Qilin-attributed attacks named in open-source reporting include Upper Merion "
                   "Township (US, ~500 GB claimed stolen), Felda Global Ventures Holdings Berhad (Malaysia), "
                   "the Big Issue (UK charity, 550 GB claimed stolen), Skender Construction (US, 651 GB "
                   "claimed stolen impacting 1,067 people), and a critical incident declared by several "
                   "London hospitals.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-campaign-2024"], source_refs=["s-wikipedia-qilin"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-campaign-chronology-2025", claim_type=ClaimType.TTP_HISTORICAL,
              text="In 2025, Qilin-attributed attacks named in open-source reporting include Inotiv (US, "
                   "178 GB claimed stolen), Asahi (major Japanese brewery, October 2025), Academie d'Amiens "
                   "(Hauts-de-France, France, more than 1TB claimed stolen -- the largest attack attributed "
                   "to Qilin to date), and Covenant Health (healthcare, June 2025, reportedly impacting more "
                   "than 478,000 individuals).",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-campaign-2025"], source_refs=["s-wikipedia-qilin"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-ttp-impact", claim_type=ClaimType.TTP_HISTORICAL,
              text="Qilin's documented impact-stage capability (T1486, T1490) includes AES-256 or ChaCha20 "
                   "domain-wide encryption with RSA-4096/RSA-2048 key protection, execution of 'vssadmin.exe "
                   "delete shadows /all /quiet' to remove volume shadow copies, and disabling vCenter High "
                   "Availability and Distributed Resource Scheduler.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-ttp-impact"], source_refs=["s-mitre-s1242"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-ttp-credential-lateral", claim_type=ClaimType.TTP_HISTORICAL,
              text="Qilin's documented credential-access and lateral-movement capability (T1003.001, T1570, "
                   "T1021.002, T1021.004) includes an embedded Mimikatz module for LSASS memory dumping, "
                   "PsExec-based distribution of a second encryptor and embedding of PsExec in the %Temp% "
                   "directory under a randomly generated filename, and enabling SSH access on ESXi hosts.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-ttp-credential-lateral"], source_refs=["s-mitre-s1242"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-ttp-defense-evasion", claim_type=ClaimType.TTP_HISTORICAL,
              text="Qilin's documented defense-evasion capability (T1070.004, T1685/T1685.005, T1036.004/"
                   ".005) includes self-deletion after execution, termination of antivirus-related processes "
                   "and clearing of Windows Event Logs, and masquerading via a scheduled task named "
                   "'TVInstallRestore' and a payload file named 'TeamViewer_Host_Setup'.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-ttp-defense-evasion"], source_refs=["s-mitre-s1242"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-ttp-initial-access", claim_type=ClaimType.TTP_HISTORICAL,
              text="Qilin's documented initial-access capability (T1190, T1566.001, T1566.002) includes "
                   "exploitation of exposed Citrix and RDP interfaces and delivery via spearphishing "
                   "attachments and spearphishing links.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-ttp-initial-access"], source_refs=["s-mitre-s1242"],
              observed_vs_context=ObservedVsContext.CONTEXT),
    ]
    for c in claims:
        graph.add_claim(c)
        graph.recompute_corroboration(c.claim_id)

    return graph


def build_ransomware_victim_claim() -> RansomwareVictimClaim:
    victim_observation = VictimObservation(
        group_named_by_source="Qilin",
        victim_name="Spoonful of Comfort",
        victim_domain=None,  # not stated by the source
        country="United States",
        sector="Hospitality (per aggregator categorization)",
        claim_date="2026-08-16T18:56:20.892782+00:00",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="Not specified by the source beyond 'unauthorized access and disruption of "
                                  "operations'.",
        sample_proof_status=EpistemicState.UNKNOWN,
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim", "c-victim-ack"],
        observed_incident_ioc_claim_ids=[],  # none located
        observed_incident_ttp_claim_ids=[],  # none located -- only actor-historical TTP context below
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=["Agenda"],
        raas_model_claim_ids=["c-raas-affiliate-split", "c-raas-operating-model",
                               "c-raas-telegram-announcements", "c-water-galura-financial-theft"],
        historical_ttp_claim_ids=["c-ttp-impact", "c-ttp-credential-lateral",
                                   "c-ttp-defense-evasion", "c-ttp-initial-access"],
        historical_tooling_claim_ids=["c-tooling-history", "c-tooling-lineage-current"],
        initial_access_history_claim_ids=["c-ttp-initial-access"],
        infrastructure_claim_ids=[],
        affiliate_behavior_claim_ids=["c-raas-affiliate-split", "c-raas-operating-model",
                                       "c-moonstone-sleet-deployment"],
        victimology_claim_ids=["c-campaign-chronology-2023", "c-campaign-chronology-2024",
                                "c-campaign-chronology-2025", "c-qilin-overview"],
        sectors=["Manufacturing", "Technology", "Financial Services", "Healthcare"],
        geographies=["United States", "France", "Canada", "United Kingdom"],
        campaign_history_claim_ids=["c-campaign-chronology-2023", "c-campaign-chronology-2024",
                                     "c-campaign-chronology-2025"],
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain immutable, offline backups with tested restoration procedures -- the "
                           "direct countermeasure to Qilin's documented shadow-copy-deletion and vCenter "
                           "HA/DRS-disabling behavior.",
        identity_hardening="Enforce MFA on all remote-access and privileged accounts; restrict and monitor "
                            "SSH access on ESXi management interfaces specifically.",
        segmentation="Segment networks to limit lateral movement from an initial foothold, including "
                     "isolating ESXi/vCenter management interfaces from general user network segments.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption "
                                   "activity and for the specific 'vssadmin.exe delete shadows /all /quiet' "
                                   "command line.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion, vCenter HA/DRS configuration "
                                      "changes, and Windows Event Log clearing (T1490, T1685.005).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks, "
                        "including a defined leak-site-monitoring process for unconfirmed extortion claims.",
    )

    return RansomwareVictimClaim(
        product_id="qilin-spoonful-of-comfort-premium-canary",
        victim_observation=victim_observation,
        actor_context=actor_context,
        generic_readiness=generic_readiness,
        # No linked_vulnerabilities -- no CVE/exploit was claimed or found for this incident, so the four
        # vulnerability-shaped markers stay NOT_APPLICABLE by construction (RansomwareVictimClaim.__post_init__).
    )


def build_metrics_registry() -> MetricsRegistry:
    registry = MetricsRegistry()
    registry.register(ExternalMetric(
        metric_id="m-skender-data-volume", name="Skender Construction claimed data volume (2024)",
        value=651, unit="GB", scope="Skender Construction, 2024 Qilin-attributed attack",
        source="Wikipedia (Qilin (cybercrime group)), citing open-source reporting",
        source_url="https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)",
        publication_year=2024, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2027-02-17",
        notes="Also reported to have impacted 1,067 individuals (names, addresses, dates of birth, payment "
              "details, passports, potentially health information); this registry entry stores only the "
              "data-volume figure.",
    ))
    registry.register(ExternalMetric(
        metric_id="m-academie-amiens-data-volume", name="Academie d'Amiens claimed data volume (2025)",
        value=1.0, unit="TB (stated as a floor: source says 'more than 1TB')",
        scope="Academie d'Amiens, October 2025 Qilin-attributed attack -- described as the largest Qilin "
              "attack to date",
        source="Wikipedia (Qilin (cybercrime group)), citing open-source reporting",
        source_url="https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)",
        publication_year=2025, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2027-02-17",
        notes="The source states 'more than 1TB' -- this is the stated floor, not an exact figure.",
    ))
    registry.register(ExternalMetric(
        metric_id="m-covenant-health-individuals", name="Covenant Health individuals impacted (2025)",
        value=478_000, unit="individuals", scope="Covenant Health, June 2025 Qilin-attributed data breach",
        source="Wikipedia (Qilin (cybercrime group)), citing open-source reporting",
        source_url="https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)",
        publication_year=2025, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2027-02-17",
        notes="Described in the source as 'reportedly' impacting this many individuals -- not independently "
              "confirmed by regulator filing in any source reviewed this session.",
    ))
    registry.register(ExternalMetric(
        metric_id="m-raas-affiliate-share", name="Qilin RaaS affiliate revenue share",
        value=82.5, unit="percent (midpoint of Group-IB's reported 80-85% range)",
        scope="Qilin RaaS affiliate program, as of Group-IB's March 2023 affiliate-panel infiltration",
        source="Wikipedia (Qilin (cybercrime group)), citing Group-IB",
        source_url="https://en.wikipedia.org/wiki/Qilin_(cybercrime_group)",
        publication_year=2023, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2027-08-17",
        notes="Group-IB's original figure is a range (80-85%), not a point estimate; this registry entry "
              "stores the midpoint for a single comparable value while the claim text preserves the full "
              "range.",
    ))
    return registry


def build_hypothesis_sets() -> list[HypothesisSet]:
    return [
        HypothesisSet(
            question="Does the 'Spoonful of Comfort' leak-site listing reflect a genuine, technically "
                      "successful compromise, or could it be an unconfirmed or exaggerated extortion claim?",
            hypotheses=(
                Hypothesis(
                    "h1", "H1: Genuine compromise, currently undisclosed",
                    "The claim reflects an actual compromise that Spoonful of Comfort has not yet "
                    "acknowledged publicly -- consistent with Water Galura's documented double-extortion "
                    "playbook, where leak-site listing typically precedes any public victim statement or "
                    "ransom-negotiation deadline.",
                    supporting_evidence_claim_ids=("c-leak-site-claim", "c-raas-operating-model"),
                    contradicting_evidence_claim_ids=(),
                    confidence="MEDIUM",
                ),
                Hypothesis(
                    "h2", "H2: Unconfirmed or overstated claim",
                    "The claim has not been technically substantiated by any source reviewed -- no proof "
                    "sample, no independent confirmation, and no victim acknowledgement were located, which "
                    "is also consistent with a leak-site posting used as extortion pressure without (or "
                    "prior to) actual data exfiltration being demonstrated.",
                    supporting_evidence_claim_ids=("c-compromise-occurred", "c-victim-ack"),
                    contradicting_evidence_claim_ids=(),
                    confidence="MEDIUM",
                ),
            ),
        ),
        HypothesisSet(
            question="If a compromise occurred, was it carried out by a standard, financially-motivated "
                      "Qilin RaaS affiliate, or could it involve a non-standard operator such as the "
                      "DPRK-linked Moonstone Sleet, which MITRE separately documents as having deployed "
                      "the same Qilin payload?",
            hypotheses=(
                Hypothesis(
                    "h1", "H1: Standard criminal RaaS affiliate",
                    "Consistent with the overwhelming majority of Qilin's documented 2023-2025 campaign "
                    "(broad sector/geography spread, financially motivated, consistent with Water Galura's "
                    "Russian-forum affiliate-recruitment model), a standard affiliate is the more probable "
                    "explanation absent any specific evidence otherwise.",
                    supporting_evidence_claim_ids=("c-raas-operating-model", "c-campaign-chronology-2023",
                                                    "c-campaign-chronology-2024", "c-campaign-chronology-2025"),
                    contradicting_evidence_claim_ids=(),
                    confidence="MEDIUM",
                ),
                Hypothesis(
                    "h2", "H2: Non-standard operator",
                    "Cannot be ruled out given MITRE's own documentation that at least one differently-"
                    "motivated, state-linked actor has independently deployed the Qilin payload -- though no "
                    "source reviewed connects Moonstone Sleet specifically to hospitality-sector targeting "
                    "or to this incident.",
                    supporting_evidence_claim_ids=("c-moonstone-sleet-deployment",),
                    contradicting_evidence_claim_ids=(),
                    confidence="LOW",
                ),
            ),
        ),
    ]


def build_intelligence_gaps(victim_observation: VictimObservation) -> list[IntelligenceGap]:
    gaps = derive_ransomware_gaps(victim_observation)
    gaps.append(IntelligenceGap(
        "Whether any of the general Qilin/Water Galura TTPs documented above (shadow-copy deletion, "
        "LSASS credential dumping, ESXi SSH enablement, TVInstallRestore/TeamViewer_Host_Setup "
        "masquerading, etc.) were actually used in this specific incident is not established by any source "
        "reviewed -- this is documented actor CAPABILITY, not incident-specific evidence.",
        "COLLECTION_GAP",
        "Incident-specific forensic artifacts, EDR telemetry, or a confirmed intrusion-vector statement from "
        "Spoonful of Comfort or an engaged incident-response firm.",
    ))
    gaps.append(IntelligenceGap(
        "Which specific actor or affiliate within the Qilin RaaS ecosystem -- a standard Water-Galura-"
        "recruited criminal affiliate, or a differently-motivated operator such as Moonstone Sleet -- is "
        "responsible for this claim is not established by any source reviewed.",
        "KNOWN_UNKNOWN",
        "CTI vendor attribution research specific to this claim, or law-enforcement/vendor telemetry tying "
        "a specific known affiliate cluster to this incident.",
    ))
    return gaps


def build_regulatory_applicabilities() -> list[RegulatoryApplicability]:
    return [
        RegulatoryApplicability(
            jurisdiction="US/HIPAA", victim_geography="United States", operations_geography="United States",
            data_subject_geography=None, sector="Hospitality", entity_classification=None,
            incident_facts_claim_ids=("c-leak-site-claim",), regulation="HIPAA",
            applicability_state=ApplicabilityState.NOT_APPLICABLE,
            basis="Spoonful of Comfort is categorized in the source reviewed as a hospitality/corporate-"
                  "gifting business, not a HIPAA-covered entity or business associate -- no source reviewed "
                  "establishes a healthcare nexus for this specific victim (contrast with Covenant Health, "
                  "a genuinely healthcare-sector Qilin-attributed 2025 victim named in the campaign "
                  "chronology above, which this determination does NOT extend to).",
        ),
        not_assessed(
            "US state data-breach notification statutes",
            reason="Notification obligations are generally triggered by confirmed compromise of specific "
                   "categories of personal information, a fact this report does not establish -- whether any "
                   "personal-information dataset was actually accessed or exfiltrated is UNKNOWN "
                   "(c-compromise-occurred), so applicability cannot be determined from the evidence "
                   "reviewed.",
        ),
        not_assessed(
            "PCI-DSS",
            reason="Spoonful of Comfort's sector (hospitality/specialty-gifting, plausibly e-commerce) "
                   "commonly processes payment card data, but whether any cardholder-data environment was "
                   "actually affected is not established by any source reviewed; PCI-DSS is a contractual/"
                   "industry framework rather than a legal reporting requirement, and applicability depends "
                   "on deployment-specific facts this report does not have.",
        ),
        RegulatoryApplicability(
            jurisdiction="US/SEC", victim_geography="United States", operations_geography="United States",
            data_subject_geography=None, sector=None, entity_classification=None,
            incident_facts_claim_ids=("c-leak-site-claim",), regulation="SEC Cyber Disclosure Rule",
            applicability_state=ApplicabilityState.NOT_APPLICABLE,
            basis="No source reviewed establishes Spoonful of Comfort as a US public company subject to SEC "
                  "reporting obligations; it is represented in the source reviewed as a private "
                  "specialty-gifting business.",
        ),
    ]


def build_forecast() -> Forecast:
    return Forecast(
        judgment="Qilin-branded ransomware activity, driven by Water Galura's ongoing RaaS affiliate "
                 "recruitment and Telegram-based announcement channel, will likely continue at or above its "
                 "documented 2023-2025 pace, with targeting continuing to span hospitality/services "
                 "alongside its historically dominant manufacturing, technology, financial-services, and "
                 "healthcare sectors.",
        time_horizon="90 days from 2026-08-17",
        supporting_observation_claim_ids=("c-campaign-chronology-2023", "c-campaign-chronology-2024",
                                           "c-campaign-chronology-2025", "c-raas-operating-model",
                                           "c-raas-telegram-announcements"),
        historical_baseline_claim_ids=("c-qilin-overview",),
        assumptions=(
            "Water Galura continues actively recruiting and retaining affiliates via Russian cybercrime "
            "forums at a pace comparable to its documented 2022-2026 operating history.",
        ),
        counter_evidence_claim_ids=(),
        alternative_scenarios=(
            "Law-enforcement action against Water Galura's affiliate infrastructure or Tor leak site (as has "
            "occurred against other major RaaS brands) disrupts the group's operating cadence within the "
            "forecast window.",
        ),
        indicators_to_watch=(
            "New named victims added to Qilin's Tor leak site at a rate consistent with or exceeding the "
            "roughly 4-5-per-year publicly documented pace",
            "Additional MITRE ATT&CK or CTI-vendor documentation of non-standard operators (beyond "
            "Moonstone Sleet) deploying the Qilin payload",
            "Law-enforcement seizure notices or takedown announcements targeting Qilin/Water Galura "
            "infrastructure",
        ),
        confidence="MEDIUM",
        confidence_rationale="Supported by three consecutive years (2023-2025) of real, individually-named, "
                              "escalating-scale documented attacks and an actively-recruiting RaaS operator "
                              "model, but tempered by the inherent unpredictability of law-enforcement "
                              "disruption events and by this review's own finding that the RaaS brand's "
                              "affiliate base is not monolithic -- at least one differently-motivated "
                              "operator has independently deployed the same payload.",
        what_would_change_assessment=(
            "A confirmed law-enforcement takedown of Water Galura's infrastructure would lower confidence "
            "sharply; a fourth consecutive year of comparable or increasing named-victim volume would raise "
            "it.",
        ),
    )


def build_detection_rule() -> DetectionRule:
    """A real, structurally valid Sigma-style detection concept grounded directly in two of Qilin's own
    documented, quotable command-line/naming indicators (c-ttp-impact, c-ttp-defense-evasion) -- marked
    SYNTAX_VALIDATED, not LAB_VALIDATED or PRODUCTION_VALIDATED, since it has not been tested against live
    telemetry this session."""
    body = (
        "title: Qilin Ransomware Shadow-Copy Deletion and TVInstallRestore Scheduled-Task Masquerade\n"
        "id: reportx-canary-qilin-vssadmin-tvinstallrestore\n"
        "status: experimental\n"
        "description: >\n"
        "  Detects two command-line indicators documented for the Qilin ransomware\n"
        "  family: vssadmin.exe invoked to delete all shadow copies, and creation\n"
        "  of a scheduled task named TVInstallRestore used to masquerade as a\n"
        "  legitimate TeamViewer maintenance task. Either indicator alone is a\n"
        "  strong ransomware impact-stage signal; this rule does not by itself\n"
        "  confirm Qilin/Water Galura attribution for any specific incident.\n"
        "references:\n"
        "  - https://attack.mitre.org/software/S1242/\n"
        "  - https://attack.mitre.org/groups/G1050/\n"
        "logsource:\n"
        "  category: process_creation\n"
        "  product: windows\n"
        "detection:\n"
        "  selection_vssadmin:\n"
        "    Image|endswith: '\\vssadmin.exe'\n"
        "    CommandLine|contains|all:\n"
        "      - 'delete'\n"
        "      - 'shadows'\n"
        "      - '/all'\n"
        "      - '/quiet'\n"
        "  selection_scheduled_task:\n"
        "    CommandLine|contains: 'TVInstallRestore'\n"
        "  condition: selection_vssadmin or selection_scheduled_task\n"
        "falsepositives:\n"
        "  - Legitimate backup/shadow-copy maintenance scripts using the same vssadmin syntax\n"
        "  - Unrelated scheduled tasks that happen to share a similar naming convention\n"
        "level: high\n"
    )
    return DetectionRule(
        rule_id="reportx-canary-qilin-vssadmin-tvinstallrestore", technique_id="T1490", format="sigma",
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
        "# Qilin / 'Spoonful of Comfort' — Premium Intelligence Canary\n\n"
        "**Classification:** TLP:CLEAR — public leak-site claim and open-source actor intelligence\n\n"
        "## Executive Summary\n\n"
        "On 2026-08-16, a group identifying itself as Qilin listed 'Spoonful of Comfort', a US "
        "hospitality-sector business, on its Tor extortion leak site. This is a single-source claim; no "
        "independent confirmation, victim statement, regulator filing, or data sample has been located. "
        "Real, directly-sourced actor context shows Qilin operating as a ransomware-as-a-service platform "
        "run by an operator group MITRE ATT&CK tracks as Water Galura, with a documented, escalating "
        "three-year campaign chronology (2023-2025) spanning manufacturing, government, healthcare, and "
        "charity sectors across multiple continents -- and, notably, MITRE's own documentation that at "
        "least one differently-motivated, state-linked actor (Moonstone Sleet) has independently deployed "
        "the same ransomware payload. None of this actor-level context is evidence of what happened, if "
        "anything, at Spoonful of Comfort specifically.\n\n"
        "## Scope and Methodology\n\n"
        "This report synthesizes five independently retrieved sources, all fetched as raw bytes via direct "
        "HTTP fetch with content_sha256 computed programmatically from the checked-in raw files, never "
        "hand-typed: the leak-site aggregator hendryadrian.com (the victim claim itself), Wikipedia's "
        "'Qilin (cybercrime group)' article (a tertiary source citing Trend Micro and Group-IB, with a real "
        "named campaign chronology), and three official MITRE ATT&CK pages -- the Qilin software profile "
        "(S1242), the Water Galura operator-group profile (G1050), and the Moonstone Sleet operator-group "
        "profile (G1036). Every claim in this report traces to at least one of these five sources via an "
        "explicit evidence_refs/source_refs chain, visible in the Sources & Evidence Ledger appendix below. "
        "No claim in this report is drawn from model memory or generic industry knowledge about ransomware "
        "conventions in general -- every specific figure, date, technique ID, and quote is source-anchored. "
        "Victim-specific observations (this incident only) are kept structurally and narratively separate "
        "from actor-historical context (what is known about Qilin/Water Galura in general) throughout.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 18:56:20 UTC on Qilin's Tor leak site. Sector: hospitality (per aggregator "
        "categorization). Country: United States. The claim describes 'unauthorized access and disruption "
        "of operations' without specifying what data, if any, was taken. No proof sample was reviewed. "
        "Whether a compromise actually occurred is UNKNOWN on current evidence -- this report does not "
        "assert it did. The aggregating source's own disclaimer is preserved here rather than smoothed "
        "over: 'This post is based on public claims made by the ransomware group qilin. I cannot confirm "
        "the accuracy of the information.'\n\n"
        "## Actor Overview: Qilin (RaaS Family)\n\n"
        "Qilin is a ransomware-as-a-service family active since at least 2022, with variants written in Go "
        "and Rust targeting Windows, Linux, and VMware ESXi, per MITRE ATT&CK's own consolidated capability "
        "profile. Originally detected by Trend Micro in August 2022 under the name 'Agenda' -- Go-language "
        "code Trend Micro assessed at the time as resembling Black Basta, BlackMatter, and REvil -- the "
        "payload was rewritten in Rust by December 2022. MITRE's current, more recent assessment describes "
        "an overlapping but not identical family comparison: Black Basta, REvil, and BlackCat. Both "
        "assessments are reported here as separate, independently attributable analytic judgments taken "
        "roughly three years apart, rather than merged into a single figure. MITRE records the majority of "
        "Qilin's documented victims as being in the US, France, Canada, and the UK, primarily in "
        "manufacturing, technology, financial services, and healthcare -- an aggregate industry-level "
        "statement, not a claim about any specific victim.\n\n"
        "## RaaS Operating Model: Water Galura\n\n"
        "MITRE ATT&CK tracks the operators of the Qilin RaaS platform as Water Galura (G1050, alias GOLD "
        "FEATHER): the group handling payload generation, ransom negotiation, and publication of stolen "
        "data for affiliates recruited on Russian cybercrime forums, using a double-extortion model, active "
        "since at least 2022. Water Galura operates a Telegram news channel to announce the RaaS to "
        "prospective affiliates, and directly extorts victims for both decryption keys and to prevent "
        "publication of exfiltrated data to their Tor leak site. Separately, Group-IB's March 2023 "
        "infiltration of Qilin's affiliate panel found that affiliates retain approximately 80-85% of each "
        "ransom payment -- a real, quantified data point on the RaaS's own economics, consistent with the "
        "broad, high-volume affiliate model MITRE's own profile describes.\n\n"
        "## Actor Ecosystem Complexity: Moonstone Sleet\n\n"
        "A RaaS brand is not always a single operator. MITRE ATT&CK separately records Moonstone Sleet "
        "(G1036, alias Storm-1789) -- a North Korean-linked threat actor conducting both financially "
        "motivated attacks and espionage, which previously overlapped significantly with the Lazarus Group "
        "before differentiating its tradecraft since 2023 -- as having deployed Qilin ransomware, citing a "
        "2025-03-06 Microsoft Threat Intelligence social-media post as MITRE's own source. That underlying "
        "post was not independently retrieved this session, so this claim is represented as REPORTED rather "
        "than CONFIRMED. This is included strictly as actor-ECOSYSTEM context: it demonstrates that more "
        "than one kind of operator can be behind a Qilin-branded incident, not that Moonstone Sleet, or any "
        "specific actor, is connected to Spoonful of Comfort -- no source reviewed makes that connection.\n\n"
        "## Documented Campaign Chronology (2023-2025)\n\n"
        "Wikipedia's article (citing open-source reporting) documents a real, escalating, named campaign "
        "history. **2023:** Thornburi Energy Storage Systems (battery manufacturer, Thailand), construction "
        "consultancy WT Partnership Asia, and Chinese car-parts manufacturer Yanfen (affecting operations at "
        "US automaker Stellantis). **2024:** Upper Merion Township (US, ~500 GB claimed stolen), Felda "
        "Global Ventures Holdings Berhad (Malaysia), the Big Issue (UK charity, 550 GB claimed stolen), "
        "Skender Construction (US, 651 GB claimed stolen impacting 1,067 people, including names, addresses, "
        "dates of birth, payment details, and passports), and a critical incident declared by several London "
        "hospitals. **2025:** Inotiv (US, 178 GB claimed stolen), Asahi (major Japanese brewery, October "
        "2025), Academie d'Amiens (Hauts-de-France, France, more than 1TB claimed stolen -- the largest "
        "attack attributed to Qilin to date), and Covenant Health (healthcare, June 2025, reportedly "
        "impacting more than 478,000 individuals). None of these prior incidents is evidence about Spoonful "
        "of Comfort; they establish the actor's documented operating pattern and scale.\n\n"
        "## Tactics, Techniques, and Procedures (ATT&CK-Mapped)\n\n"
        "MITRE ATT&CK documents Qilin's capability across the full attack lifecycle, quoted directly here. "
        "**Initial access (T1190, T1566.001, T1566.002):** exploitation of exposed Citrix and RDP "
        "interfaces, and delivery via spearphishing attachments and links. **Credential access and lateral "
        "movement (T1003.001, T1570, T1021.002, T1021.004):** an embedded Mimikatz module for LSASS memory "
        "dumping; PsExec-based distribution of a second encryptor; PsExec embedded in the %Temp% directory "
        "under a randomly generated filename; and enabling SSH access on ESXi hosts. **Defense evasion "
        "(T1070.004, T1685/T1685.005, T1036.004/.005):** self-deletion after execution; termination of "
        "antivirus-related processes and clearing of Windows Event Logs; and masquerading via a scheduled "
        "task named 'TVInstallRestore' and a payload file named 'TeamViewer_Host_Setup'. **Impact (T1486, "
        "T1490):** AES-256 or ChaCha20 domain-wide encryption with RSA-4096/RSA-2048 key protection; "
        "execution of 'vssadmin.exe delete shadows /all /quiet'; and disabling vCenter High Availability and "
        "Distributed Resource Scheduler. All of this is documented CAPABILITY -- no TTP specific to this "
        "incident has been observed by any source reviewed.\n\n"
        "## Detection\n\n"
        "A Sigma detection concept is provided at SYNTAX_VALIDATED maturity only -- neither lab testing nor "
        "any deployment validation has been performed this session -- targeting two of Qilin's own "
        "documented, quotable indicators: the 'vssadmin.exe delete shadows /all /quiet' command line and "
        "creation of a scheduled task named 'TVInstallRestore'. A match does not by itself confirm Qilin "
        "attribution; both are documented ransomware/impact-stage indicators that could theoretically "
        "appear in other contexts (see the rule's own falsepositives field). Full rule body:\n\n"
        f"```yaml\n{detection_rule.body}```\n\n"
        "## Hunting\n\n"
        "Given the documented, specific naming conventions in Qilin's masquerading TTPs, a defensible "
        "hunting hypothesis is to search endpoint process and file-creation telemetry for the exact strings "
        "'TVInstallRestore' and 'TeamViewer_Host_Setup' outside of genuine TeamViewer installation activity, "
        "and to search command-line telemetry for PsExec invocations sourced from randomly-named files "
        "inside %Temp% rather than a standard PsExec installation path. Separately, given Water Galura's "
        "documented use of SSH enablement on ESXi hosts (T1021.004), hunting teams operating VMware "
        "environments should review ESXi SSH-service enable/disable audit logs for unexpected activation "
        "events outside of planned maintenance windows. This report does not include incident-specific IOCs "
        "for Spoonful of Comfort -- none were located by any source reviewed.\n\n"
        "## Forecast\n\n"
        "MEDIUM confidence that Qilin-branded activity will continue at or above its documented 2023-2025 "
        "pace over the next 90 days, with continued targeting spanning hospitality/services alongside its "
        "historically dominant sectors -- tempered by the inherent unpredictability of law-enforcement "
        "disruption events and by this review's own finding that the RaaS brand's affiliate base is not "
        "monolithic. See the structured forecast record (supporting observations, assumptions, alternative "
        "scenarios, and indicators to watch) in this bundle's `forecasts` field.\n\n"
        "## Alternative Hypotheses\n\n"
        "Two genuinely open analytic questions are weighed explicitly rather than resolved by assumption. "
        "**First**, whether the leak-site listing reflects a genuine, currently-undisclosed compromise "
        "(**H1**, consistent with Water Galura's documented double-extortion playbook) versus an unconfirmed "
        "or overstated claim (**H2**, consistent with the total absence of a proof sample, independent "
        "confirmation, or victim acknowledgement). **Second**, if a compromise did occur, whether it was "
        "carried out by a standard, financially-motivated Water-Galura-recruited affiliate (**H1**, "
        "consistent with the overwhelming majority of Qilin's documented campaign) versus a non-standard "
        "operator such as Moonstone Sleet (**H2**, which cannot be ruled out given MITRE's own documentation "
        "but has no source connecting it specifically to this incident).\n\n"
        "## Regulatory Considerations\n\n"
        "HIPAA is assessed NOT_APPLICABLE: Spoonful of Comfort is a hospitality/specialty-gifting business "
        "with no established healthcare nexus, explicitly distinguished from Covenant Health, a genuinely "
        "healthcare-sector Qilin-attributed 2025 victim named in the campaign chronology above. US state "
        "data-breach notification statutes and PCI-DSS are both assessed NOT_ASSESSED: notification and "
        "cardholder-data-environment obligations depend on which specific data, if any, was actually "
        "accessed, and that fact is UNKNOWN on current evidence. The SEC Cyber Disclosure Rule is assessed "
        "NOT_APPLICABLE: no source reviewed establishes Spoonful of Comfort as a US public company.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- immutable backups, MFA and ESXi SSH-access hardening, "
        "network segmentation isolating management interfaces, behavioral detection for mass encryption and "
        "the specific vssadmin command line, monitoring for shadow-copy/HA/DRS/event-log tampering, and a "
        "tested IR plan with a defined leak-site-monitoring process -- is provided as general hardening "
        "grounded in Qilin's own documented TTPs, not as evidence any specific technique was used against "
        "this victim.\n\n"
        "## Intelligence Gaps\n\n"
        "Seven gaps are explicitly unresolved by any source reviewed for this report: victim acknowledgement "
        "is unavailable; no incident-specific IOCs were observed; no proof sample of the claimed stolen data "
        "exists; no independent confirmation of the leak-site claim was located; no initial-access or "
        "incident-specific TTP evidence was found; whether any of Qilin's documented general TTPs were used "
        "in this specific incident is unestablished; and which specific actor or affiliate is responsible "
        "for this claim -- a standard Water-Galura-recruited affiliate or a non-standard operator -- is "
        "unestablished.\n\n"
        "## Technical Recommendations\n\n"
        "1. Maintain immutable, tested, offline backups as the direct countermeasure to Qilin's documented "
        "shadow-copy-deletion and vCenter HA/DRS-disabling behavior (evidence: c-ttp-impact).\n"
        "2. Harden ESXi/vCenter management interfaces -- disable unnecessary SSH access and monitor for "
        "unexpected SSH-enablement events -- against Qilin's documented ESXi-targeting TTPs (evidence: "
        "c-ttp-credential-lateral, c-ttp-impact).\n"
        "3. Deploy monitoring for Qilin's specific documented masquerading indicators ('TVInstallRestore', "
        "'TeamViewer_Host_Setup') via the detection rule above (evidence: c-ttp-defense-evasion).\n\n"
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

    return ReportBundle(
        report_id="qilin-spoonful-of-comfort-premium-canary",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={"victim_confirmation": ["c-leak-site-claim", "c-victim-ack", "c-compromise-occurred"]},
        detection_rules=[detection_rule],
        metrics_registry=registry,
        cited_metric_ids=["m-skender-data-volume", "m-academie-amiens-data-volume",
                           "m-covenant-health-individuals", "m-raas-affiliate-share"],
        rendered_metric_ids=["m-skender-data-volume", "m-academie-amiens-data-volume",
                              "m-covenant-health-individuals", "m-raas-affiliate-share"],
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
        technical_recommendation_count=3,
        technical_recommendations_with_evidence_basis=3,
    )
