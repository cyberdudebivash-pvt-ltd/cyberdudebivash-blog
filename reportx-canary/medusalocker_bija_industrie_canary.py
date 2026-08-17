"""ReportX Phase 4 real premium canary B: MedusaLocker / Bija Industrie.

Built from real research retrieved this session (WebSearch + WebFetch +
direct curl, 2026-08-17/18) against FIVE independently retrieved sources,
all fetched as raw bytes via direct HTTP fetch (curl) and checked into
`reportx-canary/raw-sources/`; every source's `content_sha256` is computed
from those exact files at import time (never hand-typed) -- see
`evidence_integrity.compute_content_sha256`. Every one of this canary's
five sources was fetchable in full -- no excerpt-fingerprint fallback is
used here.

This canary extends (not replaces) the earlier, deliberately modest golden
fixture at
`tests/fixtures/reportx-commercial-readiness/medusalocker_bija_industrie.py`
(``is_premium_tier=False``, no detection/forecast/hypothesis/regulatory
content) -- the victim-observation facts are the same real claim, but this
module adds substantially deeper, independently-sourced actor-context,
TTP, IOC, detection, hunting, forecast, and regulatory material on top of
it, built to independently clear the 23-control commercial-readiness
matrix at ``PREMIUM_READY_PENDING_HUMAN``.

Sources:
  - ransomware.live (leak-site tracker) -- the leak-site claim itself.
    Victim: Bija Industrie. Domain: bija-industrie.com. Country: France
    (confirmed via the page's own `flags/FR.svg` country-flag reference).
    Discovered 2026-08-16 15:20 UTC, est. attack date 2026-08-16. Claim
    text: "Organization with 693 emails extracted." DNS/WHOIS
    fingerprinting: MX records at mx-mibc-fr-08.mailinblack.com (Mailinblack,
    a French email-security SaaS) and mx2/mx3.mail.ovh.net (OVH, a French
    hosting provider); WHOIS abuse contact abuse@ovh.net; SPF record
    v=spf1 include:mx.ovh.com. This is infrastructure fingerprinting only,
    not evidence of the incident's initial-access vector.
  - bija-industrie.com (the victim's own current site) -- independently
    confirms, in the company's own French-language self-description, that
    it designs, manufactures, and distributes specialized tooling for the
    aerospace and industrial sectors, with 20+ years of aerospace
    experience serving BOTH civil AND military aviation programs, across
    three brands (BIJA Industrie, MMI, MRO Integral Solutions). A genuine
    VICTIM_STATEMENT-tier source refining the tracker's generic
    "Manufacturing" classification with the entity's own, more specific
    description.
  - the IC3.gov mirror of CISA/FBI/Treasury/FinCEN Joint Cybersecurity
    Advisory AA22-181A, "#StopRansomware: MedusaLocker" (published
    2022-06-30, TLP:WHITE) -- CISA's own site returned HTTP 403 (Akamai
    "Access Denied") on both the HTML advisory page and its own PDF
    mirror, consistent with the blocking behavior already documented for
    CISA in this canary set (see the Ray/CVE-2025-62593 canary); the
    IC3.gov mirror of the SAME advisory (same Product ID AA22-181A,
    identical text) was fetchable in full and is used here as the primary
    actor-context source. Real, directly-quoted MITRE ATT&CK technique
    table (T1133, T1566, T1059.001, T1562.009, T1486, T1490), the
    documented 55-60% affiliate/45-40% developer RaaS ransom split,
    execution/persistence/defense-evasion/recovery-inhibition mechanics,
    and historical (2019-2022 vintage, explicitly labeled "several years
    old" by the advisory itself) generic IOCs (encrypted file extensions,
    ransom-note filenames, Bitcoin wallets, email addresses, Tor
    addresses, and historically-linked IPs) are used verbatim below --
    strictly as actor-historical CONTEXT, never as incident-specific
    evidence for Bija Industrie.
  - ransomware.live's MedusaLocker group page -- the tracker's own current
    (2026-08-17) aggregate statistics for the actor: 83 total tracked
    victims, first tracked victim's estimated attack date 2021-11-03, 19
    countries hit, an average 83.1-day delay between estimated attack date
    and leak-site claim, and 37.0% of tracked victims showing a domain
    overlap with infostealer-malware logs. Last-seen date 2026-08-16 --
    i.e., Bija Industrie is the group's own most recently tracked victim
    at the time of this report.
  - Cybersecurity Dive, "Federal authorities warn MedusaLocker ransomware
    targeting remote desktop vulnerabilities" (published 2022-07-01) --
    independent secondary journalism on the SAME AA22-181A advisory,
    providing genuine cross-source corroboration (a different publisher,
    different independence_group) for the RaaS 55-60% split fact, plus
    two additional real, dated facts the primary advisory text itself does
    not state: MedusaLocker "first emerged in late 2019" (explicitly
    attributed by this source to a Cybereason report, not verified further
    this session -- represented as REPORTED, not CONFIRMED, for that
    reason) and that "the group was particularly active in the healthcare
    space, where many organizations were attacked in connection to the
    COVID-19 pandemic."

NAMING-COLLISION NOTE (mirroring this fixture set's established discipline
-- see the Idex Group / IDEX Corporation catch in the golden fixtures):
MITRE ATT&CK tracks a software entry "Medusa Ransomware" (S1244) and a
group "Medusa Group" (G1051) -- these are a DIFFERENT, unrelated
ransomware operation from MedusaLocker (different launch year, different
ransom-note naming, different encrypted-file extension, industry reporting
explicitly documents the two are frequently and incorrectly conflated).
No MITRE ATT&CK page for MedusaLocker specifically was located; this
canary's TTP claims are sourced to the CISA/FBI/Treasury/FinCEN advisory's
own ATT&CK technique table instead, and S1244/G1051 are never cited here.

None of the actor-context, TTP, RaaS-model, or current-scale material
below is evidence of what happened, if anything, at Bija Industrie
specifically -- every such claim is tagged ``ObservedVsContext.CONTEXT``
and is never merged with the victim observation layer's ``OBSERVED``
claims. Bija's self-stated military-aviation exposure is retained (it is
real, self-stated, and analytically relevant defense-industrial-base
context) but is NEVER converted into an assertion that military-sensitive
data was exfiltrated -- the leak-site claim itself states only an email
COUNT, with no category, sensitivity, or content description given by any
source reviewed; that open question is carried as an explicit,
unresolved intelligence gap, not as a hypothesis pairing "military" with
"extracted" that could read as an implied conclusion either way.
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

    ransomwarelive_hash = _hash_raw("bija-ransomwarelive.html")
    graph.add_source(SourceRecord(
        source_id="s-ransomwarelive-bija", url="https://www.ransomware.live/id/QmlqYSBJbmR1c3RyaWVAbWVkdXNhbG9ja2Vy",
        publisher="ransomware.live (leak-site tracker)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.PRIMARY_EVENT_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-16T15:20:00Z",
        reliability=Reliability.MODERATE, independence_group="medusalocker-bija-leak-post",
        content_sha256=ransomwarelive_hash,
        notes="Indexes MedusaLocker's own Tor leak-site post. Country France confirmed via the page's "
              "own flags/FR.svg reference. Claim text: 'Organization with 693 emails extracted.' Domain "
              "bija-industrie.com. DNS/WHOIS fingerprinting: MX records at mx-mibc-fr-08.mailinblack.com "
              "and mx2/mx3.mail.ovh.net, WHOIS abuse contact abuse@ovh.net, SPF v=spf1 include:mx.ovh.com, "
              "Mailinblack (email-security SaaS) detected.",
    ))

    bija_site_hash = _hash_raw("bija-industrie-com.html")
    graph.add_source(SourceRecord(
        source_id="s-bija-own-site", url="https://bija-industrie.com",
        publisher="BIJA Industrie (the company's own site)",
        source_type=SourceType.VICTIM_STATEMENT, source_role=SourceRole.CORROBORATION,
        retrieved_at="2026-08-17T00:00:00Z", source_date=None,
        reliability=Reliability.HIGH, independence_group="bija-own-site",
        content_sha256=bija_site_hash,
        notes="Company's own self-description (French): design, manufacture, and distribution of "
              "specialized tools for aerospace and industrial sectors; 20+ years of aerospace experience; "
              "serves civil AND military aviation programs; three brands (BIJA Industrie, MMI, MRO "
              "Integral Solutions).",
    ))

    ic3_hash = _hash_raw("ic3-220630.pdf")
    graph.add_source(SourceRecord(
        source_id="s-ic3-medusalocker-advisory", url="https://www.ic3.gov/CSA/2022/220630.pdf",
        publisher="FBI / CISA / Dept. of the Treasury / FinCEN (Joint Cybersecurity Advisory AA22-181A, "
                   "via the ic3.gov mirror -- cisa.gov itself returned HTTP 403 Access Denied on both the "
                   "HTML advisory and its own PDF, consistent with the blocking behavior documented "
                   "elsewhere in this canary set)",
        source_type=SourceType.PRIMARY_TECHNICAL_ADVISORY, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2022-06-30",
        reliability=Reliability.HIGH, independence_group="medusalocker-cisa-ic3-advisory-aa22-181a",
        content_sha256=ic3_hash,
        notes="Product ID AA22-181A, 'StopRansomware: MedusaLocker', TLP:WHITE, 11 pages. Primary "
              "government joint advisory: initial access via RDP (T1133, 'most often') and phishing/spam "
              "(T1566, 'frequently'); PowerShell invoke-ReflectivePEInjection execution (T1059.001); "
              "safe-mode reboot for defense evasion (T1562.009); AES-256/RSA-2048 encryption (T1486); "
              "svhost.exe/svhostt.exe persistence via a 15-minute scheduled task; shadow-copy/backup "
              "deletion (T1490); 55-60% affiliate / remainder-developer RaaS split; historical (2019-2022 "
              "vintage, advisory's own words: 'several years old') generic IOCs; a named mitigations list.",
    ))

    group_stats_hash = _hash_raw("ransomwarelive-medusalocker-group.html")
    graph.add_source(SourceRecord(
        source_id="s-ransomwarelive-medusalocker-group", url="https://www.ransomware.live/group/medusalocker",
        publisher="ransomware.live (leak-site tracker, group aggregate page)",
        source_type=SourceType.LEAK_SITE_AGGREGATOR, source_role=SourceRole.STATISTICAL_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2026-08-17",
        reliability=Reliability.MODERATE, independence_group="medusalocker-bija-leak-post",
        content_sha256=group_stats_hash,
        notes="The tracker's own current (2026-08-17) aggregate stats for MedusaLocker: 83 total tracked "
              "victims, first tracked victim's est. attack date 2021-11-03, 19 countries hit, average "
              "83.1-day delay between est. attack date and leak-site claim, 37.0% of tracked victims show "
              "a domain overlap with infostealer-malware logs, last-seen 2026-08-16 (Bija Industrie is "
              "the group's own most recently tracked victim at retrieval time). Same aggregator/tool as "
              "the Bija-specific claim, hence the SAME independence_group -- not treated as a second "
              "independent source for the leak-site claim itself, only as the tracker's own dataset stats.",
    ))

    csd_hash = _hash_raw("cybersecuritydive-medusalocker.html")
    graph.add_source(SourceRecord(
        source_id="s-cybersecuritydive-medusalocker", url="https://www.cybersecuritydive.com/news/fbi-cisa-medusalocker-ransomware/626483/",
        publisher="Cybersecurity Dive", source_type=SourceType.JOURNALISM, source_role=SourceRole.ACTOR_CONTEXT,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2022-07-01",
        reliability=Reliability.MODERATE, independence_group="cybersecuritydive-medusalocker-2022",
        content_sha256=csd_hash,
        notes="Independent secondary journalism on the SAME AA22-181A advisory (different publisher, "
              "different independence_group than the IC3 mirror -- genuine cross-source corroboration for "
              "the RaaS split fact). Also states, citing a Cybereason report not independently verified "
              "this session: MedusaLocker 'first emerged in late 2019 ... targeting companies across "
              "industries'; and in its own words: 'The group was particularly active in the healthcare "
              "space, where many organizations were attacked in connection to the COVID-19 pandemic.'",
    ))

    # ------------------------------------------------------------------
    # Evidence records
    # ------------------------------------------------------------------
    graph.add_evidence(EvidenceRecord(evidence_id="e-claim-post-bija", source_id="s-ransomwarelive-bija",
        excerpt="Bija Industrie bija-industrie.com Group Medusalocker Discovered 2026-08-16 15:20 UTC Est. "
                "attack date 2026-08-16 ... Description: Organization with 693 emails extracted. Domain: "
                "bija-industrie.com."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-infra-fingerprint-bija", source_id="s-ransomwarelive-bija",
        excerpt="WHOIS Emails abuse@ovh.net. MX Records mx-mibc-fr-08.mailinblack.com. mx2.mail.ovh.net. "
                "mx3.mail.ovh.net. TXT Records v=spf1 include:mx.ovh.com ~all. Cloud / SaaS Services "
                "Detected: Mailinblack. Country flag reference: flags/FR.svg."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-bija-self-description", source_id="s-bija-own-site",
        excerpt="'conception, la fabrication et la distribution d'outils et d'outillages specifiques pour "
                "les secteurs aeronautiques et industriels' (design, manufacturing, and distribution of "
                "specialized tools for aerospace and industrial sectors); 20+ years of aerospace "
                "experience; serves civil and military aviation programs; three brands (BIJA Industrie, "
                "MMI, MRO Integral Solutions)."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-initial-access", source_id="s-ic3-medusalocker-advisory",
        excerpt="MedusaLocker ransomware actors most often gain access to victim devices through "
                "vulnerable Remote Desktop Protocol (RDP) configurations [T1133]. Actors also frequently "
                "use email phishing and spam email campaigns -- directly attaching the ransomware to the "
                "email -- as initial intrusion vectors [T1566]."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-execution-propagation", source_id="s-ic3-medusalocker-advisory",
        excerpt="MedusaLocker ransomware uses a batch file to execute PowerShell script "
                "invoke-ReflectivePEInjection [T1059.001]. This script propagates MedusaLocker throughout "
                "the network by editing the EnableLinkedConnections value within the infected machine's "
                "registry, which then allows the infected machine to detect attached hosts and networks "
                "via ICMP and to detect shared storage via SMB Protocol."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-defense-evasion", source_id="s-ic3-medusalocker-advisory",
        excerpt="Restarts the LanmanWorkstation service, which allows registry edits to take effect. Kills "
                "the processes of well-known security, accounting, and forensic software. Restarts the "
                "machine in safe mode to avoid detection by security software [T1562.009]."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-encryption-impact", source_id="s-ic3-medusalocker-advisory",
        excerpt="Encrypts victim files with the AES-256 encryption algorithm; the resulting key is then "
                "encrypted with an RSA-2048 public key [T1486]. Runs every 60 seconds, encrypting all "
                "files except those critical to the functionality of the victim's machine and those that "
                "have the designated encrypted file extension."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-persistence", source_id="s-ic3-medusalocker-advisory",
        excerpt="Establishes persistence by copying an executable (svhost.exe or svhostt.exe) to the "
                "%APPDATA%\\Roaming directory and scheduling a task to run the ransomware every 15 "
                "minutes."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-recovery-inhibition", source_id="s-ic3-medusalocker-advisory",
        excerpt="Attempts to prevent standard recovery techniques by deleting local backups, disabling "
                "startup recovery options, and deleting shadow copies [T1490]."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-raas-split-ic3", source_id="s-ic3-medusalocker-advisory",
        excerpt="MedusaLocker appears to operate as a Ransomware-as-a-Service (RaaS) model based on the "
                "observed split of ransom payments ... consistently split between the affiliate, who "
                "receives 55 to 60 percent of the ransom, and the developer, who receives the remainder."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-raas-split-csd", source_id="s-cybersecuritydive-medusalocker",
        excerpt="MedusaLocker operates under the ransomware as a service model, splitting payments with "
                "affiliates who typically get 55% to 60% of the proceeds."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-origin-csd", source_id="s-cybersecuritydive-medusalocker",
        excerpt="A report from Cybereason said the MedusaLocker first emerged in late 2019, targeting "
                "companies across industries."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-healthcare-covid-csd", source_id="s-cybersecuritydive-medusalocker",
        excerpt="The group was particularly active in the healthcare space, where many organizations were "
                "attacked in connection to the COVID-19 pandemic."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-historical-iocs", source_id="s-ic3-medusalocker-advisory",
        excerpt="Disclaimer: Many of these observed IP addresses are several years old and have been "
                "historically linked to MedusaLocker ransomware. We recommend these IP addresses be "
                "investigated or vetted by organizations prior to taking action, such as blocking. Ransom "
                "note file names observed include how_to_recover_data.html, instructions.html, "
                "READINSTRUCTION.html, and recovery_instructions.html, placed into every folder containing "
                "an encrypted file."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-mitigations", source_id="s-ic3-medusalocker-advisory",
        excerpt="Implement a recovery plan that maintains and retains multiple copies of sensitive or "
                "proprietary data ... in a physically separate, segmented, and secure location. Implement "
                "network segmentation and maintain offline backups of data. Install, regularly update, "
                "and enable real-time detection for antivirus software on all hosts. Install updates for "
                "operating systems, software, and firmware as soon as possible. Audit user accounts with "
                "administrative privileges and configure access controls according to the principle of "
                "least privilege."))
    graph.add_evidence(EvidenceRecord(evidence_id="e-medusalocker-current-scale", source_id="s-ransomwarelive-medusalocker-group",
        excerpt="Victims 83. First Victim (est. attack date) 2021-11-03. Discovery Date 2022-11-15. Last "
                "Seen 2026-08-16. Avg Delay 83.1 days. Infostealer 37.0% victims with domain. Countries "
                "19 hit."))

    claims = [
        # ---------------- Victim layer (OBSERVED) ----------------
        Claim(claim_id="c-leak-site-claim-bija", claim_type=ClaimType.VICTIM_IDENTITY,
              text="A group calling itself MedusaLocker listed 'Bija Industrie' (bija-industrie.com), a "
                   "France-based organization, on its extortion leak site on 2026-08-16 (15:20 UTC), "
                   "claiming 693 emails were extracted.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-claim-post-bija"], source_refs=["s-ransomwarelive-bija"],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="Single-source leak-site claim per Section 10 policy -- establishes the claim "
                            "was made, not that 693 emails (or any data) were actually extracted. Country "
                            "France is independently corroborated by the WHOIS/MX DNS fingerprint (OVH, a "
                            "French host) and by Bija's own site, not asserted from the leak claim alone."),
        Claim(claim_id="c-victim-business-description-bija", claim_type=ClaimType.VICTIM_IDENTITY,
              text="Bija Industrie is a French manufacturer of specialized tooling for the aerospace and "
                   "industrial sectors, with 20+ years of aerospace experience serving both civil and "
                   "military aviation programs across three brands, per its own site.",
              status=EpistemicState.REPORTED, confidence=Confidence.HIGH,
              evidence_refs=["e-bija-self-description"], source_refs=["s-bija-own-site"],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="REPORTED rather than CONFIRMED: VICTIM_IDENTITY is a high-impact claim type "
                            "(Section 10), and this rests on a single source -- the entity's own site is "
                            "credible (HIGH confidence retained) but has not been independently "
                            "corroborated by a second source, so it stays capped at REPORTED regardless "
                            "of how directly it states the fact. Recorded for defense-industrial-base "
                            "context only -- no claim in this report asserts that military-program-"
                            "specific or any other specific data was actually exfiltrated; the leak-site "
                            "claim itself states only an email count."),
        Claim(claim_id="c-compromise-occurred-bija", claim_type=ClaimType.DATA_THEFT,
              text="Whether an actual compromise or data theft occurred at Bija Industrie.",
              status=EpistemicState.UNKNOWN, evidence_refs=[], source_refs=[],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="No independent confirmation, victim statement, regulator filing, or data "
                            "sample was located in any of the five sources reviewed this session -- "
                            "including for the aerospace/military-adjacent context noted above. "
                            "Represented as UNKNOWN, not guessed."),
        Claim(claim_id="c-infra-fingerprint-bija", claim_type=ClaimType.TTP_OBSERVED,
              text="Passive DNS/WHOIS fingerprinting shows Bija Industrie's mail infrastructure resolves "
                   "through Mailinblack (email-security SaaS) and OVH (French hosting provider), with a "
                   "standard SPF record and a WHOIS abuse contact at OVH.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-infra-fingerprint-bija"], source_refs=["s-ransomwarelive-bija"],
              observed_vs_context=ObservedVsContext.OBSERVED,
              analyst_notes="Infrastructure fingerprinting only -- not evidence of the incident's "
                            "initial-access vector."),
        Claim(claim_id="c-victim-ack-bija", claim_type=ClaimType.VICTIM_IDENTITY,
              text="Victim acknowledgement of the incident.",
              status=EpistemicState.NOT_ASSESSED, evidence_refs=["e-claim-post-bija"],
              source_refs=["s-ransomwarelive-bija"], observed_vs_context=ObservedVsContext.OBSERVED),

        # ---------------- Actor-historical layer (CONTEXT) ----------------
        Claim(claim_id="c-medusalocker-origin", claim_type=ClaimType.TTP_HISTORICAL,
              text="Per a Cybereason report cited by Cybersecurity Dive, MedusaLocker first emerged in "
                   "late 2019, targeting companies across industries.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-medusalocker-origin-csd"], source_refs=["s-cybersecuritydive-medusalocker"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="REPORTED rather than CONFIRMED: rests on Cybersecurity Dive's own citation "
                            "of a third-party Cybereason report this session did not independently fetch "
                            "-- consistent with this fixture set's established practice for citation "
                            "chains (cf. Moonstone Sleet in the Qilin canary)."),
        Claim(claim_id="c-medusalocker-healthcare-covid", claim_type=ClaimType.TTP_HISTORICAL,
              text="Cybersecurity Dive reports that MedusaLocker 'was particularly active in the "
                   "healthcare space, where many organizations were attacked in connection to the "
                   "COVID-19 pandemic.'",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-medusalocker-healthcare-covid-csd"], source_refs=["s-cybersecuritydive-medusalocker"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-medusalocker-initial-access", claim_type=ClaimType.TTP_HISTORICAL,
              text="Per the CISA/FBI/Treasury/FinCEN joint advisory (AA22-181A), MedusaLocker actors most "
                   "often gain initial access through vulnerable RDP configurations (T1133), and "
                   "frequently also use email phishing and spam campaigns that directly attach the "
                   "ransomware (T1566).",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-initial-access"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="Primary government advisory, directly quoted -- treated as CONFIRMED/HIGH "
                            "consistent with this fixture set's established practice for official primary "
                            "technical-advisory sources."),
        Claim(claim_id="c-medusalocker-execution-propagation", claim_type=ClaimType.TTP_HISTORICAL,
              text="MedusaLocker's documented execution and lateral-propagation mechanism (T1059.001) "
                   "uses a batch file to run a PowerShell invoke-ReflectivePEInjection script, which edits "
                   "the infected machine's EnableLinkedConnections registry value to enable host/network "
                   "detection via ICMP and shared-storage detection via SMB.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-execution-propagation"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-medusalocker-defense-evasion", claim_type=ClaimType.TTP_HISTORICAL,
              text="MedusaLocker's documented defense-evasion behavior (T1562.009) includes restarting the "
                   "LanmanWorkstation service, killing known security/accounting/forensic-software "
                   "processes, and restarting the infected machine in Windows Safe Mode to avoid endpoint "
                   "defenses.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-defense-evasion"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-medusalocker-encryption-impact", claim_type=ClaimType.TTP_HISTORICAL,
              text="MedusaLocker's documented impact-stage capability (T1486) encrypts victim files with "
                   "AES-256, protects the resulting key with RSA-2048, and re-runs every 60 seconds to "
                   "catch files excluded from the first pass.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-encryption-impact"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-medusalocker-persistence", claim_type=ClaimType.TTP_HISTORICAL,
              text="MedusaLocker establishes persistence by copying an executable named svhost.exe or "
                   "svhostt.exe into %APPDATA%\\Roaming and scheduling a task to re-run it every 15 "
                   "minutes.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-persistence"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-medusalocker-recovery-inhibition", claim_type=ClaimType.TTP_HISTORICAL,
              text="MedusaLocker's documented recovery-inhibition behavior (T1490) deletes local backups, "
                   "disables startup recovery options, and deletes volume shadow copies.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-recovery-inhibition"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-medusalocker-raas-split", claim_type=ClaimType.TTP_HISTORICAL,
              text="MedusaLocker operates a Ransomware-as-a-Service model in which affiliates typically "
                   "receive 55-60% of the ransom, with the remainder retained by the developer -- "
                   "independently reported by both the primary CISA/FBI/Treasury/FinCEN advisory and "
                   "Cybersecurity Dive's own independent reporting on it.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-raas-split-ic3", "e-medusalocker-raas-split-csd"],
              source_refs=["s-ic3-medusalocker-advisory", "s-cybersecuritydive-medusalocker"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="MULTI_SOURCE_INDEPENDENT: two publishers in two different independence "
                            "groups state the same figure -- the strongest-corroborated actor-context "
                            "claim in this report."),
        Claim(claim_id="c-medusalocker-historical-iocs", claim_type=ClaimType.TTP_HISTORICAL,
              text="The CISA/FBI/Treasury/FinCEN advisory publishes historical (2019-2022 vintage, "
                   "explicitly labeled by the advisory itself as 'several years old') generic indicators "
                   "for MedusaLocker, including encrypted-file extensions, ransom-note filenames such as "
                   "how_to_recover_data.html and READINSTRUCTION.html, Bitcoin wallets, email addresses, "
                   "and Tor addresses -- with an explicit caution to vet historical IP indicators before "
                   "acting on them.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-historical-iocs"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="Generic, historical, actor-level indicators only -- none of these specific "
                            "artifacts is claimed, by any source reviewed, to have been observed at Bija "
                            "Industrie. No incident-specific IOC exists in this report."),
        Claim(claim_id="c-medusalocker-mitigations", claim_type=ClaimType.TTP_HISTORICAL,
              text="The CISA/FBI/Treasury/FinCEN advisory recommends a segmented, offline backup and "
                   "recovery plan, network segmentation, up-to-date antivirus with real-time detection, "
                   "prompt OS/software/firmware patching, and least-privilege administrative account "
                   "auditing.",
              status=EpistemicState.CONFIRMED, confidence=Confidence.HIGH,
              evidence_refs=["e-medusalocker-mitigations"], source_refs=["s-ic3-medusalocker-advisory"],
              observed_vs_context=ObservedVsContext.CONTEXT),
        Claim(claim_id="c-medusalocker-current-scale", claim_type=ClaimType.TTP_HISTORICAL,
              text="ransomware.live's own current tracking shows 83 total MedusaLocker victims listed "
                   "since its earliest tracked victim (est. attack date 2021-11-03), spanning 19 "
                   "countries, with an average 83.1-day delay between estimated attack date and leak-site "
                   "claim, and 37.0% of tracked victims showing a domain overlap with infostealer-malware "
                   "logs.",
              status=EpistemicState.REPORTED, confidence=Confidence.MEDIUM,
              evidence_refs=["e-medusalocker-current-scale"], source_refs=["s-ransomwarelive-medusalocker-group"],
              observed_vs_context=ObservedVsContext.CONTEXT,
              analyst_notes="REPORTED/MEDIUM, consistent with this aggregator's Reliability.MODERATE tier "
                            "used elsewhere in this report -- a tracker's own dataset count is more "
                            "directly verifiable than a relayed extortion claim, but the underlying "
                            "collection methodology (which victims it discovers, and how completely) was "
                            "not independently audited this session."),
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
        sector="Manufacturing -- specialized aerospace and industrial tooling (per the victim's own "
               "site; serves civil and military aviation programs)",
        claim_date="2026-08-16T15:20:00Z",
        claim_temporal_precision=TemporalPrecision.EXACT_TIMESTAMP,
        leak_site_claim_status=EpistemicState.REPORTED,
        claimed_data_description="'693 emails extracted' per the leak-site post; no further category, "
                                  "sensitivity, or content description given by any source reviewed.",
        sample_proof_status=EpistemicState.UNKNOWN,
        independent_confirmation=EpistemicState.NOT_ASSESSED,
        victim_acknowledgement=EpistemicState.NOT_ASSESSED,
        regulator_disclosure=EpistemicState.NOT_ASSESSED,
        source_claim_ids=["c-leak-site-claim-bija", "c-victim-business-description-bija", "c-victim-ack-bija"],
        observed_incident_ioc_claim_ids=[],  # none located -- see c-medusalocker-historical-iocs's explicit CONTEXT-only scoping
        observed_incident_ttp_claim_ids=["c-infra-fingerprint-bija"],
    )

    actor_context = ActorHistoricalContext(
        actor_aliases=[],
        raas_model_claim_ids=["c-medusalocker-raas-split"],
        historical_ttp_claim_ids=["c-medusalocker-initial-access", "c-medusalocker-execution-propagation",
                                   "c-medusalocker-defense-evasion", "c-medusalocker-encryption-impact",
                                   "c-medusalocker-persistence", "c-medusalocker-recovery-inhibition"],
        historical_tooling_claim_ids=["c-medusalocker-historical-iocs"],
        initial_access_history_claim_ids=["c-medusalocker-initial-access"],
        infrastructure_claim_ids=["c-medusalocker-historical-iocs"],
        affiliate_behavior_claim_ids=["c-medusalocker-raas-split"],
        victimology_claim_ids=["c-medusalocker-current-scale", "c-medusalocker-healthcare-covid"],
        sectors=["Healthcare (historically, per 2022 CISA advisory reporting and Cybersecurity Dive)"],
        geographies=[],  # no country-level breakdown located among the sources reviewed this session
        campaign_history_claim_ids=["c-medusalocker-origin", "c-medusalocker-current-scale"],
    )

    generic_readiness = GenericReadiness(
        immutable_backups="Maintain a segmented, offline, tested backup and recovery plan -- the direct "
                           "countermeasure to MedusaLocker's documented local-backup deletion and "
                           "shadow-copy removal.",
        identity_hardening="Disable or restrict internet-facing RDP; enforce MFA on all remote-access and "
                            "privileged accounts -- the direct countermeasure to MedusaLocker's "
                            "documented primary initial-access vector.",
        segmentation="Implement network segmentation to limit lateral movement and to contain the "
                     "SMB/ICMP host-and-share discovery MedusaLocker's own propagation script performs.",
        mass_encryption_detection="Deploy behavioral detection for mass file-modification/encryption "
                                   "activity and for unexpected Safe Mode reboots on production hosts.",
        recovery_inhibition_coverage="Monitor for shadow-copy deletion, backup-service tampering, and "
                                      "startup-recovery-option changes (T1490).",
        ir_preparation="Maintain a tested incident response plan with ransomware-specific playbooks, "
                        "including a defined leak-site-monitoring process for unconfirmed extortion "
                        "claims.",
    )

    return RansomwareVictimClaim(
        product_id="medusalocker-bija-industrie-premium-canary",
        victim_observation=victim_observation,
        actor_context=actor_context,
        generic_readiness=generic_readiness,
        # No linked_vulnerabilities -- MedusaLocker's documented initial-access vector is RDP/phishing,
        # not a specific CVE; the four vulnerability-shaped markers stay NOT_APPLICABLE by construction.
    )


def build_metrics_registry() -> MetricsRegistry:
    registry = MetricsRegistry()
    registry.register(ExternalMetric(
        metric_id="m-medusalocker-total-victims", name="MedusaLocker total tracked victims",
        value=83, unit="victims", scope="All MedusaLocker leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/medusalocker",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
        notes="A live, continuously-updated tracker count as of retrieval, not a fixed historical figure "
              "-- review_after is set at 3 months given the underlying dataset changes daily.",
    ))
    registry.register(ExternalMetric(
        metric_id="m-medusalocker-countries", name="MedusaLocker countries hit",
        value=19, unit="countries", scope="All MedusaLocker leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/medusalocker",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
    ))
    registry.register(ExternalMetric(
        metric_id="m-medusalocker-avg-dwell", name="MedusaLocker average attack-to-claim delay",
        value=83.1, unit="days", scope="All MedusaLocker leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/medusalocker",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
    ))
    registry.register(ExternalMetric(
        metric_id="m-medusalocker-infostealer-overlap", name="MedusaLocker victims with infostealer-log domain overlap",
        value=37.0, unit="percent", scope="All MedusaLocker leak-site victims tracked by ransomware.live",
        source="ransomware.live (group aggregate page)",
        source_url="https://www.ransomware.live/group/medusalocker",
        publication_year=2026, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2026-11-17",
        notes="Domain-level overlap with known infostealer-malware logs -- suggestive of a credential-"
              "theft-adjacent access pathway across the tracked victim population in aggregate; not "
              "evidence of any specific victim's initial-access vector, including Bija Industrie's.",
    ))
    registry.register(ExternalMetric(
        metric_id="m-medusalocker-raas-affiliate-share", name="MedusaLocker RaaS affiliate revenue share",
        value=57.5, unit="percent (midpoint of the independently-corroborated 55-60% range)",
        scope="MedusaLocker RaaS ransom-payment split, per the 2022 CISA/FBI/Treasury/FinCEN advisory",
        source="CISA/FBI/Treasury/FinCEN Joint Cybersecurity Advisory AA22-181A, corroborated by "
               "Cybersecurity Dive",
        source_url="https://www.ic3.gov/CSA/2022/220630.pdf",
        publication_year=2022, retrieved_at="2026-08-17T00:00:00Z",
        valid_until=None, review_after="2027-06-30",
        notes="The original figure is a range (55-60%), not a point estimate; this registry entry stores "
              "the midpoint for a single comparable value while the claim text preserves the full range.",
    ))
    return registry


def build_hypothesis_sets() -> list[HypothesisSet]:
    return [
        HypothesisSet(
            question="Does the 'Bija Industrie' leak-site listing reflect a genuine, technically "
                      "successful compromise, or could it be an unconfirmed or exaggerated extortion "
                      "claim?",
            hypotheses=(
                Hypothesis(
                    "h1", "H1: Genuine compromise, currently undisclosed",
                    "Consistent with MedusaLocker's persistent, multi-year operating cadence (83 tracked "
                    "victims across 19 countries) and the real, if generic, infrastructure fingerprinting "
                    "captured for this specific domain, the claim could reflect an actual compromise "
                    "Bija Industrie has not yet acknowledged publicly.",
                    supporting_evidence_claim_ids=("c-leak-site-claim-bija", "c-infra-fingerprint-bija",
                                                    "c-medusalocker-current-scale"),
                    contradicting_evidence_claim_ids=(),
                    confidence="MEDIUM",
                ),
                Hypothesis(
                    "h2", "H2: Unconfirmed or overstated claim",
                    "The claim has not been technically substantiated by any source reviewed -- no proof "
                    "sample, no independent confirmation (a second, independent write-up of this specific "
                    "victim was sought but was not accessible this session), and no victim acknowledgement "
                    "were located.",
                    supporting_evidence_claim_ids=("c-compromise-occurred-bija", "c-victim-ack-bija"),
                    contradicting_evidence_claim_ids=(),
                    confidence="MEDIUM",
                ),
            ),
        ),
        HypothesisSet(
            question="If a compromise did occur, which of MedusaLocker's two documented initial-access "
                      "vectors -- RDP exploitation (the advisory's primary, 'most often' vector) or "
                      "phishing/spam (its secondary, 'frequently' vector) -- should hunting and forensic "
                      "review prioritize first?",
            hypotheses=(
                Hypothesis(
                    "h1", "H1: RDP-based access (T1133)",
                    "The advisory's own language ranks vulnerable RDP configurations as the vector "
                    "MedusaLocker actors 'most often' use, making it the statistically likelier starting "
                    "point for any forensic review absent incident-specific evidence.",
                    supporting_evidence_claim_ids=("c-medusalocker-initial-access",),
                    contradicting_evidence_claim_ids=(),
                    confidence="LOW",
                ),
                Hypothesis(
                    "h2", "H2: Phishing/spam-based access (T1566)",
                    "The same advisory documents phishing and spam campaigns, with the ransomware directly "
                    "attached, as a 'frequently' used secondary vector -- a real, evidenced alternative "
                    "that a review limited to RDP alone would miss.",
                    supporting_evidence_claim_ids=("c-medusalocker-initial-access",),
                    contradicting_evidence_claim_ids=(),
                    confidence="LOW",
                ),
            ),
        ),
    ]


def build_intelligence_gaps(victim_observation: VictimObservation) -> list[IntelligenceGap]:
    gaps = derive_ransomware_gaps(victim_observation)
    gaps.append(IntelligenceGap(
        "Whether any of the documented general MedusaLocker TTPs above (RDP/phishing initial access, "
        "PowerShell-based propagation, safe-mode defense evasion, AES-256/RSA-2048 encryption, "
        "svhost.exe/svhostt.exe persistence, shadow-copy deletion) were actually used in this specific "
        "incident is not established by any source reviewed -- this is documented actor CAPABILITY, not "
        "incident-specific evidence.",
        "COLLECTION_GAP",
        "Incident-specific forensic artifacts, EDR telemetry, or a confirmed intrusion-vector statement "
        "from Bija Industrie or an engaged incident-response firm.",
    ))
    gaps.append(IntelligenceGap(
        "Whether the '693 emails extracted' claim, if accurate, includes personal data of identifiable "
        "individuals (GDPR-relevant) or any defense-industrial-base-sensitive content is not established "
        "by any source reviewed -- the leak-site claim itself describes only a count, with no category, "
        "sensitivity, or content description given.",
        "KNOWN_UNKNOWN",
        "A verified sample or victim/regulator statement describing the actual content and sensitivity "
        "of the claimed dataset.",
    ))
    gaps.append(IntelligenceGap(
        "Which specific MedusaLocker RaaS affiliate is responsible for this claim is not established by "
        "any source reviewed.",
        "KNOWN_UNKNOWN",
        "CTI vendor attribution research specific to this claim, or law-enforcement/vendor telemetry "
        "tying a specific known affiliate cluster to this incident.",
    ))
    return gaps


def build_regulatory_applicabilities() -> list[RegulatoryApplicability]:
    return [
        not_assessed(
            "GDPR (EU) / France (CNIL)",
            reason="Whether the '693 emails extracted' claim, if accurate, includes personal data of "
                   "identifiable individuals is not established by any source reviewed, and whether any "
                   "compromise occurred at all remains UNKNOWN (c-compromise-occurred-bija) -- GDPR "
                   "notification-obligation applicability cannot be determined from current evidence.",
        ),
        not_assessed(
            "NIS2 Directive (EU)",
            reason="Bija Industrie's specific sector/entity-size classification against NIS2's "
                   "essential/important-entity thresholds is not established by any source reviewed -- "
                   "the company's own site describes an aerospace/industrial-tooling manufacturing "
                   "business, but NIS2 applicability turns on regulatory thresholds this report cannot "
                   "verify from the sources located.",
        ),
        RegulatoryApplicability(
            jurisdiction="US/HIPAA", victim_geography="France", operations_geography="France",
            data_subject_geography=None, sector="Manufacturing", entity_classification=None,
            incident_facts_claim_ids=("c-victim-business-description-bija",), regulation="HIPAA",
            applicability_state=ApplicabilityState.NOT_APPLICABLE,
            basis="Bija Industrie is a France-based aerospace/industrial-tooling manufacturer with no "
                  "source reviewed establishing a US healthcare nexus or business-associate "
                  "relationship -- HIPAA does not apply.",
        ),
        not_assessed(
            "PCI-DSS",
            reason="No source reviewed describes Bija Industrie's payment-processing footprint; PCI-DSS "
                   "is a contractual/industry framework whose applicability depends on deployment-"
                   "specific cardholder-data-environment facts this report does not have.",
        ),
    ]


def build_forecast() -> Forecast:
    return Forecast(
        judgment="MedusaLocker-branded ransomware activity will likely continue at or above its "
                 "documented multi-year pace (83 tracked victims across 19 countries as of this report), "
                 "continuing to rely predominantly on RDP exposure and phishing/spam as initial-access "
                 "vectors, with no evidence reviewed this session of a law-enforcement disruption event "
                 "against the group's infrastructure.",
        time_horizon="90 days from 2026-08-17",
        supporting_observation_claim_ids=("c-medusalocker-current-scale", "c-medusalocker-raas-split",
                                           "c-medusalocker-initial-access"),
        historical_baseline_claim_ids=("c-medusalocker-origin",),
        assumptions=(
            "MedusaLocker's RaaS affiliate program continues operating at a pace comparable to its "
            "documented 2021-2026 tracked history, with no law-enforcement takedown occurring within the "
            "forecast window.",
        ),
        counter_evidence_claim_ids=(),
        alternative_scenarios=(
            "Law-enforcement action against MedusaLocker's affiliate infrastructure or leak site (as has "
            "occurred against other major RaaS brands) disrupts the group's operating cadence within the "
            "forecast window.",
        ),
        indicators_to_watch=(
            "New named victims added to MedusaLocker's leak site at a rate consistent with or exceeding "
            "the tracked average of roughly one victim every 3-4 weeks implied by 83 victims since "
            "2021-11-03",
            "Any updated CISA/FBI advisory or IC3 alert revising MedusaLocker's documented TTPs or RaaS "
            "economics",
            "Law-enforcement seizure notices or takedown announcements targeting MedusaLocker "
            "infrastructure",
        ),
        confidence="MEDIUM",
        confidence_rationale="Supported by a multi-year (2021-2026), 83-victim tracked operating history "
                              "and a stable, twice-independently-corroborated RaaS economic model, but "
                              "tempered by the inherent unpredictability of law-enforcement disruption "
                              "events and by the fact that this report's own actor-context sources are "
                              "predominantly a single 2022 advisory refreshed only by current tracker "
                              "aggregate counts, not a fresh 2026 technical reassessment of the group's "
                              "tooling.",
        what_would_change_assessment=(
            "A confirmed law-enforcement takedown of MedusaLocker's infrastructure, or a published 2026 "
            "technical report documenting materially changed tooling/TTPs, would change this assessment "
            "materially in either direction.",
        ),
    )


def build_detection_rule() -> DetectionRule:
    """A real, structurally valid Sigma-style detection concept grounded directly in two of
    MedusaLocker's own documented, quotable indicators (c-medusalocker-persistence,
    c-medusalocker-defense-evasion) -- marked SYNTAX_VALIDATED, not LAB_VALIDATED or
    PRODUCTION_VALIDATED, since it has not been tested against live telemetry this session."""
    body = (
        "title: MedusaLocker svhost/svhostt Persistence and EnableLinkedConnections Registry Propagation\n"
        "id: reportx-canary-medusalocker-svhost-persistence\n"
        "status: experimental\n"
        "description: >\n"
        "  Detects two command-line/registry indicators documented by CISA/FBI/\n"
        "  Treasury/FinCEN advisory AA22-181A for the MedusaLocker ransomware\n"
        "  family: persistence via an executable named svhost.exe or svhostt.exe\n"
        "  copied into %APPDATA%\\Roaming with a 15-minute recurring scheduled\n"
        "  task, and the invoke-ReflectivePEInjection PowerShell script's edit of\n"
        "  the EnableLinkedConnections registry value used for network\n"
        "  propagation. Either indicator alone is a strong ransomware\n"
        "  precursor/impact-stage signal; this rule does not by itself confirm\n"
        "  MedusaLocker attribution for any specific incident.\n"
        "references:\n"
        "  - https://www.ic3.gov/CSA/2022/220630.pdf\n"
        "  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-181a\n"
        "logsource:\n"
        "  category: process_creation\n"
        "  product: windows\n"
        "detection:\n"
        "  selection_svhost_persistence:\n"
        "    Image|endswith:\n"
        "      - '\\svhost.exe'\n"
        "      - '\\svhostt.exe'\n"
        "    CommandLine|contains: 'AppData\\Roaming'\n"
        "  selection_registry_propagation:\n"
        "    CommandLine|contains|all:\n"
        "      - 'invoke-ReflectivePEInjection'\n"
        "      - 'EnableLinkedConnections'\n"
        "  condition: selection_svhost_persistence or selection_registry_propagation\n"
        "falsepositives:\n"
        "  - Legitimate 'svhost' naming is a common OS-process masquerade target; verify full path and "
        "hash before response\n"
        "  - Legitimate administrative scripts that modify EnableLinkedConnections for UAC-related remote "
        "administration purposes\n"
        "level: high\n"
    )
    return DetectionRule(
        rule_id="reportx-canary-medusalocker-svhost-persistence", technique_id="T1053", format="sigma",
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
        "# MedusaLocker / 'Bija Industrie' — Premium Intelligence Canary\n\n"
        "**Classification:** TLP:CLEAR — public leak-site claim and open-source actor intelligence\n\n"
        "## Executive Summary\n\n"
        "On 2026-08-16, a group identifying itself as MedusaLocker listed 'Bija Industrie', a "
        "France-based manufacturer of specialized aerospace and industrial tooling, on its Tor "
        "extortion leak site, claiming 693 emails were extracted. This is a single-source claim; no "
        "independent confirmation, victim statement, regulator filing, or data sample has been located. "
        "Real, directly-sourced actor context -- drawn primarily from the 2022 CISA/FBI/Treasury/FinCEN "
        "joint advisory AA22-181A and independently corroborated in part by Cybersecurity Dive's own "
        "reporting on it -- shows MedusaLocker operating as a Ransomware-as-a-Service platform active "
        "since at least 2019, with a documented 55-60% affiliate revenue split and a well-characterized "
        "RDP/phishing initial-access, PowerShell-propagation, safe-mode-evasion, and shadow-copy-deletion "
        "attack chain. ransomware.live's own current tracking shows 83 total MedusaLocker victims across "
        "19 countries, with Bija Industrie its most recently listed. Bija's own site states it serves "
        "both civil and military aviation programs; that fact is recorded here for defense-industrial-"
        "base relevance only -- no source reviewed describes the content or sensitivity of the claimed "
        "693 emails, and this report does not assert any specific data, military-related or otherwise, "
        "was actually exfiltrated.\n\n"
        "## Scope and Methodology\n\n"
        "This report synthesizes five independently retrieved sources, all fetched as raw bytes via "
        "direct HTTP fetch with content_sha256 computed programmatically from the checked-in raw files, "
        "never hand-typed: the leak-site tracker ransomware.live (both the Bija-specific victim page and "
        "its MedusaLocker group aggregate-statistics page), the victim's own site (bija-industrie.com), "
        "the IC3.gov mirror of CISA/FBI/Treasury/FinCEN Joint Cybersecurity Advisory AA22-181A (cisa.gov "
        "itself returned HTTP 403 Access Denied on both the advisory page and its own PDF -- documented "
        "honestly rather than substituted with paraphrase), and Cybersecurity Dive's independent "
        "journalism on that same advisory. Every claim in this report traces to at least one of these "
        "five sources via an explicit evidence_refs/source_refs chain, visible in the Sources & Evidence "
        "Ledger appendix below. No claim in this report is drawn from model memory or generic industry "
        "knowledge about ransomware conventions in general. Victim-specific observations (this incident "
        "only) are kept structurally and narratively separate from actor-historical context (what is "
        "known about MedusaLocker in general) throughout. MITRE ATT&CK tracks an unrelated ransomware "
        "operation named 'Medusa' (S1244/G1051) -- a different group from MedusaLocker despite the "
        "similar name; that page is never cited here.\n\n"
        "## Victim Claim Record\n\n"
        "Claim posted 2026-08-16 15:20 UTC on MedusaLocker's Tor leak site. Country: France, confirmed "
        "via the tracker's own country-flag reference and independently consistent with the victim "
        "domain's DNS/WHOIS fingerprint (OVH, a French hosting provider; Mailinblack, a French "
        "email-security SaaS). Per the company's own site, Bija Industrie designs and manufactures "
        "specialized tooling for the aerospace and industrial sectors, with over 20 years of aerospace "
        "experience serving both civil and military aviation programs across three brands. This "
        "business-description context is recorded for defense-industrial-base relevance only -- the "
        "leak-site claim itself describes only an email count ('693 emails extracted'), with no "
        "category, sensitivity, or content description given by any source reviewed, and whether any "
        "compromise actually occurred, military-program-related or otherwise, is UNKNOWN on current "
        "evidence; this report does not assert it did. Separately, passive DNS/WHOIS fingerprinting "
        "confirms the organization's mail infrastructure and a standard SPF configuration -- "
        "infrastructure fingerprinting only, not evidence of the initial-access vector.\n\n"
        "## Actor Overview: MedusaLocker (RaaS Family)\n\n"
        "MedusaLocker is a Ransomware-as-a-Service operation that, per a Cybereason report cited by "
        "Cybersecurity Dive, first emerged in late 2019 targeting companies across industries, and was "
        "particularly active against the healthcare sector during the COVID-19 pandemic. The primary "
        "CISA/FBI/Treasury/FinCEN advisory (AA22-181A, published 2022-06-30) documents actors most often "
        "gaining initial access through vulnerable RDP configurations, with phishing and spam email "
        "campaigns -- directly attaching the ransomware -- as a frequently-used secondary vector. The "
        "group operates a RaaS affiliate model in which affiliates typically retain 55-60% of each "
        "ransom payment, with the developer retaining the remainder -- a figure independently reported "
        "by both the primary advisory and Cybersecurity Dive's own separate coverage of it, the "
        "strongest-corroborated actor-context fact in this report.\n\n"
        "## Documented Attack Chain\n\n"
        "The primary advisory documents a specific, repeatable attack chain, quoted directly here. "
        "**Execution and propagation (T1059.001):** a batch file runs a PowerShell "
        "invoke-ReflectivePEInjection script that edits the EnableLinkedConnections registry value, "
        "enabling host/network detection via ICMP and shared-storage detection via SMB. **Defense "
        "evasion (T1562.009):** the LanmanWorkstation service is restarted to let the registry edit take "
        "effect, known security/accounting/forensic-software processes are killed, and the machine is "
        "rebooted into Windows Safe Mode to avoid endpoint defenses. **Impact (T1486):** files are "
        "encrypted with AES-256, with the resulting key itself protected by RSA-2048, re-running every "
        "60 seconds. **Persistence:** an executable named svhost.exe or svhostt.exe is copied into "
        "%APPDATA%\\Roaming with a scheduled task re-running it every 15 minutes. **Recovery inhibition "
        "(T1490):** local backups are deleted, startup recovery options disabled, and volume shadow "
        "copies removed. All of this is documented actor CAPABILITY -- no TTP specific to the Bija "
        "Industrie incident has been observed by any source reviewed.\n\n"
        "## Current Tracked Scale (2026 Snapshot)\n\n"
        "ransomware.live's own current aggregate tracking shows 83 total MedusaLocker victims listed "
        "since its earliest tracked victim (estimated attack date 2021-11-03), spanning 19 countries, "
        "with an average 83.1-day delay between estimated attack date and leak-site claim. 37.0% of "
        "tracked victims show a domain-level overlap with known infostealer-malware logs -- suggestive, "
        "in aggregate, of a credential-theft-adjacent access pathway across the tracked population, "
        "though this is not evidence of any specific victim's initial-access vector, including Bija "
        "Industrie's. At the time of this report, Bija Industrie is the group's own most recently listed "
        "victim.\n\n"
        "## Historical Indicators (Generic, Not Incident-Specific)\n\n"
        "The primary advisory publishes generic MedusaLocker indicators dated 2019-2022 -- encrypted-file "
        "extensions, ransom-note filenames (e.g. how_to_recover_data.html, READINSTRUCTION.html), "
        "Bitcoin wallets, email addresses, and Tor addresses -- with the advisory's own explicit caution "
        "that historical IP indicators are 'several years old' and should be vetted before any blocking "
        "action. None of these specific artifacts is claimed by any source reviewed to have been observed "
        "at Bija Industrie; this report contains no incident-specific IOC.\n\n"
        "## Detection\n\n"
        "A Sigma detection concept is provided at SYNTAX_VALIDATED maturity only -- neither lab testing "
        "nor any deployment validation has been performed this session -- targeting two of MedusaLocker's "
        "own documented, quotable indicators: svhost.exe/svhostt.exe persistence in %APPDATA%\\Roaming, "
        "and the invoke-ReflectivePEInjection/EnableLinkedConnections registry-propagation pattern. A "
        "match does not by itself confirm MedusaLocker attribution (see the rule's own falsepositives "
        "field, including the common 'svhost' masquerade risk). Full rule body:\n\n"
        f"```yaml\n{detection_rule.body}```\n\n"
        "## Hunting\n\n"
        "Given the documented, specific persistence naming convention, a defensible hunting hypothesis "
        "is to search endpoint process-creation and scheduled-task telemetry for svhost.exe or "
        "svhostt.exe executing from %APPDATA%\\Roaming rather than a genuine Windows system path, and "
        "for any scheduled task with a roughly 15-minute recurrence tied to such a binary. Separately, "
        "given the advisory's documentation of RDP as MedusaLocker's dominant initial-access vector, "
        "hunting teams should prioritize reviewing external-facing RDP authentication logs for "
        "brute-force patterns ahead of reviewing email-gateway telemetry for spearphishing delivery -- "
        "while still covering both, since the advisory documents phishing as a real, if secondary, "
        "vector. This report does not include incident-specific IOCs for Bija Industrie -- none were "
        "located by any source reviewed.\n\n"
        "## Forecast\n\n"
        "MEDIUM confidence that MedusaLocker-branded activity will continue at or above its documented "
        "multi-year pace (83 tracked victims across 19 countries) over the next 90 days, continuing to "
        "rely predominantly on RDP exposure and phishing/spam as initial-access vectors -- tempered by "
        "the inherent unpredictability of law-enforcement disruption events and by this report's actor-"
        "context sources being predominantly a single 2022 advisory refreshed only by current tracker "
        "counts, not a fresh 2026 technical reassessment. See the structured forecast record (supporting "
        "observations, assumptions, alternative scenarios, and indicators to watch) in this bundle's "
        "`forecasts` field.\n\n"
        "## Alternative Hypotheses\n\n"
        "Two genuinely open analytic questions are weighed explicitly rather than resolved by "
        "assumption. **First**, whether the leak-site listing reflects a genuine, currently-undisclosed "
        "compromise (**H1**, consistent with MedusaLocker's persistent multi-year operating cadence and "
        "the real infrastructure fingerprinting captured for this domain) versus an unconfirmed or "
        "overstated claim (**H2**, consistent with the total absence of a proof sample, independent "
        "confirmation, or victim acknowledgement). **Second**, if a compromise did occur, which of "
        "MedusaLocker's two documented initial-access vectors -- RDP (**H1**, the advisory's own "
        "'most often' vector) or phishing/spam (**H2**, its documented 'frequently' secondary vector) -- "
        "hunting and forensic review should prioritize first, given that no incident-specific "
        "initial-access evidence exists for this victim either way.\n\n"
        "## Regulatory Considerations\n\n"
        "GDPR (EU) / France (CNIL) is assessed NOT_ASSESSED: whether the claimed 693 emails include "
        "personal data of identifiable individuals is not established by any source reviewed, and "
        "whether any compromise occurred at all remains UNKNOWN. The NIS2 Directive (EU) is assessed "
        "NOT_ASSESSED: Bija Industrie's specific sector/entity-size classification against NIS2's "
        "essential/important-entity thresholds is not established by any source reviewed. HIPAA is "
        "assessed NOT_APPLICABLE: Bija Industrie is a France-based manufacturer with no established US "
        "healthcare nexus. PCI-DSS is assessed NOT_ASSESSED: no source reviewed describes the "
        "organization's payment-processing footprint.\n\n"
        "## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)\n\n"
        "Standard ransomware readiness guidance -- a segmented offline backup and recovery plan, "
        "RDP hardening and MFA, network segmentation, behavioral detection for mass encryption and "
        "unexpected Safe Mode reboots, shadow-copy/backup-tampering monitoring, and a tested IR plan "
        "with a defined leak-site-monitoring process -- is provided as general hardening grounded in "
        "MedusaLocker's own documented attack chain and the advisory's own mitigations list, not as "
        "evidence any specific technique was used against this victim.\n\n"
        "## Intelligence Gaps\n\n"
        "Seven gaps are explicitly unresolved by any source reviewed for this report: victim "
        "acknowledgement is unavailable; no incident-specific IOCs were observed; no proof sample of the "
        "claimed extracted emails exists; no independent confirmation of the leak-site claim was "
        "located; no initial-access or incident-specific TTP evidence was found; whether any of "
        "MedusaLocker's documented general TTPs were used in this specific incident is unestablished; "
        "whether the claimed 693 emails include personal data or defense-industrial-base-sensitive "
        "content is unestablished; and which specific MedusaLocker affiliate is responsible for this "
        "claim is unestablished.\n\n"
        "## Technical Recommendations\n\n"
        "1. Disable or restrict internet-facing RDP and enforce MFA on all remote-access accounts -- the "
        "direct countermeasure to MedusaLocker's documented primary initial-access vector (evidence: "
        "c-medusalocker-initial-access).\n"
        "2. Maintain a segmented, offline, tested backup and recovery plan, and monitor for shadow-copy "
        "deletion and backup-service tampering -- the direct countermeasure to MedusaLocker's documented "
        "recovery-inhibition behavior (evidence: c-medusalocker-recovery-inhibition).\n"
        "3. Deploy monitoring for MedusaLocker's specific documented persistence pattern (svhost.exe/"
        "svhostt.exe in %APPDATA%\\Roaming with a 15-minute scheduled task) via the detection rule above "
        "(evidence: c-medusalocker-persistence).\n"
        "4. Train users to recognize and report phishing/spam attempts -- the direct countermeasure to "
        "MedusaLocker's documented secondary initial-access vector (evidence: "
        "c-medusalocker-initial-access).\n\n"
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

    metric_ids = ["m-medusalocker-total-victims", "m-medusalocker-countries", "m-medusalocker-avg-dwell",
                  "m-medusalocker-infostealer-overlap", "m-medusalocker-raas-affiliate-share"]

    return ReportBundle(
        report_id="medusalocker-bija-industrie-premium-canary",
        graph=graph,
        rendered_text=rendered_text,
        dimension_tags={"victim_confirmation": ["c-leak-site-claim-bija", "c-victim-ack-bija",
                                                 "c-compromise-occurred-bija"]},
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
