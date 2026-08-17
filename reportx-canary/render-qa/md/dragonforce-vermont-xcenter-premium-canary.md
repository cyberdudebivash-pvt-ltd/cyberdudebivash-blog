# DragonForce / 'Vermont XCenter' — Premium Intelligence Canary

**Classification:** TLP:CLEAR — public leak-site claim and open-source actor intelligence

## Executive Summary

On 2026-08-17, a group identifying itself as DragonForce listed 'Vermont XCenter', a Brazil-based omnichannel contact-center/BPO operating for almost three decades, on its Tor extortion leak site. This is a single-source claim describing no specific data category, volume, or sample; no independent confirmation, victim statement, regulator filing, or data sample has been located. Real, directly-sourced actor context -- drawn from Group-IB's named-analyst research and a current (February 2026) Blackpoint Cyber threat profile -- shows DragonForce as one of the most active RaaS operations currently tracked (639 victims across 65 countries), operating two malware variants derived from the leaked LockBit 3.0 builder and the Conti codebase, with a documented pattern of rapidly exploiting newly disclosed CVEs and a significant 2025 evolution into a multi-brand 'ransomware cartel' partnered with LockBit. Vermont XCenter's own site documents a healthcare-adjacent 'Vermont Health' service line; that fact is recorded for context only -- no source reviewed describes the content or sensitivity of any data potentially affected, and this report does not assert any specific data was actually exfiltrated.

## Scope and Methodology

This report synthesizes five independently retrieved sources, all fetched as raw bytes via direct HTTP fetch with content_sha256 computed programmatically from the checked-in raw files: the leak-site tracker ransomware.live (both the Vermont-specific victim page and its DragonForce group aggregate-statistics page), the victim's own site (vermont.com.br, in Portuguese), Group-IB's named-analyst research (2024-09-25), and Blackpoint Cyber's current 30-page threat profile (February 2026). Every claim in this report traces to at least one of these five sources via an explicit evidence_refs/source_refs chain, visible in the Sources & Evidence Ledger appendix below. Victim-specific observations (this incident only) are kept structurally and narratively separate from actor-historical context (what is known about DragonForce in general) throughout. Where the two CTI vendor sources independently corroborate the same fact -- the 80% affiliate revenue split and the two-variant malware lineage -- this report marks that corroboration explicitly rather than treating it as single-sourced.

## Victim Claim Record

Claim posted 2026-08-17 09:24 UTC on DragonForce's Tor leak site. Country: Brazil, confirmed via the tracker's own country-flag reference. Per the company's own site, Vermont XCenter is an omnichannel contact-center/BPO operating for almost three decades, with services spanning customer service, telesales, technical support, CRM implementation, and a distinct 'Vermont Health' line covering patient registration and pharmacovigilance support. This business-description context is recorded for completeness only -- the leak-site listing itself states no data category, volume, or sample; the tracker's 'Description' field is only the victim's own scraped site metadata, not a separate claim of stolen data, verified directly against the raw page this session. Whether any compromise actually occurred is UNKNOWN on current evidence; this report does not assert it did. Separately, aggregated infostealer telemetry indicates a notably larger exposure signal than other victims in this canary set -- 2 compromised employee endpoints, 48 compromised end-user credentials, 9 exposed third-party employee credentials, and 18 external attack-surface exposures -- alongside passive-DNS fingerprinting showing Microsoft 365 email and a Zendesk integration. None of this is attributed to the incident's initial-access vector by any source.

## Actor Overview: DragonForce (RaaS-to-Cartel Evolution)

DragonForce was first identified in August 2023 and operated as a private group until June 2024, when it advertised a RaaS affiliate program on the Russian-language cybercriminal forum RAMP, offering affiliates 80% of ransom revenue -- a figure independently reported by both Group-IB and Blackpoint Cyber, published roughly 17 months apart. The group operates two Windows ransomware variants, also independently confirmed by both vendors: one derived from the leaked LockBit 3.0 builder, and a ContiV3-based build using BYOVD, scheduled-task persistence, and ChaCha8 encryption keyed via CryptGenRandom(), with files renamed under a customizable '.dragonforce_encrypted' extension. DragonForce intrusions have been linked to SystemBC, Cobalt Strike, and Mimikatz (Group-IB), and separately documented using SimpleHelp RMM abuse for persistence and the BadRentdvr2 vulnerable driver for BYOVD privilege escalation (Blackpoint Cyber). In March 2025, the group announced a shift to a 'ransomware cartel' model, encouraging affiliates to build their own brands while continuing to use DragonForce tooling; in August 2025 it announced a formal partnership with LockBit (reportedly a 20% cut for infrastructure, encryptors, and negotiation support), and reportedly launched a paid 'data analysis service' targeting organizations with $15M+ annual revenue.

## Historical Vulnerability Exploitation (Generic, Not Incident-Specific)

Blackpoint Cyber documents DragonForce actors as having exploited 11 named CVEs across 2021-2024: Apache Log4j (CVE-2021-44228, CVSS 10); three Ivanti Connect Secure/Policy Secure CVEs; a Windows Internet Shortcut Files flaw (CVE-2024-21412); a FortiOS SSL-VPN out-of-bound write (CVE-2024-21762); a SonicOS access-control flaw (CVE-2024-40766); three 2024 SimpleHelp RMM CVEs covering privilege escalation, path traversal, and arbitrary file upload; and a FortiOS/FortiProxy authentication bypass (CVE-2024-55591). This is documented actor CAPABILITY only -- no source reviewed claims any of these specific CVEs was the initial-access vector for Vermont XCenter, and this report makes no such claim.

## Tactics, Techniques, and Procedures (ATT&CK-Mapped)

Blackpoint Cyber's MITRE ATT&CK mapping documents DragonForce's capability across the full attack lifecycle: **initial access** (T1078, T1133, T1189, T1190, T1566); **persistence** (T1053, T1078, T1543, T1547); **defense evasion** (T1027, T1070, T1112, T1140, T1211, T1218, T1222, T1553, T1562, T1564, T1679); **credential access** (T1003.001 LSASS memory, T1003.002 SAM); **discovery** (T1012, T1016, T1018, T1057, T1069, T1082, T1083, T1087, T1135, T1482, T1673); **lateral movement** (T1021 RDP/SMB, T1210, T1570); **collection** (T1005, T1560); **command and control** (T1071, T1090, T1105, T1219, T1571); **exfiltration** (T1041, T1048, T1567); and **impact** (T1486 encryption, T1489 service stop, T1490 recovery inhibition, T1491 defacement, T1529 system shutdown, T1657 financial theft). All of this is documented actor CAPABILITY -- no TTP specific to the Vermont XCenter incident has been observed by any source reviewed.

## Actor Ecosystem: Associations and the DragonForce Malaysia Question

Blackpoint Cyber documents a broader, partly-contested association ecosystem: linked attacks from BlackLock/Mamona; a forum-user association (Bjorka); Devman payloads reportedly built on DragonForce infrastructure; near-identical LockBit 3.0 builder source code (per Cyble); a posted Qilin partnership announcement; mixed and contested reports about a RansomHub relationship ranging from a cooperative merge to an exit scam; and Scattered Spider observed deploying the DragonForce variant against Retail-sector targets. Separately, Trend Micro independently tracks the same operation under the name 'Water Tambanakua'. The actor's own most sensitive identity question -- any connection to the Malaysian hacktivist collective 'DragonForce Malaysia', which announced ransomware ambitions via Telegram in 2023 -- is explicitly framed by Blackpoint Cyber itself as unresolved: an 'even chance' either way, 'has yet to be confirmed'. This report represents that question as genuinely UNKNOWN rather than asserting or dismissing a lineage connection.

## Current Tracked Scale (2026 Snapshot)

Blackpoint Cyber's Diamond Model characterizes DragonForce's typical victim as financially-motivated/opportunistically selected, most frequently in Industrials (Manufacturing) and most frequently headquartered in North America, generally focused on organizations with $15M+ in annual revenue -- an aggregate profile Vermont XCenter, a Brazil-based BPO, falls outside of rather than matches, which this report notes rather than smooths over. ransomware.live's own current aggregate tracking shows 639 total DragonForce victims across 65 countries, with a 19.0-day average delay between estimated attack date and leak-site claim, and 28.2% of tracked victims showing a domain-level overlap with known infostealer-malware logs. At the time of this report, Vermont XCenter is the group's own most recently listed victim. This report also records an open discrepancy rather than resolving it silently: the tracker's own earliest tracked victim has an estimated attack date of 2022-10-20, predating both named vendors' 'August 2023 discovery' dating by roughly ten months -- no source reviewed explains this gap.

## Detection

A Sigma detection concept is provided at SYNTAX_VALIDATED maturity only -- neither lab testing nor any deployment validation has been performed this session -- targeting two of DragonForce's own documented, quotable indicators: unexpected SimpleHelp RMM installation activity, and files renamed with the '.dragonforce_encrypted' extension. A match does not by itself confirm DragonForce attribution (see the rule's own falsepositives field, including the documented fact that affiliates can customize the encrypted-file extension). Full rule body:

```yaml
title: DragonForce SimpleHelp RMM Persistence and dragonforce_encrypted Ransom Note Pattern
id: reportx-canary-dragonforce-simplehelp-persistence
status: experimental
description: >
  Detects two documented DragonForce indicators: unexpected installation
  or execution of the legitimate SimpleHelp RMM tool used to maintain
  persistent access (per Blackpoint Cyber's Known Tools table), and
  files renamed with the '.dragonforce_encrypted' extension used by the
  group's ContiV3-based encryptor variant. Neither indicator alone
  confirms DragonForce attribution for any specific incident --
  SimpleHelp is a legitimate RMM tool with benign uses, and affiliates
  reportedly have the option to customize the encrypted-file extension.
references:
  - https://blackpointcyber.com/wp-content/uploads/2026/02/DragonForce-1.pdf
  - https://www.group-ib.com/blog/dragonforce-ransomware/
logsource:
  category: process_creation
  product: windows
detection:
  selection_simplehelp_new_install:
    Image|endswith:
      - '\SimpleHelp.exe'
      - '\Remote.exe'
    CommandLine|contains: 'install'
  selection_encrypted_extension:
    TargetFilename|endswith: '.dragonforce_encrypted'
  condition: selection_simplehelp_new_install or selection_encrypted_extension
falsepositives:
  - Legitimate, IT-authorized SimpleHelp RMM deployments -- verify against a known-good asset inventory before response
  - Affiliates reportedly customize the encrypted-file extension, so absence of '.dragonforce_encrypted' specifically does not rule out this variant family
level: high
```

## Hunting

Given the documented, specific persistence pattern, a defensible hunting hypothesis is to search endpoint software-inventory and process-creation telemetry for SimpleHelp (or another unexpected RMM tool) installed outside a known-good IT asset inventory, cross-referenced against scheduled-task creation events consistent with the group's documented persistence mechanism. Separately, given the group's documented pattern of rapid adoption of newly disclosed remote-access-software CVEs (the SimpleHelp chain being the most recent example), hunting teams should prioritize patch-verification sweeps across internet-facing RMM, VPN, and firewall management interfaces ahead of narrower endpoint-only hunts. This report does not include incident-specific IOCs for Vermont XCenter -- none were located by any source reviewed.

## Forecast

MEDIUM confidence that DragonForce-branded and cartel-affiliated activity will continue at or above its documented current pace (639 tracked victims across 65 countries) over the next 90 days, with continued active exploitation of recently disclosed vulnerabilities and continued expansion of its cartel/white-label partnership model -- tempered by the inherent unpredictability of law-enforcement disruption events and by this report's own sources' genuine uncertainty about the cartel model's cohesion. See the structured forecast record (supporting observations, assumptions, alternative scenarios, and indicators to watch) in this bundle's `forecasts` field.

## Alternative Hypotheses

Two genuinely open analytic questions are weighed explicitly rather than resolved by assumption. **First**, whether the leak-site listing reflects a genuine, currently-undisclosed compromise (**H1**, consistent with DragonForce's persistent operating cadence and a notably larger infostealer-exposure signal than this canary set's other victims) versus an unconfirmed or overstated claim (**H2**, consistent with the total absence of a proof sample, independent confirmation, or victim acknowledgement). **Second**, whether DragonForce ransomware is connected to the hacktivist collective 'DragonForce Malaysia' (**H1**, a real, dated 2023 statement of ransomware intent) versus an unrelated operation having adopted the same name for attribution evasion (**H2**) -- a question this report's own primary vendor source frames as genuinely even-odds, not one this report resolves.

## Regulatory Considerations

LGPD (Brazil) is assessed NOT_ASSESSED: whether any compromise occurred at all is UNKNOWN, and no source describes the content or category of any data potentially affected. HIPAA/US healthcare business-associate exposure is assessed NOT_ASSESSED: Vermont XCenter's own site documents a healthcare-adjacent 'Vermont Health' service line, but no source identifies a specific US HIPAA-covered-entity client or confirms any patient data was affected. PCI-DSS is assessed NOT_ASSESSED: the contact-center/telesales business model plausibly involves payment-card data, but no source describes the specific cardholder-data-environment footprint. The SEC Cyber Disclosure Rule is assessed NOT_APPLICABLE: no source establishes Vermont XCenter as a US public company.

## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)

Standard ransomware readiness guidance -- immutable backups, MFA and credential-exposure monitoring, network segmentation against RDP/SMB-based lateral movement, behavioral detection for known tooling and mass encryption, shadow-copy/service-stop monitoring, and a tested IR plan with a defined leak-site-monitoring process -- is provided as general hardening grounded in DragonForce's own documented attack lifecycle, not as evidence any specific technique was used against this victim.

## Intelligence Gaps

Eight gaps are explicitly unresolved by any source reviewed for this report: victim acknowledgement is unavailable; no incident-specific IOCs were observed; no proof sample of any claimed data exists; no independent confirmation of the leak-site claim was located; no initial-access or incident-specific TTP evidence was found; whether any of DragonForce's documented general TTPs were used in this specific incident is unestablished; the 2022-10-20-versus-2023 origin-date discrepancy in the tracker's own dataset is unresolved; and which specific DragonForce affiliate or cartel-partner brand is responsible for this claim is unestablished.

## Technical Recommendations

1. Maintain a software-inventory baseline for authorized RMM tools and alert on any unexpected SimpleHelp (or similar) installation -- the direct countermeasure to DragonForce's documented persistence technique (evidence: c-dragonforce-tooling).
2. Prioritize patch-verification sweeps across internet-facing VPN/firewall/RMM management interfaces, given DragonForce's documented pattern of rapid adoption of newly disclosed CVEs in exactly this category of software (evidence: c-dragonforce-cve-history).
3. Deploy monitoring for DragonForce's specific documented persistence and encryption indicators via the detection rule above (evidence: c-dragonforce-variants).
4. Enforce MFA on all remote-access and privileged accounts and monitor for third-party/end-user credentials appearing in infostealer-log marketplaces, given the notably large infostealer-exposure signal observed for this specific victim (evidence: c-infostealer-exposure-vxc).

## Appendix A: Sources & Evidence Ledger

Every source registered in this report's evidence graph, its retrieval/integrity metadata, and every captured excerpt tied to it -- the complete evidentiary basis for every claim above.

### s-ransomwarelive-vxc — ransomware.live (leak-site tracker)

- URL: https://www.ransomware.live/id/VmVybW9udCBYQ2VudGVyQGRyYWdvbmZvcmNl
- Type: LEAK_SITE_AGGREGATOR
- Reliability: MODERATE
- Retrieved: 2026-08-17T00:00:00Z
- content_sha256: `bd393f3f6c8e2d8bbd740ad00d926bc46800f176b5f8213d1a1a1048f5245422`

> Vermont XCenter listed by DragonForce, discovered 2026-08-17 09:24 UTC, est. attack date 2026-08-17; domain vermont.com.br; country BR (flags/BR.svg); sector 'Not Found' at the tracker. No distinct data-volume or category claim -- the 'Description' field is the victim's own scraped site meta-description.

> Infostealer activity detected by HudsonRock. Compromised Employees: 2. Compromised Users: 48. Third Party Employee Credentials: 9. External Attack Surface: 18.

> MX Records: vermont-com-br.mail.protection.outlook.com (Microsoft 365). TXT Records: v=spf1 include:spf.protection.outlook.com include:mail.zendesk.com -all. Cloud/SaaS Services Detected: Global Sign, Zendesk. WHOIS Emails: No emails found.

### s-vermont-own-site — Vermont XCenter (the company's own site, Portuguese)

- URL: https://vermont.com.br
- Type: VICTIM_STATEMENT
- Reliability: HIGH
- Retrieved: 2026-08-17T00:00:00Z
- content_sha256: `6f7c67489d66a13558ede273850f7bf27bac22bf1c1d7583cce6ac19e592f307`

> 'A VERMONT e um Contact Center Omnichannel feito do seu jeito. Atuando ha quase tres decadas, com infraestrutura robusta para atender as mais diversas operacoes de atendimento e vendas.' (Vermont is an Omnichannel Contact Center made your way. Operating for almost three decades, with robust infrastructure serving diverse customer-service and sales operations.)

> 'Saude e programa de suporte ao paciente: Gestao de relacionamento, atendimento de farmacovigilancia, duvidas com atendimento de profissionais de saude. Cadastro de pacientes, resgate de servicos, atencao a rede credenciada.' (Health and patient-support program: relationship management, pharmacovigilance support, healthcare-professional support. Patient registration, service recovery, accredited-network care.)

### s-groupib-dragonforce — Group-IB ('Inside the Dragon: DragonForce Ransomware Group', by named analysts Nikolay Kichatov, Sharmine Low, Alexey Kashtanov)

- URL: https://www.group-ib.com/blog/dragonforce-ransomware/
- Type: CTI_VENDOR_RESEARCH
- Reliability: MODERATE
- Retrieved: 2026-08-17T00:00:00Z
- content_sha256: `461b0b4419bcd37327e573f1f6ec157d86884be77c49fbc0e8a3680fa61a6aea`

> DragonForce is a Ransomware-as-a-Service operation ... Discovered in August 2023, DragonForce has been targeting companies in critical sectors using a variant of the leaked LockBit3.0 builder and, more recently, in July 2024, with their own ransomware variant.

> DragonForce operates a Ransomware-as-a-Service (RaaS) affiliate program utilizing a variant of LockBit3.0, and the other, though initially claimed as original, is based on ContiV3 ... BYOVD, scheduled-task persistence, and expanded encryption customization.

> Group-IB's research also links DragonForce activity to SystemBC, Cobalt Strike, Mimikatz, and network-reconnaissance tooling used during real intrusions.

### s-blackpoint-dragonforce — Blackpoint Cyber ('DragonForce Ransomware Threat Profile', 30 pages)

- URL: https://blackpointcyber.com/wp-content/uploads/2026/02/DragonForce-1.pdf
- Type: CTI_VENDOR_RESEARCH
- Reliability: MODERATE
- Retrieved: 2026-08-17T00:00:00Z
- content_sha256: `204555128b4150a2db216a1255af54d0f67c5bda6d960b6e52cfb29709b6894f`

> DragonForce ransomware was first identified in August 2023. DragonForce ransomware operated as a private group until June 2024 when the group advertized their affiliate program on the Russian-language cybercriminal forum, RAMP. The group reportedly offers 80% of a ransom payment to the affiliates.

> DragonForce has two ransomware variants - one based on LockBit Ransomware and another based on the Conti Ransomware variant. The Conti fork of DragonForce renames files with a '.dragonforce_encrypted' extension; however, affiliates reportedly have the option to customize the extension. For each file, the ChaCha8 key and IV is generated by the CryptGenRandom() function.

> Known Tools: PowerShell and WMI (execution); at and schtasks (persistence); SimpleHelp (legitimate RMM tool abused to maintain persistent access); BadRentdvr2 (vulnerable driver used for BYOVD, executing kernel-mode routines via ThrottleStop.sys).

> In March 2025, the group announced their shift to a 'ransomware cartel'. In the announcement, affiliates were encouraged to continue using DragonForce tools but to branch out and create their own brand ... In August 2025, DragonForce announced a partnership with the LockBit operation to create a 'ransomware cartel' [Ransombay: DragonForce reportedly charges 20% of the ransom payment in exchange for infrastructure, malware, and ongoing support]. In August 2025, the group reportedly launched a 'data analysis service' ... offered to affiliates targeting organizations with an annual revenue of $15 million or more ... The fee for this service reportedly ranges from 0-23% of ransom payments.

> Known Exploited Vulnerabilities: CVE-2021-44228 (Apache Log4j, CVSS 10); CVE-2023-46805 / CVE-2024-21887 / CVE-2024-21893 (Ivanti Connect Secure and Policy Secure); CVE-2024-21412 (Microsoft Windows Internet Shortcut Files, CVSS 8.1); CVE-2024-21762 (FortiOS sslvpnd out-of-bound write, CVSS 9.8); CVE-2024-40766 (SonicOS improper access control, CVSS 9.8); CVE-2024-57726 / CVE-2024-57727 / CVE-2024-57728 (SimpleHelp RMM privilege escalation / path traversal / arbitrary file upload, CVSS 9.9 / 7.5 / 7.2); CVE-2024-55591 (FortiOS and FortiProxy authentication bypass, CVSS 9.8).

> MITRE ATT&CK mappings span the full lifecycle: Initial Access (T1078, T1133, T1189, T1190, T1566); Persistence (T1053, T1078, T1543, T1547); Privilege Escalation; Defense Evasion (T1027, T1070, T1112, T1140, T1211, T1218, T1222, T1553, T1562, T1564, T1679); Credential Access (T1003.001 LSASS Memory, T1003.002 SAM); Discovery (T1012, T1016, T1018, T1057, T1069, T1082, T1083, T1087, T1135, T1482, T1673); Lateral Movement (T1021 RDP/SMB, T1210, T1570); Collection (T1005, T1560); Command and Control (T1071, T1090, T1105, T1219, T1571); Exfiltration (T1041, T1048, T1567); Impact (T1486, T1489, T1490, T1491, T1529, T1657).

> DragonForce Malaysia: A hacktivist group from Malaysia that announced via their Telegram in 2023 that they were planning on developing a ransomware operation. Any connection between the two groups has not been confirmed ... There is an even chance that the ransomware is related to the hacktivist group ... There is an even chance that another operation has adopted the name in an effort to evade detection and attribution.

> Associations: BlackLock/Mamona (linked attacks, possibly part of the cartel); Bjorka (a forum user linked via a leaked database); Devman (payloads built on DragonForce infrastructure, also linked to Qilin); LockBit (near-identical builder source code per Cyble, formal cartel partnership announced August 2025); Qilin (a posted partnership announcement alongside LockBit); Ransomhub (mixed, contested reports -- ranging from a cooperative merge to an exit scam); Scattered Spider (observed deploying the DragonForce variant against Retail-sector targets); tracked by Trend Micro under the name 'Water Tambanakua'.

> Executive Summary: Most frequently targeted industry: Industrials (Manufacturing). Most frequently targeted victim HQ region: North America. Diamond Model victim characteristics: financially-motivated, opportunistic; Industrials (Manufacturing); North America-focused; $15M+ revenue focus.

### s-ransomwarelive-dragonforce-group — ransomware.live (leak-site tracker, group aggregate page)

- URL: https://www.ransomware.live/group/dragonforce
- Type: LEAK_SITE_AGGREGATOR
- Reliability: MODERATE
- Retrieved: 2026-08-17T00:00:00Z
- content_sha256: `c8ad62ca8f5f5144ee0cf7e520213935f54c18376c9a3615ef50e2eb96615142`

> Victims 639. First Victim (est. attack date) 2022-10-20. Discovery Date 2023-12-13. Last Seen 2026-08-17. Avg Delay 19.0 days. Infostealer 28.2% victims with domain. Countries 65 hit.

