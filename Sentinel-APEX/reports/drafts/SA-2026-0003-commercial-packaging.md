# Commercial Packaging Brief — SA-2026-0003
## JetBrains TeamCity Authentication Bypass & Path Traversal (CVE-2024-27198, CVE-2024-27199)

## Product Name
"TeamCity Dual-CVE Bulletin — Two Confirmed Ransomware Campaigns, KEV Deadline
Two Years Overdue" (working title; leads with the two most verifiable, most
urgent facts in the report — independent double confirmation of exploitation
and the overdue federal deadline — rather than the CVE numbers alone).

## Target Customer
Primary: organizations running JetBrains TeamCity On-Premises as CI/CD build
infrastructure — a distinct buyer persona from this platform's first two
reports (SA-2026-0001's SharePoint targeted general IT/knowledge-worker
infrastructure; SA-2026-0002's PAN-OS GlobalProtect targeted network/perimeter
security teams). This report's natural buyer is DevSecOps and Platform
Engineering leadership, plus the AppSec function responsible for build
infrastructure — a buyer this platform has not yet directly addressed.
Secondary: MSSPs advising software-engineering-heavy clients; any security
team running a KEV-catalog compliance sweep, where CVE-2024-27198 now sits
among the most overdue deadlines this platform has documented.

## Customer Pain Points
1. "It's just our build server, not customer-facing" — CI/CD infrastructure
   is routinely under-prioritized relative to customer-facing systems; this
   report's own data (CVSS 9.8, EPSS 99.97th percentile, CISA KEV
   `knownRansomwareCampaignUse: Known`) is the concrete counter-argument a
   security team can bring to engineering leadership.
2. "Is this real exploitation or theoretical risk?" — resolved more
   decisively than either prior report: two separate first-party vendor
   telemetry sources (GuidePoint Security, Trend Micro) each independently
   confirm their own distinct named ransomware strain, rather than one
   contested aggregator claim.
3. JetBrains' own advisory bundles both CVEs into a single remediation
   narrative without technically distinguishing that CVE-2024-27199 alone
   (CVSS 7.3, limited admin actions) is far less severe than
   CVE-2024-27198 alone (CVSS 9.8, full compromise) — a distinction that
   matters for anyone relying on a partial mitigation or a scanner keyed to
   only one of the two CVE IDs.

## Business Value
Converts an internal-tooling vulnerability that is easy to deprioritize into
a same-day escalation, backed by this platform's strongest evidence base to
date: two independently sourced, first-party-confirmed ransomware campaigns
rather than one. Gives a security team the CVE-vs-CVE severity distinction
JetBrains' own advisory omits, plus the same administrative-access/session
and access-log review action this platform established as standard guidance
for authentication-bypass findings in SA-2026-0002.

## Competitive Differentiation
Three concrete, verifiable trust signals: (1) two ransomware campaigns
confirmed from two independent first-party sources — the strongest
attribution confidence this platform has produced to date (contrast
SA-2026-0002, where the only available ransomware claim had zero supporting
reference and was excluded rather than repeated); (2) verified directly via
this platform's own `cli.py certify` command while preparing this brief:
this is the first report in the program's history to reach unconditional
**CERTIFIED** status — zero blocking or advisory findings across all five
applicable domains — where both prior reports (SA-2026-0001, SA-2026-0002)
shipped CERTIFIED WITH CONDITIONS; (3) the report continues the transparency
practice established in SA-2026-0002: it explicitly documents a technique it
deliberately did not map (T1218.007, despite `msiexec` being the exact LOLBin
observed in the confirmed chain) and excludes a false-positive technique
(T1071) that this platform's own automated graph-ingestion produced — now a
repeatable practice demonstrated across two consecutive reports, not a
one-off.

## Recommended Pricing / Tier Placement
Current production tier structure (`docs/PRICING.md`, canonical values from
`api/_lib/payment-utils.js`): a Free API tier (100 requests/day, no card
required), then three paid tiers — Starter (₹999/$12/mo), Pro/"SOC
Professional" (₹1,499/$18/mo), and Enterprise (₹4,999/$60/mo). Per
`pricing.html`'s own feature matrix, complete IOC feed access and Sigma/YARA
detection rules are Pro and above; pre-disclosure CVE reports are
Enterprise-only. Recommend the same acquisition pattern already used for
SA-2026-0001/0002: publish the Executive Brief variant as the free
acquisition hook, gate the full technical report behind Pro/Enterprise.

**Honest caveat**: this platform's Quality Framework v2 (GTIEP v1) scores
this report **48/100 — BLOCKED tier** (verified directly via `cli.py
certify` for this brief, threshold 60) — the highest of the three real
reports scored to date (SA-2026-0001: 43, SA-2026-0002: 37, this report:
48), and the *only* one of the three with real, published IOCs (five:
an IP:port, two SHA-256 hashes, an encrypted-file extension, and a
ransom-note filename). Reading `scoring.py` directly to explain the gap
rather than guessing: the score is still held below threshold for two
specific, checkable reasons, neither of which is IOC scarcity. First,
`detection_value`/`soc_value`/`dfir_value` all score low because no
Sigma/YARA/other detection format is embedded in this report — the same
reason SA-2026-0001 and SA-2026-0002 scored low. Second,
`executive_value` and `commercial_value` each award a fixed +25 specifically
for `threat_actor`-typed entities, and this report's own front matter
correctly records `threat_actors: []` — BianLian and Jasmin are tracked as
`malware_families` (ransomware strains), because no source available to this
platform names a specific operator or intrusion-set for either campaign,
only the ransomware family itself. The scoring engine currently has no
equivalent credit path for a confirmed malware-family/ransomware-strain
entity in the absence of a named actor — worth flagging as a candidate
scoring-model refinement, not a report defect, since declining to invent an
actor name no source supports is exactly the restraint this platform's
governance requires.

## Upsell Opportunities
- A recurring **"Most Overdue KEV Deadlines"** content angle: CVE-2024-27198's
  deadline (2024-03-28) is, as of this report, the single most overdue
  deadline this platform has documented across all three reports to date —
  a running "oldest still-active KEV deadlines" product has a natural
  cadence and a built-in urgency hook that doesn't depend on any one CVE.
- **Build-infrastructure security assessment**: distinct from the
  session/access-log review already offered against SA-2026-0002 — this
  report's own guidance (confirm no TeamCity instance below 2023.11.4
  remains exposed, then review administrative-account and access logs for
  the period it ran an affected build) is a scoped, sellable service
  specifically for CI/CD build infrastructure, a system class this
  platform has not previously packaged a service around.

## Cross-Sell Opportunities
- Enterprise consulting/assessment: "we'll audit your build infrastructure's
  internet exposure and review TeamCity administrative-account activity
  against the confirmed compromise window" directly extends this report's
  own most distinctive guidance, and is a natural second sale alongside the
  SA-2026-0002 session-review offering for any enterprise running both
  PAN-OS and TeamCity — a common combination in mid-to-large engineering
  organizations.

---
*Companion commercial brief to SA-2026-0003 — not a governance document, a
product brief for this specific report.*
