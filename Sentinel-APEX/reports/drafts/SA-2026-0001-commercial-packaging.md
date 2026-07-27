# Commercial Packaging Brief — SA-2026-0001
## Critical SharePoint Deserialization RCE (CVE-2026-50522)

## Product Name
"SharePoint ToolShell-Class RCE — Active Exploitation Bulletin" (working title;
"ToolShell-class" signals the credential-theft-survives-patching pattern to
readers already familiar with the 2025 SharePoint exploitation wave, without
claiming these are the same campaign).

## Target Customer
Primary: CISOs and IT/security leadership at any enterprise running
on-premises Microsoft SharePoint (2016, 2019, or Subscription Edition) —
this is a large, identifiable install base, not a niche audience.
Secondary: MSSPs needing to advise multiple SharePoint-running clients at
once; SOC teams needing the detection/hunting content directly.

## Customer Pain Points
1. "We patched it, are we safe?" — the report's entire value proposition is
   answering "no, not necessarily" with the specific reason why, which a
   bare CVE listing or vendor advisory does not make clear.
2. Sequencing confusion — CISA's own guidance (hunt, then patch, then
   rotate) is not intuitive and is easy to get backwards under pressure.
3. No time to synthesize four related CVEs and a dozen news sources into
   one action plan during an active-exploitation window.

## Business Value
Directly actionable within the hour it's read: a security leader gets a
decision matrix, a specific remediation sequence, and board-ready language
in one document instead of assembling it from CISA, NVD, and three security
news outlets under time pressure during a live incident.

## Competitive Differentiation
Every fact in this report is independently corroborated through two paths —
public reporting (The Hacker News, Help Net Security, SecurityWeek) **and**
this platform's own live query against NVD/EPSS/CISA KEV at generation
time — with the one genuine cross-source discrepancy found (an
authentication-requirement claim contradicted by the authoritative CVSS
vector) preserved and resolved in the text rather than silently dropped.
That resolved-discrepancy transparency is a concrete, demonstrable
trust differentiator against a vendor bulletin that states one claim with no
visible cross-check.

## Recommended Pricing / Tier Placement
This repository's existing pricing structure (`pricing.html`,
per `BUSINESS-TRANSFORMATION-ROADMAP-2026.md`) has three tiers: Free,
Pro (₹1,499 / $18 mo), Enterprise (₹4,999 / $60 mo). Recommend gating the
**full report** (all sections below Executive Summary) behind Pro or
Enterprise, and publishing the **Executive Brief variant** as free/gated-lead
content — the free tier is the acquisition hook (proves analytical quality),
the full technical report with the Sigma rule and hunting guidance is the
paid differentiator SOC/detection teams actually need.

**Honest caveat**: this platform's own commercial-scoring engine
(`scoring.py`) rates this specific report 43/100 — BLOCKED tier — because
it has zero public IOCs to extract (none exist yet for this campaign) and
its Sigma rule is hand-embedded rather than auto-generated. See
`platform/open-issues.md` Issue 3. That does not mean the report lacks
commercial value — a fresh, well-corroborated, actively-exploited KEV entry
with a clear remediation-sequencing insight is exactly the kind of content
that drives trial signups — but it does mean this specific report should
not be priced as if it were a mature, IOC-rich campaign report. Recommend
treating "fresh critical vulnerability bulletin" as its own lower-friction,
faster-cadence product line (see Upsell below) rather than benchmarking it
against a fully-resolved campaign report's depth.

## Upsell Opportunities
- A follow-up **campaign correlation report** once/if the four related
  SharePoint CVEs' relationship is clarified by researchers or this
  platform's own knowledge-graph correlation across future related
  intelligence — naturally upgrades this bulletin into a deeper Enterprise
  product as more evidence accumulates (see Future Outlook in the main
  report — this is exactly the `supersedes` version-bump case EIOS Layer 8
  anticipates).
- **Detection Content Pack**: this report's one Sigma rule generalizes into
  a small pack (add KQL/Splunk/Suricata variants of the same behavioral
  logic) sellable as a standalone detection-engineering product.

## Cross-Sell Opportunities
- Enterprise consulting/assessment offering (already listed in
  `enterprise.html` per the roadmap doc): "we'll audit your SharePoint
  exposure and execute the hunt-patch-rotate sequence for you" is a natural
  paid-services extension of a report whose core insight is "the sequence
  matters, and it's easy to get wrong under pressure."

---
*Companion commercial brief to SA-2026-0001 — not a governance document, a
product brief for this specific report.*
