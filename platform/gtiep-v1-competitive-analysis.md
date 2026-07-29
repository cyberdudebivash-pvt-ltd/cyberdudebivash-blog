# GTIEP v1 — SOURCED COMPETITIVE ANALYSIS
## What the 10 named CTI vendors actually publish, and what it means for the Sentinel APEX report standard

---

## Methodology and honest limits

Every vendor below was researched directly (WebFetch against their live
public blog/research pages, plus web search, July 2026) rather than
recalled from memory — matching this platform's own "no unverifiable
claims" content governance. Sources are cited per vendor.

**What this can and cannot tell us**: all 10 vendors' full paid
intelligence products (their actual customer-facing reports, confidence
methodology internals, proprietary data feeds) are not publicly readable —
what follows is built from their *public* blog posts and research
pages, which is a real and useful signal of structure and approach, but
is not the same as having read a paid Recorded Future or Intel 471
report end to end. Treat the per-vendor notes below as directionally
accurate, evidence-backed characterizations, not exhaustive audits of
products this platform has no access to. This is the same "Intelligence
Gap" / "Collection Gap" discipline this platform already applies to its
own published reports (see `Sentinel-APEX/eios/layer-13-editorial-style-guide.md`),
applied here to researching competitors instead of CVEs.

## Two corrections to the named vendor list itself

Before comparing report structure, two of GTIEP v1's ten named
competitors need a factual update, found during this research rather than
assumed from the original list:

1. **"Google Threat Intelligence" and "Mandiant" are, for practical
   purposes, the same organization.** Google acquired Mandiant in 2022;
   Mandiant's research now publishes under `cloud.google.com/blog/topics/threat-intelligence`
   as "Google Threat Intelligence Group" (GTIG) content, alongside
   legacy Mandiant-branded posts. GTIEP's list effectively names this
   vendor twice.
2. **"Secureworks CTU" no longer exists as an independent organization.**
   Sophos completed its $859M acquisition of Secureworks in February 2025
   ([Cybersecurity Dive](https://www.cybersecuritydive.com/news/sophos-completes-859m-acquisition-of-secureworks/739027/),
   [Sophos](https://www.sophos.com/en-us/press/press-releases/2025/02/sophos-completes-secureworks-acquisition)).
   The Counter Threat Unit — which tracked 150+ threat groups and
   published an annual Threat Report — is now part of **Sophos X-Ops**
   ([Sophos](https://www.sophos.com/en-us/secureworks-sophos-acquistion)).
   `secureworks.com/blog` itself now 301-redirects to `sophos.com/en-us/news`
   (confirmed directly, not asserted). References to "Secureworks CTU" as
   a standalone competitor should be understood as Sophos X-Ops going
   forward.

Both corrections matter beyond trivia: naming a target competitively
without knowing it was absorbed into a larger organization 18 months ago
is exactly the kind of unverified claim this platform's own governance
exists to prevent.

## Per-vendor findings (sourced)

| Vendor | Actor-naming convention | Detection content published | Structural signature |
|---|---|---|---|
| **Google TI / Mandiant** ([source](https://cloud.google.com/blog/topics/threat-intelligence)) | Recently overhauled "Cyber Threat Actor Naming System" | IOCs, hardening/remediation guidance alongside analysis | Read-time-labeled posts (3 min to 68 min), explicitly "frontline investigations, expert analysis, tools and guidance" — positions incident-response experience as the differentiator |
| **Microsoft Threat Intelligence (MSTIC)** ([source](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/)) | Weather-themed (Storm-\*, \*Typhoon, \*Sleet, \*Tempest, \*Blizzard) — a real, consistent, memorable taxonomy | Detection tied explicitly to Microsoft Defender + Sentinel products | Telemetry-driven ("deployment patterns... across customer environments") — the differentiator is breadth of first-party sensor data, not third-party sourcing |
| **CrowdStrike** ([source](https://www.crowdstrike.com/en-us/blog/)) | Animal-suffix adversary names (\*SPIDER, etc.) | Detection tied to the Falcon platform explicitly ("Falcon Platform Prevents...") | Segments content by domain ("Threat Hunting & Intel," "From The Front Lines") and publishes industry-specific annual reports |
| **Unit 42 (Palo Alto)** ([source](https://unit42.paloaltonetworks.com/)) | Own threat-actor-group taxonomy | Technique tagging (C2, DGA, DLL Sideloading, AMSI, etc.) for cross-reference | Annual Global Incident Response Report series; strong technique/tooling tagging discipline |
| **Recorded Future (Insikt Group)** ([source](https://www.recordedfuture.com/research)) | — | — | Stated mission: "research that creates action to disrupt adversaries" — action-oriented framing over descriptive reporting (full methodology/confidence disclosure not visible on the public research index) |
| **Cisco Talos** ([source](https://blog.talosintelligence.com/)) | References specific actor/malware identifiers per post (e.g. observed cluster IDs) | **Publishes actual Snort rule content directly in posts** (e.g. tied to Patch Tuesday coverage) — the most concretely "give the reader a working detection artifact" of the vendors checked | Category-organized (Threat Spotlight, Vulnerability Deep Dive, quarterly IR trends) |
| **Secureworks CTU → Sophos X-Ops** ([source](https://www.sophos.com/en-us/secureworks-sophos-acquistion)) | Pre-acquisition: "GOLD "+codename group taxonomy | Historically an annual State of the Threat Report | Now folded into Sophos X-Ops' broader MDR/XDR telemetry — no longer an independently-branded CTI research output |
| **Intel 471** ([source](https://public.intel471.com/products/threat-intelligence/)) | — | IOC feed via their "Malware Emulation and Tracking System" (METS) | Three distinct report *types*, not just posts: **Information Reports** (tactical/operational, HUMINT-sourced), **Threat Actor Profile Reports** (TTP deep-dive, ATT&CK-aligned), **Malware Intelligence Reports** (config/C2/encryption-key extraction detail) — a genuinely different, more product-line-shaped structure than the blog-post vendors above |
| **Flashpoint** ([source](https://flashpoint.io/blog/)) | — | — | Named methodology: **"Flashpoint Method"** for vulnerability prioritization (real-world risk × exploitability × business impact); covers cybercrime, physical/geopolitical risk, and illicit-community tradecraft — broader scope than pure malware/APT reporting |

## Cross-vendor pattern (what "premium" actually looks like, evidenced across all of them)

Every vendor checked shares three structural habits regardless of naming
convention or specialization:

1. **A consistent, owned actor/campaign naming taxonomy.** Not just an
   internal label — a *branded*, externally recognizable identity (Storm-\*,
   \*SPIDER, GOLD \*) that becomes the vendor's own IP over time. Sentinel
   APEX has no naming taxonomy of its own today — it references other
   vendors' actor names (LockBit, APT41, etc.) but has never coined one.
2. **Detection content is a first-class deliverable, not an afterthought
   appendix.** Talos ships Snort rules directly in blog posts; CrowdStrike
   and Microsoft explicitly tie findings to their own product's detection
   surface; Intel 471 has a dedicated Malware Intelligence Report type
   built entirely around extraction/detection detail.
3. **Report *type* varies by intent, not just by audience.** Intel 471's
   three report types (Information/Actor-Profile/Malware) are organized by
   *what kind of finding it is* — closer to GTIEP v1's subject-type
   template ask than to Sentinel APEX's current audience-only template
   axis (`platform/gtiep-v1-audit.md` item 9).

## What this means for the Sentinel APEX report standard (direct implications)

- **A Sentinel APEX naming convention is a real, evidenced gap**, not
  invented by this analysis — every vendor checked has one; Sentinel APEX
  does not. Out of scope for this sprint (naming a threat actor is an
  editorial/brand decision, not an engineering one) but worth recording as
  a finding, not silently noticed and dropped.
- **Talos's "ship the actual rule, not just a description" habit directly
  supports this sprint's Quality Framework work** (`platform/gtiep-v1-audit.md`'s
  Priority 4 item) — Detection Value as a real scored dimension, not just
  a gate pass/fail, is exactly the discipline Talos's public posts
  demonstrate.
- **Intel 471's report-type-by-intent structure is the strongest evidence
  for GTIEP v1's Priority 6 (subject-type templates)** being the right next
  axis to build on, once this sprint's foundational work (quality
  framework, missing sections, one real template) lands — corroborates
  rather than contradicts the audit's own staging decision to build one
  template (Threat Actor Profile) well this sprint rather than 21 shallow
  ones.

---
*CyberDudeBivash® Sentinel APEX — Global Threat Intelligence Excellence Program, Sourced Competitive Analysis*
