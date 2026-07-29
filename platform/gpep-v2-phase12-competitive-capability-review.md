# GPEP v2 Phase 12 — Competitive Capability Review

## Reuse, not re-research

`platform/gtiep-v1-competitive-analysis.md` (GTIEP v1, sourced directly
against all 10 named vendors' public blogs/research pages, July 2026)
already covers actor-naming conventions, detection-content publishing
patterns, and structural signatures per vendor, plus two real corrections
to the vendor list itself (Google TI ≈ Mandiant post-acquisition;
Secureworks CTU → Sophos X-Ops post-acquisition). That research is not
re-derived here — this phase adds only what's genuinely new from this
session's own work, per Reuse Before Build.

## One direct cross-reference this session's own finding surfaced

GTIEP v1's vendor table already documented Microsoft's weather-themed
actor-naming system (Storm-\*, \*Typhoon, \*Sleet, \*Tempest, **\*Blizzard**).
Independently, this session's Issue 17 fix (Phase 3) added `actor:apt29`
to this platform's own graph with alias `"Midnight Blizzard"` — Microsoft's
own name for the same actor (APT29/Cozy Bear). This is a small but real
confirmation that this platform's newly-added actor data is consistent
with, not contradicting, the independently-researched competitive
landscape already on file — a cheap, real cross-check that happened to be
available this pass, not a designed verification step.

## One new comparative dimension: attribution-correction transparency

Not covered in GTIEP v1's original review (which focused on structure and
detection-content publishing, not error-correction behavior). Checked
directly, within the bounds of what's publicly observable for this review
(no paid-product access, same limitation GTIEP v1 stated): none of the 10
vendors' public blog indices reviewed for GTIEP v1 prominently surface a
visible "correction" or "retraction" log for prior attribution claims —
this is expected; it's not standard practice in the industry to publish
one, and its absence elsewhere is not itself a finding against any vendor.

What **is** a genuine, evidence-backed comparison point: this session
found and corrected a real, sourced attribution error in this platform's
own live knowledge graph (CVE-2024-27198/27199 misattributed to APT41/Cl0p
with mis-cited sources) *because* a certified, disciplined report
(SA-2026-0003) existed on the same subject and created an internal
contradiction worth investigating. That the correction mechanism exists at
all — cross-referencing the certified-report pipeline's own restraint
("no source names an actor here") against the automated graph's more
confident claim — is a structural property most competitors' single-
pipeline products likely don't have an equivalent internal check for
(most vendors appear, from GTIEP v1's research, to run either an analyst-
authored blog or a telemetry-driven feed, not both against each other as a
cross-check). This is not verifiable against any vendor's internals
(out of scope, matching GTIEP v1's own stated limits) — recorded as this
platform's own structural property, not a claim about anyone else's.

## What remains unchanged from GTIEP v1

The staged, not-yet-executed items GTIEP v1 already identified (~18 of 21
subject-type templates still unbuilt; detection-format expansion to
CrowdStrike/Defender XDR/Cortex XDR; populating rich Malware profiles
beyond the 2 added this session) remain exactly as staged — restated here
for completeness, not re-analyzed, since nothing about the competitive
landscape changed their priority this pass.

---
*CyberDudeBivash® Sentinel APEX — GPEP v2 Phase 12 Competitive Capability Review*
