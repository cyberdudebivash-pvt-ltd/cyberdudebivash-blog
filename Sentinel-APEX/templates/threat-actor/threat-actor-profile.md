---
title: "<Threat Actor Name> — Threat Actor Profile"
report_id: "SA-TA-<YYYY>-<NNNN>"
date: "<YYYY-MM-DD>"
tlp: "TLP:CLEAR"
audience: "soc,ciso,threat-hunter"
overall_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
---

# <Threat Actor Name> — Threat Actor Profile

**GTIEP v1 subject-type template** — the first of GTIEP v1's 21 proposed
report types actually built (see `platform/gtiep-v1-audit.md` item 9).
Populate this template FROM the platform's own curated threat-actor
records (`api/_lib/threat-graph.js`'s `THREAT_ACTOR_DB`) via
`Sentinel-APEX/renderer/threat-actor-profile.js`'s
`buildThreatActorProfileMarkdown()` — do not hand-write a profile for an
actor that already has a curated entry; extend the curated entry instead
(Reuse Before Build). This closes report structure's "Threat Actor
Analysis" gap (`platform/gtiep-v1-audit.md` item 1) with real data, not a
fabricated example.

## Executive Summary
<One paragraph: who this actor is, what they do, why a reader should care
right now. No jargon.>

## Identity

| Field | Value |
|---|---|
| Primary name | |
| Known aliases | |
| Category | *(ransomware_group \| nation_state \| cybercrime \| hacktivist \| ...)* |
| Motivation | |
| Sophistication | *(opportunistic \| advanced \| ...)* |
| Suspected origin | |
| Status | *(active \| dormant \| disrupted)* |
| First observed | |
| Last observed | |

## Targeting

**Target sectors**: <list>

**Target regions**: <list>

<One paragraph: is targeting broad/opportunistic or narrow/deliberate?
State the evidence, not just the list.>

## Known TTPs (MITRE ATT&CK)

| Technique ID | Name | Notes |
|---|---|---|
| | | |

*Every technique ID listed above must trace to this actor's curated
`ttps[]` entry or a specific cited incident — never asserted from general
reputation alone.*

## Associated CVEs

| CVE ID | Role | Notes |
|---|---|---|
| | | |

*"Role" = how this actor uses the CVE (initial access, privilege
escalation, etc.), not just that it's associated.*

## Campaign History
<Narrative: major named campaigns/incidents, dated, evidence-cited. Link
to this platform's own `intelligence/`/`cve/` pages where a campaign
overlaps a report already published here — do not duplicate content that
already has a canonical page.>

## Detection & Hunting Guidance
<Hunt hypotheses keyed to this actor's specific TTPs, not generic
technique-based hunting already covered elsewhere. Reference this
platform's ATT&CK-keyed Sigma/YARA/KQL content where a rule already
exists for one of this actor's known techniques — do not regenerate it.>

## Confidence Assessment

| Dimension | Rating | Basis |
|---|---|---|
| Attribution | | |
| TTP accuracy | | |
| Targeting scope | | |
| Overall | | |

## Intelligence Gaps
- <Honest list of what isn't known/confirmed about this actor>

## Sources
<Every cited reference, real and checkable — this platform's evidentiary
convention (`[Verified Fact]`/`[Analyst Assessment]`/`[Intelligence Gap]`/
`[Unresolved Reference]`, `Sentinel-APEX/eios/layer-13-editorial-style-guide.md`)
applies here exactly as it does in every other report type.>

---
*CyberDudeBivash® Sentinel APEX — Threat Actor Intelligence*
