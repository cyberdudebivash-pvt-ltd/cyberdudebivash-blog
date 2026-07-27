# SENTINEL APEX — INTELLIGENCE REPORT PROMPT
## Task Prompt: General Threat Intelligence Report Production

> **Usage:** Load `master-prompt.md` first. This prompt governs the production
> of a full Sentinel APEX intelligence report from one or more source articles,
> advisories, or vendor writeups. For malware-centric or CVE-centric sources,
> use `malware-prompt.md` or `cve-prompt.md` instead.

---

## TASK

You are given raw source material (news article, vendor advisory, government
alert, researcher writeup, or telemetry summary). Produce a complete Sentinel
APEX enterprise intelligence report following the 60-section structure defined
in the master prompt.

## INPUT CONTRACT

The operator provides:

| Field | Required | Description |
|---|---|---|
| `source_material` | YES | Full text of the source article(s) or advisory |
| `source_urls` | YES | Canonical URLs for the References section |
| `report_type` | NO | `campaign` \| `incident` \| `actor-profile` \| `sector-threat` (default: infer). For subject-matter classification (CVE, malware, APT, AI security, etc.), see `master-prompt.md` § Report Type Taxonomy. |
| `audience_priority` | NO | `executive` \| `soc` \| `dfir` \| `hunting` (default: balanced) |
| `known_context` | NO | Prior Sentinel APEX reporting on the same actor/campaign for correlation |

## PRODUCTION RULES

1. **Extraction first.** Before writing, extract structured data from the
   source: actors, victims, sectors, geographies, CVEs, malware families,
   infrastructure, timestamps, TTPs. Anything not present in the source is
   NOT a verified fact.
2. **Enrichment second.** Map extracted TTPs to MITRE ATT&CK technique IDs
   (with sub-techniques where determinable). Cross-reference CVEs against
   CVSS, EPSS, and CISA KEV status when known. Label enrichment drawn from
   analyst knowledge rather than the source as ANALYST ASSESSMENT with an
   explicit confidence level.
3. **Verified Facts section** contains ONLY claims directly supported by the
   cited sources. Every other analytical claim carries a label
   (ANALYST ASSESSMENT / HYPOTHESIS / ESTIMATED / LIKELY / POSSIBLE /
   UNCONFIRMED / UNKNOWN) and a confidence rating with justification.
4. **Detection content must be syntactically valid.** Sigma rules must be
   valid YAML with `title`, `id` (UUID), `status`, `description`,
   `references`, `logsource`, `detection`, `falsepositives`, and `level`.
   KQL/SPL/EQL queries must target real tables/indexes and real field names.
   If the source lacks enough detail for a high-confidence rule, produce a
   behavioral rule and mark it `status: experimental` with an explicit note.
5. **IOC discipline.** Every indicator appears in exactly one category
   (Confirmed / Observed / Historical / Behavioral / Derived / Hypothetical).
   Defang all network IOCs (`hxxp://`, `[.]`). Include first-seen /
   last-seen context when the source provides it.
6. **No fabrication.** No invented IOCs, no invented victim names, no
   invented CVE numbers, no invented telemetry. If a section cannot be
   populated from evidence plus clearly-labeled assessment, state the
   intelligence gap instead.
7. **Correlation.** If `known_context` is supplied, explicitly correlate:
   what is new, what is consistent, what contradicts prior reporting.

## OUTPUT CONTRACT

- Format: Markdown, H2 for the numbered sections from the master structure.
- Front matter block at the top:

```yaml
---
title: "<report title — specific, non-clickbait>"
report_id: "SA-<YYYY>-<NNNN>"
date: "<YYYY-MM-DD>"
tlp: "TLP:CLEAR"
report_type: "<campaign|incident|actor-profile|sector-threat>"
threat_actors: []
malware_families: []
cves: []
sectors: []
attack_ids: []
overall_confidence: "<VERY LOW|LOW|MEDIUM|HIGH|VERY HIGH>"
sources: []
---
```

- Version-control fields (`version`, `last_updated`, `supersedes`,
  `review_status`, `analyst`, `reviewer`, `change_log`) are additive to the
  block above — see `Sentinel-APEX/eios/layer-08-report-version-control.md`.
- Executive Summary: maximum 250 words, readable by a non-technical board
  member, states the "so what" in the first sentence.
- Executive Risk Snapshot: single table — Severity, Exploitation Status,
  Exposure, Business Impact, Urgency, Overall Confidence.
- References: numbered list, every URL from `source_urls`, plus any
  framework references (MITRE, NVD, CISA) actually used.
- Save location: `reports/drafts/` until the quality gate passes, then
  `reports/final/`.

## QUALITY GATE (REPORT-SPECIFIC ADDITIONS)

In addition to the master quality gate:

- [ ] Front matter is complete and machine-parseable
- [ ] Every ATT&CK ID in the body appears in front matter `attack_ids`
- [ ] Every IOC is defanged and categorized
- [ ] All detection rules are syntactically valid
- [ ] Executive Summary ≤ 250 words and self-contained
- [ ] All source URLs appear in References
- [ ] Intelligence Gaps section is honest — states what is NOT known
