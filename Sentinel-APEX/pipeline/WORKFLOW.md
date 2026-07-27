# SENTINEL APEX — CTI PRODUCTION PIPELINE

The recommended AI workflow for turning raw source material into
enterprise-grade, published intelligence products.

> This is the operational (file-system/command) view of the pipeline.
> `Sentinel-APEX/eios/layer-02-intelligence-governance.md` and
> `layer-14-release-pipeline.md` give the conceptual and governance/approval
> views of the same 8 stages, broken into finer-grained sub-stages and named
> approval gates respectively — see either for the mapping table.

```
┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ 1. COLLECT  │──▶│ 2. NORMALIZE │──▶│ 3. ENRICH    │──▶│ 4. DRAFT     │
│ sources     │   │ extract data │   │ MITRE/CVE/…  │   │ analyst report│
└─────────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                                │
┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────▼───────┐
│ 8. PUBLISH  │◀──│ 7. SEO +     │◀──│ 6. VARIANTS  │◀──│ 5. QUALITY   │
│ blog + APEX │   │ interlink    │   │ exec/soc/…   │   │ gates        │
└─────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

## Stage 1 — Collect
Gather source material: vendor advisories, government alerts (CISA/NCSC),
researcher writeups, NVD entries, KEV catalog, RSS/threat feeds.
Record canonical URLs. Store raw inputs (not committed) or references in the
draft front matter `sources:`.

## Stage 2 — Normalize & Extract
Extract structured data with no interpretation: actors, victims, sectors,
geographies, CVEs, malware families, infrastructure, timestamps, TTPs, hashes.
Anything not in the source is NOT a verified fact. This becomes the
`Verified Facts` section source-of-truth.

## Stage 3 — Enrich with CTI Frameworks
Map to MITRE ATT&CK (+ D3FEND, CAPEC, CWE). Cross-reference CVEs against
CVSS, EPSS, CISA KEV. Cluster infrastructure. Establish malware lineage.
All enrichment beyond the source is labeled ANALYST ASSESSMENT with a
confidence level and justification.

## Stage 4 — Draft
Load `prompts/master-prompt.md` + the matching task prompt
(`report-prompt.md`, `malware-prompt.md`, or `cve-prompt.md`). Produce the
full report into `reports/drafts/`. Emit detection artifacts to
`sigma/`, `yara/`, `kql/`, `suricata/`, `osquery/`. Persist per-entity
intelligence to `intelligence/{cves,malware,apt,ransomware,phishing}/`.

## Stage 5 — Quality Gates
Run `quality/quality-gate.md` checklist. Verify facts are supported,
assessments are labeled, confidence is justified, ATT&CK IDs are accurate,
IOCs are categorized and defanged, detection content is syntactically valid.
FAIL → return to Stage 4. PASS → move report to `reports/final/`.

## Stage 6 — Produce Output Variants
Derive audience-specific products from the final report using
`templates/{executive,soc,ir,hunting}/`:
- Executive brief (board / CISO)
- SOC detection brief (analysts)
- IR playbook (DFIR)
- Threat hunting playbook (hunt team)

## Stage 7 — SEO & Internal Linking
Apply `seo/` guidance: metadata, schema.org, OpenGraph, keyword clustering,
internal links to related CVEs/actors/families and to Sentinel APEX products.
Never sacrifice analyst quality for SEO.

## Stage 8 — Publish & Distribute
Publish to `reports/published/` and the blog; distribute via the Sentinel
APEX portal. Archive superseded versions to `archive/`. Record performance
in `analytics/`.

## Governance
Follows the CYBERDUDEBIVASH® SENTINEL APEX Governance Constitution
(`/CLAUDE.md`): Trust → Quality → Security → Revenue → Scalability →
Authority → Stability → Speed. No product ships until the quality gate and
God-Mode release gate pass. Never fabricate intelligence.
