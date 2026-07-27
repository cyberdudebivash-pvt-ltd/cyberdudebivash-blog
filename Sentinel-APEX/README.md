# CyberDudeBivash® Sentinel APEX — Threat Intelligence Division

A production-grade CTI publishing pipeline that transforms raw cybersecurity
source material into enterprise-grade intelligence products — with security,
evidence quality, and maintainability as first-class concerns.

This is the intelligence-production workspace for the Sentinel APEX ecosystem.
It operates under the governance defined in the repository-root `CLAUDE.md`
(Sovereign AI Executive Governance Constitution) and feeds
`blog.cyberdudebivash.in` (media & acquisition) and the Sentinel APEX portal
(`intel.cyberdudebivash.com`, product & delivery).

## Directory Layout

```
Sentinel-APEX/
├── eios/               Enterprise Intelligence Operating System (v2) — the
│                       14-layer governance architecture: mission, lifecycle,
│                       object model, quality gates, confidence model, version
│                       control, API schema. Start at eios/README.md.
├── engine/             Intelligence Engine (Phase 2) — tested Python package:
│                       normalization, IOC/ATT&CK extraction, NVD/EPSS/KEV
│                       enrichment, knowledge graph, executable quality gates,
│                       intelligence scoring/commercial tiering, multi-platform
│                       Detection Engine (Phase 3)
├── engine-node/        Node port of the Detection Engine, wired into the live
│                       generator (fetch-live-intel.js) to emit Sigma/KQL/
│                       Splunk/OSQuery + Suricata in every report
├── prompts/            System + task prompts (load master first)
│   ├── master-prompt.md    Core identity, structure, section-by-section
│   │                       drafting instructions (governed by eios/ for
│   │                       lifecycle/evidence/confidence/version control)
│   ├── report-prompt.md    General intelligence report task prompt
│   ├── malware-prompt.md   Malware family / sample report task prompt
│   └── cve-prompt.md       CVE / vulnerability report task prompt
├── reports/
│   ├── drafts/         Work in progress (pre quality gate)
│   ├── final/          Passed quality gate, ready to publish
│   └── published/      Live products
├── intelligence/       Reusable per-entity intelligence
│   ├── cves/  malware/  apt/  ransomware/  phishing/
├── templates/          Audience-specific output variants
│   ├── executive/  soc/  ir/  hunting/  board/  detection-engineer/
├── sigma/  yara/  kql/  suricata/  osquery/   Detection content library
├── images/             Report graphics / diagrams
├── scripts/            Automation helpers
├── automation/         Pipeline automation
├── seo/                SEO + internal-linking guidance
├── quality/            Quality gate checklist
├── pipeline/           End-to-end workflow definition
├── analytics/          Performance measurement
├── docs/               Documentation
└── archive/            Superseded versions
```

## How to Produce a Report

1. **Collect** source material and record canonical URLs.
2. **Normalize** — extract structured data (actors, CVEs, IOCs, TTPs). Nothing
   outside the source is a verified fact.
3. **Enrich** with MITRE ATT&CK, CVSS, EPSS, CISA KEV; label all analyst-added
   context with confidence.
4. **Draft** — load `prompts/master-prompt.md` + the matching task prompt, and
   write into `reports/drafts/`. Emit detection artifacts to the rule libraries.
5. **Quality gate** — run `quality/quality-gate.md`. Pass → move to
   `reports/final/`.
6. **Variants** — derive executive / SOC / IR / hunting products from
   `templates/`.
7. **SEO + interlink**, then **publish** to `reports/published/` and distribute.

Full detail: `pipeline/WORKFLOW.md`. Governance context for every step above
(evidence classification, object model, confidence dimensions, version
metadata, commercial scoring): `eios/README.md`.

## Core Principles

- **Never invent facts.** Verified fact, analyst assessment, and hypothesis are
  always distinguished, and every assessment carries a justified confidence
  level (VERY LOW → VERY HIGH).
- **Evidence quality first.** IOCs are categorized and defanged; detection
  content is syntactically valid; hashes match sources exactly.
- **More valuable than the source.** Every product must give a CISO, SOC
  analyst, threat hunter, and incident responder something they can act on.

---
*CyberDudeBivash® Sentinel APEX — AI-Governed Enterprise Threat Intelligence*
