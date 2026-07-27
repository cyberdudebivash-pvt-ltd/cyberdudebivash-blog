# SENTINEL APEX — ENTERPRISE INTELLIGENCE OPERATING SYSTEM (EIOS)
## Version 2.0 — Modular Governance Architecture

---

## What EIOS is

EIOS is the governance architecture for how Sentinel APEX intelligence is
created, validated, versioned, and maintained. It is the successor to the
**v1 monolithic prompt system** (`Sentinel-APEX/prompts/master-prompt.md` +
its task prompts + `quality/quality-gate.md`), which defined *what* a report
should contain. EIOS v2 additionally defines *how* intelligence is produced,
governed, and kept alive over time — split into 14 layered components
instead of one continuously-growing document.

**v1 is not deleted.** Per the repository's Deprecation Instead of Deletion
policy, every v1 file remains authoritative and functional. Each now carries
a banner pointing to its EIOS v2 equivalent. New reports should be produced
against EIOS v2; reports already in `reports/final/` or `reports/published/`
under the v1 contract remain valid as published — they are not retroactively
relabeled.

## Relationship to CLAUDE.md

`CLAUDE.md` (repository root) is the repo-wide engineering and business
governance constitution — it governs *all* code and content on this
platform, including the blog. EIOS is a specialization of that constitution
for one domain: CTI report production. Where the two overlap (evidence
discipline, no-fabrication, production stability), EIOS defers to CLAUDE.md
as the higher authority. EIOS adds the CTI-specific machinery CLAUDE.md does
not: report lifecycle, evidence taxonomy, object model, detection maturity,
confidence dimensions, version-control metadata.

## The 14 layers

| Layer | File | Status |
|---|---|---|
| 1 — Executive Mission | `layer-01-executive-mission.md` | New (distilled from v1) |
| 2 — Intelligence Governance | `layer-02-intelligence-governance.md` | New, reconciled with `pipeline/WORKFLOW.md` |
| 3 — Intelligence Object Model | `layer-03-intelligence-object-model.md` | Partially implemented — see file for what's coded vs. specified |
| 4 — Production Quality Gates | `layer-04-quality-gates.md` | Implemented — extends `engine/sentinel_engine/quality.py` |
| 5 — Multi-Audience Output | `layer-05-multi-audience-output.md` | Implemented — see `templates/` |
| 6 — Detection Engineering Standards | `layer-06-detection-engineering-standards.md` | New, extends v1's platform coverage |
| 7 — Intelligence Confidence Model | `layer-07-confidence-model.md` | New — supersedes v1's dimension list |
| 8 — Report Version Control | `layer-08-report-version-control.md` | New — extends front matter |
| 9 — Intelligence Relationships | `layer-09-intelligence-relationships.md` | Implemented — see `engine/sentinel_engine/knowledge_graph.py` |
| 10 — Commercial Readiness | `layer-10-commercial-readiness.md` | Reconciled with `quality/quality-gate.md` §6–8 |
| 11 — Continuous Intelligence | `layer-11-continuous-intelligence.md` | New, extends v1 report sections 56–57 |
| 12 — Enterprise API Readiness | `layer-12-enterprise-api-readiness.md` | Spec only — no changes to the live `api/v1/` product surface |
| 13 — Editorial Style Guide | `layer-13-editorial-style-guide.md` | Reconciled with v1 WRITING STYLE + `entities.py` lexicon |
| 14 — Enterprise Release Pipeline | `layer-14-release-pipeline.md` | Reconciled with `pipeline/WORKFLOW.md` |

Each layer file states, up front, what already exists in code versus what is
newly specified. Nothing in EIOS claims a capability is "production
validated" unless a test or a live code path backs it — this platform does
not publish unverifiable claims about itself any more than it does about a
threat actor.

## How to use EIOS when producing a report

1. Start from Layer 1 (mission) and Layer 2 (lifecycle + evidence
   classification) — these apply to every report, unconditionally.
2. Load the v1 task prompt matching the report's subject
   (`prompts/report-prompt.md`, `cve-prompt.md`, or `malware-prompt.md`) —
   EIOS does not replace the section-by-section drafting instructions, it
   governs the process and metadata around them.
3. Tag the report's structural type using Layer 3's object model and Layer 8's
   version-control metadata.
4. Produce detection content per Layer 6's maturity model.
5. Run Layer 4's quality gates (`cli.py gate <report>`) before promotion.
6. Derive audience variants per Layer 5.
7. Move through Layer 14's release pipeline to publication.
8. Layer 11 governs what happens after publication — a report is not "done"
   at publish time.

## Versioning this document

This is EIOS **v2.0.0**. Changes to any layer's file should be recorded in
that file's own changelog note (see Layer 8's version-control convention,
which EIOS applies to itself). There is no forced sunset date for v1 — dual-run
until a repository owner sets one; silent removal is prohibited under
`CLAUDE.md`.

---
*CyberDudeBivash® Sentinel APEX — Enterprise Intelligence Operating System*
