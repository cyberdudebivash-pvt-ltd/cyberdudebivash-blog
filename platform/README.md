# SENTINEL APEX ENTERPRISE PLATFORM SPECIFICATION (EIPS)
## Version 4.0 — Governance Hierarchy Index

---

## What this is, honestly

EIPS was requested as a 14-layer platform constitution sitting above EIOS
and EITO. Before writing 14 files, Stage 2 of `eito/lifecycle.md`
("Repository Intelligence — check what already exists") was applied to this
request itself. Result: **8 of the 14 layers already exist**, correctly, in
`CLAUDE.md`, `Sentinel-APEX/eios/`, `eito/`, or
`BUSINESS-TRANSFORMATION-ROADMAP-2026.md`. Restating them here would create
exactly the single-source-of-truth problem this whole document family exists
to prevent — the same failure mode found and fixed twice already this
session (`Sentinel-APEX/prompts/` vs. root `/prompts/`).

So `platform/` is an **index and the genuinely new material only** — not a
14-file restatement. If you specifically want the full literal restatement
despite the duplication (e.g. for an external-facing document with a
different audience than this codebase), say so and it can be produced
separately; this version optimizes for the codebase staying internally
consistent.

## Governance hierarchy

```
CLAUDE.md                          Repository-wide constitution (all code, all content)
│
├── EIPS (platform/)               Platform-wide index — this document
│   │
│   ├── EIOS (Sentinel-APEX/eios/) CTI intelligence governance — what to produce
│   │
│   └── EITO (eito/)               Task execution methodology — how to execute
│
├── Report templates               Sentinel-APEX/templates/
├── Quality gates                  Sentinel-APEX/quality/, engine/sentinel_engine/quality.py
├── Detection standards            EIOS Layer 6
├── Knowledge models               EIOS Layer 3 (+ this doc's two additions)
├── Automation pipelines           platform/automation.md
├── APIs                           EIOS Layer 12 (schema only — see Scope Boundary)
├── Documentation                  Sentinel-APEX/docs/, this directory
└── Release governance             EIOS Layer 14, eito/lifecycle.md Stage 9
```

## The 14-layer mapping

| # | EIPS layer as requested | Where it actually lives |
|---|---|---|
| 1 | Platform Constitution | `CLAUDE.md` Section 0 (Engineering Decision Order) + EIOS Layer 1 — already exists, not restated |
| 2 | Canonical Knowledge Model | EIOS Layer 3 — already exists; two entities it lacked (`Organization`, `Sector`) added there directly rather than forking a second knowledge-model doc |
| 3 | Capability Map | **New** — `platform/capabilities.md` |
| 4 | AI Agent Architecture | `eito/modes.md` — already exists (CTI/Detection Engineering/DFIR/Executive/Platform Architecture/Product Strategy modes are this layer's agents, framed as lenses rather than personas) |
| 5 | Workflow Engine | `eito/lifecycle.md` — already exists (10 stages) |
| 6 | Validation Framework | EIOS Layer 4 (intelligence/technical/detection validation) + `eito/lifecycle.md` Stage 7 (engineering validation) — already exists |
| 7 | Release Governance | EIOS Layer 14 + `eito/lifecycle.md` Stage 9 — already exists |
| 8 | Commercial Product Model | EIOS Layer 10 (scoring/tiering mechanism) + `BUSINESS-TRANSFORMATION-ROADMAP-2026.md` (actual product tiers, revenue streams, pricing) — already exists and is more grounded than a fresh hypothetical tier list would be |
| 9 | Platform Quality Metrics | **New** — `platform/quality-metrics.md` (genuinely different in kind: continuous KPIs, not per-report pass/fail gates) |
| 10 | Extensibility Framework | **New** — `platform/extensibility.md` |
| 11 | Enterprise Automation | **New** — `platform/automation.md` |
| 12 | Customer Experience | **Out of scope** — see below |
| 13 | Operations | **Out of scope** — see below |
| 14 | Strategic Roadmap | `BUSINESS-TRANSFORMATION-ROADMAP-2026.md` — already exists, detailed, and grounded in a verified current-state audit; do not fork a second roadmap |

## Scope boundary — why Layers 12 and 13 are not here

`CLAUDE.md` draws an explicit line: `intel.cyberdudebivash.com` is the
Sentinel APEX product/delivery portal (dashboards, customer-facing API
portal); this repository (`blog.cyberdudebivash.in`) is the media/acquisition
engine and feeds it. **This repository contains no code for that portal.**
Writing a Customer Experience specification (web portal, dashboards,
saved-intelligence UX, role-based views) or an Operations specification
(backup, disaster recovery, incident response for that system) from here
would not be documentation — it would be invented detail about a system
never inspected, which is the exact failure mode (fabricated technical
claims) this entire document family exists to prevent Sentinel APEX from
committing about *threats*. It should not commit it about itself.

If those specifications are needed, they belong in that portal's own
repository, written with visibility into its actual code.

## An unresolved finding, not a fix

While researching Layer 2/3, a third instance of the duplication pattern
already found twice this session turned up — this one in **live production
code**, not documentation, and therefore not something this pass resolved
unilaterally. See `platform/open-issues.md`.

---
*CyberDudeBivash® Sentinel APEX — Enterprise Platform Specification*
