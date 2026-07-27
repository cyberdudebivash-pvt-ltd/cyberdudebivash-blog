# ENTERPRISE INTELLIGENCE TASK ORCHESTRATOR (EITO)
## Version 3.0 — Execution Methodology

---

## What EITO is, and isn't

EIOS (`Sentinel-APEX/eios/`) governs **what** Sentinel APEX intelligence
looks like: report structure, evidence classification, object model,
detection maturity, confidence dimensions. EITO governs **how any task in
this repository gets executed** — CTI report or not. It applies equally to
"write a CVE report," "refactor the billing webhook," and "design next
quarter's pricing tiers."

EITO does not replace `CLAUDE.md`. It is more granular and more general at
once: granular because it breaks "do this carefully" into ten named,
checkable stages; general because — unlike EIOS, which is CTI-specific —
EITO's modes (see `modes.md`) cover platform architecture and product
strategy work on the blog itself, not only Sentinel-APEX content. Where
`CLAUDE.md` already mandates a mechanism, EITO points to it rather than
re-specifying it — see `lifecycle.md`'s mapping table.

## Placement

This lives at the repository root, a sibling to `CLAUDE.md` and
`Sentinel-APEX/`, because its scope is the whole repository, not one
subsystem. `Sentinel-APEX/eios/` stays where it is — CTI governance belongs
with the CTI engine it governs.

## Contents

| File | Covers |
|---|---|
| `lifecycle.md` | The 10-stage execution lifecycle (Mission Understanding → Continuous Improvement), mapped against the `CLAUDE.md` mechanisms and EIOS layers it reuses |
| `modes.md` | The 6 specialized operating modes and how to pick one |
| `decision-framework.md` | The pre-change decision checklist and the end-of-task deliverable contract |

## Why this document exists — a worked example, not a hypothetical

While building this, Stage 2 of `lifecycle.md` ("Repository Intelligence" —
check what already exists before proposing anything) was applied to EITO's
own predecessor task and immediately surfaced a real defect: a second,
independent CTI prompt architecture at `/prompts/` (repository root, outside
`Sentinel-APEX/`) that neither of the last two conversation turns had found,
created in the same automated commit as `Sentinel-APEX/prompts/` and never
reconciled with it. Its own README claimed to be loaded by
`ai-security-intel.yml` — a claim that a direct grep of the actual code
disproved. That directory has since been marked superseded and its one
genuinely new idea (hype-language detection) absorbed into
`Sentinel-APEX/engine/sentinel_engine/quality.py`.

That is the entire justification for Stage 2 existing as a named,
non-skippable stage rather than an assumed habit: it caught something a
habit alone had already missed once.

---
*CyberDudeBivash® Sentinel APEX — Enterprise Intelligence Task Orchestrator*
