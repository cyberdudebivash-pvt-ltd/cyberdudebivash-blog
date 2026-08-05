# Project TITAN Stage 9 Phase 1 — Blog Repository Addendum: Graph Discovery Findings

**Status:** Companion to `TITAN_STAGE9_PHASE1_GRAPH_DISCOVERY_REPORT.md` (intel-platform repo,
same commit round), which is the primary Stage 9 Phase 1 deliverable. This file exists so
anyone reading this repository finds the blog-relevant subset in the same place, per this
program's standing cross-repo addendum practice (`TITAN_STAGE7_BLOG_ADDENDUM.md`,
`TITAN_STAGE8_BLOG_ADDENDUM.md`).

## What this stage found on the blog side

Stage 9 Phase 1 is a graph-implementation discovery continuation (ADR-0010: Relationship Graph
Ownership). Most new findings this stage are intel-platform-side (two new same-repository
implementations, a 16-file long tail, and a CI-signal-integrity finding — see the primary
report). Two findings are blog-specific:

### 1. R2 (`knowledge_graph.py`) confirmed manual-only, not scheduled automation

ADR-0010's Existing Implementations table describes R2's consumer as "Report generation
pipeline," which reads as active, running automation. Direct tracing this stage found:

- `KnowledgeGraph()` is constructed only at `Sentinel-APEX/engine/cli.py:156` and in this
  repository's own test suite (`tests/test_pipeline.py`, `tests/test_knowledge_graph.py`,
  `tests/test_report_ingest.py`).
- `pipeline.py:61` does call `graph.ingest(doc, report_id)` as part of the automated
  `SourceDocument -> NormalizedDoc` path — but the only workflow referencing
  `sentinel_engine`/`cli.py`/`pipeline.py` at all, `.github/workflows/intelligence-engine-ci.yml`,
  runs only `pytest tests/` and a `py_compile` check on push. It does not invoke `cli.py`
  against real report data.
- This repository's actual high-frequency automated publishing
  (`.github/workflows/ai-security-intel.yml`, source of the frequent "SENTINEL APEX AI-SEC:
  pub=N" commits) does not reference `sentinel_engine` at all.
- `platform/open-issues.md` Issue 9 independently confirms this in the repository's own words:
  *"`KnowledgeGraph()` was never constructed anywhere except `cli.py run`/`score`."*
- `Sentinel-APEX/knowledge-graph.json` (the persisted graph output) is static at the same
  bulk-commit timestamp (`5bcccee`, 2026-08-03) as the rest of `api/_lib/`, consistent with no
  ongoing automated refresh since.

**None of this is new code or a defect** — `report_ingest.py` (already merged, tied to a
pre-TITAN initiative this repository calls GIKEP/GTIEP v1, see `platform/open-issues.md`
Issues 9 and 15) is real, correct, tested remediation for a real gap it identifies honestly in
its own docstring. The finding is narrower: **R2 is a correct, well-tested, manually-invoked
tool, not a live scheduled pipeline**, which is a more accurate characterization than ADR-0010's
current text implies. Logged as `TITAN_TECH_DEBT_REGISTER.md` DEBT-019 (intel-platform repo,
Low-Medium, documentation-accuracy item, not a production risk) and as part of ADR-0010
Revision 3.

### 2. One additional R5-cluster file found: `api/_lib/investigation-graph.js`

A repository-wide `**/*graph*` glob found `api/_lib/investigation-graph.js` — not individually
named by Stage 7 or 8. It is constructed with R5's `graphEngine`/`graphTraversal` (`GraphEngine`,
`graph-traversal.js`) as injected dependencies and is consumed by
`api/v1/workbench/investigations.js`. Stage 8 already confirmed `api/v1/workbench/*` returns
Vercel's platform-level `NOT_FOUND` as part of its R5 dead-code-cluster finding — this file
falls under that same confirmed-dormant umbrella. **Not a new live surface**, just one more file
belonging to an already-catalogued dormant cluster. Folded into R5's file list in the primary
report rather than given a separate ID.

## What did not change

R2, R4, and the full R5 cluster (`graph-engine.js`, `graph-traversal.js`,
`relationship-engine.js`, `correlation-engine.js`) are all present, unchanged, and last touched
by the same bulk commit (`5bcccee`, 2026-08-03) Stage 7/8 already characterized. No code changes
were made to any blog-repo graph implementation this stage — this addendum, like the primary
report, is discovery and documentation only, per Stage 9's own charter ("Stop implementation.
Document.").

## Where the rest of the picture lives

The full graph candidate matrix (R1-R7 plus the intel-platform long tail), the corrected
producer trace for R3, the FastAPI subsystem assessment, and the Phase 4 authorization
determination (**BLOCKED**) are intel-platform-side and documented in that repository's
`TITAN_STAGE9_PHASE1_GRAPH_DISCOVERY_REPORT.md` and `docs/adr/0010-relationship-graph-ownership.md`
(Revision 3). Nothing in this addendum changes that determination.
