# EIPS — OPEN ARCHITECTURAL ISSUES

Findings surfaced by applying `eito/lifecycle.md` Stage 2 (Repository
Intelligence) honestly. Not fixes — this session already made two
unilateral consolidation calls (`Sentinel-APEX/prompts/` vs. root
`/prompts/`, both inert documentation) and should not make a third on live
revenue-bearing code without explicit sign-off. That is the difference
between this entry and the two prior ones.

## Issue 1 — Two independent knowledge-graph / scoring engines

**Found while researching EIPS Layer 2/3.**

| | `Sentinel-APEX/engine/sentinel_engine/` | `api/_lib/` |
|---|---|---|
| Graph | `knowledge_graph.py` — entities + relation triples, JSON-persisted | `threat-graph.js` (656 lines) — "Threat Actor Graph Engine v2.0," CVE→Actor→Campaign→IOC, 4-factor confidence attribution formula |
| Scoring | `scoring.py` — 9 weighted dimensions, 0–100, deterministic, FREE/PRO/ENTERPRISE tiering | `threat-scorer.js` (303 lines) — "AI Threat Scoring Engine v2.0," 7 weighted normalized features, 0–100, explicit `reasoning[]` per score |
| Runtime status | Offline tooling — no CI wires it automatically | **Live** — `threat-scorer.js` is required by `api/_lib/intel.js` (a live endpoint) and `api/_lib/enrichment-pipeline.js` |
| Cross-references | Zero — confirmed by grep in both directions | Zero |

Both engines independently arrived at the same design philosophy
(explicit weighted formula, auditable, no black-box scoring) without
sharing a line of code. Neither is wrong on its own terms; the risk is
drift — a scoring change made in one will never be reflected in the other,
and a customer asking "why did this get an Enterprise-tier score in one
place and a different number in the api response" has no single answer to
give them.

**Why this wasn't touched**: `threat-scorer.js` sits behind a live, paid API
endpoint. Consolidating it is a functional-behavior change to revenue
infrastructure, not a documentation edit — a fundamentally different risk
class from the `/prompts/` cleanup. It needs an explicit decision on which
formula is canonical (or whether both are intentionally kept for different
audiences — offline analyst tooling vs. live API scoring at different
latency/data-freshness budgets, which would be a legitimate reason to keep
both, unlike the `/prompts/` case where neither was live).

**Recommendation, not action**: decide canonical ownership, then either (a)
have the offline engine call the live scorer's logic (or vice versa) via a
shared formula definition, or (b) explicitly document why two are
intentional and keep this table as the record of that decision.

## Issue 2 — `industry-intelligence.md` has no home

Noted in `extensibility.md` — the one idea from the deprecated `/prompts/`
directory with no canonical replacement. Low stakes (nothing depends on it
today); listed here so it doesn't get silently lost.

---
*CyberDudeBivash® Sentinel APEX — Open Architectural Issues*
