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

## Issue 3 — Three real defects found producing the platform's first report (SA-2026-0001)

Found by actually running real source material (a well-corroborated, multi-source
CVE-2026-50522 writeup) through the pipeline end to end for the first time —
exactly the kind of gap that stays invisible until something real goes
through the machinery.

1. **`ioc_extractor.py` treats citation URLs as indicators.** `cli.py run`
   against source text containing a "Sources:" list extracted the cited
   news-article URLs themselves (thehackernews.com, helpnetsecurity.com,
   securityweek.com) as IOCs, then generated Suricata rules flagging
   traffic to those legitimate outlets as `classtype:trojan-activity`.
   Reproducible: feed any source document with a references/sources
   section through `cli.py run`. Needs a citation-vs-indicator
   distinction — e.g. excluding URLs that appear after a "Sources:"/
   "References:" marker, or requiring an explicit malicious-context cue —
   before this engine's raw IOC/Suricata output can be trusted unreviewed.

2. **`attack_mapper.py`'s keyword matching produces confident wrong
   mappings.** The same run mapped **T1486 (Data Encrypted for Impact)** at
   a stated HIGH CONFIDENCE from a sentence about attribution being
   unknown — no ransomware/encryption content existed anywhere in the
   source. A keyword-proximity false match presented with the same
   confidence label as a correct match is a real trust problem: nothing in
   the current output distinguishes "matched cleanly" from "matched a
   coincidental keyword."

3. **`scoring.py`'s dimensions measure auto-extractable structure, not
   analyst-report quality.** SA-2026-0001, hand-authored, quality-gate
   PASSED, independently-verified Sigma rule, honestly reports zero public
   IOCs (because none exist yet for this campaign, not because none were
   sought) — scored 43/100, BLOCKED tier. `detection_value`/`soc_value`/
   `dfir_value` are computed from `PipelineResult.detections[]`/`iocs[]`,
   populated by the automated extractor, not from a hand-embedded,
   independently-validated Sigma rule in report prose. A correct, honest,
   gate-passing report on a fresh vulnerability with no public IOCs yet
   will structurally score low under the current model. This is either
   evidence the scoring model needs an analyst-authored-content path, or
   a deliberate signal that fresh-vulnerability bulletins with no IOCs
   aren't meant to be premium-tier by design — which one is true is a
   product decision, not an engineering one, and is not resolved here.

None of these were fixed in this pass — (1) and (2) are core engine files
(`ioc_extractor.py`, `attack_mapper.py`) other future reports depend on, and
(3) is a product-tiering policy question. All three are flagged, not
patched, pending an explicit decision on scope and priority.

---
*CyberDudeBivash® Sentinel APEX — Open Architectural Issues*
