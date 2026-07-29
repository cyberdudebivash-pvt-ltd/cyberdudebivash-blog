# GPEP v2 Phase 3 — Knowledge Graph Evolution

Companion to Phase 1's audit; this document covers the specific review
angles Phase 3 asks for that Phase 1 didn't already fully address, and
records the one expansion actually made this pass (per the instruction to
"expand the graph only where supported by validated intelligence").

## What changed this pass

Full detail in `platform/open-issues.md` Issue 17 and Phase 1's Knowledge
Graph / Malware Intelligence sections; summarized here:

1. **Corrected a real mis-attribution**: CVE-2024-27198 (TeamCity)
   → `actor:apt29` (was `actor:apt41`/`actor:cl0p`, mis-sourced), verified
   via independent research (FortiGuard citing Mandiant; a dedicated
   technical investigation), not recalled from memory.
2. **Populated the Malware node type for the first time**
   (`malware:bianlian`, `malware:jasmin`), sourced from SA-2026-0003's own
   citations. `stats.malware`: 0 → 2.
3. Both changes made through the existing `addNode`/`addEdge`/`saveGraph`
   functions (no new mechanism built), and covered by 8 new regression
   tests.

Net effect on live stats: `actors` 8 → 9, `malware` 0 → 2, `total_nodes`
9,678 → 9,681, `edges` 3,515 → 3,514 (net −1: removed 3 unsupported edges,
added 2 malware edges + 2 corrected actor edges).

## Entity relationships & confidence — reviewed, not changed

The confidence-attribution model (`computeActorAttribution`'s 4-signal
weighting: ioc_overlap 0.40, keyword_match 0.20, source_mentions 0.20,
campaign_overlap 0.20) is real, deterministic, and internally consistent —
verified by reading it in full while diagnosing Issue 17, not assumed
correct. It worked exactly as designed for the actors it evaluates; the
problem in Issue 17 was in `CVE_ACTOR_MAP`'s curated seed data (a
hand-maintained input to the model), not the confidence math itself. No
change made to the scoring mechanism.

## Correlation & campaign clustering — reviewed, one systemic risk surfaced

`campaign-engine.js`'s weighted clustering and the `co_occurs_with` edges
added across GEPMO v1/GPEP v1/GCDOM v1 are real and already tested against
live cardinality. **New finding this pass**: `actor:apt41`'s node alone
carries dozens of `exploits`/`executes` edges at a flat 0.85 confidence
against auto-aggregated content (2026-dated CVEs, `SENTINELAPEX-*`,
`REDDIT_CYBER-*`, `DARKREADING-*`, `THEHACKERNEWS-*`, `BLEEPINGCOMPUTER-*`
article IDs) — these are the automated pipeline's own keyword-match
output, not individually source-verified the way the 8 curated
`THREAT_ACTOR_DB` entries' `known_cves` are. Issue 17's fix corrected the
one instance that directly contradicted a certified report; it did not
audit this much larger volume. This is now the single largest known
unknown about the graph's accuracy and is escalated to the Innovation
Backlog (Phase 11) as a Strategic Investment, not resolved here.

## Threat actor intelligence — one gap closed, one left open

APT29 (Cozy Bear/BlueBravo) — one of the most significant, publicly
documented nation-state actors in existence — had **zero** curated entry in
`THREAT_ACTOR_DB` before this pass, despite `api/_lib/intelligence-hub.js`
already referencing "apt29" in an unrelated keyword-classification list.
Closed by this pass's fix, scoped narrowly to what the sourced research
actually supports (1 known CVE, not a full profile buildout). A broader
question — which other major, real actors (APT28, Lazarus, Sandworm, Scattered
Spider, etc., several already referenced as bare keywords elsewhere in the
codebase) are similarly "known to the codebase's classification logic but
absent from the curated graph" — is not answered here; flagged for Phase 11.

## Malware relationships — populated for the first time, narrowly

See "What changed" above. The relationship used (`associated_with`) is
deliberately the least specific available label in this file's own
documented vocabulary (`exploits | executes | uses | targets | linked_to |
associated_with | attributed_to | includes`) — SA-2026-0003 itself
documents the Jasmin chain at process-tree detail but does not claim the
CVE "executes" or "uses" the malware in a mechanistically precise sense;
"associated_with" avoids overclaiming a specific mechanism the source
material doesn't assert.

## Infrastructure / supply-chain / cloud / AI relationships — no first-class
representation exists; not built this pass

Checked the graph's actual node types (`ThreatActor | CVE | Campaign |
Malware | IOC`) and relationship vocabulary directly: none of
infrastructure, supply-chain, cloud, or AI-specific relationships exist as
distinct first-class concepts today. IOC nodes (IPs, domains, hashes) are
the closest existing proxy for "infrastructure," used generically across
all entity types rather than as a dedicated infrastructure-relationship
type. Building any of these four would be a real schema expansion, not a
data-population task like the Malware fix — and per this phase's own
instruction to expand "only where supported by validated intelligence,"
none is attempted without a concrete report or dataset that would populate
it. Recorded as a gap, not a recommendation to build speculatively.

## Recommendation

The single highest-priority follow-up from this phase is not a new
capability — it's verifying the accuracy of what the automated pipeline has
already written into the graph. A lightweight audit script (does each
`exploits`/`executes` edge's cited source URL text actually contain the
target CVE ID or a matching keyword) would be cheap to build against the
existing `sources` array every edge already carries, and would turn "we
found one instance by inspecting a node by hand" into "we know how many
instances exist."

---
*CyberDudeBivash® Sentinel APEX — GPEP v2 Phase 3 Knowledge Graph Evolution*
