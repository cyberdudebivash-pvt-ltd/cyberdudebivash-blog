# SENTINEL APEX — Campaign Delivery Integrity v1
## Production Certification

**Date:** 2026-08-24
**Branch:** `claude/p0-campaign-delivery-integrity-v1`
**Prior tranche:** PR #129 (Phase 0 audit — found this defect; did not fix it)

---

## 1. Executive Verdict

**RELEASE_CERTIFIED**

Fixed the root cause (destructive overwrite semantics in `campaign-engine.js`'s `saveCampaigns()`, called every ~30-minute ingestion cycle with only that cycle's freshly-clustered batch), added a second, independent defense-in-depth guard at the actual write chokepoint, and recovered the ~1,187 campaigns already lost from `campaigns.json` before this fix existed — reconstructed directly from the threat graph's own correctly-accumulated Campaign nodes, with no external source replayed and no field invented. Verified against real production data at every step, not synthetic fixtures alone.

## 2. Customer Impact

Before this fix, `GET /api/v1/intel/campaigns` — a paid, tier-gated endpoint — returned **0 campaigns** to every customer, on every request, regardless of plan. After this fix: 1,187 campaigns, growing correctly on every future ingestion cycle instead of resetting to whatever that cycle's batch happened to contain (frequently 0, given a single ~30-minute fetch rarely produces a fresh cluster of ≥2 related items or one item scoring ≥60).

## 3. Root Cause

Fresh reproduction on current `main` (not assumed from PR #129's numbers, which were 3 weeks old at time of measurement there and have since grown):

```
api/intel/campaigns.json:    0 campaigns    (generated 2026-08-24T11:52:20Z)
api/intel/threat-graph.json: 1,187 Campaign-type nodes (same timestamp)
```

`fetch-live-intel.js` calls `runEnrichmentPipeline(filteredItems)` once per ~30-min cycle, where `filteredItems` is only that cycle's freshly-fetched, signal-filtered batch (confirmed via `fetch-live-intel.js:3207-3227` — `correlateAndMerge(allBatches)` → `filterSignalFromNoise()`, no historical corpus involved). Inside the pipeline, `buildCampaigns(validItems)` clusters only that batch, and `saveCampaigns({ campaigns })` (`enrichment-pipeline.js:559`, pre-fix) persisted exactly that batch's output via a raw `fs.writeFileSync` — no load-then-merge. The threat graph never had this problem: `buildGraphFromIntel()` calls `loadGraph()` (loads the persisted graph) before `addNode()` upserts into it, so Campaign nodes correctly accumulate release over release. Only the *separate* `campaigns.json` artifact lacked that same load-then-upsert pattern.

Also checked and ruled out: `api/_lib/intel.js`'s `loadJSON`/`PATHS` (the actual customer-facing read path) is already correctly Cloudflare-Workers-safe (bundled `require()` on Workers, `fs.readFileSync` on Node/Vercel) — the defect was purely on the write side, not a second bug in how the data gets served.

## 4. Canonical Architecture

**Decision: the live threat graph (`api/_lib/threat-graph.js`'s persisted `Campaign` nodes) remains canonical for campaign existence and identity — unchanged from PR #129's finding.** `campaigns.json` is a *projection/persistence artifact* derived from campaign-clustering output, not an independent source of truth; its job is to accumulate correctly, not to originate data the graph doesn't already have. This fix makes it behave that way for the first time.

```
fetch-live-intel.js (28 sources, ~30-min cadence)
    ↓ buildCampaigns()          — clusters THIS cycle's batch only
    ↓ linkActorsToCampaignsGraph() — upserts Campaign nodes into the
    │                                 PERSISTED graph (already correct)
    ↓ mergeCampaigns(existing, thisCycle) — NEW: upserts into the
    │                                        PERSISTED campaigns.json
    ↓ saveCampaigns()           — NEW: catastrophic-drop guard at the
    │                                  single write chokepoint
    ↓
api/intel/campaigns.json (now correctly accumulates)
    ↓ api/_lib/intel.js:getCampaigns()
    ↓
GET /api/v1/intel/campaigns (customer-facing, paid tier)
```

## 5. Before / After State

| | Before | After |
|---|---|---|
| `campaigns.json` campaign count | 0 | 1,187 |
| Graph Campaign node count | 1,187 | 1,187 (unchanged) |
| `campaigns.json` IDs ⊆ graph IDs | N/A (empty) | **True** |
| graph IDs ⊆ `campaigns.json` IDs | False | **True** |
| Exact ID-set equality (graph ↔ API) | False | **True** — verified directly against the real files after this fix |
| Behavior on the *next* ingestion cycle | Overwrites to just that cycle's batch (often 0) | Merges into the existing 1,187+, monotonically accumulating |

## 6. Campaign Identity

Unchanged — `buildCampaignId()` (`campaign-engine.js`, pre-existing) already produces deterministic IDs (CVE-based, or a content hash of the cluster's first 3 sorted item IDs), which is exactly what safe upsert-by-ID merging requires. No new identity scheme was needed; this was verified, not assumed, before building the merge on top of it.

## 7. Merge Semantics

Implemented in `mergeCampaign()`/`mergeCampaigns()` (`campaign-engine.js`):

| Field | Semantics |
|---|---|
| `related_intel_ids` / `related_intel` | Union by item `id` (incoming wins on a rare id collision) |
| `shared_iocs` | Union, deduplicated, capped at 25 (matches `buildCampaigns()`'s own cap) |
| `shared_cves` | Union, deduplicated |
| `threat_actors` | Union by actor `id`, keeping whichever observation has higher confidence |
| `first_seen` / `last_seen` | Recomputed as min/max over the full merged `related_intel[]` dates — correct regardless of arrival order (see §13) |
| `max_priority_score`, `confidence` | Max of existing vs. incoming — never decreases |
| `has_kev` / `has_ransomware` / `has_exploited` | OR — never downgraded |
| `severity` | Recomputed from the merged flags above via `severityFromFlags()` (a scalar-flag variant of the existing `campaignSeverity()`, since the persisted `related_intel[]` projection doesn't carry every field the original raw-item-shaped function expects — verified by tracing the exact field mismatch, not assumed) |
| `campaign_id`, `name`, `clustering_model` | Stable — never rewritten by a later merge, so a campaign's identity and displayed name never shift under a customer who referenced it |
| `reasoning[]` | Union, deduplicated, capped at 12; a new entry is appended noting the merge event when new items were actually gained |

## 8. Evidence Preservation

Every merge is a set union or a min/max over already-evidence-backed fields — nothing is dropped, nothing is invented. The one-time historical backfill (§9) is held to a stricter standard: every field is either a graph node/edge attribute set at original ingestion time or a straightforward aggregate over such attributes; `clustering_model` is explicitly tagged `graph_reconstruction_v1` (never `weighted_v2`) so a reconstructed campaign can never be mistaken for one produced by the original live clustering run, and the original clustering `reasoning` string (persisted on the graph node) is preserved in the reconstructed object's `reasoning[]` alongside a new note disclosing that it was reconstructed, not re-clustered.

## 9. Historical Backfill (executed this round)

`reconstructCampaignsFromGraph(graph)` (`campaign-engine.js`) derives full campaign objects from the graph's `Campaign` nodes and their edges (`includes` → related CVE/Intel, `executes` ← attributing actors, a 2-hop `includes`→`linked_to` → IOC traversal for `shared_iocs`). Run via `scripts/backfill-campaigns-from-graph.js`, defaulting to dry-run; executed with `--write` after dry-run evidence was clean:

```
Graph Campaign nodes:        1187
Reconstructed from graph:    1187
Currently in campaigns.json: 0
New (not already present):   1187
Result after merge:          1187
clustering_model breakdown:  {"graph_reconstruction_v1":1187}
```

Quality checks against the real production graph (not a synthetic fixture): 0 campaigns with `item_count === 0` (no orphan/broken reconstructions), 1,187 unique IDs (no duplicates), all 1,187 have `first_seen` set, severity distribution is unskewed (46 CRITICAL / 461 HIGH / 608 MEDIUM / 72 LOW), and a spot-checked sample (`campaign:cve-2023-27351`, "PaperCut Exploitation Wave") cross-verified correctly against `threat-graph.js`'s own hardcoded `CVE_ACTOR_MAP` ground truth (LockBit + Cl0p, exactly as that map declares). Known, honestly-disclosed fidelity gap: reconstructed `shared_iocs` can undercount relative to what the *original* live clustering run would have captured, because the graph's own `includes`-edge IOC linkage was already capped at ingestion time (`buildGraphFromIntel()` keeps at most 5 IOC nodes per intel item) — this is a real, disclosed limitation of the reconstruction, not a defect in the reconstruction logic itself.

## 10. Freshness

Not changed this round beyond what accumulation now correctly reflects. `campaigns.json`'s `generated` timestamp updates every write, same as before. No new freshness SLO claimed — the existing ~30-minute ingestion cadence is unchanged, and this fix does not alter it.

## 11. Catastrophic-Drop Protection

`saveCampaigns()` now reads the *current on-disk* campaign count immediately before any write and refuses to persist a smaller count than what's already there (when the existing count is ≥5, avoiding false positives on legitimately-small/bootstrap state), unless the caller explicitly passes `{ allowDrop: true }`. This is deliberately placed at the single write chokepoint, not just in the one caller this round changed — so a future caller that bypasses `mergeCampaigns()` and calls `saveCampaigns()` with a raw batch again (reintroducing the original bug) gets caught immediately rather than silently repeating the 1,187→0 incident. Verified directly: a test simulates the exact production incident (1,187 existing → an empty write) and confirms it's blocked, with the existing file left untouched.

## 12. Cloudflare Runtime

No Cloudflare-specific code changed. `campaigns.json` is bundled at Worker build time on that runtime (`api/_lib/intel.js`'s own documented tradeoff — Workers only sees a new campaigns.json on redeploy, not on every commit the way Vercel's `fs.readFileSync` does) — this fix corrects the *data*, which benefits both runtimes identically once each next reads/rebundles it.

## 13. Security

No new attack surface. `mergeCampaigns()`/`reconstructCampaignsFromGraph()` are pure functions with no I/O; `saveCampaigns()`'s only new behavior is a read-before-write count check on a path that was already trusted. Adversarial input handling verified by test: malformed campaigns (missing `campaign_id`) are skipped rather than crashing the merge; `null`/`undefined` array fields on either side of a merge don't crash; duplicate `campaign_id`s within a single incoming batch merge into one rather than creating two.

## 14. API Contract

No route or response-shape change. `GET /api/v1/intel/campaigns` and `GET /api/v1/intel/campaign/{id}` are unchanged at the contract level — they now simply have real data to serve. `runEnrichmentPipeline()`'s return shape gained new `stats` fields (`campaigns_created`, `campaigns_updated`, `campaigns_total`, `campaigns_save_blocked`); the pre-existing `stats.campaigns` field is deliberately left meaning "this cycle's batch count" for backward compatibility, since `fetch-live-intel.js:3229` already logs it under that meaning.

## 15. Observability

`enrichment-pipeline.js`'s own `log()` now reports, every cycle: how many campaigns this cycle's batch produced, how many were genuinely new vs. updates to existing campaigns, and the total accumulated count — plus an explicit log line if a save was blocked or failed. This reuses the pipeline's existing `console.log`-based convention rather than introducing a new metrics system, consistent with how the rest of this pipeline is already instrumented.

## 16. Performance

`reconstructCampaignsFromGraph()` processed the full real 1,187-campaign, 11,959-node, 3,773-edge graph in 708ms in this environment — a one-time cost for the backfill, not a per-request cost. `mergeCampaigns()` on the live per-cycle batch size (typically tens of campaigns, not 1,187) is negligible; not separately benchmarked given the trivial input size involved in normal operation.

## 17. Test Evidence

```
$ node --test tests-js/*.test.js
# tests 155  (123 pre-existing + 25 merge/guard tests + 7 reconstruction tests)
# pass 155

$ node --test workers/lib/*.test.js
# tests 116
# pass 116

$ npx jest --silent
Test Suites: 1 skipped, 50 passed, 50 of 51 total
Tests:       60 skipped, 1797 passed, 1857 total

$ npx tsc --noEmit
(zero output — zero type errors)
```

Real-file safety was explicitly verified, not assumed: `saveCampaigns()`'s guard tests mock `fs` (Node's built-in `node:test` mock API) rather than touching the real `api/intel/campaigns.json`; an md5 checksum of that file was confirmed unchanged before and after running the full mocked-`fs` test suite.

## 18. Adversarial QA

Covered by the new test suite: malformed campaign objects (missing `campaign_id`) in either merge input; `null`/`undefined` array fields; duplicate `campaign_id`s within one incoming batch; a Campaign graph node with zero `includes` edges (reconstructs as zero-item rather than crashing); replay of the identical batch twice (idempotent, no unbounded growth); an out-of-order replay where an *older* observation arrives in a *later* cycle (`first_seen`/`last_seen` still resolve correctly because they're recomputed as min/max over the full set, not by trusting arrival order); the exact production incident itself (1,187 existing → an empty write, reproduced and confirmed blocked).

## 19. Live Verification

No live deployment access from this sandbox (same limitation as every prior round). Verified instead against the real, current production data files committed in this repository: `api/intel/threat-graph.json` and `api/intel/campaigns.json`, both regenerated by the actual live ~30-minute bot cadence (confirmed via their `generated` timestamps, ~22 minutes before this check). The graph↔API ID-set consistency invariant (`api campaign IDs == graph campaign IDs`) was checked directly against these real files after the fix and confirmed exactly equal.

## 20. Known Limitations

- Reconstructed campaigns' `shared_iocs` can undercount relative to a live clustering run's original output, for the reason disclosed in §9 — a real, bounded, honestly-labeled gap, not silently hidden.
- No live Cloudflare/Vercel deployment verification (sandbox limitation, consistent with every prior round).
- The catastrophic-drop guard's floor (5) and its "any decrease at all" threshold are a deliberate, documented choice, not empirically tuned against long-running production telemetry (none was available) — worth revisiting if it ever produces a false-positive block on a legitimate small edge case.
- This round did not build a dedicated freshness/observability dashboard or alerting integration (Phase 30/31 of the mandate) — the existing `console.log` convention was extended, not replaced; a dedicated alerting layer remains a documented gap, same status as before this round (`platform/capabilities.md` already tracks this under Observability/Monitoring).

## 21. Rollback

Each commit in this round is independent and revertible:
- The `mergeCampaigns()`/`saveCampaigns()` guard code change (`api/_lib/campaign-engine.js`, `api/_lib/enrichment-pipeline.js`) can be reverted on its own — the next ingestion cycle would resume the pre-fix overwrite behavior, but no data already accumulated would be lost by the revert itself.
- The one-time backfill (`api/intel/campaigns.json`'s data change) can be reverted independently via `git revert` on that specific commit, restoring the file to its pre-backfill (empty) state, without affecting the code fix.

---
*Certified: campaign delivery integrity v1 — RELEASE_CERTIFIED.*
