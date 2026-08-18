# SENTINEL APEX v5.0 — Freshness Watchdog Failure: Root Cause & Fix

**Date:** 2026-08-18
**Trigger:** `freshness-check.yml` CRITICAL failure — "Pipeline Down (CRITICAL - AUTO-RECOVERY) — Latest items 379 minutes old — pipeline stalled." (run `32139103387`, commit `14d2aca`, exit code 2).
**Scope:** `fetch-live-intel.js` only (the SENTINEL APEX v5.0 Node ingestion engine feeding `blog.cyberdudebivash.in`). This is a separate pipeline from the Python/Blogger syndication path fixed in PR #91 — different codebase, different workflow, different failure mode.

---

## Proof Before Change

| Field | Entry |
|---|---|
| **Objective** | Stop the pipeline from perpetually stalling (zero new items ingested for 6+ hours despite the workflow itself running "successfully" every ~15–30 min) by closing the specific mechanism that causes it. |
| **Affected files** | `fetch-live-intel.js` (production fix); `tests-js/watermark-lookback-floor.test.js` (new regression tests). |
| **Existing component reused** | The exact fix shape already shipped for `fetchNVD()` (`nvdMinLookbackHours`, v5.1, "prevents 5-min window starvation") — generalized into one shared helper, `watermarkStart()`, rather than re-derived per call site. |
| **Evidence modification is required** | Real production job log (run `32139132783`, job `95717358499`): `📡 Sources active : 1/28`, with a uniform "fetched N, filtered to 0" pattern across all 26 RSS/API-incremental sources for 14+ consecutive runs (~6h20m). Real `live-intel.json`: newest item `_addedAt` frozen at `06:32:44Z` while `metadata.generated` kept advancing every run. Real, live-fetched BleepingComputer RSS feed: clean, standard, `Date`-parseable `pubDate` values, but a genuine ~5h43m publishing gap (07:14→12:57 UTC) — proving the pipeline's own polling architecture, not a parsing bug or a coincidental industry-wide news drought, is what turned one source's ordinary quiet period into a full-pipeline stall. |
| **Risk classification** | LOW. Single file, additive helper + 7 one-line call-site substitutions, no behavior change to already-correct code (`fetchNVD` untouched), no schema/route/API changes. |
| **Expected regression risk** | None identified. Widening the lookback window can only *include* items a healthy run would already include; `isPublished()` (TTL-keyed dedup) and `writeLiveIntel()`'s `isNewToFeed` check (keyed against what's already in the `live-intel.json` rolling window) both already make re-seeing an already-known item a safe no-op — verified by reading both call paths directly, not assumed. |
| **Rollback plan** | Revert this commit. No state migration, no schema change — `intel-state.json`'s shape is unchanged. |

## Root cause

Every incremental-poll source computes its next fetch window as:

```js
const afterDate = lastFetch ? new Date(lastFetch) : new Date(Date.now() - <fallback>);
```

`setSourceLastFetch()` ratchets `lastFetch` forward to `Date.now()` on **every successful fetch**, independent of whether any items were found. This means the window has **zero overlap between polls** — each one starts exactly where the last one ended. That's fine as long as every source posts more often than the poll interval. It fails the moment any source has a real quiet period longer than that interval: the watermark keeps chasing "now," and once it passes the source's actual last item, nothing that source publishes will be picked up until it posts *again* — the pipeline has no way to look back and self-heal.

This is not hypothetical: `fetchNVD()` already carries a fix for this exact defect (`nvdMinLookbackHours: 4`, added in v5.1, whose own comment says "prevents 5-min window starvation"). That fix was never generalized to the seven other `lastFetch`-driven fetch paths, which retained the original unprotected pattern:

- `fetchCISAKev`, `fetchCISAAlerts`, `fetchGitHubAdvisories`
- `fetchRSS` — the shared helper behind 20+ named sources (BleepingComputer, The Hacker News, DarkReading, SecurityWeek, Talos, Unit42, CrowdStrike, SentinelOne, Rapid7, Microsoft Security, Reddit, SANS ISC, Krebs, etc.)
- `fetchExploitDB`, `fetchPacketStorm`, `fetchFullDisclosure`

With several of those sources *also* independently broken that day (NVD API 404s, PacketStorm's RSS domain resolving to an unrelated TLS certificate, Talos/Rapid7/CERT-EU feed URLs 404ing, Reddit 429s, abuse.ch 401s — all genuine external failures, not this bug), the pool of sources that could self-correct on any given run shrank further, making a full-pipeline stall much more likely to manifest and persist.

## The fix

Added one pure helper, mirroring `fetchNVD()`'s already-proven logic exactly:

```js
function watermarkStart(lastFetch, minLookbackHours, fallbackMs) {
  const minStart = new Date(Date.now() - minLookbackHours * 3600000);
  const rawStart = lastFetch ? new Date(lastFetch) : new Date(Date.now() - fallbackMs);
  return rawStart < minStart ? rawStart : minStart;
}
```

Applied at all seven unprotected call sites with a new `CFG.rssMinLookbackHours = 4` (same value as the proven NVD floor). Each call site's own cold-start fallback (7 days for CISA/GitHub/RSS, 2 days for ExploitDB/PacketStorm/FullDisclosure) is preserved unchanged — only the steady-state floor is added. `fetchNVD()` itself was not touched.

## What this does not fix (named, not silently dropped)

- **NVD API 404s, PacketStorm's TLS-mismatched domain, Talos/Rapid7/CERT-EU 404s** — genuine external breakage (moved/dead feed URLs, an apparently expired/repurposed PacketStorm RSS domain). Not a code defect in this pipeline; needs its own source-by-source URL audit.
- **"QUALITY GATE REJECTED: ... Missing/invalid: references / link"** (0/15 candidates passed in the same run) — confirmed, by reading `writeLiveIntel()`'s call site, to run *after* `live-intel.json` is already written from the full `enrichedItems` set, so it gates blog-post/product-package generation (`posts/*.html`, `api/intel/products/*.json`), not `freshness-check.yml`'s `live-intel.json`/`_addedAt` metric. Real, but a separate defect from the one this fix addresses.
- **Two pre-existing, unrelated CI gaps found while running the full suite** (both reproduced identically on a clean `origin/main` checkout, confirmed via `git stash` + re-run before this fix was applied): `Sentinel-APEX/engine`'s `test_certify_real_end_to_end_with_the_actual_node_rendering_check` (environment-only — `certify-rendering.js` reports "Not Applicable" rather than "Pass," already noted as a known gap in PR #91's own test plan), and `scripts/assure.sh`'s `--renderer` stage, whose target directory `Sentinel-APEX/renderer/tests/` does not exist in this checkout at all.

## Test plan

- 5 new regression tests (`tests-js/watermark-lookback-floor.test.js`, `node --test`): floor wins over a too-recent watermark; an already-wide watermark is never narrowed; cold-start fallback wins when wider than the floor; cold-start is still floored when the fallback is narrower; and a direct before/after reproduction of the production scenario (a real quiet-period item excluded by the old bare watermark, included by `watermarkStart()`).
- Full `tests-js` suite: 106/106 pass (101 pre-existing + 5 new), zero regressions.
- `Sentinel-APEX/engine-node` suite: 106/106 pass.
- `Sentinel-APEX/engine` (Python) suite: 892/893 pass — the one failure confirmed pre-existing (see above).
- `node --check fetch-live-intel.js`: clean.

## Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `fetchNVD()`'s min-lookback-floor pattern (v5.1), generalized into `watermarkStart()`; `isPublished()`/`writeLiveIntel()`'s existing dedup as the safety net that makes a wider window safe |
| Existing API routes extended | N/A — no API surface change |
| Existing pages extended | N/A |
| New components introduced | 1 pure helper function (`watermarkStart`), justified: the identical 3-line pattern was duplicated at 7 call sites with no floor; extracting it is what let the fix apply uniformly instead of being re-derived (and potentially re-diverged) 7 times |
| Duplicate components introduced | 0 |
| Duplicate routes introduced | 0 |
| Backward compatibility preserved | PASS — `intel-state.json` shape unchanged, `fetchNVD()` untouched, all fallback windows preserved |
| Build passing with zero errors | PASS |
