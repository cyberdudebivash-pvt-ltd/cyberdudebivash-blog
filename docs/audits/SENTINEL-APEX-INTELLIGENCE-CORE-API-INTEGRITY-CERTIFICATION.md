# SENTINEL APEX — Intelligence-Core API Routing & Integrity Remediation
## Production Certification

**Date:** 2026-08-24
**Branch:** `claude/sentinel-apex-global-cti-commercial-v3`
**Scope note:** This is a first, narrow tranche within the much larger "P0/P1 Master Production Program — Global CTI Platform & Intel Factory Commercial Transformation v3" mandate. It is **not** that mandate's final certification. See `SENTINEL-APEX-GLOBAL-CTI-COMMERCIAL-TRANSFORMATION-V3-RESUME-CHECKPOINT.md` for what remains and why this tranche was chosen first.

---

## Executive Verdict

**RELEASE_CERTIFIED_WITH_LIMITATIONS**

This round closes the exact follow-up item `SOC-WORKBENCH-RELEASE-CERTIFICATION.md` (2026-08-21) left open: *"`correlations.js`/`objects.js`/`similarity.js`/`publish.js` sub-path routing — auth added, routing gap not fixed this round."* All four files are now reachable, tested, and — where a deeper defect was found underneath the routing gap — honest about what they can and cannot do. No existing capability was removed or narrowed; every change is additive or corrective to code that was already completely unreachable in production.

---

## Background

Four intelligence-core API route files (`api/v1/intelligence/correlations.js`, `objects.js`, `similarity.js`, `publish.js`) were written assuming Vercel would forward the full request path via `req.url` for any sub-path under their mount point. It does not: Vercel's file-based routing only maps a file to its own bare base path. Every request to a sub-path (e.g. `/api/v1/intelligence/objects/{id}/approve`) 404'd at Vercel's routing layer before any of this code ever ran, because `vercel.json` carried no rewrite for these four mount points. This exact defect, and its fix pattern (`api/_lib/request-path.js`'s `resolvePathParts()` + a `:apexSubpath*` wildcard rewrite per mount point), was already identified, proven, and shipped for `workbench/investigations.js`, `workbench/cases.js`, and `intelligence/graph.js`. These four files were the explicitly named, not-yet-fixed remainder.

## Changed components

**Modified (existing files, no new routes/pages/exports):**
- `api/v1/intelligence/correlations.js` — routing fix + honest-501 fix (see below)
- `api/v1/intelligence/objects.js` — routing fix + two additional pre-existing routing bugs fixed
- `api/v1/intelligence/similarity.js` — routing fix + identity-trust fix
- `api/v1/intelligence/publish.js` — routing fix + one additional pre-existing routing bug fixed
- `vercel.json` — four new wildcard rewrites, following the exact pattern already in use for the three previously-fixed mount points

**New (test-only, zero production surface):**
- `api/v1/intelligence/__tests__/correlations.test.js`
- `api/v1/intelligence/__tests__/objects.test.js`
- `api/v1/intelligence/__tests__/similarity.test.js`
- `api/v1/intelligence/__tests__/publish.test.js`

No page routes, API response shapes (beyond the two corrections below), configuration keys, or CI steps were touched. No dependency changes.

## Defects discovered this round

Reading the routing-gap fix pattern across these four files surfaced more than the routing gap alone. In order of discovery:

1. **Routing gap (all 4 files)** — as described above; every sub-path request 404'd before reaching handler code.
2. **`objects.js` base-path CREATE/SEARCH unreachable regardless of routing** — `POST`/`GET /api/v1/intelligence/objects` required `!id`, but for this exact URL shape `id` (`pathParts[length-2]`) always resolves to the literal, truthy string `'intelligence'`. `!id` was therefore always `false` — these two routes could never match, independent of the routing-gap fix.
3. **`objects.js` bare-ID GET/PUT unreachable regardless of routing** — `GET`/`PUT /api/v1/intelligence/objects/{id}` required `id && !action`, but for this shape `action` (`pathParts[length-1]`) always holds the real object ID (never empty) and `id` always holds the literal `'objects'`. The condition could never be true.
4. **`similarity.js` `handleMergeDuplicates` identity-trust gap** — the merge-duplicates write path read an `analyst` field straight from the request body and used it, unverified, as the acting identity passed to `similarityEngine.mergeDuplicates()` — the same class of bug already fixed in every other write path in this codebase this quarter (`investigations.js`, `cases.js`, `graph.js`, `objects.js`, and this same file's other handlers). The route dispatcher already passed the authenticated `caller` into this function; the function itself just didn't accept it.
5. **`publish.js` `GET /status/{id}` had `action`/`id` reversed** — this is the one named route in the file where the literal segment comes *before* the real ID (`/publish/status/{id}`, vs. every other route in the file being `/publish/{verb}` with no ID at all). The handler checked `action === 'status'`, but for this shape `action` (last segment) holds the real ID and `id` (second-to-last) holds the literal `'status'` — the reverse of what every other check in the file correctly assumes for its own, differently-shaped URL. This route was unreachable even after the routing-gap fix. Caught by a route-handler test, not by static reading — the same reading pass had already (incorrectly) concluded this file needed only the routing swap.
6. **`correlations.js` — all 5 handlers called an API that was never implemented (the most significant finding).** The route handlers call `correlationEngine.correlateThreatsActors(id, confidence)`, `.detectCampaigns(id, timeWindow)`, `.clusterMalwareVariants(id, threshold)`, `.clusterInfrastructure(id)`, and `.correlateIOCs(id)` — an entity-ID/graph-traversal-shaped API. The actual `CorrelationEngine` class (`api/_lib/correlation-engine.js`) has no constructor (so the `graphEngine`/`traversal` instances passed into `new CorrelationEngine(graphEngine, traversal)` are silently discarded) and implements a **completely different** API shaped around a single, pre-loaded investigation object (`correlateThreatActors(investigation)`, `correlateCampaigns(investigation)`, etc., used by the report-generation pipeline). Confirmed directly against the real class, not inferred:
   - `correlateThreatsActors`, `detectCampaigns`, `clusterMalwareVariants`, `clusterInfrastructure` do not exist on the class at all → would throw `TypeError: ... is not a function` (an unhandled-looking 500) once the routing gap was fixed.
   - `correlateIOCs(id)` *does* resolve to a real method, but with the wrong argument shape: called with a string ID instead of an investigation object, `investigation.iocs` reads as `undefined` → `[]` → the method silently returns an empty array for **any** input, every time, without ever throwing. This is the more dangerous of the two failure modes: a SOC analyst calling this endpoint would receive a well-formed `200 { relatedIOCs: [], count: 0 }` response that looks like a genuine "no correlations found" result but is actually structurally incapable of returning anything else.
   - A related, out-of-scope-for-this-round finding: `api/_lib/ai-analyst.js`'s `suggestAttributionTargets()` calls `this.correlationEngine.getIncomingByType(entityId, 'operates')` — a third nonexistent method on the same class. This method is not reachable from any currently-wired route (no `workbench/investigations.js` endpoint calls `suggestAttributionTargets`), so it was left as-is and is only noted here for completeness.

## Defects fixed

1–5 above are fixed directly (routing pattern applied per file; the two `objects.js` condition bugs corrected using the same `id === '<mount-name>' && action` idiom already proven in `investigations.js`/`cases.js`; `similarity.js`'s `handleMergeDuplicates` now takes `caller` and uses `caller.id`; `publish.js`'s status route condition and argument corrected).

For finding 6, the fix deliberately **stops short of implementing the missing graph-based correlation algorithms**. Designing "correlate threat actors near this actor," "detect campaigns," "cluster malware variants," and "cluster infrastructure" as real, graph-traversal-driven capabilities (what constructing `GraphTraversal` in this file's module scope clearly signals was the original intent) is genuine threat-intelligence feature engineering — confidence semantics, traversal depth, what counts as a correlation — not a routing fix, and inventing that under time pressure risks shipping a plausible-looking but arbitrary correlation feature to enterprise SOC customers, which is precisely the kind of fabricated-looking output CLAUDE.md's non-negotiable rules and the Enterprise Trust Enforcement Layer prohibit.

Instead, all 5 `correlations.js` handlers now return an explicit, honest `501 NOT_IMPLEMENTED` with a clear error message, rather than either crashing (a 500 that looks like a bug) or silently returning a fabricated-looking empty result (the `correlateIOCs` case). This is judged a strict improvement over both the pre-fix state (404, indistinguishable from "route doesn't exist") and the state the routing fix alone would have produced (500 crash / silently-empty 200), at effectively zero implementation risk. Building the real capability is tracked as follow-up work, not silently deferred — see the resume-checkpoint doc.

## Requirements proven

- `POST`/`GET /api/v1/intelligence/objects` (create, search) are reachable and functional.
- `GET`/`PUT /api/v1/intelligence/objects/{id}` (retrieve, update) resolve the real object ID, not the literal `objects` segment.
- `POST /api/v1/intelligence/objects/{id}/{review,approve,publish,retract}` and `GET /api/v1/intelligence/objects/{id}/history` are reachable, not shadowed by the bare-ID fallback, and attribute every write to the authenticated `caller.id`, never a client-supplied field.
- `GET /api/v1/intelligence/similarity/{id}/find`, `/{id}/ioc-matches`, `/duplicates` are reachable.
- `POST /api/v1/intelligence/similarity/merge` is reachable and attributes the merge to `caller.id`, ignoring any client-supplied `analyst` field.
- `POST /api/v1/intelligence/publish/{submit,approve,publish,retract}`, `GET /pending`, `GET /published` are reachable and attribute every action to `caller.id`.
- `GET /api/v1/intelligence/publish/status/{id}` resolves the real intelligence ID and is reachable (previously unreachable under any circumstances, including before the routing-gap fix existed as a concept).
- `GET /api/v1/intelligence/correlations/{id}/{actors,campaigns,malware-variants,infrastructure,iocs}` are all reachable (routing fixed) and return a structured `501` rather than crashing or fabricating results.
- All four files' `OPTIONS` preflight and unauthenticated-request paths behave identically to the already-certified pattern (`401` before any manager/engine method is invoked).
- Zero regression: the full pre-existing Jest suite (50 suites, 1797 tests, 1 pre-existing unrelated skip) passes unchanged after these edits.

## Requirements NOT yet proven

- **Live Vercel behavior.** No live Vercel deployment, `ANALYST_KEYS`, or Upstash Redis instance is reachable from this sandbox (same limitation documented in `SOC-WORKBENCH-RELEASE-CERTIFICATION.md`). The rewrite syntax is identical, character-for-character in structure, to the three already-proven rewrites for `investigations`, `cases`, and `graph`, and `vercel.json` was validated as well-formed JSON, but the actual routing behavior at the edge is unverified by a live request.
- **The real graph-based correlation capability** for `correlations.js` — explicitly not attempted this round (see Defects fixed §6).
- **UI/consumer integration.** No frontend code calls any sub-path of these four mount points today (confirmed by repo-wide search) — so this round has no UI regression surface, but also no live-UI proof the fix is consumed correctly once something does call it.

## Production evidence

```
$ npx jest --silent
Test Suites: 1 skipped, 50 passed, 50 of 51 total
Tests:       60 skipped, 1797 passed, 1857 total
Time:        8.098s
```
(The 1 skipped suite, `phase-12-enterprise-excellence.test.js`, is pre-existing and unrelated to this round's changes — untouched by this diff.)

```
$ npx jest api/v1/intelligence/__tests__/{correlations,objects,similarity,publish}.test.js --silent
Test Suites: 4 passed, 4 total
Tests:       40 passed, 40 total
```

```
$ npx tsc --noEmit
(zero output — zero type errors)
```

```
$ node -e "JSON.parse(require('fs').readFileSync('vercel.json','utf8'))"
vercel.json OK
```

Every one of the 40 new tests exercises the real class (`IntelligenceManager`, `SimilarityEngine`, `PublishingPipeline`, `CorrelationEngine`) via `jest.spyOn` on its actual prototype methods — not a hand-rolled mock of the interface — which is precisely what surfaced defects 5 and 6 above: `jest.spyOn` on a genuinely nonexistent method fails immediately, and a test asserting real call arguments against the real signature fails immediately when the route computes the wrong argument.

## Known limitations

- `correlations.js`'s five capabilities are explicitly not implemented (honest 501, not silent failure) — see resume-checkpoint doc for the recommended design starting point (build on the `GraphTraversal` instance this file already constructs).
- `ai-analyst.js`'s `suggestAttributionTargets()` has the same class of nonexistent-method defect as `correlations.js` did, but is currently unreachable from any wired route, so it was left untouched this round (Zero Unnecessary Modification — no evidence this specific code path needs to change today).
- This round did not perform the Phase 0 audit called for by the full 70-phase master mandate. See the resume-checkpoint doc.

## Unexecuted tests

- No live-Vercel end-to-end test (no reachable deployment).
- No live-Redis integration test for `publish.js`'s `handleGetPending`/`handleGetPublished` beyond mocked `zrange`/`zrevrange` calls.
- No load/performance testing of any of the four routes.

## Certification

| Dimension | Status |
|---|---|
| Build passing (tsc --noEmit) | PASS |
| Full Jest regression (pre-existing + new) | PASS — 1797/1797 non-skipped |
| New route-handler tests | PASS — 40/40 |
| Backward compatibility | PASS — all four mount points were 100% unreachable pre-fix; zero known consumers of the old (404) or intermediate (500/fabricated-empty) behavior |
| Duplicate routes/components introduced | 0 |
| Security (identity attribution) | PASS — `similarity.js` merge path now attributes to `caller.id`, matching every other write path in this codebase |
| Honest-failure discipline (no fabricated CTI output) | PASS — `correlations.js` returns 501, not a fabricated empty/misleading result |
| vercel.json validity | PASS |

**Verdict: RELEASE_CERTIFIED_WITH_LIMITATIONS** — safe to merge. The limitations above are explicit, tested-around (the 501s are asserted by test, not assumed), and tracked, not silently shipped.

## Rollback

Each of the five changed files is independent; any subset can be reverted with `git revert` against this commit without affecting the other four. Reverting `vercel.json`'s four new rewrite lines alone restores the exact pre-fix 404 behavior for all four mount points with no other side effects (the four rewrites are pure additions at the end of the existing `rewrites` array, colocated with the three already-shipped equivalents).

## Next steps (per CLAUDE.md's continuous self-improvement cadence)

1. Design and implement the real graph-based `correlations.js` capability on top of `GraphTraversal` (highest-leverage: closes the one remaining honest-501 in this round, and is the deepest gap found).
2. Fix or remove `ai-analyst.js`'s `suggestAttributionTargets()` (dead code with the same defect class — either wire it to a real route with a correct implementation, or leave clearly marked as unreachable).
3. Begin the Phase 0 audit called for by the full "Global CTI Platform & Intel Factory Commercial Transformation v3" mandate — see the resume-checkpoint doc for a proposed starting scope.
