# SENTINEL APEX — Cloudflare Workers Sub-Path Routing Parity
## Production Certification

**Date:** 2026-08-24
**Branch:** `claude/p0-intelligence-core-correlation-v1`
**Scope note:** This is the concrete, shipped deliverable from a Phase 0 "Intelligence Core Truth Audit" round whose primary mandate (build a new correlation engine) resolved to **NO-GO** on the evidence — see `SENTINEL-APEX-GLOBAL-CTI-V3-PHASE0-PRODUCTION-TRUTH-AUDIT.md` for the full audit and reasoning. This document certifies the one piece of production code this round actually changed.

---

## Executive Verdict

**RELEASE_CERTIFIED**

Closes, on Cloudflare Workers, the exact sub-path routing gap that PR #128 already closed on Vercel for the same 7 files. Mid-session, the user clarified that Vercel is being retired (decision final; technical cutover incomplete) and Cloudflare Workers is the sole target going forward — making this the concrete, evidence-grounded priority for this round instead of new correlation-engine code. Verified end-to-end against the real handler stack, not just route-table unit tests.

## Background

`api/v1/workbench/investigations.js`, `workbench/cases.js`, `intelligence/graph.js`, `intelligence/correlations.js`, `intelligence/objects.js`, `intelligence/similarity.js`, `intelligence/publish.js` all do their own internal sub-path routing (e.g. `/objects/{id}/approve`) via `api/_lib/request-path.js`'s `resolvePathParts()`, which reads `req.query.apexSubpath`. On Vercel, that query param is populated by a `/mountPath/:apexSubpath*` → `/mountPath?apexSubpath=:apexSubpath*` wildcard rewrite per mount point in `vercel.json` (3 fixed in the SOC Workbench round, 4 more in PR #128).

Cloudflare Workers has no declarative rewrite config to mirror that in — routing there is hand-rolled in `workers/lib/route-table.js`'s `resolveRoute()`, whose `DIRECT_API_HANDLERS` was (and remains) an **exact-path** `Set` lookup with no wildcard/prefix matching. `platform/open-issues.md` Issue 19 had already found and documented this exact gap for `cases.js`/`approvals.js` via a real `wrangler dev` probe during the Cloudflare migration's own parity-matrix certification — this round confirms it applied identically to all 7 files PR #128 fixed on Vercel, and closes it.

## Changed components

**Modified:**
- `workers/lib/route-table.js` — added `APEX_SUBPATH_HANDLERS` (a `Set` of the same 7 mount-point base paths already in `DIRECT_API_HANDLERS`) and a prefix-match loop in `resolveRoute()`: a request whose path starts with `{base}/` now resolves to `{ type: 'handler', handlerPath: base, query: { apexSubpath: <remaining segments> } }`, exactly mirroring the shape Vercel's rewrite produces. `APEX_SUBPATH_HANDLERS` is exported for testability.

**No change required to:**
- `workers/lib/router.js` — `dispatch()` already does `req.query = { ...req.query, ...routeQuery }` (line 93), so `route.query.apexSubpath` reaches `req.query.apexSubpath` — exactly what `resolvePathParts()` already expects — with zero changes to the dispatch layer.
- Every handler file itself — they already use `resolvePathParts()`, proven correct by PR #128's Vercel-side tests; this fix only changes how the query param they already read gets populated on this second runtime.

**New (test-only):**
- 13 new tests in `workers/lib/route-table.test.js` (unit-level `resolveRoute()` behavior for all 7 mount points, multi-segment sub-paths, the bare-base-path case staying on the exact-match rule, and two negative cases).
- 2 new tests in `workers/lib/router.test.js` (real end-to-end `handleFetch()` dispatch through the actual compat shim and actual handler files — not mocks).

## Defects fixed

The routing gap described above, for all 7 files, on Cloudflare Workers. No other defects found or fixed in this pass (the Cloudflare-side handler modules are the *same* `.js` files already fixed/tested on the Vercel side in PR #128 — this change only affects how a request reaches them on this runtime).

## Requirements proven

- `resolveRoute()` correctly resolves sub-paths for all 7 mount points (`investigations`, `cases`, `graph`, `correlations`, `objects`, `similarity`, `publish`), including multi-segment sub-paths (e.g. `case-1/notes`, `status/intel-123`).
- The bare base path (no sub-path) is unaffected — still resolved by the pre-existing exact-match rule, `query: {}`.
- A path that merely starts similarly without a separating `/` (e.g. `/api/v1/intelligence/objectsextra`) is correctly *not* treated as a sub-path.
- A handler not in `APEX_SUBPATH_HANDLERS` (e.g. `api/v1/auth`) still correctly 404s on an unmapped sub-path — this fix does not loosen routing for files that were never meant to have this behavior.
- **End-to-end, through the real stack**: `GET /api/v1/intelligence/objects/{id}` and `POST /api/v1/workbench/cases/{id}/notes` both reach the real handler (proven by the handler's own `401 UNAUTHORIZED` from `requireAnalyst` — a routing failure would 404, not 401) with no `ANALYST_KEYS` configured in the test environment, exactly the same proof pattern PR #128 used on the Vercel side.
- All existing `DIRECT_API_HANDLERS`/`DYNAMIC_API_HANDLERS`/pretty-URL-rewrite/asset/redirect/blocked-path behavior is unchanged (regression-proven, not assumed).

## Requirements NOT yet proven

- **Live Cloudflare Workers deployment.** Per the Phase 0 audit, Cloudflare Workers is not yet the live production DNS target (`wrangler.jsonc` still declares "no routes, no custom_domains, no production hostname" — confirmed this session). This fix is proven correct against the real handler stack under Node's test runner (`workers/lib/*.test.js`, the same harness `router.test.js`'s existing "real end-to-end handler dispatch" tests already use), not against an actual deployed Workers instance — no deployment access from this sandbox.
- Whether any *other* file beyond these 7 has the same class of gap — out of scope for this pass; `route-table.test.js`'s existing 32-function parity check continues to guard against a new file being added without a route.

## Production evidence

```
$ node --test workers/lib/*.test.js
# tests 116
# suites 18
# pass 116
# fail 0

$ node --test workers/lib/route-table.test.js   (isolated re-run)
# tests 63
# pass 63

$ npx jest --silent   (full existing suite, confirming zero cross-contamination)
Test Suites: 1 skipped, 50 passed, 50 of 51 total
Tests:       60 skipped, 1797 passed, 1857 total

$ npx tsc --noEmit
(zero output — zero type errors)
```

## Known limitations

- Not live-deployment-verified (see above) — no Cloudflare Workers deployment reachable from this sandbox.
- Does not address the Vercel deployment gap found in the same Phase 0 audit (Finding 3) — out of scope by design, since Vercel is being retired.
- Does not address `campaigns.json`'s overwrite bug (Finding 2) — unrelated to routing, deliberately deferred per the audit's own reasoning.

## Unexecuted tests

- No live Workers deployment smoke test.
- No load/performance testing of the new prefix-match loop (it's O(7) per unmatched request before falling through to `DYNAMIC_API_HANDLERS`/`null` — negligible, but not benchmarked).

## Certification

| Dimension | Status |
|---|---|
| Unit tests (route-table.js) | PASS — 63/63 |
| End-to-end tests (router.js, real handler dispatch) | PASS — 116/116 workers suite |
| Full existing regression (jest) | PASS — 1797/1797 non-skipped, zero regressions |
| TypeScript | PASS — zero errors |
| Backward compatibility | PASS — every existing route/rule unchanged, additive-only |
| Security (auth gate reached correctly) | PASS — proven via real 401, not assumed |
| Duplicate routes/components introduced | 0 |

**Verdict: RELEASE_CERTIFIED** — safe to merge. Mirrors an already-proven fix pattern onto a second runtime; no new design risk, no data-foundation question (this is pure routing, unlike the correlation-engine question this round explicitly declined to act on).

## Rollback

Revert the single commit touching `workers/lib/route-table.js` (+ its test files). `router.js` and every handler file are untouched, so rollback has zero effect on anything else.

## Next steps

See `SENTINEL-APEX-GLOBAL-CTI-V3-PHASE0-PRODUCTION-TRUTH-AUDIT.md` §19 for the full roadmap. Immediate next: complete the actual Cloudflare Workers production cutover (DNS + `wrangler.jsonc` production bindings) — an operator-authorized action outside this audit's engineering scope, but this fix removes one concrete blocker to it.
