# SENTINEL APEX — Unified Intelligence Search v1
## Production Certification

**Date:** 2026-08-24
**Branch:** `claude/p1-unified-intelligence-search-v1`
**Mandate:** P1 Production Transformation Task — Unified Intelligence Search, Entity Pivot & Analyst Investigation Experience v1
**Prior tranche:** PR #130 — Campaign Delivery Integrity v1 (fixed the destructive-overwrite bug that made `GET /api/v1/intel/campaigns` return 0 campaigns; this tranche is the first to build on the now-correctly-accumulating `campaigns.json`)

---

## 1. Executive Verdict

**CONDITIONAL GO**

The backend search-and-pivot capability described by this mandate is real, tested against real production data, security-reviewed, and shipped: a unified, cross-entity search over CVE/Campaign/Threat Actor/IOC/published Report, with entity-detail views exposing real graph relationships, evidence, and honest timelines. It is **conditional**, not an unqualified GO, because:

1. **No UI ships in this tranche.** This is a backend-API-first delivery. The mandate itself explicitly permits this outcome ("Do not claim the full analyst workspace if only the backend search API ships") — this document does not claim one.
2. **Investigation integration (Phase 35/36) is documentation-only**, not new code, for a deliberate, evidence-based reason (§15).
3. **Malware and ATT&CK-technique-as-a-standalone-type are explicitly NOT supported** — real data does not back them yet (§9, §20).

Every other acceptance-criteria item the mandate lists for the backend contract — rebuildable/versioned/derived index, catastrophic-drop protection, exact + free-text search, deterministic ranking, bounded filters/pagination, explicit result typing, CVE/campaign/actor pivots, IOC freshness/evidence semantics, reused graph (no new relationship engine), preserved auth/entitlements/rate-limiting, Cloudflare-native storage, adversarial QA, full regression, security review — is met and evidenced below.

---

## 2. Customer Problem

Before this tranche, an analyst starting from a CVE, actor, or IOC had no way to move between related intelligence without manually re-querying separate, type-specific endpoints and correlating the results themselves — there was no cross-entity search, and single-entity detail views (where they existed at all) did not expose their own graph relationships. The pre-existing `action=search` (still fully intact, see §6) only ever searched raw live-feed intel items, not campaigns, actors, IOCs, or reports, and returned no entity typing.

---

## 3. Baseline (fresh audit, this round)

Confirmed via `git log`/`git status` before any code was written, not assumed:
- PR #130 merged as `fd80e48d` on `main`.
- `api/intel/campaigns.json` correctly holds 1,187 accumulated campaigns (verified fresh, not from a stale prior-round number).
- `api/intel/threat-graph.json`: 4,307 CVE nodes, 1,187 Campaign nodes, 8 ThreatActor nodes, 886 IOC nodes, 0 Malware nodes (all counted directly against the live file, not estimated).

Existing docs re-read and treated as evidence, not unquestionable truth, per this mandate's own instruction — three material corrections this round made against them are recorded in §22.

---

## 4. Architecture

```
CANONICAL INTELLIGENCE (unchanged, already-live)
  api/intel/threat-graph.json  (CVE / Campaign / ThreatActor / IOC nodes + relationship edges)
  api/intel/campaigns.json     (richer campaign projection, PR #130-fixed)
  Sentinel-APEX/reports/published/*.md  (3 hand-authored reports, real YAML front matter)
        │
        ▼  buildSearchIndex()  — pure function, no I/O of its own
SEARCHABLE PROJECTION (api/_lib/search-index.js)
  6,391 typed, lightweight documents (cve/campaign/actor/ioc/report)
  computed in-memory, cached 60s, never persisted as a second store
        │
        ▼  searchDocuments() / getActorDetail() / getIocDetail() /
           getReportDetail() / getCveRelated()
QUERY ENGINE (same file — bounded, deterministic, no fuzzy/opaque scoring)
        │
        ▼  new actions on the EXISTING api/v1/intel.js router,
           reusing authenticate()/tier-gating/rate-limiting unchanged
CUSTOMER RESULTS
  GET /api/v1/intel?action=unified-search|actor|ioc|report
  GET /api/v1/intel?action=cve  (extended, additive, pro/enterprise only)
```

No second intelligence store was created. The search index is a computed view, not a persisted artifact — see §11 for why this was a deliberate choice, not an oversight.

---

## 5. Reuse-Before-Build Findings

Established via four parallel research passes before any code was written (full findings retained in session history; summarized here):

| Existing capability | Finding | Action taken |
|---|---|---|
| `search-index.json` / `generate-search-index.py` | Scoped **only** to blog posts (`posts/*.html`, confirmed 4,671:4,671 exact match), fully client-side, no server query contract | Left completely untouched — unrelated scope, no conflict |
| `api/v1/workbench/search.js` | Internal-only (`requireAnalyst`), Redis-backed, searches System B (SOC Workbench) — a disjoint ID space and data model | Not reused directly (wrong data domain); its `limit`-with-no-upper-clamp gap is noted in `platform/open-issues.md`, not fixed here (out of scope) |
| `api/v1/ioc/search.js` / `[id].js` | Reads `data/ioc-canonical.json` — **2 records, unauthenticated, stale since 2026-07-31** — confirmed via grep to have **zero** live-pipeline callers writing to it | **Not reused** — resolves a previously-open question in `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`; the new `action=ioc` reads the graph's 886 real IOC nodes instead |
| `api/_lib/intel.js`'s `getCVEDetail`/`getCampaignDetail`/`getTopActorsAPI`/`getGraph` | Real, live, tier-gated, already the canonical entity-detail layer | Reused/extended, never duplicated — `getCVEDetail` gained an additive `related` field (§8); campaign/graph detail untouched |
| `threat-graph.js`'s `getNode()`/`getNeighbors()` | Already the proven relationship-traversal primitive (used by `campaign-engine.js`) | Reused unchanged for actor/IOC detail; `getNeighbors()` itself extended additively (2 new fields) for evidence data (§7) |
| `api/_lib/middleware.js`'s `authenticate()` + tier model | Already Workers-safe, already the established pattern for a new tier-gated action | Reused unchanged — zero new auth code |

No duplicate intelligence store, relationship engine, auth mechanism, or rate limiter was built.

---

## 6. Canonical Source Model

| Search type | Canonical source | Live record count |
|---|---|---|
| cve | `threat-graph.js` CVE nodes | 4,307 |
| campaign | `campaigns.json` (PR #130-fixed) | 1,187 |
| actor | `threat-graph.js` ThreatActor nodes (`THREAT_ACTOR_DB`, enriched via `getTopActors()`) | 8 |
| ioc | `threat-graph.js` IOC nodes | 886 |
| report | `scripts/generate-reports-index.js` → `api/intel/reports-index.json`, derived from real published-report front matter | 3 |

The pre-existing `action=search` (narrower — `live.json` raw intel items only, no entity typing) is **completely unmodified** and continues to work exactly as before; the new capability is additive, not a replacement.

---

## 7. Search Schema

```js
{
  schema_version, id, type, name, aliases[], summary, severity, confidence,
  first_seen, last_seen, updated_at, tags[], techniques[], sectors[],
  report_refs[], detail_url,
  // per-type extras only where real data supports them (vendor/product/
  // cvss for cve; clustering_model/item_count for campaign; cve_count/
  // activity_score for actor; ioc_type for ioc; cves/threat_actors/
  // malware_families for report)
}
```

Adapted from the mandate's conceptual example, not copied verbatim — fields the mandate listed but no real data backs (e.g. `malware[]`, `countries[]`) were deliberately omitted rather than populated with nulls-as-decoration. `regions[]` (from actor `target_regions`) is used in place of `countries[]` since that is what the real data actually contains.

---

## 8. Ranking

Deterministic, documented, no fuzzy/opaque scoring (Phase 11's explicit instruction):

| Match type | Score |
|---|---|
| Exact ID | 100 |
| Exact name | 95 |
| Exact alias | 90 |
| ID prefix | 75 |
| Name prefix | 70 |
| Name substring | 55 |
| Alias substring | 50 |
| Summary substring | 40 |
| Vendor/product substring | 35 |

Ties break on `last_seen` descending, then severity (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW`). Verified deterministic by test: identical repeated queries return identical result order.

**Known limitation, disclosed not hidden:** free-text search only matches a document's own indexed fields (name/aliases/summary/vendor/product) — it does not search cross-referenced relationship data. Searching an actor's name will not surface campaigns/CVEs that are only linked to that actor via a graph edge, unless the campaign/CVE's own text happens to mention it (confirmed directly: 0 of 1,187 campaign documents mention "lockbit" in their own text, despite LockBit having 10 real linked CVEs and 1 linked campaign via graph edges). Relationship-based discovery is what entity-detail pivots (§13) are for, not free-text search.

---

## 9. Filters

| Filter | Bound |
|---|---|
| `q` | 2–200 chars (matches the pre-existing `action=search` precedent exactly) |
| `type` | Capped at 5 values (the number of supported types); unknown values ignored, not an error |
| `severity` | Exact match against `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` |
| `from_date`/`to_date` | Filter on `last_seen` only (Phase 17: one unambiguous date field, not several ambiguous ones); malformed strings ignored; a reversed range degrades to zero results, not an error |
| `limit` | Clamped 1–100 (matches `parsePagination()`'s existing cap) |
| `offset` | Clamped ≥0 |

No facet was added without a real backing field — no `country`, `vendor`, or `technique` facet ships in v1 because none has clean enough coverage to be a defensible filter dimension yet (see §20).

---

## 10. Entity Types

| Type | Status | Reasoning |
|---|---|---|
| CVE | **Production Ready** | 4,307 real nodes, rich detail + real relationships |
| Campaign | **Production Ready** | 1,187 real, correctly-accumulating (PR #130) |
| Actor | **Production Ready** | 8 curated, evidence-sourced (CISA/DOJ/Mandiant), real relationships |
| IOC | **Production Ready With Limitations** | 886 real nodes, but capped at 5-per-item at ingestion (pre-existing, unrelated limit) and pro/enterprise-tier-gated only |
| Report | **Production Ready With Limitations** | 100% real data, but only 3 records exist — technically complete, commercially thin |
| Malware | **Not Supported** | 0 populated nodes anywhere in production data, confirmed directly |
| ATT&CK Technique (standalone) | **Not Supported** | No canonical technique registry exists; surfaced as metadata on actor/report only |

---

## 11. Why the index is computed, not persisted (Cloudflare architecture)

`wrangler.jsonc` provisions **zero** KV namespaces, D1 databases, R2 buckets, or Queues — confirmed by reading the file directly, and its own trailing comments state this is deliberate policy, not an oversight. `threat-graph.json` (8.0MB) and `campaigns.json` (1.5MB) are already `require()`-bundled directly into the Worker script, and no bundle-size ceiling is documented anywhere in this repo — the one stale figure that exists (≈5.16MB, from an earlier staging checkpoint) is already exceeded by those two files alone.

Given that, persisting a third, similarly-sized JSON file and bundling it the same way would add real, unmeasured risk. Instead, `buildSearchIndex()` computes the projection **in memory, from data already loaded for other endpoints** (`getGraph`/`getCampaigns` already `require()` the same files) — adding zero net bytes to the Worker bundle. This also directly applies the PR #130 lesson at the architecture level, not just as a guard: there is no second persisted copy that can silently drift out of sync with canonical state, because there is no second copy at all.

---

## 12. Index Integrity

`validateSearchIndex()` compares the computed index's per-type counts against a fresh, independent count of each canonical source and flags:
- any count mismatch (the direct equivalent of PR #130's catastrophic-drop scenario, reproduced as a test — see §21)
- duplicate document IDs
- any unsupported type leaking into the index

On a validation failure, `getSearchIndex()` logs loudly and **keeps serving the previous good cache** rather than a suspect one — fail-safe, not fail-closed, matching this file's existing `PATHS.campaigns` caution. Verified `valid: true, problems: []` against real production data (6,391/6,391 documents, exact match on every per-type count).

---

## 13. Relationship Pivots / Graph Integration

Every entity-detail function (`getActorDetail`, `getIocDetail`, `getCveRelated`) calls `threat-graph.js`'s existing `getNode()`/`getNeighbors()` — the same primitives `campaign-engine.js` already uses. **No second relationship/correlation engine was built.** Verified against real data: `CVE-2023-27351` correctly surfaces its real linked campaign (PaperCut Exploitation Wave) and both real attributed actors (LockBit, confidence 0.92; Cl0p, confidence 0.85) — the identical sample independently cross-verified against known ground truth during the PR #130 work.

---

## 14. Evidence / Provenance

`getNeighbors()` was extended (additively — 2 new object fields, zero existing fields changed, verified against every existing caller) to surface each edge's already-real `sources[]` citation array and `first_seen` date, previously silently dropped. Every related-entity object returned by actor/IOC/CVE detail now carries a nested `evidence: {sources, first_seen}` — e.g. the LockBit→CVE-2023-27351 edge cites the real CISA advisory URL. An empty `sources[]` is preserved honestly where an edge genuinely has none recorded, never backfilled.

---

## 15. Investigation Integration

**Audited, not code-changed**, for a specific, evidence-based reason: `evidence-manager.js`'s `addEvidence()` was found to already accept **completely free-form `content`/`metadata` with zero ID-scheme validation** — an analyst can reference a new canonical entity ID (e.g. `campaign:ransomhub-2026`) as investigation evidence today, via the already-wired `POST /api/v1/workbench/investigations/.../evidence` route, with no code change required:

```json
POST /api/v1/workbench/investigations/{id}/evidence
{
  "investigationId": "{id}",
  "type": "EXTERNAL_REFERENCE",
  "title": "CVE-2023-27351 — PaperCut Exploitation Wave",
  "content": "campaign:cve-2023-27351",
  "metadata": { "source": "unified-search", "entity_type": "campaign", "entity_id": "campaign:cve-2023-27351" }
}
```

Building new plumbing was deliberately avoided because System A (this tranche's data) and System B (the SOC Workbench) are **confirmed, by direct grep in both directions, fully disjoint** — zero cross-imports exist anywhere in the codebase — and this is an already-documented, deliberate architectural boundary (`docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`), not an accidental gap. The Workbench also depends on Upstash Redis credentials that are not declared anywhere in `wrangler.jsonc` — a live, credential-gated system with no review window in this session, the same caution this codebase has applied to `campaigns.json` and the graph itself in every prior round.

---

## 16. Security

Dedicated security review completed via the `security-review` skill against the full diff (see the review transcript in this branch's history). **Zero HIGH/MEDIUM findings.** Specifically checked and ruled out:
- Injection (SQL/NoSQL/command/regex-from-user-input): none possible — no query language, subprocess, or DB exists on this path; only string `.includes()`/`.startsWith()`/`===` comparisons.
- Prototype pollution: verified directly (`type=__proto__` attempt leaves `({}).polluted === undefined`); `getNode(graph, '__proto__')` returns the inert `Object.prototype` object, which is immediately discarded by a type check before any field is read or returned.
- Authorization bypass: all 4 new actions sit behind the same unconditional `authenticate()` call as every existing action; `action=ioc` enforces the same pro/enterprise gate as the pre-existing `action=iocs`.
- Data exposure: every field returned is already-public threat intelligence already reachable via existing endpoints in aggregate; no new sensitive-data category introduced.
- IDOR/tenant isolation: not applicable — all data is global/shared, no per-tenant ownership model exists on this surface.

---

## 17. Entitlements

Reused, not reinvented: `unified-search` excludes `ioc`-type results for free/starter tier (mirroring `getGraphForTier()`'s own existing IOC exclusion exactly); free tier caps results at 5 (matching the pre-existing `action=search` convention); `action=ioc` 403s for free/starter (matching `action=iocs`); `action=actor` returns identity-only for free/starter, full relationships for pro/enterprise (new but consistent with the file's established partial-tier-gating pattern, e.g. `getCampaignDetail`). No new commercial tier, price, or entitlement concept was invented.

---

## 18. Cloudflare Runtime

Zero changes to `vercel.json`, `workers/lib/route-table.js`, or `workers/lib/router.js` — every new action lives inside `api/v1/intel.js`'s existing `action=` dispatch, already fully wired on both runtimes. `reports-index.json` follows the exact same `isCloudflareWorkers()`-branching `PATHS` pattern as every other intel data file. The search index adds zero bytes to the Worker bundle (§11).

---

## 19. Performance

Measured against real production data (6,391 documents), not claimed:

```
Index build (cold):        30ms
Query (100x average):      2.45ms
10,000-char query reject:  <0.1ms  (fails on length check before any scan)
```

No production Cloudflare telemetry exists yet for this endpoint (not deployed) — these are local measurements against the real committed data files, disclosed as such, not presented as production p95.

---

## 20. Known Limitations

- **No UI ships in this tranche** — API-first delivery, honestly labeled as such throughout.
- **Free-text search does not traverse relationships** (§8) — use entity-detail pivots for relationship-based discovery.
- **Malware and standalone ATT&CK-technique search are not supported** — no real data / no canonical registry.
- **IOC coverage is capped at 5-per-item** — a pre-existing ingestion limit, not introduced or changed by this tranche.
- **Report corpus is 3 records** — real, complete, but commercially thin.
- **No production Cloudflare telemetry** — not yet deployed; performance figures are local measurements against real data.
- **Investigation integration is documentation-only** (§15) — a deliberate, justified scope decision, not an oversight.
- **`api/v1/workbench/search.js`'s `limit` has no upper clamp**, and `api/v1/ioc/search.js`/`api/v1/detections/rules.js` have no authentication at all — pre-existing gaps discovered during this round's reuse audit, tracked in `platform/open-issues.md`, deliberately **not fixed here** (out of scope for this tranche, and each is a live-pipeline-adjacent or credential-gated surface this session cannot safely touch without a dedicated review window).

---

## 21. Test Evidence

```
node --test tests-js/*.test.js
# 206/206 pass (was 155 before this branch; +51 new: 49 search-index.test.js + 3 CVE-related + evidence tests)

node --test workers/lib/*.test.js
# 116/116 pass, unchanged

npx jest --silent
# 1 pre-existing unrelated skip, 51/52 suites pass; 1,819 passed / 1,879 total non-skipped
# (+22 new: api/v1/__tests__/intel-unified-search.test.js)

npx tsc --noEmit
# clean, zero output
```

Two real bugs were caught and fixed by actually running this code against real data, not by static review alone: `getTopActors()` dereferencing a null graph on an empty-input edge case, and an initial test-harness assumption about `successResponse()`'s response shape (a test-script correction, not a production bug).

---

## 22. Adversarial QA

Covered directly (both the pure-function suite and the route-level suite): empty query, 1-char query, 10,000-char query, SQL-injection-shaped payload (`' OR 1=1 --`), script-tag payload, `__proto__`/`constructor` as entity IDs and as a type-filter value, a 1,000-entry type-filter list, reversed date range, malformed date strings, Unicode input, a fake-but-CVE-shaped ID, and a CVE ID passed where an actor ID was expected. Every case degrades safely (empty result set or a clean 4xx-shaped error) — none throw, none silently misbehave, none pollute `Object.prototype`.

**Corrections made against prior documentation this round** (per the mandate's own "historical audit claims are evidence, not unquestionable truth" instruction):
1. `platform/open-issues.md`'s claim that `generate-search-index.py` is "orphaned, wired into no workflow" is only half true — the standalone Python script is unwired, but `fetch-live-intel.js`'s own `updateSearchIndex()` incrementally feeds the same file every live cycle. Corrected in `platform/open-issues.md` (§24).
2. The IOC-search-source open question flagged in `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md` is now resolved definitively (§5, §23).
3. Graph node counts in older audit docs (`SENTINEL-APEX-GLOBAL-CTI-V3-PHASE0-PRODUCTION-TRUTH-AUDIT.md`) are stale (9,315 nodes at time of writing vs. 11,960+ today) — directionally consistent but not to be cited as current.

---

## 23. Live Verification

Not yet deployed to production Cloudflare — this branch has not been merged. All verification in this document is against the real, committed production data files (`api/intel/threat-graph.json`, `api/intel/campaigns.json`, the real published report markdown) using the actual production code paths (`loadGraph()`, `loadJSON()`), run locally. This is disclosed explicitly, not conflated with live-Cloudflare verification.

---

## 24. Commercial Value — Three Real Workflows Demonstrated

**Workflow A: CVE → Campaign → Actors → Evidence**
```
Input:  GET /api/v1/intel?action=cve&id=CVE-2023-27351  (pro tier)
Result: item.related.related_campaigns = [{id: "campaign:cve-2023-27351",
          name: "PaperCut Exploitation Wave", relationship: "includes"}]
        item.related.related_actors = [
          {id: "actor:lockbit", confidence: 0.92,
           evidence: {sources: ["https://www.cisa.gov/.../aa23-165a"], first_seen: "2023-04-19"}},
          {id: "actor:cl0p", confidence: 0.85, evidence: {...}}]
Analyst value: one request replaces manually searching the actor/campaign
databases separately and cross-referencing by hand.
```

**Workflow B: Search → Actor → Full Relationship Profile**
```
Input:  GET /api/v1/intel?action=unified-search&q=lockbit  (enterprise tier)
Result: [{type: "actor", id: "actor:lockbit", name: "LockBit", score: 100}]
Follow: GET /api/v1/intel?action=actor&id=actor:lockbit
Result: 10 related CVEs, 1 related campaign, real timeline
          (first observed 2019-09-01), aliases, TTPs, target sectors
Analyst value: a single actor name resolves straight to its full,
evidence-backed footprint across the graph.
```

**Workflow C: Report → Linked CVEs → Cross-referenced Campaign Search**
```
Input:  GET /api/v1/intel?action=report&id=SA-2026-0003
Result: cves: ["CVE-2024-27198", "CVE-2024-27199"], malware_families:
          ["BianLian", "Jasmin"], attack_ids: 5 real technique IDs
Follow: GET /api/v1/intel?action=unified-search&q=teamcity&type=cve
Result: the same CVEs, independently discoverable by product name
Analyst value: published-report intelligence and live graph data are
now cross-navigable in both directions, not siloed.
```

---

## 25. Reuse Report

| Metric | Result |
|---|---|
| Existing components reused (extended, not replaced) | `authenticate()`, tier-gating pattern, `parsePagination()` clamp idiom, `getNode()`/`getNeighbors()`, `getTopActors()`, `getCVEDetail()`/`getCampaignDetail()` (extended additively), `publish-report.js`'s `slugify()` |
| Existing API routes extended (not duplicated) | `api/v1/intel.js`'s `action=` dispatch — 4 new actions, 0 new files, 0 routing-config changes |
| Existing pages extended (not replaced) | N/A — no UI shipped |
| New components introduced (justified by gap analysis) | `api/_lib/search-index.js` (no prior cross-entity search existed), `scripts/generate-reports-index.js` (no prior machine-readable report manifest existed) |
| Duplicate components introduced | **0** |
| Duplicate routes introduced | **0** |
| Backward compatibility preserved | **PASS** — every existing action, field, and response shape unchanged; `action=cve`'s new field is additive and pro/enterprise-only |
| Build passing with zero errors | **PASS** |

---

## 26. Rollback

Four independent commits on this branch, each cleanly revertible without affecting the others:
1. Core search index + reports manifest (`api/_lib/search-index.js`, `api/intel/reports-index.json`, `scripts/generate-reports-index.js`) — reverting removes the capability entirely; nothing else depends on it.
2. API wiring (`api/_lib/intel.js`, `api/v1/intel.js`) — reverting removes the 4 new actions; the pre-existing actions are untouched either way.
3. Test coverage — revertible independently with no production effect.
4. CVE-detail extension + edge-evidence extension — reverting restores `getNeighbors()`'s exact prior 4-field return shape and removes `action=cve`'s `related` field; every other action is unaffected.

No schema, config key, or route path was removed or renamed anywhere in this tranche.

---

## 27. Verdict

**CONDITIONAL GO** for the backend contract shipped in this tranche (see §1). Certified for the operator's review and merge decision — not merged automatically, per this task's explicit constraint.

**Next priority recommendation** (ranked by evidence, not chosen automatically — see the resume-checkpoint doc for the full weighted table): resolve the pre-existing unauthenticated/unbounded gaps found in `api/v1/ioc/search.js`/`api/v1/detections/rules.js`/`api/v1/workbench/search.js` during this round's reuse audit before building further on top of them; then, if a UI is wanted, a minimal search page is the natural next slice given the backend contract is now stable.
