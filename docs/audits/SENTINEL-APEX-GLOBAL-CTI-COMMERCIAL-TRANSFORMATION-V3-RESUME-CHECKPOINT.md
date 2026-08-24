# SENTINEL APEX — Global CTI Commercial Transformation v3 — Resume Checkpoint

**Date:** 2026-08-24 (round 1); updated 2026-08-24 (round 2, same day, different branch)
**Branch:** `claude/sentinel-apex-global-cti-commercial-v3` (round 1, merged as PR #128); `claude/p0-intelligence-core-correlation-v1` (round 2, this update)
**Written per:** the master mandate's own "Long-Run Checkpoint Policy" — stop at a safe boundary, commit, push, update the PR, and leave a clear resume point rather than attempting the full 70-phase mandate in one uninterrupted pass.

**READ THIS FIRST IF RESUMING:** §7 below (added in round 2) contains the single most important thing to know before touching deployment, routing, or correlation work again: **Vercel is being retired** (decision final per the user, mid-round-2; technical cutover incomplete) **and Cloudflare Workers is now the sole target platform.** Also: round 1's "Thread A" (build real correlation logic for `intelligence/correlations.js`) is now **answered — NO-GO** — see §7. Do not restart Thread A as originally framed below without reading §7 first.

---

## 1. What this checkpoint is (and isn't)

The mandate this branch is named for — "P0/P1 Master Production Program — CYBERDUDEBIVASH® SENTINEL APEX™ Global CTI Platform & Intel Factory Commercial Transformation v3" — is a 70-phase specification covering the intelligence object model, evidence/provenance, entity resolution, knowledge graph, correlation engine, search, watchlists, alerting, SOC workbench, detection engineering, STIX/TAXII, enterprise API, webhooks, entitlements, billing, security, multi-tenancy, observability, and backup/DR, ending in a full platform certification.

**That mandate's Phase 0 audit has not been performed yet.** This checkpoint does not rank the 70 phases or select a "highest-value coherent tranche" from among them in the way the mandate describes. Instead, this round did something narrower and, on the evidence available at the start of the session, more clearly justified: it closed a **specific, already-identified, already-scoped gap** that a prior, separate certification round (`SOC-WORKBENCH-RELEASE-CERTIFICATION.md`, 2026-08-21) had explicitly flagged as its own unfinished follow-up. See `SENTINEL-APEX-INTELLIGENCE-CORE-API-INTEGRITY-CERTIFICATION.md` for the full record of that work.

The reasoning for choosing that over starting the 70-phase audit cold: a known, precisely-diagnosed defect with an already-proven fix pattern (three sibling files already fixed the same way) is lower-risk and faster to certify correctly than a fresh audit of a much larger surface would have been to even scope safely in the remaining session budget. It is a legitimate, evidence-based first tranche — just not *the* tranche the master mandate's own document enumerates as its "required first implementation tranche." That work is still ahead.

## 2. What happened this round (chronological)

1. Read the master mandate in full; read `SOC-WORKBENCH-RELEASE-CERTIFICATION.md` and `CUSTOMER-DASHBOARD-SUBSCRIPTION-CERTIFICATION.md` (both already existing on `main`) to establish what was already built and what was explicitly left open.
2. Confirmed via source inspection that the routing gap in `correlations.js`, `objects.js`, `similarity.js`, `publish.js` was still present and unfixed.
3. Applied the proven `resolvePathParts`/`MOUNT_PATH` fix pattern to all four files.
4. While applying the fix, discovered and fixed four additional, previously-undocumented defects (full detail in the certification doc): two routing-condition bugs in `objects.js`, one identity-trust bug in `similarity.js`, one reversed-segment bug in `publish.js`.
5. Discovered that `correlations.js`'s five handlers call a `CorrelationEngine` API that was never implemented anywhere in the codebase (confirmed against the real class, not inferred) — the deepest finding this round. Rather than build the missing graph-based correlation feature under time pressure, made all five handlers return an honest `501 NOT_IMPLEMENTED`.
6. Added four `vercel.json` wildcard rewrites, matching the existing pattern exactly.
7. Wrote 40 new route-handler tests across four new test files, all spying on real class prototypes (not hand-rolled mocks) — this is what caught defects 4 and 5/6 above; static reading alone had missed them.
8. Ran the full pre-existing Jest suite (1797 tests) plus `tsc --noEmit`: zero regressions.
9. Wrote the certification doc and this checkpoint.

## 3. Certification status

`SENTINEL-APEX-INTELLIGENCE-CORE-API-INTEGRITY-CERTIFICATION.md` — **RELEASE_CERTIFIED_WITH_LIMITATIONS**. Read it before touching any of the four files it covers again; it explains exactly what's proven, what's explicitly a known limitation (the `correlations.js` 501s), and what's out of scope.

## 4. Test baseline (reproduce before trusting any further change)

```
npx jest --silent
# Expect: 1 skipped, 50 passed, 50 of 51 suites; 60 skipped, 1797 passed, 1857 total tests

npx jest api/v1/intelligence/__tests__/{correlations,objects,similarity,publish}.test.js --silent
# Expect: 4 passed, 4 total; 40 passed, 40 total

npx tsc --noEmit
# Expect: no output
```

The 1 pre-existing skipped suite is `api/_lib/__tests__/phase-12-enterprise-excellence.test.js` — unrelated to this round, do not investigate it as part of resuming this checkpoint unless a future task specifically calls for it.

## 5. Next exact action if resuming

Two independent threads are open. Pick based on what the resuming session is actually asked to do:

**Thread A — close the correlations.js gap this round left honest-but-incomplete.**
Build real entity-ID/graph-traversal-based correlation methods on `CorrelationEngine`, or a new class, using the `GraphTraversal` instance `correlations.js` already constructs (`findRelatedEntitiesBFS`, `findShortestPath` are proven primitives — see `api/v1/intelligence/__tests__/graph.test.js`). Do **not** touch the existing investigation-object-shaped methods on `CorrelationEngine` (`correlateThreatActors`, `correlateCampaigns`, etc.) — they're used by the report-generation pipeline via `findCorrelations()`; this is additive-only. Design the actual correlation semantics deliberately (what "correlated with confidence >= X" means for each of actors/campaigns/malware/infrastructure/IOCs) rather than guessing — this is real threat-intel feature design, not a mechanical fix. Update the five `correlations.js` handlers to call it, replace the honest-501s with real results, replace the corresponding `correlations.test.js` tests (they currently assert 501 specifically so they'll fail loudly the moment this lands — that's intentional).

**Thread B — the actual Phase 0 audit of the 70-phase master mandate.**
Has not started. A responsible starting scope, following the mandate's own six-plane model as a mental map (not necessarily a repo split):
1. Inventory what already exists per plane (intelligence object model, evidence/provenance, entity resolution, knowledge graph, correlation, search, alerting, SOC workbench, detection engineering, STIX/TAXII, enterprise API/webhooks, entitlements/billing, security, multi-tenancy, observability, backup/DR) against what the mandate specifies.
2. For each plane, cite concrete evidence (file paths, existing certification docs, test coverage) rather than re-deriving from scratch — this codebase already has substantial infrastructure (`intelligence-manager.js`, `graph-engine.js`, `investigation-manager.js`, `publishing-pipeline.js`, billing in `api/v1/billing.js`, etc.) that a fresh audit must find and reuse, not rebuild.
3. Rank gaps P0-P3 per the mandate's own instructions.
4. Propose the "required first implementation tranche" the mandate asks for, with justification, before writing any code.
5. Get the ranked plan in front of the user/PR reviewer before starting a large build — the mandate is explicit that this is not a green light for an unsupervised big-bang rewrite.

Thread A is smaller, self-contained, and already has a clear design starting point. Thread B is the actual master mandate but is a multi-session undertaking. Do not attempt both in one sitting.

## 6. Items still requiring explicit owner authorization before executing

- Any schema/entitlement/billing change (Phase references to STIX/TAXII, enterprise API contracts, multi-tenancy) that would break an existing customer-facing contract — the master mandate itself requires no irreversible migration without dry-run/manifest/backup/canary/rollback, and Level 3 (Backward Compatibility) in `CLAUDE.md` requires the same.
- Designing the real `correlations.js` algorithm (Thread A) is a product/analyst-facing decision about what "correlation" and "confidence" mean to a paying SOC customer — reasonable to design and propose, but flag the specific confidence-scoring approach for review before it starts shaping customer-visible output, per the Enterprise Trust Enforcement Layer's rule against unverifiable threat-intelligence claims.

---

## 7. Round 2 update (2026-08-24, branch `claude/p0-intelligence-core-correlation-v1`)

A second same-day round picked up Thread B in a narrower form: not the full 70-phase audit, but the specific Phase 0 "Intelligence Core Truth Audit" the next mandate in this series asked for, as a gate before building "Correlation Engine v1." Full detail: `SENTINEL-APEX-GLOBAL-CTI-V3-PHASE0-PRODUCTION-TRUTH-AUDIT.md` and `SENTINEL-APEX-CLOUDFLARE-WORKERS-ROUTING-PARITY-CERTIFICATION.md`. Three things every future session needs to know:

**7.1 — Thread A is answered: NO-GO on building new correlation logic for `intelligence/correlations.js`.**
Real, evidence-backed, explainable, deterministic correlation **already exists and is live in production** — `api/_lib/threat-graph.js` + `campaign-engine.js` + `enrichment-pipeline.js` produce `co_occurs_with` edges between Campaigns/CVEs/Actors (62 real edges confirmed live, growing every ~30-min ingestion cycle), each with a `sources[]` citation, `reasoning[]`, and `signals{}` breakdown. It's exposed today via `/api/v1/intel/graph` (paid tier). Building a second correlation engine behind `intelligence/correlations.js` would be exactly the duplication this whole mandate series' Non-Negotiable Execution Principle (AUDIT → REUSE → PROVE → DESIGN → BUILD) prohibits — that route's `IntelligenceObject` data space is also disjoint (different ID scheme, Redis vs. file-persisted, analyst-curated vs. bot-populated) from the graph that has real data, so wiring one to the other isn't a simple integration either. **Do not restart Thread A as round 1 framed it.** If correlation work resumes, the right target is exposing System A's already-real `co_occurs_with` layer better (see the Phase 0 audit's §19 P1 items), not building new logic for System B.

**7.2 — Vercel is being retired. Cloudflare Workers is the sole target platform going forward.**
User-confirmed mid-round-2 (not yet reflected in most of this repo's own docs, several of which still describe Vercel as current production — treat those as stale until updated): the retirement decision is final, but the technical cutover (DNS, `wrangler.jsonc` production routes/bindings) is not complete. Round 2 responded by closing the Cloudflare-side mirror of PR #128's Vercel routing fix (`workers/lib/route-table.js`'s `APEX_SUBPATH_HANDLERS`) rather than doing further Vercel work. **Do not add anything new to `vercel.json` going forward** — if a routing/config change is needed, make it in `workers/lib/route-table.js` (+ `router.js`'s `HANDLER_MODULES` if a new handler file is added) instead, and update `vercel.json` only if explicitly asked to keep Vercel limping along during the transition.

**7.3 — A large, pre-existing, unrelated production gap was found on the (still-live, still-DNS-pointed-to) Vercel deployment.**
Direct live HTTP testing found that only `api/v1/*.js` files flat at the top level, plus files explicitly listed in `vercel.json`'s `functions` block, are actually reachable — every nested-subdirectory file *not* explicitly listed 404s with Vercel's own platform 404, even at its bare base path. That's roughly 24 of 32 total API function files, including the entire `intelligence/`, `workbench/`, `ioc/`, `quality/`, `customer/`, `reports/`, `analysis/`, `detections/` surfaces. This predates and is unrelated to any routing-gap fix from PR #127/#128 — it means most of the SOC Workbench may have never been reachable in production at all, on the platform DNS still points to as of this checkpoint. Given §7.2, this was **not fixed** this round (deliberately — fixing a platform being retired is likely wasted effort; finishing the Cloudflare cutover matters more). If Vercel is still live and this matters operationally before the cutover completes, that's a decision for whoever owns the cutover timeline, not something to silently patch.

**7.4 — Also found and deliberately NOT fixed this round**: `api/intel/campaigns.json` (the paid `/api/v1/intel/campaigns` endpoint's backing store) is fully overwritten, not merged, every ~30-min ingestion cycle — confirmed live at 0 campaigns despite the graph holding 1,187 accumulated Campaign nodes. Real, live, currently-reducing-customer-value bug. Fix design is sketched in the Phase 0 audit's §19 — deliberately not attempted this round because it touches the same live, no-review-window bot pipeline that `platform/open-issues.md` Issue 8 repeatedly declined to modify without a dedicated sprint.

**Test baseline after round 2** (in addition to §4 above, unchanged):
```
node --test workers/lib/*.test.js
# Expect: 18 suites, 116 tests, 116 pass, 0 fail
```
