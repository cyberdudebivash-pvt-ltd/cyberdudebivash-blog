# SENTINEL APEX — Global CTI Commercial Transformation v3 — Resume Checkpoint

**Unrelated parallel thread, not part of this lineage:** a separate P0
mandate ("Intel Factory Publication Reliability, Blogger Syndication
Recovery & Customer Delivery Assurance v1", `claude/p0-intel-factory-publication-reliability-v1`,
2026-08-24) fixed a CI-signal defect in the Python Blogger syndication
pipeline (`automation/main.py` and friends) — entirely outside this
checkpoint's JS/intelligence-core scope, but worth knowing about if
resuming any work on this repo. See
`docs/audits/SENTINEL-APEX-INTEL-FACTORY-PUBLICATION-RELIABILITY-V1-CERTIFICATION.md`.
Nothing below this note is affected by it.

**Date:** 2026-08-24 (round 1); updated 2026-08-24 (round 2); updated 2026-08-24 (round 3); updated 2026-08-24 (round 4); updated 2026-08-24 (round 5, same day, different branch each time)
**Branch:** `claude/sentinel-apex-global-cti-commercial-v3` (round 1, merged as PR #128); `claude/p0-intelligence-core-correlation-v1` (round 2, merged as PR #129); `claude/p0-campaign-delivery-integrity-v1` (round 3, merged as PR #130); `claude/p1-unified-intelligence-search-v1` (round 4, merged as PR #131); `claude/p1-intelligence-dossiers-v1` (round 5, this update, PR open)
**Written per:** the master mandate's own "Long-Run Checkpoint Policy" — stop at a safe boundary, commit, push, update the PR, and leave a clear resume point rather than attempting the full 70-phase mandate in one uninterrupted pass.

**READ THIS FIRST IF RESUMING:** §10 below (added in round 5) is the most consequential update — the first genuinely new customer-facing **UI** in this lineage (Intelligence Dossiers: `dossier.html` + `action=dossier`), built on top of round 4's search/entity-detail backend, exactly the "minimal search UI page" round 4 itself predicted as the natural next slice (§9.6 item 2) — except delivered as a full evidence-backed dossier, not just a search results page. §9 (round 4): Unified Intelligence Search is merged (PR #131) — search index, `action=unified-search`/`actor`/`ioc`/`report` all live. §8 (round 3): the campaign-delivery defect is fixed AND merged (PR #130) — `campaigns.json` now correctly accumulates. §7 (round 2) still holds: **Vercel is being retired** (decision final per the user; technical cutover incomplete) **and Cloudflare Workers is the sole target platform.** Round 1's "Thread A" (build real correlation logic for `intelligence/correlations.js`) remains **NO-GO** — see §7.1. Do not restart any of these without reading §7, §8, §9, and §10 first.

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

---

## 8. Round 3 update (2026-08-24, branch `claude/p0-campaign-delivery-integrity-v1`)

Fixed the campaign-delivery defect §7.4 (round 2) found and deliberately deferred. Full detail: `docs/audits/SENTINEL-APEX-CAMPAIGN-DELIVERY-INTEGRITY-V1-CERTIFICATION.md`, `docs/audits/SENTINEL-APEX-VERCEL-RETIREMENT-INVENTORY.md`, `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`.

**8.1 — Root cause fixed at the source, not patched around.** `campaign-engine.js` gained `mergeCampaigns()`/`mergeCampaign()` (upsert-by-`campaign_id`, field-specific merge semantics — union arrays, min/max dates, OR flags, max confidence, severity recomputed from merged flags) and `saveCampaigns()` gained an independent catastrophic-drop guard at the actual write chokepoint (refuses to persist a count decrease below what's already on disk, unless explicitly told to). `enrichment-pipeline.js` now loads existing `campaigns.json` and merges into it every cycle instead of overwriting. **Do not revert this to a raw `saveCampaigns({ campaigns })` call** — that reintroduces the exact incident this fixed.

**8.2 — The ~1,187 already-lost campaigns were recovered, not left for a future round.** `reconstructCampaignsFromGraph()` derives full campaign objects from the graph's own Campaign nodes/edges (dry-run validated against the real production graph first — 1,187/1,187 reconstructed, zero duplicates/orphans, a spot-checked sample cross-verified against `threat-graph.js`'s own hardcoded ground truth). Executed via `scripts/backfill-campaigns-from-graph.js --write`. Honestly labeled `clustering_model: 'graph_reconstruction_v1'` (never `weighted_v2`) with a disclosed fidelity gap on `shared_iocs` (see the certification doc §9) — this is not claimed to be identical to what live clustering would have produced, only a faithful, non-fabricated derivation of what the graph already recorded. **If resuming: `api/intel/campaigns.json` now has 1,187 real campaigns committed in this branch — do not treat a future empty/near-empty count as normal without checking whether the merge fix (8.1) is still in place.**

**8.3 — Graph↔API consistency verified, not assumed.** Post-fix, `campaigns.json`'s campaign IDs and the graph's Campaign node IDs are in exact agreement (1,187 = 1,187), checked directly against the real committed files, not a synthetic fixture.

**8.4 — Also produced this round, as explicitly asked for by the mandate**: `docs/audits/SENTINEL-APEX-VERCEL-RETIREMENT-INVENTORY.md` (classifies Vercel artifacts by retirement readiness, built on top of the pre-existing `VERCEL_MIGRATION_INVENTORY.md` rather than re-deriving it; flags the Vercel Cron trigger status for `api/cron/dispatch-intel.js` as the one genuinely **UNKNOWN** item blocking a safe cutover) and `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md` (per-domain canonical-ownership table, to prevent a repeat of 8.1's failure mode for any other intelligence type).

**Test baseline after round 3** (in addition to §4 and round 2's baseline above):
```
node --test tests-js/*.test.js
# Expect: 155 tests, 155 pass, 0 fail (123 pre-existing + 25 merge/guard + 7 reconstruction)

node --test workers/lib/*.test.js
# Expect: 116 tests, 116 pass, 0 fail (unchanged from round 2)

npx jest --silent
# Expect: 1 skipped suite (unrelated, pre-existing), 1797 passed, 0 failed

npx tsc --noEmit
# Expect: no output
```

**Next recommended tranche, as of round 3** (superseded by round 4's own ranking in §9.6 below — kept here for history):
1. **Resolve the Vercel Cron `UNKNOWN` status (§8.4)** — the one concrete blocker this round found standing between "Cloudflare routing is ready" and "cutover is safe." Low implementation risk, high blocking value; mostly requires operator dashboard access this session doesn't have, not code.
2. **Malware node population** — still the most-referenced, longest-standing real gap (`platform/open-issues.md` Issue 8, unchanged across 4 sprints) blocking a genuinely complete correlation/graph story; real entity-extraction work, not a quick fix.
3. **Actor-attribution coverage** (still ~2%/~1% of the graph) — same reasoning as malware population; would make the correlation layer (already real and live) meaningfully more useful without requiring new architecture.
4. Do **not** restart Thread A (SOC-workbench correlation-engine building) until the workbench has real analyst-generated data to correlate — re-check `evidence-manager.js`/`intelligence-manager.js` population before considering this again.

---

## 9. Round 4 update (2026-08-24, branch `claude/p1-unified-intelligence-search-v1`, PR #131 open, not yet merged)

Shipped Unified Intelligence Search v1 on top of round 3's now-correctly-accumulating campaign data. Full detail: `docs/audits/SENTINEL-APEX-UNIFIED-INTELLIGENCE-SEARCH-V1-CERTIFICATION.md` (CONDITIONAL GO — read it before touching `api/_lib/search-index.js` or the new `api/v1/intel.js` actions again).

**9.1 — What shipped.** A genuinely cross-entity search (CVE/Campaign/ThreatActor/IOC/published-Report) computed **in-memory from already-canonical data**, never persisted as a second store — deliberately, to structurally eliminate the drift-risk class round 3's campaign-delivery fix had to guard against rather than merely guard against it again. New actions on the existing `api/v1/intel.js` router: `action=unified-search`, `action=actor`, `action=ioc`, `action=report`. `action=cve` gained an additive, pro/enterprise-only `related` field (real campaigns/actors via graph edges). Every existing action, route, and response field is unchanged — zero routing-file (`vercel.json`/`route-table.js`/`router.js`) changes were needed, since this stays inside `api/v1/intel.js`'s existing `action=` dispatch pattern.

**9.2 — Malware and standalone ATT&CK-technique search are explicitly NOT supported**, for the same evidence-based reason round 3's own capability-map entry already established: 0 populated Malware nodes exist anywhere in production data (re-confirmed directly this round), and no canonical ATT&CK technique registry exists in this codebase at all. Building either would mean a search feature advertising coverage that isn't real — refused per this mandate's own STRICT TRUTH RULE. **If resuming: do not add these as supported search types without first re-verifying real data backs them** (re-run the same direct-count check this round did against the live graph).

**9.3 — Resolved a previously-open architectural question.** `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md` had flagged, unresolved, whether `api/v1/ioc/search.js`/`[id].js` share the same IOC data as the graph. Confirmed this round: they do not — that route reads a separate, disconnected, unauthenticated, near-empty (2-record) store (`data/ioc-canonical.json`) that nothing in the live pipeline writes to. The new `action=ioc` correctly uses the real 886-node graph instead. **The old `ioc/search.js` route itself was not fixed** — see 9.4.

**9.4 — Found, not fixed: three pre-existing security/robustness gaps.** `api/v1/ioc/search.js`, `api/v1/ioc/[id].js`, and `api/v1/detections/rules.js` have **no authentication at all**; `api/v1/workbench/search.js`'s `limit` param has no upper clamp. All four tracked in detail as `platform/open-issues.md` Issue 20. Deliberately not fixed this round — each deserves its own reviewed sprint rather than a drive-by fix riding along with an unrelated feature, matching this codebase's own established caution (Issue 1, Issue 8).

**9.5 — Investigation integration is documentation-only, not new code.** `evidence-manager.js`'s `addEvidence()` was found to already accept free-form content with zero ID-scheme validation — referencing a new canonical entity ID as investigation evidence works today via the already-wired `POST /api/v1/workbench/investigations/.../evidence` route, with no code change. Not built further because System A (this round's data) and System B (SOC Workbench) are confirmed, by grep in both directions, fully disjoint — a deliberate, already-documented architectural boundary, not an accidental gap to casually bridge.

**Test baseline after round 4** (in addition to §4 and rounds 2/3's baselines above):
```
node --test tests-js/*.test.js
# Expect: 206 tests, 206 pass, 0 fail (155 prior + 51 new)

node --test workers/lib/*.test.js
# Expect: 116 tests, 116 pass, 0 fail (unchanged)

npx jest --silent
# Expect: 1 skipped suite (unrelated, pre-existing), 1819 passed, 0 failed (was 1797; +22 new)

npx tsc --noEmit
# Expect: no output
```

**9.6 — Next recommended tranche** (ranked by evidence per the mandate's own weighted-factor table — customer value / commercial value / data readiness / trust impact weighted High, differentiation/engineering risk/operational cost weighted Medium — not chosen automatically):
1. **Fix the three unauthenticated/unbounded gaps in Issue 20 (§9.4)** — highest trust-impact-per-effort ratio of anything currently open: small, mechanical, well-understood fixes (add the standard `authenticate()` call, add a `Math.min()` clamp) once someone confirms no current caller depends on the existing behavior.
2. **A minimal search UI page**, now that the backend contract (§9.1) is stable and tested — the natural next slice if a UI is wanted, deliberately not attempted this round to keep the backend certification honest and complete rather than shipping a shallow version of both.
3. **Malware node population** and **actor-attribution coverage** — unchanged from round 3's own ranking (§8's list), still real, still not a quick fix; now additionally unlocks the Malware search-type exclusion (§9.2) once real data exists.
4. **Resolve the Vercel Cron `UNKNOWN` status** — unchanged from round 3, still mostly an operator-dashboard-access blocker, not code.
5. Do **not** restart Thread A (SOC-workbench correlation-engine building) — unchanged reasoning from round 3.

## 10. Round 5 update (2026-08-24, branch `claude/p1-intelligence-dossiers-v1`, PR open, not yet merged)

Shipped CVE and Campaign Intelligence Dossiers on top of round 4's search/entity-detail backend — the first customer-facing **UI** anywhere in this v3 lineage. Full detail: `docs/audits/SENTINEL-APEX-INTELLIGENCE-DOSSIERS-V1-CERTIFICATION.md` (CONDITIONAL GO — read it before touching `api/_lib/intelligence-dossier.js` or `dossier.html` again).

**10.1 — What shipped.** `api/_lib/intelligence-dossier.js` (new): `buildCveDossier()`/`buildCampaignDossier()`, a computed, decision-oriented projection (identity, deterministic assessment, risk, exploitation, relationships, evidence, timeline, ATT&CK context, detections, reports, analyst actions, data quality) over the exact same canonical sources round 4 already established — no new intelligence store. New action `GET /api/v1/intel?action=dossier&type=cve|campaign&id=...` on the existing router. New customer-facing page `dossier.html`, matching the platform's existing design system exactly (same CSS custom properties, same in-memory-only API-key pattern as `api-dashboard.html`).

**10.2 — Closed a real, pre-existing Cloudflare-Workers-reachability gap, additively.** `getCVEDetail()`'s rich per-CVE archive (`api/intel/cve/*.json` — real EPSS scores 40% populated, source citations 99% populated, structured scoring explanation 98% populated) was only ever reachable on its `!isCloudflareWorkers()` branch — meaning this real, already-computed data was invisible on the platform's own declared canonical runtime. `scripts/generate-cve-enrichment-index.js` (new, same proven pattern as round 4's `generate-reports-index.js`) aggregates it into a small (1.3MB), bundleable `api/intel/cve-enrichment-index.json`. Nothing computed or invented — every field copied verbatim.

**10.3 — Threat Actor and Malware dossiers deliberately NOT built.** Actor: `action=actor` (round 4) already delivers full identity/relationships/timeline for all 8 curated actors — a third dossier wrapper around already-shipped data was judged to dilute focus without a clear new outcome; CVE/Campaign dossiers link to `action=actor` rather than duplicating it. Malware: 0 populated nodes, unchanged finding from every prior round. **If resuming: do not build either without first re-verifying real data backs them**, same discipline round 4's §9.2 already established for search types.

**10.4 — Detections found honestly unavailable, not force-fit.** Investigated `api/intel/products/*.json` (1,664 files) directly as a possible per-CVE detection source: only 19% have any real content, and the one sample checked had an empty `cves[]` and low-signal output (a Suricata rule matching a citation URL). No reliable CVE/campaign-keyed detection index exists anywhere in this codebase. `buildDetectionsSection()` always honestly returns `available: false`. Tracked as `platform/open-issues.md` Issue 22 with a concrete suggested-fix design (a build-time aggregator matching the same proven pattern as 10.2, gated by a quality check on what counts as a genuine detection). **If resuming: do not wire live per-request scanning of the products directory** — it would violate this dossier's own bounded-output discipline and risks surfacing low-quality "detections" the CLAUDE.md truth policy exists to prevent.

**10.5 — Found and fixed two real bugs via real browser QA (Playwright/Chromium), not caught by static review or unit tests alone.** (a) A tier-bypass gap: the CVE/campaign dossier's relationship computation originally queried the graph directly regardless of tier, bypassing the same free/starter gate `action=cve`'s `attachCveRelated()` already enforces — fixed by gating inside `intelligence-dossier.js` itself, verified across all 4 tiers. (b) An XSS gap: `renderReports()` in `dossier.html` used `esc()` (HTML-escaping only, no URL-scheme validation) for a report's `href`, letting a `javascript:` URL render as a live clickable link — fixed by routing through the same `safeHref()` scheme-validator already used correctly elsewhere on the page. Also found and fixed a mobile-nav horizontal-overflow bug (a CSS rule present in `api-dashboard.html` that wasn't copied over). Final tallies: 41/41 main QA checks, 10/10 adversarial XSS/injection checks, all against real Chromium and real production data.

**10.6 — Investigation/Case integration confirmed not safely reachable, not built.** Re-confirmed round 4's §9.5 finding by reading `api/v1/workbench/investigations.js`/`cases.js` directly this round: gated exclusively by `requireAnalyst()`/`X-Analyst-Key`, zero customer/session auth path anywhere in either file. An "Add to Investigation" button on this customer-facing page would be non-functional for its actual audience — not built, per the mandate's own "no half-working UI buttons" instruction.

**Test baseline after round 5** (in addition to §4 and rounds 2/3/4's baselines above):
```
node --test tests-js/*.test.js
# Expect: 208 tests, 208 pass, 0 fail (206 prior + 2 new: dossier_url contract)

node --test workers/lib/*.test.js
# Expect: 116 tests, 116 pass, 0 fail (unchanged)

npx jest --silent
# Expect: 1 skipped suite (unrelated, pre-existing), 1838 passed, 0 failed (was 1819; +19 new: intel-dossier.test.js)

npx tsc --noEmit
# Expect: no output
```
Real-browser QA (not part of the above, no CI wiring yet — ad hoc Playwright scripts in this session's scratchpad, not committed to the repo): 41/41 main + 10/10 adversarial checks passed. **If resuming and real browser QA is needed again: Playwright's Node driver is not a repo dependency** (installed ephemerally outside the repo this round, deliberately not added to `package.json` for a one-time QA pass) — re-install if needed (`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install playwright`, browser binary is pre-installed at `/opt/pw-browsers/chromium` in this environment).

**10.7 — Next recommended tranche** (ranked by evidence, not chosen automatically):
1. **Build the detection-to-entity linkage index (Issue 22, §10.4)** — the single highest-leverage remaining gap between what the dossier promises structurally (a `detections` section) and what it can honestly deliver today.
2. **Fix the three unauthenticated/unbounded gaps in Issue 20 (round 4 §9.4)** — still open, still the highest trust-impact-per-effort ratio of anything else currently tracked.
3. **Saved Searches / Watchlists / Alerting**, per the master mandate's own suggested next sequence (Dossiers → Watchlists → Change Detection → Alerts) — now that both the search backend (round 4) and a real dossier UI (round 5) exist to build a "watch this CVE/campaign" feature on top of.
4. Malware node population, actor-attribution coverage, Vercel Cron status — unchanged, still real, still not quick fixes.
5. Do **not** restart Thread A — unchanged reasoning from round 3.
