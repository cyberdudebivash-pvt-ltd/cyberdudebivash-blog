# SENTINEL APEX — Global CTI Platform Phase 0 Production Truth Audit

**Date:** 2026-08-24
**Branch:** `claude/p0-intelligence-core-correlation-v1`
**Mandate:** P0/P1 Master Production Task — Intelligence Core Truth Audit + Evidence-Backed Correlation Engine v1
**Scope of this document:** Phase 0 only (mandatory production-truth audit, required before any correlation-engine code). Per this mandate's own STRICT TRUTH RULE and Non-Negotiable Execution Principle, Phase 0's findings **block** Phases 1–51 unless they affirmatively support building new correlation logic. They do not, for the reason in the Executive Verdict below — but Phase 0 itself surfaced two other real, evidence-based, shippable findings that this round acted on.

---

## 1. Executive Findings

Three findings dominate this audit, in order of how much they should change what anyone does next:

1. **A real, evidence-backed, explainable, deterministic (zero-LLM) correlation capability already exists and is live in production**, in `api/_lib/threat-graph.js` + `campaign-engine.js` + `enrichment-pipeline.js`. It computes `co_occurs_with` correlation edges between Campaigns, CVEs, and Actors from real accumulated data, every edge carries a `sources[]` citation, every campaign carries a `reasoning[]` array, every actor attribution carries a `signals{}` breakdown and an `evidence_summary`, and traversal is defensively capped against combinatorial blowup. As of this audit (verified against the live `api/intel/threat-graph.json`, regenerated 2026-08-24T08:40:53Z — 20 minutes before this check), it holds **62 real `co_occurs_with` edges** across 11,957 nodes and 3,773 edges. **This is, in substance, the "Evidence-Backed Correlation Engine v1" this mandate describes** — it just was never labeled that, having evolved across five prior sprints (GCTIKF v1, GEPMO v1, GCDOM v1, GPEP v1, Phase 2 Hardening) under different names. Building a second, parallel correlation engine would be exactly the duplication this mandate's own Non-Negotiable Execution Principle (AUDIT → REUSE → PROVE → DESIGN → BUILD) prohibits.

2. **A real, live, currently-active commercial-impact bug**: `campaigns.json` (which backs the paid, tier-gated `GET /api/v1/intel/campaigns` endpoint) is fully **overwritten**, not merged, on every ~30-minute ingestion cycle — `saveCampaigns({ campaigns })` in `enrichment-pipeline.js` persists only the current cycle's freshly-clustered campaigns. The **graph** correctly accumulates Campaign nodes forever (1,187 of them, confirmed live), but the **customer-facing endpoint** has no memory across cycles. Verified live right now: `campaigns.json` holds **0 campaigns** despite the graph's 1,187 accumulated Campaign nodes. Every paying customer hitting `/api/v1/intel/campaigns` today sees an empty result. **Not fixed this round** — deliberately, matching this exact file's own established caution precedent (see §18) — but documented with a specific, scoped fix design in the roadmap.

3. **Vercel — the platform's declared production target until this session — has a large, pre-existing, unrelated deployment gap, and mid-session the user clarified that Vercel is being retired in favor of Cloudflare Workers.** Direct live HTTP testing against `blog.cyberdudebivash.in` (still resolving to Vercel at the time of this audit) found that only files flat at the top level of `api/v1/*.js`, plus files explicitly listed in `vercel.json`'s `functions` block, are actually deployed as reachable serverless functions. Every nested-subdirectory file *not* explicitly listed — roughly 24 of the repository's 32 total API function files, including the entire `intelligence/`, `workbench/`, `ioc/`, `quality/`, `customer/`, `reports/`, `analysis/`, and `detections/` surfaces — 404s at Vercel's own edge, even at its bare base path with no sub-path involved. This predates and is unrelated to the routing-gap work in PR #127/#128; it means most of the SOC Workbench and Intelligence Object API has likely never been reachable on production Vercel at all, regardless of any routing fix. Given the user's mid-session instruction that the Vercel-retirement decision is final (technical cutover incomplete), this round did not attempt to fix Vercel's gap — instead it closed the equivalent, already-known routing gap on the actual target platform, Cloudflare Workers (see §19 and the certification doc for this tranche).

**Everything else in this document is supporting evidence for those three findings**, plus the architecture map, capability inventory, and roadmap the mandate's Phase 50 requires.

---

## 2. Architecture Graph

The intelligence core is not one system. It is **three**, independently evolved, with no shared ID space or shared code path between them:

```
┌─────────────────────────────────────────────────────────────────────┐
│ SYSTEM A — Live Bot Pipeline (JS, file-persisted, canonical)         │
│                                                                       │
│  fetch-live-intel.js (28 sources, ~30-min cadence)                  │
│      │                                                               │
│      ▼ correlateAndMerge() → filterSignalFromNoise()                │
│      ▼                                                               │
│  enrichment-pipeline.js  runEnrichmentPipeline(filteredItems)        │
│      │  Step 3: threat-graph.js buildGraphFromIntel()                │
│      │  Step 4/7: threat-graph.js computeActorAttribution()          │
│      │            (4-signal: ioc_overlap/keyword/mentions/campaign)  │
│      │  Step 5: campaign-engine.js buildCampaigns()                  │
│      │            (weighted: ioc/cve/time/text, threshold 0.60)      │
│      │  Step 6b/c/d: linkCorrelated{Campaigns,CVEs,Actors}()         │
│      │            → co_occurs_with edges (THE real correlation layer)│
│      ▼                                                               │
│  api/intel/threat-graph.json (persisted, accumulates forever)        │
│  api/intel/campaigns.json    (persisted, OVERWRITTEN each cycle —    │
│                                confirmed bug, see Finding 2)          │
│      │                                                               │
│      ▼ api/_lib/intel.js (getGraph/getCampaigns/getTopActorsAPI)     │
│      ▼                                                               │
│  api/v1/intel.js — customer-facing, tier-gated, PAID                 │
│  (/api/v1/intel/graph, /campaigns, /top-actors, /campaign/{id})      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ SYSTEM B — SOC Workbench (JS, Redis-persisted, analyst-curated)      │
│                                                                       │
│  Analyst manual action via workbench UI/API                         │
│      │                                                               │
│      ▼                                                               │
│  intelligence-manager.js / intelligence-object.js                    │
│      IDs: intel_<type>_<sha256:16>  — DISJOINT from System A's IDs   │
│      (actor:x / CVE-x / campaign:x, plain strings)                   │
│      │                                                               │
│      ├─ graph-engine.js / graph-traversal.js / relationship-engine.js│
│      ├─ investigation-manager.js / case-manager.js                   │
│      ├─ evidence-manager.js (real schema, investigation-scoped)      │
│      ├─ similarity-engine.js (entity dedup — NOT evidence-backed     │
│      │    correlation; Levenshtein name + property-overlap + conf.   │
│      │    distance. Mandate's own Phase 1.2 distinction: this is     │
│      │    "similarity," not "correlation.")                          │
│      └─ correlation-engine.js (investigation-object-shaped API only  │
│           — correlateThreatActors(investigation), NOT entity-ID/     │
│           graph-based; PR #128 made its would-be entity-ID callers   │
│           return honest 501s rather than fabricate)                  │
│      │                                                               │
│      ▼                                                               │
│  api/v1/intelligence/{objects,correlations,similarity,publish,graph} │
│  api/v1/workbench/{investigations,cases,dashboard,search}            │
│  — internal-only (requireAnalyst/X-Analyst-Key), not customer-facing │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ SYSTEM C — Offline Python Engine (Sentinel-APEX/engine, hand-authored│
│  report pipeline)                                                    │
│  knowledge_graph.py / scoring.py / attack_mapper.py / ioc_extractor.py│
│  Explicitly declared NOT canonical (2026-07-29 decision, still true):│
│  "threat-graph.js (live JS) is canonical" for both Graph and Scoring.│
│  Not further re-audited this round beyond confirming that decision   │
│  still holds and is unrelated to the correlation-engine question.    │
└─────────────────────────────────────────────────────────────────────┘
```

**The mandate's implicit premise — that "correlation" is one missing capability to design and build — does not survive contact with this architecture.** System A already has it, live, evidence-backed, and growing. System B has the right *shape* (evidence-manager.js, graph-engine.js) but essentially no populated data (built days ago, analyst-curated only, no automated feed). System C is explicitly not canonical for anything correlation-related. There is no single "the correlation engine" to build; there is a real one to expose better, and a sparse one that would need real analyst usage before any correlation logic on top of it could be anything but fabricated.

---

## 3. Capability Inventory

| Capability | Implementation | Runtime | Customer Facing | Wired | Tested | Canonical | Status |
|---|---|---|---|---|---|---|---|
| Live threat graph (nodes/edges) | `threat-graph.js` | Live JS, file-persisted | Yes (paid tier) | Yes | Partial (no dedicated test file found for threat-graph.js itself; exercised indirectly) | **Yes** (2026-07-29 decision) | ACTIVE |
| Actor attribution (4-signal, evidence-backed) | `threat-graph.js:computeActorAttribution` | Live JS | Yes (via graph/campaigns) | Yes | Indirect | Yes | ACTIVE |
| Campaign clustering (weighted similarity) | `campaign-engine.js:buildCampaigns` | Live JS | Yes (paid tier) | Yes | Yes (`tests-js/campaign-correlation.test.js` referenced in open-issues.md) | Yes | ACTIVE, but see campaigns.json bug |
| Campaign↔Campaign / CVE↔CVE / Actor↔Actor correlation (`co_occurs_with`) | `enrichment-pipeline.js:linkCorrelated{Campaigns,CVEs,Actors}` | Live JS | Yes (via graph endpoint) | Yes | Yes (`tests-js/{campaign,cve,actor}-correlation.test.js`) | Yes | **ACTIVE — this is the mandate's "correlation engine," already shipped** |
| Tier gating (FREE/PRO/ENTERPRISE) | `enrichment-pipeline.js:applyTierGating` | Live JS | Yes | Yes | Not verified this round | Yes | ACTIVE |
| Intelligence object lifecycle (DRAFT→REVIEW→APPROVED→PUBLISHED) | `intelligence-object.js` / `intelligence-manager.js` | Live JS, Redis | No (internal/analyst only) | Yes (routing fixed PR #128) | Yes (unit + route tests) | Yes, for this object type | ACTIVE but likely near-empty (analyst-curated, workbench days old) |
| SOC Workbench graph (entity relationships) | `graph-engine.js` / `graph-traversal.js` / `relationship-engine.js` | Live JS, Redis | No | Yes | Yes | Yes, for this object type | ACTIVE but likely near-empty |
| Evidence/provenance model (investigation-scoped) | `evidence-manager.js` | Live JS, Redis | No | Yes | Not independently re-verified this round | Yes | ACTIVE but likely near-empty — populated only by analyst action |
| Entity-ID correlation for `IntelligenceObject`s | `api/v1/intelligence/correlations.js` handlers | Live JS | No | Yes (routes reachable, PR #128) | Yes (honest-501 asserted by test) | **No canonical implementation exists** | **STUB (deliberately, honestly — 501)** |
| Entity dedup / similarity (SOC Workbench) | `similarity-engine.js` | Live JS, Redis | No | Yes | Yes | Yes, for this object type | ACTIVE but likely near-empty |
| Offline knowledge graph (Python) | `knowledge_graph.py` | Offline, not automated | No | Partial | Not re-verified this round | **No** (2026-07-29 decision) | DORMANT / CANDIDATE FOR REFACTORING |
| Offline scoring (Python) | `scoring.py` | Offline | No | Partial | Not re-verified this round | **No** (2026-07-29 decision) | DORMANT |
| Detection generation (Sigma/KQL/Splunk/OSQuery/Suricata) | `engine-node/detection-engine.js` + `sigma_builder.py` | Live JS (5-min cadence) + parity Python | Yes (paid) | Yes | Not re-verified this round | Yes (deliberate dual-runtime, not duplication) | STABLE (per capabilities.md, not re-verified) |

---

## 4. Live vs. Dormant Capabilities

- **Live and accumulating**: `api/intel/threat-graph.json` (11,957 nodes / 3,773 edges, generated 20 minutes before this check) and the enrichment pipeline that builds it. This is a genuinely live, growing, evidence-backed system.
- **Live but architecturally broken (overwritten, not accumulated)**: `api/intel/campaigns.json` — Finding 2 above.
- **Deployed but likely unreachable in production (Vercel)**: `api/v1/intelligence/*`, `api/v1/workbench/*`, and 5 other subdirectories — Finding 3 above. Code-complete, unit-tested, and *possibly never once served a real request in production*.
- **Schema-complete but data-empty**: the SOC Workbench's `IntelligenceObject`/evidence/graph stack (System B). No automated feed populates it; it depends entirely on analyst usage of a workbench that was only built and certified 3 days before this audit (`SOC-WORKBENCH-RELEASE-CERTIFICATION.md`, 2026-08-21).
- **Explicitly non-canonical, not automated**: the offline Python engine (System C) — a 2026-07-29 decision, re-confirmed, not re-litigated this round.

---

## 5–10. Intelligence Core / Graph / Objects / Similarity / Correlation / Campaign

Covered together, since in this codebase these six mandate-requested sections map onto the two-system split in §2 rather than six independent subsystems:

- **Graph**: two graphs exist. System A's (`threat-graph.js`) is canonical, live, and the one with real correlation edges. System B's (`graph-engine.js`) is the SOC Workbench's per-object relationship graph — schema-complete, likely near-empty.
- **Objects**: `IntelligenceObject` (System B) is the only formal "intelligence object" model in this codebase. System A has no equivalent formal object type — its nodes are typed dicts (`ThreatActor`/`CVE`/`Campaign`/`Malware`/`IOC`) in a plain graph, not versioned/lifecycle-gated objects.
- **Similarity**: System B's `similarity-engine.js` computes entity *similarity* (Levenshtein name distance + property overlap + confidence-level distance) for deduplication — explicitly not evidence-backed correlation, and the mandate's own Phase 1.2 distinction ("similarity" vs. "correlation") already applies to it correctly. System A's `campaign-engine.js:computeItemSimilarity` is a *different* similarity function (IOC/CVE/time/text weighted Jaccard), used as an intermediate signal inside campaign clustering — also not itself "correlation" in the mandate's sense, but its *output* (clustered campaigns) feeds directly into real correlation (`co_occurs_with` edges).
- **Correlation**: System A's `co_occurs_with` edges are the real thing. System B's `correlation-engine.js` is not implemented for entity-ID/graph-based correlation at all (PR #128 confirmed this and shipped honest 501s rather than crash or fabricate).
- **Campaign**: `campaign-engine.js` (System A) is a mature, weighted, explainable clustering engine with documented formulas, time-decay, actor-overlap bonuses, and per-campaign `reasoning[]`. It is real and good. Its output's *persistence* (`campaigns.json`) is broken (Finding 2).

---

## 11. Evidence / Provenance

Two real, distinct evidence models exist, matching the two-system split:

- **System A**: every `co_occurs_with` edge carries `sources: [...]` (e.g. `"shared CVE: CVE-2023-27351"`); every actor attribution carries `evidence_summary` and a `signals{}` breakdown; every campaign carries `reasoning[]`. This is evidence-as-citation, generated automatically from the graph's own already-existing edges — not a separate evidence *store*, but a real, auditable evidence *trail*.
- **System B**: `evidence-manager.js` is a genuine, separate evidence *store* — typed (`ARTICLE`/`THREAT_REPORT`/`IOC`/`MALWARE`/`FILE`/`HASH`/`PCAP`/`URL`/`DOMAIN`/`SCREENSHOT`/`EXTERNAL_REFERENCE`/`DETECTION_RULE`/`NOTE`), Redis-persisted, `investigationId`-scoped, with `sourceUrl`, `confidence`, `linkedGraphEntities`, and timeline recording. Real schema. Populated only by analyst action within an active investigation — given the workbench is 3 days old, very likely near-empty in production today. Not independently re-verified against live Redis this round (no credentials available in this sandbox, consistent with every prior round's documented limitation).

Neither model is missing. What's missing is a model that spans both — but building one would require either merging two systems with disjoint ID spaces (a large, genuinely risky architectural change, not something to attempt as a side effect of a correlation-engine task) or picking one system's evidence model as canonical for correlation purposes, which this audit does implicitly by recommending System A's `co_occurs_with` layer as the thing to expose better (§19), not by proposing a merge.

## 12. Search

Not independently re-audited this round beyond what capabilities.md already documents (`search-index.json` / `generate-search-index.py`, Stable, scoped to `posts/` only). `api/v1/workbench/search.js` and `api/v1/ioc/search.js` exist as separate, SOC-workbench/IOC-specific search surfaces — not examined in depth this round; flagged as a gap for a future audit pass, not assumed equivalent to the posts-only search index.

## 13. Workbench

Covered in `SOC-WORKBENCH-RELEASE-CERTIFICATION.md` (2026-08-21) and `SENTINEL-APEX-INTELLIGENCE-CORE-API-INTEGRITY-CERTIFICATION.md` (this branch's parent, 2026-08-24). This audit's contribution: confirming those certifications' code-level claims are accurate, while also discovering (Finding 3) that the underlying Vercel deployment may have never actually served any of it in production. The workbench's correctness was never in question; its *reachability* was.

## 14–15. API / Customer Surfaces

- **Customer-facing, paid**: `api/v1/intel.js`'s `/graph`, `/campaigns`, `/top-actors`, `/campaign/{id}` — the System A surface. This is where real correlation data (`co_occurs_with`) is already exposed today, tier-gated.
- **Internal-only, analyst-facing**: `api/v1/intelligence/*`, `api/v1/workbench/*` — System B, gated by `X-Analyst-Key`/`requireAnalyst`, never customer-facing by design.
- **Deployment reachability**: see Finding 3. This section would normally describe response-shape stability and versioning; instead, this round's most material finding about the API surface is that a large fraction of it may not be reachable on the currently-live platform at all.

## 16. Security

No new security findings this round beyond what PR #128 already fixed (identity-trust bugs, routing-gap-driven unreachability) and what this round's Cloudflare fix preserves (`requireAnalyst` auth gate is untouched — the Cloudflare fix only changes how `req.query.apexSubpath` is populated before the handler's own auth check runs, exactly mirroring the Vercel mechanism; verified live end-to-end via `router.test.js`'s new tests that an unauthenticated sub-path request gets the handler's real 401, not a routing bypass).

## 17. Commercial Readiness

- **System A (live public graph/campaigns/actors)**: commercially live today, with one real, currently-active bug reducing its value (Finding 2 — campaigns endpoint effectively empty).
- **System B (SOC Workbench)**: not commercially exposed (internal-only by design), and its production reachability on Vercel is now in question (Finding 3) independent of that design choice.
- **Correlation specifically**: commercially *already delivered* via System A's `/graph` endpoint (`co_occurs_with` edges are included in the returned graph data for Pro/Enterprise tiers per `getGraphForTier()`), just never marketed or documented as "correlation." This is a communications/product-marketing gap, not an engineering one — worth flagging to whoever owns commercial positioning, out of scope for this engineering audit to act on further.

## 18. Architectural Duplication

- **Confirmed, not new**: Python (System C) vs. live JS (System A) — already decided 2026-07-29, live JS canonical, not re-litigated.
- **Newly characterized this round**: System A vs. System B are not "duplication" in the sense Issue 1 uses the term (same capability, two implementations) — they are genuinely different capabilities (automated public threat intelligence vs. analyst-curated case work) that happen to both produce graph-shaped data. Recommending a merge would be architecturally reckless without a much deeper design pass; this audit does not recommend one.
- **`campaigns.json`'s overwrite-not-merge bug (Finding 2)** is not architectural duplication, but it is the same class of "shared, revenue-adjacent infrastructure changed without a dedicated review window" risk that Issue 8's own entries in `platform/open-issues.md` explicitly called out for this exact file across four prior sprints — which is why this round documents it rather than patching it live (see §19).

## 19. P0/P1/P2 Roadmap

**P0 (this round, shipped):**
- Closed the Cloudflare Workers sub-path routing gap for the same 7 files PR #128 already fixed on Vercel (`workers/lib/route-table.js`'s `APEX_SUBPATH_HANDLERS` prefix-match, mirroring `vercel.json`'s wildcard rewrites; `router.js`'s existing `req.query` merge required no change). 116/116 workers tests pass, including 2 new real end-to-end dispatch tests proving unauthenticated sub-path requests reach the real handler's own 401, not a routing 404. Chosen over new correlation-engine code because: (a) Phase 0 found real correlation already exists and shipping a second one would be duplication the mandate itself prohibits; (b) the user's mid-session instruction made Cloudflare Workers parity the concrete, evidence-grounded, immediately actionable priority; (c) it directly serves the "unblock the Cloudflare cutover" goal implied by that instruction.

**P0 (not this round — explicitly deferred, not silently dropped):**
- **Fix `campaigns.json`'s overwrite-not-merge bug** (Finding 2). Design sketch: `saveCampaigns()` (or a new wrapper called before it in `enrichment-pipeline.js`) should load the existing `campaigns.json`, merge the current cycle's freshly-built campaigns into it by `campaign_id` (update in place if a campaign gained new `related_intel_ids`, insert if new), rather than replacing the array wholesale. Deliberately not attempted in this same round: this is the exact same live, ~30-min-cadence, no-review-window production pipeline that `platform/open-issues.md`'s own Issue 8 entries repeatedly declined to touch without "a dedicated sprint with room to test against the real graph first" — that reasoning still applies, especially for a first-time contributor to this specific file in this session. Needs: a merge-correctness test against a realistic accumulated `campaigns.json` fixture (not just an empty-file case), and explicit consideration of whether/how a campaign's `related_intel_ids` should grow vs. stay fixed once first clustered.
- **Diagnose and fix (or consciously accept and document) the Vercel deployment gap** (Finding 3) — moot if the Cloudflare cutover completes first, but until then, ~24 of 32 production API functions are likely unreachable on the platform DNS currently points to. If the cutover is imminent, the right action may simply be "finish the cutover," not "fix Vercel."

**P1:**
- Complete the Cloudflare Workers production cutover itself (DNS, `wrangler.jsonc` production routes/bindings, `PRODUCTION-CUTOVER-RUNBOOK.md` Section 6) — outside this audit's engineering scope (requires operator DNS authorization per that runbook), but this round's routing-parity fix removes one concrete blocker to it.
- Expose System A's existing `co_occurs_with` correlation more directly/discoverably (e.g. a dedicated `/api/v1/intel/correlations/{id}` view derived from already-existing graph edges) rather than only as a sub-field of the full `/graph` response — a product/API-design decision, not a new correlation *capability*.
- Re-audit System B's real data population once the SOC Workbench has had genuine analyst usage (it's 3 days old as of this audit) — only then would building entity-ID correlation for `IntelligenceObject`s have a real, non-fabricated data foundation, per this mandate's own STRICT TRUTH RULE.

**P2:**
- The offline Python→live-JS refactor for Scoring/Graph (2026-07-29 decision, refactor itself still not scoped) — unrelated to this mandate, carried forward from `platform/open-issues.md` unchanged.
- Malware node type population (`threat-graph.js` supports it structurally; nothing populates it) — real, known, unchanged gap.
- Deepen `api/v1/workbench/search.js`/`api/v1/ioc/search.js` audit (§12) — not reached this round.
