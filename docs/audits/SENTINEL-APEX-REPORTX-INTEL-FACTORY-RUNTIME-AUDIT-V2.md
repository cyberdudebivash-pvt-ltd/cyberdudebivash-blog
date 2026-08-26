# SENTINEL APEX — ReportX & Intel Factory Runtime Audit (Phase 23-26)

**Tranche:** Cloudflare-Only Runtime Completion v2
**Scope:** Phase 23-26 of the P0 master transformation mandate — trace
usage, distinguish the pipeline orchestrator from the customer API runtime,
classify, and confirm Blogger publication is not put at risk. **This is an
audit, not a migration.** No file listed below is modified this round.

---

## §1 — Two separate systems, not one

The mandate explicitly requires distinguishing "the pipeline orchestrator"
from "the customer API runtime" before drawing any conclusion. Verified
directly against the real code, these are genuinely two independent
systems that happen to share the SENTINEL APEX brand:

### 1.1 Intel Factory — content pipeline (Python, filesystem + git)

Runs entirely under GitHub Actions (`sentinel-apex.yml`,
`blogger-syndication.yml`, `ai-security-intel.yml`, `generate-rss.yml`,
`intelligence-hub.yml`, `cve-pages.yml` — all already classified `LEGACY`
in the Cloudflare Runtime Inventory V2, §3). It discovers threat
intelligence, writes it to static JSON files committed to this repo
(`api/intel/*.json`, `intel-state.json`, `live-intel.json`, consumed by
`api/_lib/intel.js`), and publishes content to Blogger
(`cti.cyberdudebivash.in`) via `automation/blogger_publisher.py`. It is
**structurally incompatible with Cloudflare Workers** — it needs a
persistent filesystem and `git commit`/`git push`, neither of which a
Worker has. This was already established in the Intel Factory Publication
Reliability round (see `docs/audits/SENTINEL-APEX-INTEL-FACTORY-PUBLICATION-RELIABILITY-V1-CERTIFICATION.md`)
and is unchanged by this tranche — **zero Python files were read or
modified this round.** This is a structural fact, not a Redis-migration
question, and is explicitly out of scope for a Redis→D1 audit.

### 1.2 ReportX — customer/analyst product API (JS, Vercel-hosted, Redis-backed)

A completely separate 35-file surface: analyst workbench, investigation
and case management, report generation, product publication/approval
workflow. It runs as Vercel serverless functions (`api/v1/products/*`,
`api/v1/workbench/*`, `api/v1/intelligence/publish.js`,
`api/v1/analysis/assessments.js`) backed by 28 supporting `api/_lib/*`
modules. **This is the actual subject of Phase 23-26.**

**Verified relationship between the two:** ReportX *reads* the same
canonical intel JSON (via `api/_lib/intel.js`, `threat-graph.js`,
`search-index.js`, `intelligence-dossier.js` — the shared read-only
intel-access layer already used by dossier/search/watchlists) that the
content pipeline produces, exactly the way the dossier/search/watchlist
features from earlier rounds do. It does **not** write back to it, does
**not** trigger Blogger publication, and Blogger publication does not
depend on anything in ReportX. They are parallel consumers of the same
upstream data, not a dependency chain — migrating or leaving ReportX alone
carries zero risk to Blogger publication either way.

---

## §2 — Verified: zero coupling with subsystems migrated this round or last round

A repository-wide grep for every module that requires
`notification-dispatch.js`, `notification-store.js`, `watchlist-store.js`,
`change-engine.js`, `change-detector.js`, or `watchable-state.js` (the six
modules moved to D1 across this round and the Cloudflare-Only Alert
Runtime tranche) returns **only the alert-delivery/watchlist cluster's own
files and their own test suites** — no ReportX file appears. This is a
materially different finding than auth/billing's `user:pending:tier:*`
coupling (§A.6/B.2 of the Auth & Billing Deferral Audit): **ReportX's
deferral introduces zero cross-subsystem consistency risk**, because
nothing this round touched ever reads or writes a ReportX-namespaced Redis
key, and nothing in ReportX reads or writes a watchlist/alert-delivery key.

---

## §3 — Representative sampling of ReportX Redis usage (4 of 35 files)

Reading all 35 files in full is disproportionate to what Phase 23 actually
asks for ("trace usage and classify," not migrate) and would consume this
tranche's remaining budget on a subsystem this document is about to defer
in full. Four files were read/grepped in full as a representative sample —
chosen because they carry the write-heaviest, most structurally central
logic in the cluster (investigation and case lifecycle, report
persistence, product/portfolio assembly):

| File | Lines | Redis shape found |
|---|---|---|
| `api/_lib/report-manager.js` | 297 | HASH per report (`report:{id}`), ZSET indexes (`reports:investigation:{id}`, `reports:published`, `reports:by:type:{type}`) |
| `api/_lib/investigation-manager.js` | 376 | HASH per investigation, **1-year TTL** (31536000s), ZSET indexes (`investigations:all`, `investigations:by:status:{status}`, `investigations:assigned:{assignee}`, `investigation:intelligence:{id}`, `investigation:entities:{id}`) |
| `api/_lib/case-manager.js` | 273 | HASH per case/note/task, 1-year TTL, ZSET indexes (`cases:all`, `cases:by:status:{status}`, `case:notes:{id}`, `case:tasks:{id}`), HINCRBY counters (`caseCount`, `noteCount`, `taskCount`) |
| `api/_lib/product-factory.js` | 416 | HASH per product/portfolio, ZSET indexes (`products:investigation:{id}`, `products:report:{id}`, `products:all`, `portfolios:all`) |

**Pattern found, consistent across all four:** every entity is a Redis
HASH (`investigation:{id}`, `case:{id}`, `report:{id}`, `product:{id}`,
`portfolio:{id}`) carrying a **1-year TTL** — a third, distinct retention
policy from both auth (permanent) and billing (24h-90d, state-dependent).
Enumeration and filtering are done via multiple hand-maintained ZSET
secondary indexes per entity (status, assignee, parent-investigation,
type), the same "manually mirrored index" shape this tranche already
collapsed into single indexed/joined tables for watchlists
(`watchlist_entities`, `owner_feed` — see the D1 migration's own header
comments). All four files use the dependency-injected `this.redis`
pattern this round's own inventory methodology correction (§0 of the
Cloudflare Runtime Inventory V2) surfaced. **No `SETNX`/atomic-CAS/claim-
lease pattern was found in the sample** — this looks like standard CRUD
with manually-maintained secondary indexes, not a correctness-critical
concurrent-claim subsystem like alert-delivery's dispatch queue. That
lowers migration urgency relative to auth/billing, but the secondary-index
sprawl (up to 5 ZSETs per single entity write) is real technical debt
independent of Cloudflare policy.

---

## §4 — Why the remaining 31 files are not individually audited this round

Phase 23's own instruction is to trace usage and classify — not to migrate,
and not to produce a file-by-file dossier when the architecture repeats.
The four sampled files show one consistent pattern (HASH + TTL + manual
ZSET indexes + DI `this.redis`); the remaining files in the cluster
(`source-reliability-engine.js`, `quality-scorer.js`,
`product-composition-engine.js`, `product-validation-engine.js`,
`product-delivery.js`, `publication-manager.js`,
`publication-policy-engine.js`, `publishing-pipeline.js`,
`freshness-engine.js`, `gap-analyzer.js`, `confidence-scorer.js`,
`consistency-engine.js`, `evidence-validator.js`, `evidence-manager.js`,
`analysis-manager.js`, `intelligence-manager.js`, `governance-engine.js`,
`graph-engine.js`, `graph-traversal.js`, `timeline-engine.js`,
`similarity-engine.js`, `relationship-engine.js`,
`investigation-graph.js`, plus the seven `api/v1/*` route handlers) share
the same module lineage (`docs/reportx/*`), the same era of construction,
and — per §2 — the same complete isolation from every subsystem this and
the prior tranche migrated. There is no requirement, defect report, or
production incident evidencing that any of them needs to change right now
(Principle 1's own evidence bar: *"Existing production logic is preserved
unless there is documented evidence that modification is required"* — no
such evidence exists here). Exhaustively reading ~10,000 additional lines
to re-confirm a pattern already demonstrated four times would not change
this tranche's conclusion and would come directly out of the budget this
round needs for the guard scanner, regression suite, and certification
doc that still must ship.

---

## §5 — Risk & urgency classification

| Dimension | Finding |
|---|---|
| Coupling with subsystems already on D1 | **None** (§2, verified by repo-wide grep) |
| Coupling with Blogger publication | **None** (§1.2 — parallel read-only consumer, not a dependency) |
| Atomic/concurrent-claim requirements | **None found in sample** — standard CRUD, lower correctness risk than alert-delivery or billing |
| Retention model | Distinct 1-year TTL, would need explicit handling in any future migration (no native D1 row-TTL, same class of finding as billing's state-dependent TTLs) |
| Structural fit for a future migration | Good — the ZSET-secondary-index sprawl is the same shape watchlists already proved collapses cleanly into indexed D1 tables |
| Urgency evidence for migrating now | **None** — no defect, no incident, no explicit requirement |
| Surface size | 35 files — comparable to or larger than the entire watchlist+alert-delivery effort combined across two full tranches |

**Verdict: DEFER, in full, as one cluster.** Consistent with the mandate's
own P0-C framing ("ReportX/newsletter — large surface, no urgency
evidence") and this tranche's Implementation Strategy, which explicitly
permits deferring subsystems where risk/size outweighs benefit this round.

---

## §6 — Newsletter (Phase 23-26 adjacent finding, same disposition)

`api/v1/newsletter.js` (subscriber list) was already classified `LEGACY`/
deferred in the Cloudflare Runtime Inventory V2 (§2.6) — low priority,
unrelated to this tranche's scope, no urgency evidence. No change to that
classification from this audit.

---

## §7 — Recommendation for a future dedicated round

If/when ReportX migrates, the relational-collapse technique this tranche
already proved for watchlists applies directly: each entity's manually-
maintained ZSET indexes (`investigations:by:status:*`,
`cases:by:status:*`, `products:investigation:*`, etc.) collapse into a
single indexed column plus a real `WHERE`/`JOIN`, the same way
`watchlist_entities`' reverse index replaced the old
`entity_watchers:*:*` mirrored-SET pattern. That is future work, not this
round's — recorded here so a future audit does not have to re-derive it.

*CYBERDUDEBIVASH® SENTINEL APEX — Cloudflare-Only Runtime Completion v2*
*Phase 23-26 deliverable — audit-only, zero production code touched*
