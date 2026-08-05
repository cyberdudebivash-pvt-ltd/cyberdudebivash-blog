# Project TITAN Stage 7 — Blog Repository Addendum

**Status:** Informational, urgent. This is the only file this stage adds to
`cyberdudebivash-blog`. No existing file — including anything under `api/`, `api/_lib/`, or
`lib/` — is modified.

---

## What was found

While tracing API interfaces for Project TITAN Stage 7 (cross-repo API governance work based
in `CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM`), a reachability trace of this repository's Vercel
deployment found that `vercel.json`'s `"functions"` block (which explicitly configures only 8
files: `api/v1/intel.js`, `auth.js`, `billing.js`, `admin.js`, two billing webhooks, a cron
job, and `api/og.js`) does **not** restrict what Vercel actually deploys — it only tunes
memory/duration for those 8. There is no `"builds"` key and no `.vercelignore` exclusion for
`api/v1/*`. Direct count: **30 `.js` files exist under `api/v1/`**, not 8.

The other 22 — `api/v1/intelligence/{confidence,correlations,graph,objects,publish,
similarity}.js`, `api/v1/workbench/{cases,dashboard,investigations,search}.js`,
`api/v1/analysis/{assessments,findings}.js`, `api/v1/customer/{dashboard,download}.js`,
`api/v1/detections/rules{,/[id]}.js`, `api/v1/ioc/{search,[id]}.js`, `api/v1/products/*`,
`api/v1/quality/index.js`, `api/v1/newsletter.js`, `api/v1/reports/index.js` — are, per
Vercel's standard file-based routing, **very likely live, deployed serverless functions that
nothing in this repository's own documentation acknowledges.**

These routes call a substantial `api/_lib/` engine cluster — `confidence-scorer.js`,
`confidence-exposure.js`, `evidence-manager.js`, `evidence-validator.js`,
`evidence-conflict-engine.js`, `evidence-traceability-engine.js`, `source-reliability-engine.js`,
`graph-engine.js` (34 entity types, 31 relationship types, Redis-persisted),
`graph-traversal.js`, `relationship-engine.js`, `correlation-engine.js`, `governance-engine.js`
(RBAC + publication policy), `quality-gates-engine.js`, `quality-scorer.js`,
`quality-validators.js`, `threat-scorer.js`, `consistency-engine.js` — that compute confidence,
evidence, source-reliability, and relationship-graph data for the same class of object (CVEs,
threat articles) this program's other ADRs already govern in the sibling intel-platform repo.

**Verified directly, not inferred:** `api/v1/intelligence/confidence.js`'s own header
documents "Returns articles, reports, and CVEs enriched with confidence scores" with a worked
example (`CVE-2024-001`, multidimensional breakdown: source_reliability, evidence_quality,
analyst_assessment, temporal_relevance, corroboration, plus a `governance` block showing
publish status/version/reviewers). `api/v1/customer/dashboard.js` is a working "Customer
Self-Service Dashboard" — purchase history, subscription status, download links, API key/tier
status.

## Why this matters for this repository specifically

This directly contradicts this repository's own `CLAUDE.md`: "DO NOT duplicate Sentinel APEX
functionality on the blog," and names `intel.cyberdudebivash.com` as the sole owner of "Live
APIs and intelligence feeds... Customer-facing API portal." No architecture document in this
repository (`docs/architecture/*`, `platform/open-issues.md`'s extensive fragmentation
tracking) mentions this system. It is not the same thing as the dormant `lib/` tree this
program flagged last stage (`TITAN_STAGE6_BLOG_ADDENDUM.md`) — that tree is confirmed to have
zero consumers; this system is very likely receiving real traffic today.

**Confidence level:** high but not certain — based on Vercel's documented default routing
behavior and the absence of any found exclusion mechanism, not on direct traffic/dashboard
confirmation, which this environment cannot obtain.

## Recommended immediate action

Whoever has this repository's Vercel dashboard or CLI access should confirm, as a priority
item, whether these 22 routes are actually serving production traffic — before any further
architectural decision is made about them. This addendum does not recommend removing,
disabling, or modifying anything; per this repository's own CLAUDE.md production-stability
principles, changing a possibly-live customer-facing system without first confirming its
actual status would itself be the riskier action.

## Where this is tracked in full

- `TITAN_STAGE7_VALIDATION.md` §2A, in `CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM`
- `TITAN_TECH_DEBT_REGISTER.md` DEBT-000 (top entry, Critical) in the same repository
- Revision sections added to `docs/adr/0007`, `0008`, `0009`, `0010` in the same repository —
  all four now explicitly blocked on this finding before they can be Accepted

---

*Project TITAN Stage 7 — cross-repository addendum. Full evidence and governance tracking live
in `CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM`'s `docs/adr/` and `TITAN_*` documents.*
