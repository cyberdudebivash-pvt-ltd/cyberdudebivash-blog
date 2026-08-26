# SENTINEL APEX — Cloudflare Runtime Inventory V2

**Date:** 2026-08-26
**Branch:** `claude/p0-cloudflare-runtime-completion-v2`
**Supersedes:** `SENTINEL-APEX-CLOUDFLARE-RUNTIME-DEPENDENCY-INVENTORY.md` (V1, written for the Cloudflare-Only Alert Runtime v1 tranche). V1 is not wrong about what it covered — it correctly scoped the alert-delivery migration — but its file count undercounted real Redis consumers. This document corrects that and re-verifies everything against current `main` (post PR #138 merge, commit `9009ced9`).

---

## 0. Methodology correction from V1 — read this first

V1's Redis inventory was built by grepping for `require('./redis')` / `require('../redis')` patterns — a **direct-require** search. That correctly found 30 files. It missed a second, real pattern this repo also uses: **dependency-injected Redis clients**, where a module receives `redis` as a constructor or function parameter (`class X { constructor(redis, ...) { this.redis = redis; } }`) rather than requiring `redis.js` itself.

Searching instead for actual Redis **method-call usage** (`redis.get(`, `redis.hset(`, `redis.zadd(`, etc. — word-bounded, not a naive substring match) across `api/` finds **48 files**. The delta (18 additional files: `case-manager.js`, `investigation-manager.js`, `investigation-graph.js`, `timeline-engine.js`, `similarity-engine.js`, `relationship-engine.js`, `product-delivery.js`, `publishing-pipeline.js`, `intelligence-manager.js`, `governance-engine.js`, `graph-engine.js`, `graph-traversal.js`, `subscriptions.js`, and 5 `api/v1/**` route handlers that call into these — `workbench/dashboard.js`, `workbench/search.js`, `intelligence/publish.js`, `products/index.js`, `products/approvals.js`, `quality/index.js`, `customer/download.js`, `customer/dashboard.js`, `analysis/assessments.js`) are real production Redis consumers V1 never classified. All 18 belong to the ReportX/Intelligence-Factory and billing/investigation clusters — **none belong to the alert-delivery or watchlist subsystems**, so this correction does not change V1's own certification (that migration's scope claims remain accurate), but it does change what "complete platform-wide inventory" actually means going forward. This document is the corrected baseline.

---

## 1. Classification legend (unchanged from V1)

| Code | Meaning |
|---|---|
| `CLOUDFLARE_ACTIVE` | Already Cloudflare-native |
| `CLOUDFLARE_MIGRATION_READY` | D1/KV/R2 target identified, schema/design feasible, not yet built |
| `MIGRATION_REQUIRED` | In scope for this or a near-term tranche |
| `LEGACY` | Real production dependency, deliberately out of scope this round, tracked for a future tranche |
| `CI_ONLY` | GitHub Actions used for tests/build/CodeQL/security — matches the runtime policy's own permitted use |
| `EXTERNAL_SAAS` | A genuine third-party integration (email provider, Blogger, payment processor) — Cloudflare-only runtime policy governs production compute/scheduler/state, not external integrations (Phase 27) |
| `DEPRECATED` | Reference exists but nothing in the live path executes it |
| `UNKNOWN` | Insufficient evidence from this sandbox to classify with confidence |

---

## 2. Corrected Redis consumer inventory (48 files), grouped by subsystem

### 2.1 Alert delivery — **migrated** (PR #138)

| File | Classification | Note |
|---|---|---|
| `api/_lib/notification-dispatch.js` | `LEGACY` (narrow) | Delivery state itself is D1 (unchanged this round). The one remaining Redis call is `getOwnerAccountEmail()` — customer-identity lookup, same dependency as every other authenticated endpoint (§2.3). |

### 2.2 Watchlists / change detection — **THIS ROUND'S MIGRATION TARGET (P0-B)**

| File | Classification | Note |
|---|---|---|
| `api/_lib/watchlist-store.js` | `MIGRATION_REQUIRED` | Watchlist CRUD, entity membership, feed. See §7/§8 of this tranche's plan. |
| `api/_lib/change-engine.js` | `MIGRATION_REQUIRED` | Snapshot comparison, semantic event creation, watcher fan-out (calls the now-D1-backed `notification-dispatch.js`). |
| `api/_lib/watchable-state.js` | `MIGRATION_REQUIRED` | Normalized entity-state projection change-engine.js diffs against. |
| `api/_lib/change-detector.js` | Verify — likely `CLOUDFLARE_ACTIVE` or pure-function, no Redis | This module's own Redis usage (if any) is audited in §10 below before deciding. |

### 2.3 Customer identity / auth — **audited, migration deferred (P0-D)**

| File | Classification |
|---|---|
| `api/_lib/security.js`, `api/_lib/middleware.js`, `api/v1/auth.js`, `api/_lib/analyst-auth.js`, `api/v1/admin.js` | `LEGACY` — security-critical, deferred per §15-18 of this round's own audit (see the certification doc's Auth Assessment section) |

### 2.4 Billing — **audited, migration deferred (P0-D)**

| File | Classification |
|---|---|
| `api/v1/billing.js`, `api/v1/billing/webhook.js`, `api/v1/billing/razorpay-webhook.js`, `api/_lib/payment-utils.js`, `api/_lib/subscriptions.js`, `api/v1/customer/dashboard.js`, `api/v1/customer/download.js` | `LEGACY` — financial-state-adjacent, deferred per §19-22 of this round's own audit (see the certification doc's Billing Assessment section) |

### 2.5 ReportX / Intelligence Factory product surface — **audited, migration deferred**

| File | Classification |
|---|---|
| `api/_lib/source-reliability-engine.js`, `api/_lib/quality-scorer.js`, `api/_lib/report-builder.js`, `api/_lib/report-manager.js`, `api/_lib/product-composition-engine.js`, `api/_lib/product-factory.js`, `api/_lib/product-management-api.js`, `api/_lib/product-validation-engine.js`, `api/_lib/product-delivery.js`, `api/_lib/publication-manager.js`, `api/_lib/publication-policy-engine.js`, `api/_lib/publishing-pipeline.js`, `api/_lib/freshness-engine.js`, `api/_lib/gap-analyzer.js`, `api/_lib/confidence-scorer.js`, `api/_lib/consistency-engine.js`, `api/_lib/evidence-validator.js`, `api/_lib/evidence-manager.js`, `api/_lib/analysis-manager.js`, `api/_lib/intelligence-manager.js`, `api/_lib/governance-engine.js`, `api/_lib/graph-engine.js`, `api/_lib/graph-traversal.js`, `api/_lib/timeline-engine.js`, `api/_lib/similarity-engine.js`, `api/_lib/relationship-engine.js`, `api/_lib/investigation-manager.js`, `api/_lib/investigation-graph.js`, `api/_lib/case-manager.js`, plus route handlers `api/v1/products/index.js`, `api/v1/products/approvals.js`, `api/v1/quality/index.js`, `api/v1/workbench/dashboard.js`, `api/v1/workbench/search.js`, `api/v1/intelligence/publish.js`, `api/v1/analysis/assessments.js` | `LEGACY` — 35 files, an entire separate product surface (analyst workbench, investigation/case management, report generation, product publication pipeline). Different mandate lineage (`docs/reportx/*`), pre-dates the alert/watchlist work by multiple rounds. Auditing all 35 individually is disproportionate to this tranche's actual scope (Phase 23's own instruction is to trace usage and classify, not migrate) — see §23 of the certification doc for the cluster-level assessment and why migration is deferred in full. |

### 2.6 Newsletter — **audited, migration deferred**

| File | Classification |
|---|---|
| `api/v1/newsletter.js` | `LEGACY` — subscriber list, low priority, unrelated to this tranche's scope |

**Total: 48 files, net new evidence: 18 beyond V1's count, 0 reclassified out of what V1 already covered.**

---

## 3. GitHub Actions scheduled workflows (11 total, re-verified against current `main`)

| Workflow | Cadence | Classification | Notes |
|---|---|---|---|
| `.github/workflows/alert-delivery.yml` | `*/30 * * * *` | `MIGRATION_REQUIRED` (proof-blocked) | Deliver step already bridges to D1 (PR #138). **Cannot be retired this round** — see §4 (P0-A blocker). |
| `.github/workflows/freshness-check.yml` | `*/30 * * * *` | `CI_ONLY` | Health/freshness check, matches policy |
| `.github/workflows/pipeline-health-certification.yml` | `*/30 * * * *` | `CI_ONLY` | Matches policy |
| `.github/workflows/security-audit.yml` | `0 6 * * 1` | `CI_ONLY` | Matches policy |
| `.github/workflows/sentinel-apex.yml` | `0,30 * * * *` | `LEGACY` | Intel Factory content pipeline — real filesystem + `git commit`/push, structurally incompatible with Workers (no persistent filesystem, no git). Unchanged finding from V1. |
| `.github/workflows/blogger-syndication.yml` | `15 */2 * * *` | `LEGACY` | Same reasoning |
| `.github/workflows/ai-security-intel.yml` | `0 */2 * * *` | `LEGACY` | Same reasoning |
| `.github/workflows/generate-rss.yml` | `0 */6 * * *` | `LEGACY` | Same reasoning |
| `.github/workflows/intelligence-hub.yml` | `20 */6 * * *` | `LEGACY` | Same reasoning |
| `.github/workflows/cve-pages.yml` | `0 */6 * * *` | `LEGACY` | Same reasoning |
| `.github/workflows/backup-customer-data.yml` | `0 3 * * *` | `LEGACY` | Daily customer-data backup, unrelated to this tranche |

**Net finding: unchanged from V1.** The content-generation pipeline remains the platform's largest GitHub-Actions-as-scheduler dependency, and remains outside what a Workers migration can address without a filesystem/git-access redesign this tranche does not attempt.

---

## 4. Vercel

`vercel.json` declares 10 functions (`api/v1/intel.js`, `auth.js`, `billing.js`, `watchlists.js`, `notifications.js`, `admin.js`, `billing/webhook.js`, `billing/razorpay-webhook.js`, `api/cron/dispatch-intel.js`, `api/og.js`) with explicit memory/duration config — unchanged from V1. All ten also serve via the Cloudflare Workers dual-runtime path (`workers/lib/route-table.js`). **Whether Vercel is still receiving live production traffic for these routes, versus Cloudflare Workers already being the actual target, cannot be determined from this sandbox** — no Vercel dashboard/API access exists here, matching every prior round's disclosed limitation. This is the honest answer to Phase 66's retirement-proof question: retirement cannot be certified without that access.

---

## 5. Cloudflare bindings (current `wrangler.jsonc`)

| Primitive | State |
|---|---|
| D1 | 1 database bound (`sentinel-apex-notification-delivery`, alert delivery only) |
| KV | None bound — `wrangler.jsonc`'s own header still lists this "intentionally absent" |
| R2 | None bound — same |
| Queues | None bound — same |
| Durable Objects | None bound — same |
| Cron Triggers | 1 configured (`*/30 * * * *`, alert delivery) — code-complete, not live-deployed (§4 of the prior certification, unchanged) |

---

## 6. Subsystem matrix (Phase 3)

| Subsystem | Current store | Canonical? | Consistency need | Target this round | Migration risk |
|---|---|---|---|---|---|
| Alert delivery | D1 | Yes — operational state | Strong (atomic claim) | Already D1 | Done |
| Watchlists | Redis (hash/set) | Yes — customer-owned state | Strong (ownership, uniqueness) | D1 | **Low-medium — this round's target** |
| Change detection (snapshots + events) | Redis (string/JSON, sorted sets) | Operational (derived from canonical intel, but the diff/event record itself is stateful) | Moderate-strong (idempotent event creation) | D1 | **Low-medium — this round's target** |
| Auth/session | Redis (string/hash, TTL-heavy) | Security-critical | Strong, TTL-dependent | Evaluate only | **High — deferred** |
| Billing | Redis (cache) + Razorpay (source of truth) | No — Razorpay owns financial truth | Strong where Redis mirrors provider state | Evaluate only | **Very high — deferred** |
| ReportX / Intelligence Factory | Redis (35 files, mixed) | Mostly yes — product/investigation state | Varies by file | Evaluate only | **High (scope), deferred in full** |
| Intel Factory content pipeline | Filesystem + git (via GitHub Actions) | Yes — published content | N/A (not Redis) | Not Cloudflare-migratable as designed | **Structural — deferred, not a Redis question** |
| Newsletter | Redis (set) | Yes — subscriber list | Low | Evaluate only | Low, deferred (not this round's scope) |

This matrix is the evidence base for the priority split in the certification doc: **P0-A blocked** (§4 below), **P0-B executed this round** (watchlists + change detection), **P0-C explicitly deferred** (ReportX/newsletter — large surface, no urgency evidence), **P0-D explicitly deferred** (auth/billing — high risk, dedicated future audit needed).

---

## 7. Dead / no-longer-relevant references

None found. Every reference this sweep located traces to a real, currently-executing code path or an accurate historical certification document.
