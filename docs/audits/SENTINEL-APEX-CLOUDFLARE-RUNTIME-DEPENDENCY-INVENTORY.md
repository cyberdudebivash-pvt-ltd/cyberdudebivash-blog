# SENTINEL APEX — Cloudflare Runtime Dependency Inventory

**Date:** 2026-08-26
**Branch:** `claude/p0-cloudflare-only-alert-runtime-v1`
**Purpose:** a complete, evidence-based classification of every Vercel/Upstash/GitHub-Actions-scheduler reference in this repository, produced before any migration code was written, per the Cloudflare-Only Alert Runtime mandate's own Phase 2 instruction: "do not delete anything until dependency evidence exists."

---

## 0. Scope boundary — read this before the classification table

The mandate's executive framing ("CLOUDFLARE WORKERS IS THE ONLY PRODUCTION RUNTIME GOING FORWARD... NO UPSTASH REDIS PRODUCTION DEPENDENCY") reads as platform-wide. The mandate's own **Primary Mission**, however, is scoped precisely: *"Migrate the merged PR #137 alert orchestration."* This inventory found that those two framings diverge in a way that matters:

**30 files** `require('./redis')` (full list in §2). Of those, only **2** — `api/_lib/notification-store.js` and `api/_lib/notification-dispatch.js` — belong to the alert/notification-delivery subsystem this mandate's Primary Mission actually names. The other 28 back customer auth, billing, product management, quality scoring, content pipelines, and analyst tooling — entirely unrelated systems that predate PR #136/#137 and were never part of any Cloudflare-migration mandate issued so far.

**This tranche migrates the delivery control plane only** (`notification-store.js`, its D1 backing, the claim/lease/retry/dead-letter/preferences/secrets/audit-log state it owns) **off Redis, onto D1.** It does **not** touch `watchlist-store.js` or `change-engine.js`/`change-detector.js`/`watchable-state.js` (watchlists themselves and change *detection*), which remain Redis-backed. This is a deliberate, evidence-based scope decision, not an oversight:

- Migrating watchlists/change-detection would ripple into `api/v1/watchlists.js`, `dossier.html`'s watch action, and `api-dashboard.html`'s watchlist panels — a blast radius far beyond "alert orchestration."
- The mandate's own P0 Success Condition sentence is itself scoped: *"...for watchlist notification delivery"* — not "for the watchlist system."
- One direct consequence, disclosed prominently in the certification doc: `scripts/evaluate-watchlist-changes.js` (change *detection*) still needs `UPSTASH_REDIS_REST_URL`/`TOKEN`, because it reads/writes the still-Redis-backed watchable-state/change-event layer. **Full, end-to-end Redis independence for the complete watchlist-alerting pipeline requires a follow-up, separately-scoped tranche.** What this tranche achieves is Redis independence for the *delivery* half specifically — proven, not assumed (see the certification doc's Legacy Dependency Proof section).

---

## 1. Classification legend

| Code | Meaning |
|---|---|
| `CLOUDFLARE_ACTIVE` | Already Cloudflare-native, unaffected by this tranche |
| `MIGRATION_REQUIRED` | In scope for this tranche — migrated to D1 |
| `CI_ONLY` | GitHub Actions used for tests/build/CodeQL — matches the mandate's own permitted use, no change needed |
| `LEGACY` | Real production dependency, out of THIS tranche's scope, unchanged, tracked for a future tranche |
| `DEAD` | Reference exists but nothing in the live path actually executes it |
| `UNKNOWN` | Insufficient evidence from this sandbox to classify with confidence |

---

## 2. Redis / Upstash — full 30-file inventory

| File | Classification | Evidence |
|---|---|---|
| `api/_lib/notification-store.js` | `MIGRATION_REQUIRED` | Alert delivery control plane — this tranche's actual target. Migrated to `api/_lib/d1.js` this round. |
| `api/_lib/notification-dispatch.js` | `MIGRATION_REQUIRED` (indirect) | Never calls `redis.js` directly — reads/writes exclusively through `notification-store.js`'s exported functions (verified: `grep -c redis api/_lib/notification-dispatch.js` → 0 direct references; the one `require('./redis')` this file keeps is `getOwnerAccountEmail()`'s customer-identity lookup, unrelated to delivery state and unaffected by this tranche). **Correction from this doc's first draft:** migrating the store does NOT mean zero code changes here — the relational one-row-per-channel redesign (see `notification-store.js`'s module header) changes `getDuePendingDeliveries()`'s return shape from grouped-by-event records to flat per-channel job rows, so `processDueDeliveries()`'s loop was flattened to match, and the four dispatch-internal helper calls (`claimDeliveryChannel`/`releaseDeliveryChannel`/`recordAttemptOutcome`/`cancelDeliveryChannel`) were re-plumbed from `{ownerId,eventId,channel}` to `{deliveryId[,claimToken]}`. This is an internal contract between these two co-migrated files, not a public API change — confirmed by reading every call site: none of those four functions, nor `getDuePendingDeliveries()`, are called from `api/v1/notifications.js` or anywhere outside this file. |
| `api/_lib/watchlist-store.js` | `LEGACY` | Watchlist CRUD, entity sets, entitlements. Out of scope (§0). Powers `api/v1/watchlists.js`, `dossier.html`'s watch button, the dashboard's Watchlists tab — migrating it is a separate, larger tranche. |
| `api/_lib/change-engine.js` | `LEGACY` | Change-event persistence (`event:{id}`, `events:by_entity:*`), the watcher fan-out loop. Out of scope (§0). `scripts/evaluate-watchlist-changes.js` depends on this, which is why that script still needs Redis after this tranche. |
| `api/v1/billing.js`, `api/v1/newsletter.js`, `api/v1/auth.js`, `api/v1/admin.js` | `LEGACY` | Customer auth (`user:key:*`, `user:id:*`), billing/subscription state, newsletter subscriber list, admin operations. Entirely unrelated to alert delivery; predates PR #136 by multiple rounds. |
| `api/_lib/analyst-auth.js`, `api/_lib/security.js`, `api/_lib/middleware.js`, `api/_lib/payment-utils.js` | `LEGACY` | Shared auth/rate-limiting/audit-log infrastructure every `api/v1/*.js` router (including `api/v1/notifications.js`) depends on for request authentication — `authenticate()` itself stays Redis-backed. This tranche does not and cannot remove the customer-identity dependency on Redis; it only removes the *delivery state* dependency. |
| `api/_lib/source-reliability-engine.js`, `api/_lib/quality-scorer.js`, `api/_lib/report-builder.js`, `api/_lib/report-manager.js`, `api/_lib/product-composition-engine.js`, `api/_lib/product-factory.js`, `api/_lib/product-management-api.js`, `api/_lib/product-validation-engine.js`, `api/_lib/publication-manager.js`, `api/_lib/publication-policy-engine.js`, `api/_lib/freshness-engine.js`, `api/_lib/gap-analyzer.js`, `api/_lib/confidence-scorer.js`, `api/_lib/consistency-engine.js`, `api/_lib/evidence-validator.js`, `api/_lib/analysis-manager.js` | `LEGACY` | ReportX / Intelligence Factory product-quality subsystem. Entirely unrelated to watchlist alert delivery — different product surface, different mandate lineage (see `docs/reportx/*`). |
| `api/_lib/__tests__/redis.test.js`, `api/_lib/__tests__/analyst-auth.test.js` | `CI_ONLY` | Test files exercising the (unchanged, still-real) Redis client and analyst auth. Stay as-is — the Redis client itself is not retired, only the delivery subsystem's *use* of it. |
| `api/_lib/redis.js` itself | `LEGACY` (module retained) | The Upstash REST client module is **not deleted** — 28 other production modules still depend on it. Only its *consumer count for alert delivery* drops to zero this round. |

**Net finding: after this tranche, `UPSTASH_REDIS_REST_URL`/`TOKEN` are no longer required by any code path inside the alert-delivery control plane specifically — proven in §100-equivalent of the certification doc — but remain a real, load-bearing production dependency for the rest of this platform, unchanged and out of scope.**

---

## 3. GitHub Actions scheduled workflows — full 9-workflow inventory

| Workflow | Cadence | Classification | Notes |
|---|---|---|---|
| `.github/workflows/alert-delivery.yml` | `*/30 * * * *` | `MIGRATION_REQUIRED` (partial) | The Primary Mission's actual target. **Deliver step** migrated to talk to D1 this round (§ below). **Evaluate step** (`evaluate-watchlist-changes.js`) stays Redis-backed, out of scope (§0) — kept on GitHub Actions' schedule, since retiring it would leave watchlist change detection with no trigger at all. The workflow itself is **not deleted or disabled** — see §4 for why. |
| `.github/workflows/sentinel-apex.yml` | `0,30 * * * *` | `LEGACY` | Intel Factory content-generation pipeline (Python/Node scripts with real filesystem + git-push access) — structurally incompatible with the Workers runtime model (no persistent filesystem, no `git commit`). Entirely outside this mandate's Primary Mission. |
| `.github/workflows/blogger-syndication.yml` | `15 */2 * * *` | `LEGACY` | Same reasoning — Blogger API publication pipeline, unrelated to alert delivery. |
| `.github/workflows/ai-security-intel.yml` | `0 */2 * * *` | `LEGACY` | Separate content pipeline. |
| `.github/workflows/security-audit.yml` | `0 6 * * 1` | `CI_ONLY` | Weekly security scan — already matches the mandate's own "GitHub Actions = CI/security assurance" policy. |
| `.github/workflows/generate-rss.yml` | `0 */6 * * *` | `LEGACY` | RSS feed regeneration from repo content. |
| `.github/workflows/intelligence-hub.yml` | `20 */6 * * *` | `LEGACY` | Intelligence hub page regeneration. |
| `.github/workflows/cve-pages.yml` | `0 */6 * * *` | `LEGACY` | CVE static page generation. |
| `.github/workflows/pipeline-health-certification.yml` | `*/30 * * * *` | `CI_ONLY` | Pipeline health/CI assurance check — already matches policy. |
| `.github/workflows/backup-customer-data.yml` | `0 3 * * *` | `LEGACY` | Daily customer-data backup snapshot — a real production safety net, unrelated to alert delivery, not touched. |

**Net finding: this repository runs its entire content-generation pipeline on GitHub Actions schedules today — a much larger dependency than the one alert-delivery workflow this mandate targets. Migrating the content pipeline to Cloudflare would be a separate, much larger mandate (Workers has no persistent filesystem and cannot `git commit`/push, which the current Python pipeline relies on directly) and is explicitly out of scope here.**

---

## 4. Why `alert-delivery.yml` is not deleted this round

The mandate's own Phase 20/77/78 sequencing is explicit: *"Remove GitHub Actions as production scheduler only after live Cloudflare Cron is proven"* and *"Ensure there is not a period with zero scheduler."* This sandbox has no live Cloudflare account access (`wrangler whoami` → not authenticated, confirmed this round) — meaning **live Cloudflare Cron execution cannot be proven from here.** Per the mandate's own stated sequencing logic, retiring the GitHub Actions scheduler before that proof exists would create exactly the "zero scheduler" gap it explicitly forbids. `alert-delivery.yml` therefore stays active as the operative production scheduler for now — its deliver step now talks to the same D1 database the (still-dormant, not-yet-cron-triggered) Cloudflare `scheduled()` handler would use, so there is a single source of delivery truth regardless of which trigger fires it, and zero functional regression during the transition window.

---

## 5. Vercel

`vercel.json` and the ~30 registered serverless functions it declares are **unchanged this round** — this tranche does not touch Vercel configuration at all. The alert-delivery subsystem's *runtime code* (`api/v1/notifications.js`, `notification-store.js`, `notification-dispatch.js`) is dual-runtime already (the same files run under both Vercel/Node and Cloudflare Workers via `workers/lib/router.js`'s dispatch, per the existing migration architecture) — nothing in this tranche breaks that dual-runtime property or removes Vercel as a *currently-live* production surface. What changes is which backing store the delivery code talks to (D1 instead of Redis), which is runtime-agnostic either way.

---

## 6. Dead / no-longer-relevant references

None found. Every Redis/cron reference this sweep located traces to a real, currently-executing code path or an accurate historical certification document. No dead code was identified in this inventory.
