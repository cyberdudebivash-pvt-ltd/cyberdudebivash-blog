# SENTINEL APEX — Auth & Billing Migration-Deferral Audit (P0-D)

**Tranche:** Cloudflare-Only Runtime Completion v2
**Scope:** Phase 15-18 (Auth) and Phase 19-22 (Billing) of the P0 master
transformation mandate.
**Disposition:** Both subsystems are audited in full below. **Neither is
migrated this round.** This document is the evidence trail the mandate
requires before a deferral is acceptable — it exists so "defer" is a
documented decision, not a silent skip.

This audit does not modify `api/_lib/security.js`, `api/_lib/middleware.js`,
`api/v1/auth.js`, `api/_lib/analyst-auth.js`, `api/v1/admin.js`,
`api/_lib/payment-utils.js`, `api/v1/billing.js`,
`api/v1/billing/webhook.js`, `api/v1/billing/razorpay-webhook.js`,
`api/_lib/subscriptions.js`, `api/v1/customer/dashboard.js`, or
`api/v1/customer/download.js` in any way. Every finding below — including
two real, pre-existing defects unrelated to the Cloudflare migration — is
documented for a future round, per this repository's Deprecation Instead
of Deletion / Zero Unnecessary Modification governance: touching
security-critical or financial-state-adjacent code without the task
requiring it is exactly the risk this audit exists to avoid.

---

## §A — Auth Assessment (Phase 15-18)

### A.1 Files audited (full read, this round)

| File | Lines | Role |
|---|---|---|
| `api/_lib/security.js` | 418 | Global request guard, rate limiting, admin-key verification, security headers |
| `api/_lib/middleware.js` | 232 | `authenticate()` — the platform's single API-key auth + per-key rate-limit chokepoint |
| `api/v1/auth.js` | 362 | Registration, `me`, `usage` endpoints |
| `api/_lib/analyst-auth.js` | 128 | Internal SOC-workbench analyst identity (env-var configured, not Redis-backed) |
| `api/v1/admin.js` | 551 | Admin payment-review router (auth gate is in-scope here; payment state is §B) |

### A.2 Redis key inventory (auth-relevant)

| Key pattern | Type | TTL | Written by | Read by | Role |
|---|---|---|---|---|---|
| `user:key:{sha256(apiKey)}` | HASH | none (permanent) | `auth.js` register, `admin.js` approve, `payment-utils.js` upgradeUserTier | `middleware.js authenticate()` on **every** authenticated request | The account/API-key identity record itself |
| `user:email:{sanitized_email}` | STRING → userId | none (permanent) | `auth.js` register | `auth.js` duplicate check, `customer/dashboard.js` | Email → userId index |
| `user:id:{userId}` | STRING → keyHash | none (permanent) | `auth.js` register | `customer/dashboard.js`, billing webhooks | userId → keyHash reverse index |
| `user:pending:tier:{safeEmail}` | STRING (JSON) | 90 days | `payment-utils.js upgradeUserTier` (billing side) | `auth.js handleRegister` (auth side) | **Cross-subsystem coupling** — see A.6 |
| `ratelimit:{keyHash}:{YYYYMMDD}` | STRING (counter) | 1 day | `middleware.js authenticate()` | same | Per-key daily API rate limit — the actual billing-tier enforcement mechanism |
| `ratelimit:global:*`, `ratelimit:admin:*`, `ratelimit:analyst:*`, `ratelimit:intent:*`, `ratelimit:submit:*` | STRING (counter) | 1 min–1 day | `security.js`, `analyst-auth.js` | same | Per-IP throttles, INCR+EXPIRE pattern |
| `analytics:auth_failures:*`, `analytics:registrations:*`, `analytics:endpoints:*`, `analytics:keys:*` | STRING/HASH counters | none/daily | fire-and-forget, `.catch(()=>{})` everywhere | admin/analytics tooling (not audited here — non-critical) | Best-effort observability, never gates a decision |
| `usage:log:{today}` | SORTED SET | none | `middleware.js logUsage()` | `auth.js handleUsage` (indirectly, via `ratelimit:*` counters, not this key directly) | Per-request usage log |

Two identities are **not** Redis-backed at all:
- **Admin** (`api/v1/admin.js`, `payment-utils.js isAdminAuthorized`): a single
  `ADMIN_SECRET_KEY` env var, timing-safe compared. Zero Redis dependency for
  the auth decision itself — only the `ratelimit:admin:*` throttle bucket
  touches Redis.
- **Analyst** (`api/_lib/analyst-auth.js`): identities come from the
  `ANALYST_KEYS` env var (`{id, name, role, key}[]`), not Redis. Only the
  `ratelimit:analyst:*` throttle bucket touches Redis.

### A.3 Consistency & atomicity requirements

- `ratelimit:{keyHash}:{day}` is read-then-written on **every single**
  authenticated API request platform-wide — by construction, this is the
  single highest-traffic Redis access pattern in the entire codebase. Redis
  `INCR` is atomic; correctness depends on that atomicity holding under real
  concurrent request volume from the same API key.
- `user:key:{hash}` is read (HGETALL) on every request and incrementally
  updated (HINCRBY `totalRequests`, HSET `lastSeen`) on every successful one.
  These writes are fire-and-forget (`.catch(()=>{})`) — they do not gate the
  response, so their consistency bar is lower than the rate-limit counter.
- `user:email:{email}` duplicate-registration guard is a plain
  `GET`-then-`SET` (not `SETNX`/atomic) — **this is a real, pre-existing
  TOCTOU race**: two concurrent registrations for the same email could both
  pass the `redis.get(emailKey)` check before either writes, producing two
  API keys for one email. This predates this tranche and is unrelated to
  Cloudflare migration; it is recorded here as a genuine finding for a
  future auth-hardening pass, not fixed in this audit-only round.

### A.4 Blast radius if migrated

`authenticate()` (middleware.js) gates every commercial API surface on the
platform: intel endpoints, the dossier API, the search API, the watchlists
API (migrated to D1 this round), the notifications API (migrated to D1 last
round), and indirectly every tier/entitlement decision downstream of them. A
migration defect here does not break one feature — it risks total API
outage or, worse, silent cross-customer authorization bypass. This is
categorically larger blast radius than any subsystem this multi-round effort
has touched to date (watchlists and alert-delivery each gate one feature
each; auth gates all of them at once).

### A.5 Latency evidence — why D1 is the wrong target *right now*, not merely untested

`api/_lib/d1.js`'s `exec()` (built and verified in the Cloudflare-Only Alert
Runtime tranche, PR #138) issues one `fetch()` HTTP call per query against
Cloudflare's REST API — the only transport available when this code runs
under plain Node, which is what happens today, since `authenticate()`'s
consumers (the `/api/v1/*` routers) are still Vercel-hosted per this
platform's own retirement-in-progress policy, not yet executing inside a
Cloudflare Worker where the native `env.DB` binding would apply. Replacing
the rate-limiter's single sub-millisecond Redis `INCR` with a full HTTP
round-trip to Cloudflare's REST API, on **every authenticated API request
platform-wide**, is a direct, evidence-based latency regression to every
paying customer's API response time — not a hypothetical risk. This is also
a wrong-target finding independent of risk tolerance: rate-limit counters
with short TTLs are the textbook fit for Cloudflare KV or a Durable Object,
not D1's relational/transactional model — "do not force every workload into
every Cloudflare product" (mandate, Phase 2) applies directly here.

### A.6 Cross-subsystem coupling with billing

`user:pending:tier:{safeEmail}` is written by the **billing** flow
(`payment-utils.js upgradeUserTier`, reached from `admin.js` payment
approval and the Stripe/Razorpay webhooks) and read+deleted by the **auth**
flow (`auth.js handleRegister`) to auto-activate a tier a customer paid for
before creating an account. Migrating auth alone, without billing, would
either break this pre-paid-tier activation path outright (auth reads D1,
billing still writes Redis) or require migrating both in lockstep — this is
concrete evidence that auth and billing must be scoped as one future
migration effort, not two independent slices, which is why this document
covers both.

### A.7 Duplicate-implementation finding (Principle 3, not fixed here)

`security.js`'s `verifyAdminKey(req)` and `payment-utils.js`'s
`isAdminAuthorized(req)` are near-identical, independently-implemented copies
of the same timing-safe `ADMIN_SECRET_KEY` check (same fixed-128-char-width
comparison, same exact-match-after pattern). This is a real Single-Source-
of-Truth violation, pre-existing and orthogonal to the Cloudflare migration.
Not consolidated in this round — doing so would touch the admin auth gate
without the current task requiring it. Recorded for a future cleanup pass.

### A.8 Risk classification

| Sub-component | Redis role | Migration verdict this round |
|---|---|---|
| `user:key:*` / `user:email:*` / `user:id:*` identity records | Source of truth (no external system owns it) | **Eventually D1 is the right target** (D1's UNIQUE constraint would even fix A.3's TOCTOU race) — but HIGH RISK, deferred to a dedicated future round sized like the alert-delivery (PR #138) or watchlist (this round) tranches |
| `ratelimit:*` counters (all namespaces) | Hot-path, short-TTL counters | **Not recommended for D1 while the API surface is Vercel-hosted** (A.5) — natural target is KV/Durable Objects, and only once the API routers themselves run on Workers |
| Admin auth (`ADMIN_SECRET_KEY`) | Not Redis-backed | No migration needed |
| Analyst auth (`ANALYST_KEYS`) | Not Redis-backed | No migration needed |

**Verdict: DEFER.** Per the mandate's own explicit permission ("DO NOT FORCE
IT... document, isolate, classify P0/P1... preferable to destabilizing
authentication"), auth migration is out of scope for this tranche.

---

## §B — Billing Assessment (Phase 19-22)

### B.1 Files audited (full read, this round)

| File | Lines | Role |
|---|---|---|
| `api/_lib/payment-utils.js` | 284 | Shared helpers: plan catalogue, audit log, `upgradeUserTier` |
| `api/v1/billing.js` | 1114 | Consolidated billing router — intents, Razorpay orders, subscriptions, product orders (targeted read of the subscription-lifecycle actions; full Redis-call grep across the whole file) |
| `api/v1/billing/webhook.js` | 169 | Stripe webhook handler |
| `api/v1/billing/razorpay-webhook.js` | 99 | Razorpay webhook handler (backup confirmation path) |
| `api/_lib/subscriptions.js` | 324 | Razorpay recurring-subscription helpers |
| `api/v1/customer/dashboard.js` | 92 | Customer-facing account/tier view (grepped, shares auth's identity keys) |
| `api/v1/customer/download.js` | 143 | Digital-product download logging (grepped) |
| `api/v1/admin.js` | 551 | Admin payment approve/reject (already read in full for §A) |

### B.2 Source-of-truth analysis — the mandate's central question

The mandate is explicit: *"never let Redis be treated as canonical financial
ledger if a provider/D1 already owns truth."* Verified directly against the
real code, across all three payment paths this platform supports:

1. **Stripe** (`billing/webhook.js`) — signature-verifies the raw webhook
   body against Stripe's own signing secret, then mirrors Stripe's already-
   decided event (`checkout.session.completed`, `customer.subscription.*`)
   onto the local `user:key:*` tier field. Redis never originates a charge.
2. **Razorpay** (`billing/razorpay-webhook.js`, and `billing.js`'s
   `verify-razorpay-payment` action) — same shape: HMAC-verifies against
   Razorpay's signature, then mirrors Razorpay's already-captured payment.
3. **Manual UPI/bank transfer** (`admin.js` approve/reject) — the source of
   truth is a **human administrator** reading a bank statement and matching
   a UTR; Redis (`payment:submission:*`) is the workflow-state and audit
   trail for that human decision, not the money itself.

**Finding: across all three payment paths, Redis is a workflow-state cache,
idempotency guard, and audit trail — never the origin of financial truth.**
This is exactly the condition under which the mandate says migration should
be deferred pending a dedicated evaluation, not treated as a routine
Redis→D1 port.

### B.3 Redis key inventory (billing-relevant) — TTL semantics are load-bearing, not incidental

| Key pattern | TTL | Behavior |
|---|---|---|
| `payment:intent:{intentId}` | 24h (`INTENT_TTL_SECONDS`) | Payment intent expires if not completed — TTL is the actual expiry mechanism |
| `payment:submission:{txn}` | 90 days (`SUBMISSION_TTL_SECONDS`) | Fraud-guard + retention window, not a cache lifetime |
| `payment:rzp:order:{orderId}` | **24h → 90 days on state transition** | Starts at intent TTL, re-armed to the 90-day submission TTL once `status` flips to `paid` |
| `payment:product:order:{sessionId}` | 24h → 90 days | Same state-dependent re-arming as Razorpay orders |
| `payment:rzp:txn:seen:{paymentId}` | 90 days | Idempotency dedup guard (§B.4) |
| `subscription:{subscriptionId}` | 90 days | Explicitly documented in `subscriptions.js` as a "cache" / "fast lookup" over Razorpay's own subscription state |
| `subscription:user:{email}:{subId}` | 90 days | User → subscription index |
| `user:pending:tier:{email}` | 90 days | Shared with auth — see A.6 |

A per-row TTL that **changes based on state transition** (intent → paid) has
no native D1 equivalent — D1 has no row expiry primitive. Replicating this
would require a scheduled cleanup job (a real design/build task, not a
schema port), or accepting unbounded row growth. This is concrete evidence
against a mechanical "replace every Redis call with an equivalent D1 query"
approach for this subsystem, consistent with the mandate's "MIGRATE WITH
PROOF, not migrate everything" instruction.

### B.4 Idempotency mechanisms already in place

Both webhook paths and the manual-submission path already implement
dedup guards using Redis `SETEX` (an atomic set-with-expiry):
`payment:rzp:txn:seen:{paymentId}` and the `payment:submission:*` duplicate-
transaction guard, both explicitly commented `// atomic set+TTL` in the
source. `razorpay-webhook.js`'s own header comment documents that this
guard is shared with `action=verify-razorpay-payment` specifically so the
client-confirmation path and the webhook backup path can't double-process
the same payment. A D1 equivalent (`INSERT ... ON CONFLICT DO NOTHING`
against a UNIQUE constraint) is feasible, but re-proving this exact
double-processing guarantee for a path that moves real money warrants its
own dedicated verification effort, not a fold-in to this tranche.

### B.5 Pre-existing defects found (documented, not fixed — out of scope)

1. **`subscriptions.js getSubscription()`** contains a `// TODO: map from
   plan` comment next to a clearly incorrect amount calculation
   (`result.quantity * (result.plan_interval ? 10000 : 0)`). Pre-existing,
   unrelated to Redis/D1.
2. **`subscriptions.js getUserSubscriptions()`** uses `redis.keys(...)` — a
   full-keyspace-scan anti-pattern (blocks Redis, doesn't scale). Pre-
   existing.
3. **`subscriptions.js handleSubscriptionWebhook()`** and its four per-event
   handlers (`handleSubscriptionActivated/Paused/Halted/Cancelled`) are
   exported but **never called anywhere in the codebase** (verified via
   repository-wide grep) — the live Razorpay webhook
   (`billing/razorpay-webhook.js`) only handles one-time
   `payment.captured`/`order.paid` events directly via `upgradeUserTier`,
   not through this dispatcher. The recurring-subscription lifecycle
   (activate/pause/halt/cancel) has no live webhook wired to it today —
   `createSubscription`/`storeSubscriptionRecord`/`pauseSubscription`/
   `cancelSubscription` themselves ARE live (called from `billing.js`'s
   `create-subscription`/`manage-subscription` actions), but the automatic
   webhook-driven side of the lifecycle is dormant. This affects the
   platform-wide subsystem status table (Task #174): subscription *creation*
   is live production behavior; subscription *webhook lifecycle* is not.

None of these three are Cloudflare-migration concerns — they are pre-
existing application defects surfaced by reading the real code for this
audit. Per Zero Unnecessary Modification, they are not touched in this
round.

### B.6 Risk classification

| Sub-component | Redis role | Migration verdict this round |
|---|---|---|
| Webhook signature verification (Stripe/Razorpay) | N/A — no Redis | No migration needed (not Redis-backed at all) |
| `payment:intent:*`, `payment:submission:*`, `payment:rzp:order:*`, `payment:product:order:*` | Workflow-state cache + idempotency guard, state-dependent TTL | Feasible eventually, but TTL re-design + idempotency re-proof required — deferred |
| `subscription:*` | Explicitly-documented cache over Razorpay's own truth | Deferred; also currently only partially wired (B.5) — migrating a partially-dormant subsystem first is poor sequencing |
| `user:pending:tier:*` | Shared with auth | Deferred with auth, see A.6 |

**Verdict: DEFER.** Financial state is never migrated casually per the
mandate's own instruction; Redis is confirmed to be a mirror of
provider-owned truth (not itself the ledger), which lowers urgency
further — there is no correctness risk in leaving it as-is, only in
touching it without a dedicated, provable migration.

---

## §C — Combined P0-D classification (feeds the platform-wide status table)

| Subsystem | Store today | Source of truth | Migration urgency | This round's action |
|---|---|---|---|---|
| Auth — identity records | Redis (permanent) | Redis itself | Real, but requires a dedicated hardening round (fixes A.3's race as a side effect) | Audited, deferred |
| Auth — rate limiting | Redis (TTL) | Redis itself | Low urgency; wrong target is D1 regardless (A.5) | Audited, deferred |
| Billing — payment/order state | Redis (state-dependent TTL) | Stripe/Razorpay/human admin | Low — Redis already correctly subordinate to provider truth | Audited, deferred |
| Billing — subscriptions | Redis (TTL, partially dormant) | Razorpay | Low, and poor sequencing target until B.5's dormant webhook path is resolved | Audited, deferred |

## §D — Recommendation for a future dedicated round

Auth and billing should be scoped as **one future P0-D tranche**, sized
comparably to the alert-delivery (PR #138) or this round's watchlist
migration, because:

1. They share one Redis key (`user:pending:tier:*`) and cannot be safely
   split across separate migration windows.
2. Auth's identity records would benefit from D1's UNIQUE-constraint
   atomicity (fixing A.3's real TOCTOU race as a natural side effect of
   migrating correctly) — a genuine argument *for* eventual migration, just
   not this round.
3. Rate-limiting should migrate to Cloudflare KV/Durable Objects, not D1,
   and only once the `/api/v1/*` routers themselves run on Workers (so the
   native binding, not the REST transport, applies) — this is a
   precondition on the broader Vercel-retirement effort, not something
   this round can unblock alone.
4. Billing's dormant subscription-webhook path (B.5) should be resolved
   (or explicitly deprecated) before subscription state is migrated, so the
   migration target reflects live behavior, not partially-dead code.

*CYBERDUDEBIVASH® SENTINEL APEX — Cloudflare-Only Runtime Completion v2*
*Phase 15-22 deliverable — audit-only, zero production code touched*
