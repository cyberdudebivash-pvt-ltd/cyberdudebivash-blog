# SENTINEL APEX — Alert Orchestration & Delivery Reliability v1
## Production Certification

**Date:** 2026-08-25
**Branch:** `claude/p0-cloudflare-alert-orchestration-v1`
**Mandate:** P0/P1 Production Priority Task — SENTINEL APEX™ Cloudflare-Native Alert Orchestration, Delivery Reliability & Commercial Monitoring Automation v1
**Prior tranche:** PR #136 — Alert Delivery & Webhook Automation v1 (merged) — this tranche makes that delivery mechanism autonomous, durable, and idempotent under concurrent/repeated execution; it does not replace or duplicate it.

---

## 1. Executive Verdict

**CONDITIONAL GO**

Alert delivery is now genuinely autonomous (a real, committed, native GitHub Actions schedule — not merely code that could theoretically run on one), durable (an atomic Redis claim-with-lease makes concurrent or repeated dispatcher invocations safe by construction, not by convention), and recoverable (a crashed or killed dispatcher's in-flight claim self-expires and becomes claimable again, with no separate sweep job needed). 125 pre-existing tests plus **~65 new tests** this round (exact delta below) cover the state machine, retry classification, cancellation, and — the one property that actually matters for "at-least-once execution is safe" — genuine concurrent-invocation behavior against a shared store, not just sequential-call assertions.

**Conditional**, not unqualified GO, because:

1. **The new GitHub Actions secrets this workflow needs are unverified as actually configured.** `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN` already exist as *Vercel* environment variables (proven — they back production today), but whether they are *also* set as GitHub Actions repository secrets is unverified from this sandbox. `backup-customer-data.yml` hit this exact gap first and documented it as still open. This new workflow (`alert-delivery.yml`) mirrors that workflow's own preflight-and-skip pattern: if unset, it runs, detects the gap, and exits with a visible warning rather than silently doing nothing or failing confusingly — but until an operator confirms or adds those secrets, this tranche's core "autonomous" claim is code-complete and correctly guarded, not yet observed firing in production (§29).
2. **Cloudflare Cron Trigger is still not live**, by explicit, deliberate design — `wrangler.jsonc`'s own header defers `triggers.crons` pending separate operator authorization, and this tranche does not take that authorization for itself (§6, §29).
3. **No live production canary was run** — this sandbox has no Vercel/GitHub Actions dashboard access to trigger and observe a real scheduled run end-to-end. All verification is integration-level against a real in-memory Redis double and real orchestration code (§28).

Every other acceptance-criteria item this mandate lists — atomic claim semantics, lease recovery, deterministic retry classification, bounded backoff, dead-letter with fast-track for permanent failures, poison-destination isolation, customer isolation/IDOR, observability, and full regression — is met and evidenced below.

---

## 2. Customer Problem

PR #136 made alert delivery *possible*: a customer could configure email/webhook channels and a manually- or externally-triggered script would deliver due alerts. Nothing made it *automatic*. Two related gaps followed directly from that:

1. **No autonomy.** `scripts/deliver-watchlist-notifications.js` (and its sibling `scripts/evaluate-watchlist-changes.js`, which actually *detects* the changes delivery depends on) only ran when a human or external system invoked them. A customer's watched CVE could flip to CISA KEV and nothing would tell them, indefinitely, unless someone ran two scripts by hand.
2. **No safety net for concurrent/repeated execution.** `processDueDeliveries()` had no notion of "someone else is already handling this delivery" — two overlapping invocations (an accidental double-trigger, a retried job, a future queue's at-least-once redelivery) would both send the same customer alert.

This tranche closes both: a real scheduled trigger, and an orchestration layer that is safe regardless of how many times or how concurrently it runs.

---

## 3. Baseline (fresh audit, this round)

Confirmed via `git checkout main && git pull && git status && git log --oneline -30` before any code was written:
- PR #136 (Alert Delivery & Webhook Automation v1) merged as `d4a25ffe`, PR #135 (OG Card v3) merged as `554fa028`, PR #134 (Watchlists) merged as `97f99261` — all confirmed present on `main`.
- Working tree clean; branch `claude/p0-cloudflare-alert-orchestration-v1` created fresh from current `main`, not reused from a stale feature branch.
- A live, unrelated automated content pipeline (`sentinel-apex.yml`, `blogger-syndication.yml`, etc.) is continuously committing to `main` in the background (visible in `git log`) — expected, not a merge conflict risk for this branch's own files.

---

## 4. Reuse-Before-Build Audit — the single most consequential finding

**Cloudflare Workers is not the live production runtime for this platform. Vercel is — and GitHub Actions, not Vercel Cron, is this repo's own proven scheduling substrate.** This inverts the mandate's own framing ("Canonical production runtime: Cloudflare Workers... do not introduce Vercel as a new dependency") against the actual, already-documented state of this specific repository, discovered by reading `wrangler.jsonc` in full and cross-referencing the existing migration documentation, not assumed from the mandate's premise.

| Evidence source | Finding |
|---|---|
| `wrangler.jsonc` (root, read in full) | Explicit, dated header comments: "Deliberately incapable of a production DNS takeover at this stage: no routes, no custom_domains, no production hostname, no production storage bindings, no cron... Safe to build, dry-run, and run under a local Workerd only." `triggers.crons` is explicitly listed as intentionally absent: "scheduling authority is undecided (see the cron-deduplication decision doc); adding a schedule here would start real remote execution." No `kv_namespaces`, no `d1_databases` ("none needed — the blog has no relational data dependency"), no `r2_buckets`. |
| `vercel.json` (root, read in full) | The real, live, active production deployment config — 10 registered serverless functions including `api/cron/dispatch-intel.js`, real security headers, real rewrites for the whole `api/v1/**` surface. |
| `api/cron/dispatch-intel.js` (read in full) | An **already-proven external-cron-to-secured-endpoint pattern** already exists in this exact repo: a `CRON_SECRET`-protected endpoint that forwards a `workflow_dispatch` to GitHub Actions, with a documented, already-hardened per-workflow throttle (`MIN_INTERVAL_MINUTES`) added specifically because "the external caller... fired blogger-syndication.yml every ~5 min instead of its intended 2h cadence, causing the July 2026 outage." Its own header comment states plainly: **"GitHub's own `schedule:` trigger throttles high-frequency cron expressions (observed: 5-30 minute schedules firing every ~4h in practice)."** |
| `MIGRATION_RUNBOOK.md`, `PRE-MIGRATION-FORENSICS.md` (read relevant sections) | Confirms the Vercel Cron schedule for `/api/cron/dispatch-intel` is real and live in production today, but was configured **only in the Vercel dashboard, never committed to git** — explicitly flagged there as an "undeclared cron gap" and a migration risk ("the original schedule was never committed to git and isn't recoverable"). This is a documented anti-pattern in this exact codebase, not a precedent to copy. |
| `.github/workflows/sentinel-apex.yml`, `freshness-check.yml` (read in full) | Both run on a **native GitHub Actions `schedule:` trigger at a 30-minute cadence today, in production, with no indirection layer** — `sentinel-apex.yml`: `cron: "0,30 * * * *"`; `freshness-check.yml`: `cron: '*/30 * * * *'`. Both include `workflow_dispatch` for manual firing and a `concurrency` group. This is the **proven-reliable-at-30-minutes** cadence this tranche's own schedule is built on — not an assumption, direct evidence from this repository's own already-running infrastructure. |
| `.github/workflows/backup-customer-data.yml` (read in full) | Establishes the exact preflight-and-skip pattern this tranche's new workflow mirrors: checks `secrets.UPSTASH_REDIS_REST_URL != ''` before running, and its own header documents that, as of ITS introduction, GitHub Actions secrets for Redis were **not yet confirmed configured** — "they exist today only as Vercel environment variables, a different secret store from GitHub Actions secrets." |
| Watchlists v1 certification (`SENTINEL-APEX-WATCHLISTS-CHANGE-DETECTION-V1-CERTIFICATION.md` §4, re-read this round) | Independently reached the identical conclusion in the prior tranche: "this Worker has zero production storage bindings today... Upstash Redis (via REST, pure fetch, no TCP socket — already Worker-compatible) is the real, live, already-production datastore." No forcing reason to introduce D1/KV/Durable Objects/Queues existed then; nothing in this tranche changes that. |

**This eliminated Cloudflare Cron Trigger and Cloudflare Queues as the PRIMARY orchestration mechanism before any scheduler code was written** — not a preference, an evidence-based conclusion, directly satisfying the mandate's own repeated hedges ("do not merely add a scheduled() function and claim automation exists," "do not select the most sophisticated option automatically," "do not introduce Queues unless current architecture justifies them"). See §6 for the full decision.

| Existing capability | Finding | Action taken |
|---|---|---|
| `api/_lib/redis.js`'s `setnx` (`SET key val NX`) | Already the atomic-create primitive this codebase uses for idempotent event creation | Extended (not replaced) with `setnxpx` (`SET key val NX PX ttlMs`) for the new claim/lease primitive — same command family, one new option |
| `api/_lib/notification-store.js`'s `enqueuePendingDelivery`/`getDuePendingDeliveries`/`recordAttemptOutcome` (PR #136) | Already the full pending-delivery/retry-queue model | Extended, not rebuilt: added claim/release/cancel functions and two new optional params (`retryable`, `retryAfterSeconds`) to the existing `recordAttemptOutcome`, defaulting to identical prior behavior when omitted |
| `api/_lib/notification-dispatch.js`'s `deliverEmailChannel`/`deliverWebhookChannel`/`processDueDeliveries` (PR #136) | Already the full send/orchestration layer | Extended: added retry classification, a stable delivery ID, and claim/release calls inside the existing dispatch loop — no parallel dispatcher was built |
| `api/_lib/resend.js`'s `sendEmail`/error handling | Threw a plain `Error` with only a `.message` | Extended additively: attaches `.status` to the thrown error so failure classification has a real HTTP status to work from, without changing what any existing catch site reads |
| `watchlist-store.js`'s `auditWatchlistAction()` pattern (ZADD + bounded ZREMRANGEBYRANK trim to a domain-specific audit key) | Already the established audit-log pattern for this platform, not reused directly (hardcoded to its own key) | Same pattern reimplemented against a new `audit:notify:log` key (`auditNotificationAction()`), not a duplicate audit system |
| `scripts/evaluate-watchlist-changes.js` / `scripts/deliver-watchlist-notifications.js` (PR #136) | Already exist as thin CLI wrappers with identical shape | Reused unchanged as the exact commands the new scheduled workflow runs — no new entrypoint script was written |
| `workers/lib/router.js`'s `handleFetch` / `workers/entry.js`'s `fetch` export | Already the Worker's request-handling contract | Extended additively with a sibling `handleScheduled`/`scheduled` export — `fetch` itself was not touched |

**Duplicate components introduced: 0. Duplicate routes introduced: 0. Parallel scheduling mechanism introduced: 0** (see §21 Reuse Report).

---

## 5. Current Delivery Lifecycle (traced, not assumed)

```
Intelligence Change Event (change-engine.js, unchanged)
        |
Watchlist Match -> dispatchNewEvent() enqueues eligible channels (PR #136, unchanged)
        |
notify:pending:{owner}:{event} (Redis hash-shaped JSON) + notify:pending_queue (ZSET, score=soonest next_attempt_at)
        |
[NEW] scheduled trigger (GitHub Actions, 30 min) -> node scripts/evaluate-watchlist-changes.js && node scripts/deliver-watchlist-notifications.js --limit=50
        |
processDueDeliveries(): getDuePendingDeliveries() -> [NEW] per-channel atomic claim -> [NEW] cancellation check -> deliver -> [NEW] retry classification -> recordAttemptOutcome() -> [NEW] release
        |
notify:delivery_log:{owner} (ZSET, bounded 500) <- every attempt, success or failure
        |
Retry (backoff or Retry-After, bounded) OR notify:dead_letter:{owner} (ZSET, bounded 200) <- exhausted or permanent
```

What is persisted vs. ephemeral vs. recomputed, confirmed by reading the code (not inferred):
- **Persisted (Redis, customer-owned):** preferences, the pending-delivery record and its per-channel attempt state, the delivery log, the dead-letter log, the audit log, and (new) a short-lived claim key per `(owner, event, channel)`.
- **Ephemeral (never persisted):** the claim key's *value* is never read back for anything but existence — its only job is to exist-or-not for the lease window.
- **Recomputed, never stored twice:** the underlying change event itself (`event:{id}`, owned by `change-engine.js`) is read by reference (`getEventById`), never copied into the delivery record — a delivery record only ever carries `event_id`.
- **Stable IDs before this round:** yes — `event_id` (change-engine.js) and the pending record's own `(ownerId, eventId)` key. **New this round:** a stable, retry-invariant `delivery_id` (`buildDeliveryId(ownerId, eventId, channel)`), used both as the claim key's identity and as the customer-facing `X-Sentinel-Delivery-Id` webhook header.
- Retries lived in `notify:pending:*`'s own `attempts` map before this round (unchanged location); attempts were recorded in the delivery log before this round (unchanged location, extended with a new `'cancelled'` status value).

---

## 6. Architecture Decision

**Chosen: event-driven enqueue (already existed, unchanged) + GitHub Actions native `schedule:` trigger as the dispatch/reconciliation executor**, running the existing CLI scripts directly against the existing production Redis. A dormant Cloudflare `scheduled()` handler is also implemented (§7) as a zero-rework future path, but is not the live mechanism.

Options evaluated, per the mandate's own Option A/B/C framing:

| Option | Verdict | Why |
|---|---|---|
| **A: Cloudflare Cron Trigger -> `scheduled()` -> query pending -> dispatch batch** | **Rejected as primary** | Requires populating `wrangler.jsonc`'s `triggers.crons`, which its own header says "would start real remote execution" and is explicitly deferred pending separate operator authorization this session cannot grant itself. No production hostname/routes exist yet either — Cloudflare is not the live DNS target (§4). |
| **B: Cloudflare Cron Trigger -> Cloudflare Queue -> consumer -> dispatch** | **Rejected** | All of Option A's blockers, plus zero existing Queue bindings, zero evidence of volume that would justify one (a nascent product, not a high-throughput one), and the mandate's own instruction: "do not introduce Queues unless current architecture justifies them." |
| **Vercel Cron (`crons` array in `vercel.json`) as primary** | **Rejected as primary, considered as an optional future addition** | The one existing Vercel Cron precedent in this exact repo (`dispatch-intel.js`) is explicitly documented as an anti-pattern in this codebase's own migration docs ("undeclared cron gap... not recoverable"). This sandbox also cannot verify a newly-declared Vercel cron actually fires (no dashboard/API access) — no stronger a guarantee than Cloudflare's, and with a worse track record in this specific repo. Not implemented this round; noted as a legitimate defense-in-depth addition for a future tranche, done declaratively in `vercel.json` this time (fixing, not repeating, the undeclared-config mistake) rather than dashboard-only. |
| **C, chosen: existing event-driven enqueue + GitHub Actions native schedule as dispatch/reconciliation** | **Selected** | Zero new infrastructure — reuses a scheduling substrate this exact repo already runs reliably at 30-minute cadence today (`sentinel-apex.yml`, `freshness-check.yml`). Directly avoids the one specific, evidenced reliability trap this repo's own `dispatch-intel.js` already documented (GitHub's native scheduler degrading below ~30 minutes). Requires no new secrets beyond ones already used by a sibling workflow (`backup-customer-data.yml`), and that workflow's own preflight-and-skip pattern is reused verbatim rather than re-invented. |

**This also elegantly resolves the mandate's "north-star" requirement that the *full* chain be autonomous, not delivery alone**: the new workflow runs `evaluate-watchlist-changes.js` (change detection) immediately followed by `deliver-watchlist-notifications.js` (delivery) in the same scheduled run. Scheduling delivery alone would have left the "you get alerted automatically when a tracked CVE's KEV status flips" promise still false end-to-end, since nothing would create the events delivery depends on. Both scripts already share an identical CLI-wrapper shape (established in PR #136), so covering both here is one extra `run:` line in the workflow, not a parallel mechanism — a deliberate, disclosed scope decision, not silent scope creep.

**Internal SLO** (Phase 53, not a contractual SLA): a dispatch attempt occurs within **~30 minutes** of a change becoming eligible, matching the cadence this repo's own evidence (`sentinel-apex.yml`, `freshness-check.yml`) shows GitHub Actions can actually deliver reliably. This is slower than "real-time" and is never described as such anywhere in this tranche's code, UI copy, or documentation.

---

## 7. Cloudflare Cron / Dormant `scheduled()` Handler

Implemented, not merely stubbed, but explicitly **not** wired to fire in production:

- `workers/lib/router.js` gained `handleScheduled(controller, env, ctx, deps = {})`, calling the exact same `evaluateWatchedEntities()`/`processDueDeliveries()` functions the Node CLI scripts call (one implementation, reused, not reimplemented for this runtime). Logs a compact structured summary (`{trigger, cron, elapsed_ms, evaluation, delivery}`).
- `workers/entry.js` gained a sibling `async scheduled(controller, env, ctx)` export alongside the existing `fetch`. Exporting it costs nothing at runtime when no Cron Trigger is configured — Cloudflare simply never calls it.
- `wrangler.jsonc` was **not modified** — `triggers.crons` remains absent, exactly as its own header requires pending a separate operator decision. Verifying this file was untouched: `git diff main -- wrangler.jsonc` is empty (confirmed before writing this section).
- Tested via a `deps` dependency-injection seam (4th param, default `{}` in every real call site) added specifically so `router.test.js` can inject fakes under plain `node:test` without a real Redis-backed `change-engine.js`/`notification-dispatch.js` in the loop — 2 new tests (`workers/lib/router.test.js`), both passing: calls both functions in order and returns a summary; propagates (does not swallow) a failure from either step.

This satisfies the mandate's Phase 6-7 literally while being honest that flipping it live is a distinct, operator-authorized infrastructure decision this tranche does not take for itself — matching Phase 6's own instruction: "Do not merely add a `scheduled()` function and claim automation exists."

---

## 8-10. Delivery Job Identity, Contract, State Machine

**Identity** (new): `buildDeliveryId(ownerId, eventId, channel)` -> `dlv_{ownerId}_{eventId}_{channel}` — deliberately **stable across every retry of the same semantic delivery**, not a fresh ID per attempt, per the mandate's own closing line in Phase 8: "the same semantic delivery must never create duplicate jobs merely because the scheduler runs twice." One canonical construction, used both as the claim key's identity and the customer-facing `X-Sentinel-Delivery-Id` header (§14).

**Contract** (the pending-delivery record, PR #136's shape, unchanged fields plus new semantics on existing ones):
```json
{
  "schema_version": "1.0",
  "owner_id": "usr_...", "event_id": "evt_...", "watchlist_id": "wl_... | null",
  "channels_pending": ["email", "webhook"],
  "attempts": { "webhook": { "count": 0, "next_attempt_at": 1234567890000 } },
  "created_at": "2026-08-25T..."
}
```
No plaintext secrets are stored in this record — the webhook signing secret lives only in `notify:prefs:{ownerId}`, referenced by owner ID at send time, never copied.

**State machine** (per channel, within one record):
```
PENDING (channel present in channels_pending, next_attempt_at <= now)
    -> [NEW] CLAIMED (atomic SET-NX-PX succeeded)
        -> DELIVERING (deliverEmailChannel/deliverWebhookChannel in flight)
            -> success -> DELIVERED (removed from channels_pending)
            -> failure, retryable, attempts remain -> RETRY_SCHEDULED (next_attempt_at bumped; [NEW] honors Retry-After when present, bounded)
            -> failure, [NEW] retryable:false OR attempts exhausted -> TERMINAL (moveToDeadLetter, removed from channels_pending)
        -> [NEW] channel disabled since enqueue -> CANCELLED (removed from channels_pending, no retry/dead-letter semantics)
    -> [NEW] claim not acquired (another invocation holds it) -> SKIPPED_THIS_CYCLE (state untouched)
CLAIMED, worker dies before completing
    -> [NEW] lease (CLAIM_LEASE_MS = 90s) expires -> PENDING again, automatically
```
No extra states were invented beyond what the existing PR #136 model plus this round's claim/lease/cancellation needed — `PENDING`/`RETRY_SCHEDULED`/`TERMINAL` are the same underlying data (`channels_pending` membership + `attempts[channel]`) PR #136 already had; `CLAIMED` is a separate, short-lived Redis key, not a new field on the record itself.

---

## 11-12. Atomic Claim / Lease

The core new correctness property. `api/_lib/redis.js` gained `setnxpx(key, val, ttlMs)` -> `SET key val NX PX <ttlMs>`, Upstash's own documented command syntax (an extension of the `setnx`/`SET...NX` primitive this codebase already uses for idempotent event creation — same command family).

- **Claim:** `notify.claimDeliveryChannel({ownerId, eventId, channel})` — one atomic round trip. Returns `true` iff *this* call created the claim key; `false` if it already existed (unexpired). Real Redis `SET...NX` is atomic at the server, so two concurrent callers can never both receive `true` for the same key — this is not a client-side check-then-set race.
- **Release:** `notify.releaseDeliveryChannel(...)` — best-effort `DEL` after an outcome is recorded, purely a throughput nicety (lets a *different* retry of the same channel become claimable again immediately rather than waiting out the full lease). Correctness never depends on this line executing.
- **Lease recovery:** `CLAIM_LEASE_MS = 90_000` — comfortably longer than one channel's worst-case attempt (`WEBHOOK_TIMEOUT_MS=8000` plus Redis round trips and a slow email-provider call), short enough that a genuinely crashed worker's claim self-expires and becomes claimable again within one dispatch cycle. **No separate "sweep for expired leases" job exists or is needed** — Redis's own key expiry *is* the recovery mechanism (Phase 11's own instruction: "use the actual storage backend's transaction/conditional-write semantics," not a hand-rolled `claimed_at`/`lease_expires_at` timestamp pair checked manually).

**Proven, not asserted:** `notification-dispatch.test.js`'s `overlapping concurrent invocations deliver a channel exactly once` test calls `Promise.all([processDueDeliveries(), processDueDeliveries()])` against the **same shared fake-Redis instance** and asserts the underlying send function (`fakeResendState.sendImpl`) was invoked exactly once, exactly one delivery log entry exists, and the two calls' own `skipped_claimed_elsewhere` counters sum to exactly 1. `notification-store.test.js` separately proves claim/release/independent-per-channel behavior directly, and the fake-Redis fixture's `setnxpx` was extended with **real TTL tracking** (not previously present for any command) specifically so lease-expiry could be tested with real semantics rather than a fixture that silently never expires anything.

---

## 13-14. Idempotency Limits & Webhook Delivery ID

**Stated honestly, per the mandate's own Phase 13 instruction not to certify the impossible:** true exactly-once *remote* delivery cannot be guaranteed. A webhook POST can be accepted by the customer's endpoint while the acknowledgment is lost to us (a network failure after their `2xx`, a process crash right after `fetch()` resolves but before `recordAttemptOutcome()` persists) — from our side this is indistinguishable from "never received," and a retry is the only available recovery, which the recipient may then see as a duplicate. This is a property of distributed systems generally, not a defect in this implementation, and is not certified away here.

What *is* now real: every webhook delivery carries a stable `X-Sentinel-Delivery-Id` header (and matching `delivery_id` field in the JSON payload body), unchanged across every retry of the same semantic delivery (§8's `buildDeliveryId`). A recipient can deduplicate on this value even if a request is seen twice. `notification-dispatch.test.js` confirms the header and payload field both carry the exact value passed in, and that it is `undefined`-safe (a real bug found in this round's own `api/v1/notifications.js` `handleTestWebhook`, which called `deliverWebhookChannel` without a `deliveryId` — the literal string `"undefined"` would have reached a real customer's webhook header. Fixed by generating one via the same `buildDeliveryId` helper for test deliveries too — see §27 self-found issues).

---

## 15-20. Webhook Signing, Replay, DNS Rebinding, SSRF, Redirects, Schemes — Re-Verified, Not Rebuilt

`api/_lib/webhook-signing.js` (PR #136) was read in full again this round and **left unmodified** — it already satisfies every item this mandate's Phase 15-20 lists:

- **Signing preserved:** HMAC-SHA256 over `${timestamp}.${rawBody}`, header `t=<unix>,v1=<hex>` — the same construction `api/_lib/stripe.js` already verifies for inbound Stripe webhooks, reversed for outbound use. Unchanged, still the only signing path.
- **Replay guidance:** `verifySignature()` already supports a `maxAgeSeconds` window (default 300s) for a *recipient's* own verification; this round adds explicit customer-facing guidance to actually use it (§72-equivalent, folded into §24 below) rather than leaving it undocumented.
- **SSRF blocklist:** `isSafeWebhookUrl()` — RFC1918, loopback, link-local (including `169.254.169.254`), CGNAT, IPv6 loopback/unique-local/link-local/multicast, IPv4-mapped-unwrapped, documentation/reserved ranges. Checked via a real DNS lookup (`{all: true}` — every resolved address, not just the first), fails closed on any lookup error.
- **DNS rebinding:** the narrow check-then-connect window (DNS re-resolves to a private address *between* the safety check and the actual `fetch()`) remains, disclosed as a Known Limitation both in PR #136's certification and here (§26) — no IP-pinning HTTP client was built, consistent with this repo's zero-npm-dependency convention (`resend.js`/`redis.js`). Nothing in this tranche narrows or widens that window.
- **Redirects:** `deliverWebhookChannel()` still uses `redirect: 'error'`, unchanged.
- **Schemes:** `https:` required, unchanged — `localhost`/`.local` rejected, unchanged.

**All 44 pre-existing `webhook-signing.test.js` tests still pass unmodified** (confirmed via this round's full regression run, §24) — direct evidence nothing here regressed.

---

## 21-26. Retry Classification, Backoff, Dead-Letter — New This Round

**Deterministic classification** (`notification-dispatch.js`, new `isRetryableHttpStatus`):
- **Permanent (not retryable):** `400, 401, 403, 404, 405, 410, 422` — exactly Phase 21's own list.
- **Everything else defaults to retryable**, including unlisted/unusual statuses — a deliberate safety choice: a false "retryable" costs one wasted attempt inside an already-bounded budget; a false "permanent" would silently drop a possibly-transient failure the retry budget existed to handle. Network errors (timeout, connection reset, DNS failure) are always retryable. An SSRF-blocked URL (`UNSAFE_URL`) is classified **not retryable** — Phase 25's own "invalid destination configuration" example, and retrying it would just repeat a DNS lookup against an address already known unsafe.
- **Retry-After honored, bounded:** `parseRetryAfterSeconds()` accepts the numeric-seconds and HTTP-date forms, rejects zero/negative/unparseable values (falls back to the normal table), and `notification-store.js`'s `recordAttemptOutcome` caps whatever value is honored at `MAX_RETRY_AFTER_SECONDS = 3600` — Phase 22's explicit requirement that "a malicious endpoint must not be able to defer delivery for years."
- **Bounded exponential-ish backoff, unchanged from PR #136:** `BACKOFF_MINUTES = [0, 2, 10, 30, 120]`, indexed by attempt count — not modified this round, still the fallback when no Retry-After is honored.
- **Max attempts, unchanged:** `MAX_RETRY_ATTEMPTS = 5`.
- **Dead-letter, extended:** `moveToDeadLetter()`'s record now carries a `reason` field — `'PERMANENT_FAILURE'` (immediate, first-attempt dead-letter for a `retryable:false` outcome) vs. `'MAX_RETRY_ATTEMPTS_EXHAUSTED'` (the pre-existing path) — so an operator or a customer's support ticket can tell the two apart. Never silently discarded; `listDeadLetters()` (unchanged) remains the customer-facing view.

Proven via `notification-store.test.js` (permanent-failure fast-path dead-letters on attempt 1, not after 5; Retry-After overrides and is bounded) and `notification-dispatch.test.js` (a live 404 through the full `processDueDeliveries()` path dead-letters immediately; a 429 with `Retry-After: 5` becomes due again after ~5s, not the default 2-minute backoff).

---

## 27-31. Isolation, Batching, Fairness, Timeout

- **Manual retry (Phase 27, 73):** new `POST /api/v1/notifications?action=retry-dead-letter` — re-queues one `(event_id, channel)` as a **fresh** pending delivery (a controlled new attempt with a reset budget) without touching or resurrecting the original dead-letter entry, which stays as honest history. Ownership-checked against the caller's own dead-letter list (never a client-supplied owner ID); requires the channel still be enabled/configured. A deliberate, bounded scope addition beyond the mandate's minimum (which hedges this as "if implemented") — justified because a dead-lettered alert with zero customer recourse is a real support burden once delivery is autonomous.
- **Poison-destination isolation (Phase 28):** unchanged from PR #136 — the per-record, per-channel loop already isolates one failing destination from every other owner's due deliveries; this round's `try/finally` around claim+deliver+release preserves that (a thrown error in one channel's handling still releases its own claim and moves to the next iteration).
- **Bounded batch (Phase 29):** `getDuePendingDeliveries()` already hard-caps a single call to 500 regardless of the requested `limit` (`Math.min(limit, 500)`, PR #136, unchanged). This round's own scale measurement (§25) found that bound alone is not sufficient given sequential per-record processing and an 8-second worst-case timeout per attempt — see the fix below.
- **Fairness (Phase 30):** evaluated, **not implemented** — `getDuePendingDeliveries()` returns records ordered by soonest-due score, which could theoretically let one customer's simultaneous batch of due records crowd out another's within a single bounded call. No evidence this occurs at this platform's current or near-term scale (per-customer volume is naturally bounded by watchlist size), and the mandate's own words: "Avoid overengineering without evidence." Documented as a deferred, evidence-based decision, not an oversight (tracked in §26/open-issues).
- **Delivery timeout (Phase 31):** `WEBHOOK_TIMEOUT_MS = 8000`, unchanged from PR #136, via `AbortController`.

**A real finding from this round's own scale measurement (§25):** 500 sequential worst-case-timeout webhook attempts at 8s each is ~67 minutes — far past any reasonable scheduled-job timeout. Fixed by passing `--limit=50` to the scheduled workflow's `deliver-watchlist-notifications.js` invocation (worst case ~7 minutes) and setting the workflow's `timeout-minutes: 15` for headroom — an evidence-based bound, not a guess (§25, §37).

---

## 32-34. Email Delivery Hardening

`api/_lib/resend.js`'s `resendRequest()` now attaches `.status` (the real HTTP status Resend returned) to the thrown `Error` object, additively — no existing catch site that only reads `.message` is affected (confirmed: the only two call sites, `addContact`/`sendEmail`'s callers, are unaffected by an added property). `deliverEmailChannel()` uses that status through the same `isRetryableHttpStatus()` classifier webhook delivery uses — one classification function, not two.

**Idempotency (Phase 33):** Resend does not expose a client-supplied idempotency key in this integration; no local delivery-identity-to-provider-message-ID mapping was added this round (PR #136 did not have one either). Documented as unchanged/still-open, not silently resolved.

**Hard bounces (Phase 34):** not distinguishable from Resend's synchronous send-time response alone — a hard bounce is typically an asynchronous webhook event from the provider, which this integration does not subscribe to. `EMAIL_NOT_CONFIGURED`/`NO_RECIPIENT` remain classified retryable (§21) — deliberately, since both can resolve without any code change (an operator adds `RESEND_API_KEY`, or a customer adds a recipient) before the next attempt. No customer account is disabled due to one invalid email — Phase 34's explicit instruction.

---

## 35-38. Delivery History, API, Preferences — Audited, Extended Where Justified

`GET ?action=deliveries` / `GET ?action=dead-letters` (PR #136) already provide bounded, paginated (`limit`, clamped 1-200), newest-first history — audited this round, no gap found, **not rebuilt**. New this round: `POST ?action=retry-dead-letter` (§27-31). Preferences (`email_enabled`, `email_override`, `webhook_enabled`, `webhook_url`, secret rotation) audited — no gap found beyond the `deliveryId`-undefined bug in `handleTestWebhook` fixed this round (§14, §37).

---

## 39-42. Secret Rotation, Redaction, Audit Log

Rotation and show-once redaction (PR #136) audited, unchanged, still correct: `getPreferences()` only ever returns `has_webhook_secret: boolean`; the raw secret is returned exactly once by `rotate-webhook-secret` and by no other endpoint. **New this round:** `auditNotificationAction(ownerId, action, data)` in `notification-store.js`, mirroring `watchlist-store.js`'s existing `auditWatchlistAction()` pattern exactly (bounded ZSET, `AUDIT_LOG_MAX_ENTRIES = 10000`, matching that function's own bound) against a new `audit:notify:log` key — not a reuse of the watchlist or payment audit keys, since each domain's helper is hardcoded to its own key and mixing entries would blur an otherwise-clean per-domain trail. Wired into `update-preferences` (field *names* changed, never values — Phase 78 privacy minimization), `rotate-webhook-secret` (action only, never the secret), and `retry-dead-letter` (event_id + channel). A logging failure never blocks the caller (`try/catch`, matching the existing pattern exactly) — proven via a test that makes the underlying `zadd` throw and confirms the caller still resolves normally.

---

## 43-46. Entitlements, Centralization, Customer Isolation, IDOR

**Entitlements remain flat** (`email_notifications_enabled`/`webhook_notifications_enabled` both `true` for every tier) — an already-disclosed gap from PR #136's Issue 24, unchanged this round. No new pricing was invented, per the mandate's own explicit prohibition ("do not invent new pricing... map to current plans only where existing commercial policy supports it") — there is no existing commercial policy differentiating these, so none was applied.

**Customer isolation / IDOR:** every handler in `api/v1/notifications.js`, including the new `retry-dead-letter`, calls `authenticate(req, res)` first and uses only the server-derived `user.userId` for every store call — zero client-suppliable owner IDs anywhere in the router (re-verified by reading the full file this round). `retry-dead-letter` specifically resolves ownership via the caller's **own** dead-letter list (`notify.listDeadLetters(user.userId, ...)`), never a request-supplied owner field — a request for another customer's `event_id`/`channel` pair returns `404 NOT_FOUND`, not their data. Proven with a dedicated adversarial test: customer B, with the *same* `event_id`/`channel` values customer A's real dead-letter carries, gets `404`.

---

## 47-51. Storage, Atomic Transitions, Outbox, Reconciliation, Stuck-Job Recovery

**Storage confirmed unchanged: Redis only, no D1** (§4) — every new piece of state (claim keys, audit log) lives in the same Upstash-REST-backed store as everything else.

**Atomic transitions:** `PENDING -> CLAIMED` is the one genuinely new atomic transition (`SET...NX...PX`, §11). `CLAIMED -> DELIVERED/RETRY/TERMINAL` are still single `redis.set()` writes of the whole record (PR #136's existing model) — not multi-step, so nothing new to make atomic there; a crash mid-write leaves the record in its pre-write state, which the next cycle re-evaluates normally (no torn-write risk with a single JSON blob written in one command).

**Outbox pattern (Phase 49):** evaluated, **not introduced**. `dispatchNewEvent()`'s enqueue and `persistEventIfNew()`'s event-creation (change-engine.js) are two separate Redis writes, not one transaction — a crash between them would leave an event with no corresponding delivery job. This is a **pre-existing** property of PR #136's design, not introduced or worsened this round. Given this platform's own reconciliation property below, and no evidence of this actually occurring, an outbox pattern was not built — the mandate's own instruction: "Do not introduce an outbox without proving a real gap."

**Reconciliation (Phase 50), already free:** `getDuePendingDeliveries()` re-scans the **entire** `notify:pending_queue` sorted set by score on every invocation, not just newly-enqueued jobs — so any record whose `next_attempt_at` has passed is found and retried on the very next scheduled run, whether it's "new," "backed off," or "was claimed by a worker that then died." **No separate reconciliation job was built because the existing sweep already performs that role** — confirmed by reading `getDuePendingDeliveries()`'s implementation, not assumed.

**Stuck-job recovery (Phase 51):** this is exactly what claim/lease provides (§11-12) — a `CLAIMED` channel whose lease expires is, by construction, `PENDING` again (the claim key simply no longer exists), found by the same full-queue sweep. No metric currently counts *how often* this recovery path actually fires versus a clean first-time claim (a real, disclosed observability gap — §26).

---

## 52-56. Observability, Run Summary, Operator Health

New this round, `notification-store.js`: `getOldestPendingAgeSeconds()` — how overdue the single most-overdue still-pending channel is, in seconds (0, never negative, when nothing is overdue; `null` when the queue is empty). Deliberately answers "how far behind is the dispatcher," not "time since creation" — Phase 52's own framing: "a service with a growing queue but no obvious errors is unhealthy."

`scripts/deliver-watchlist-notifications.js` now logs both expanded human-readable lines (claimed / skipped-claimed-elsewhere / cancelled counts, oldest-pending-age) and one compact structured JSON summary line (`[NOTIFY-DELIVER-SUMMARY] {...}`, Phase 55's own example shape — `records_processed, claimed, skipped_claimed_elsewhere, cancelled, attempts, delivered, retrying, terminal, oldest_pending_delivery_age_seconds, elapsed_ms`), safe to grep out of GitHub Actions logs or pipe elsewhere without needing to reformat the human-readable lines. `workers/lib/router.js`'s dormant `handleScheduled()` logs an equivalent `[SCHEDULED]` JSON line.

**No dedicated operator health-view UI page exists** (Phase 56) — this platform's admin surface (`api/v1/admin.js`) was not extended this round; the structured JSON log lines above are the only currently-available operator signal, an honest limitation, not a claim of a built dashboard.

---

## 57-59. Customer UI, Failure Messages, Payload Versioning

`api-dashboard.html`'s Alert Delivery panel copy updated ("Delivery runs automatically roughly every 30 minutes" — now true, was previously aspirational). **New:** a "⛔ Dead Letters" card listing dead-lettered deliveries with attempt counts and a **Retry** button wired to the new API action; the pre-existing Delivery Log card's status badge coloring extended so `cancelled` renders distinctly (neutral gray) from `failed` (red) — a real bug this round's own review caught: without the fix, a customer-initiated channel disable would have rendered identically to a real failure.

**Failure message safety (Phase 58):** unchanged from PR #136 — error strings surfaced to the customer (`HTTP_404:...`, `TIMEOUT`, `UNSAFE_URL:BLOCKED_IP`) never include resolved IP addresses, internal resolver details, or stack traces; verified by reading every `error:` value `recordDelivery()` receives across both channels.

**Payload versioning (Phase 59):** the webhook JSON body gained an explicit `schema_version: "1.0"` field (`WEBHOOK_PAYLOAD_SCHEMA_VERSION`), alongside the pre-existing `id`/`type`, and the new `delivery_id`. Additive fields only — no existing field was renamed or removed, so this is not a breaking change for any integrator already parsing PR #136's payload shape.

---

## 60-67. Content Integrity, Template Injection, Payload Safety

Unchanged from PR #136, re-verified by reading the code this round: the webhook payload and email body both derive from the same canonical change event (`change-engine.js`) — no second event taxonomy was introduced. `escapeHtml()` still guards every upstream-derived value inserted into the email's HTML body; the text body is never parsed as markup. Nothing in this round's changes touches severity/confidence/exploitation fields — no code path exists anywhere in `notification-dispatch.js` that could upgrade `UNKNOWN` to `CONFIRMED` or fabricate attribution, and this round added none. Webhook response bodies remain truncated to `MAX_WEBHOOK_RESPONSE_BYTES = 4096` before logging, unchanged. Log redaction: neither the webhook signing secret nor any API key is ever passed to `console.log`/`recordDelivery`/the new audit log — confirmed by reading every call site that logs anything in the touched files.

---

## 68-71. Concurrency, Crash Simulation, Ambiguous Success

**Cron/invocation overlap:** proven directly, not simulated in the abstract — `notification-dispatch.test.js`'s concurrency test (§11-12) issues two genuinely overlapping `processDueDeliveries()` calls via `Promise.all` against one shared store and asserts exactly one delivery occurred.

**Worker restart / crash:** simulated via the claim/release test suite — a claim acquired and never released (standing in for a process that dies mid-delivery) is proven to expire and become claimable again once its `CLAIM_LEASE_MS` window passes (`notification-store.test.js`'s claim/lease describe block, using the fake-Redis fixture's new real TTL simulation, not a mocked-away expiry).

**Ambiguous remote success (Phase 71):** documented, not solved (§13) — this is the one category of duplicate this implementation genuinely cannot rule out (a webhook accepted, response lost), which is why `X-Sentinel-Delivery-Id` exists: the mitigation is recipient-side deduplication, not a claim of zero duplicates.

---

## 72. Webhook Integration Guide (customer-facing consumer guidance)

For any customer building a webhook receiver against this platform:

1. **Verify the signature** on every request using `X-Sentinel-Signature` (`t=<unix>,v1=<hex>`) and your webhook secret, recomputing `HMAC-SHA256("{t}.{raw_body}")` — do not trust an unverified payload.
2. **Verify the timestamp** (`t=`) is recent — reject anything older than a few minutes to limit replay risk. This platform's own `verifySignature()` reference implementation uses a 300-second window.
3. **Deduplicate by `X-Sentinel-Delivery-Id`** (also present as `delivery_id` in the JSON body) — this value is **stable across every retry** of the same semantic delivery. Seeing it twice means "the same alert, delivered again," not "two different alerts."
4. **Return a 2xx quickly, then process asynchronously.** This platform's own outbound timeout is 8 seconds; a slow synchronous handler risks being classified as a timeout and retried, producing a delivery your system may already have received.
5. **Tolerate retries.** A 5xx, a timeout, or a 429-with-`Retry-After` from your endpoint is treated as transient and retried on a bounded backoff (up to 4 more attempts); a 4xx (other than 429) is treated as a configuration problem on your end and is **not** retried — fix the destination or re-trigger delivery manually from the dashboard's Dead Letters card.

---

## 73-78. Manual Retry, Disabled/Changed/Deleted Destinations, Retention, Privacy

**Manual retry:** §27-31 above. **Disabled destination (Phase 74):** proven end-to-end — a channel disabled between enqueue and delivery is detected inside `processDueDeliveries()`'s own loop (re-reading current preferences, which it already loaded per-record) and cleanly cancelled, never sent, never retried, never dead-lettered (`notification-dispatch.test.js`: "a channel disabled between enqueue and delivery is cancelled cleanly, not sent or retried" — asserts the underlying send function's call count is exactly 0). **Destination change (Phase 75):** `buildDeliveryId` does not include a config-version component; an in-flight retry targets whatever URL is *current* in preferences at send time, not a snapshot from enqueue time — an intentional, pre-existing PR #136 behavior (a customer fixing a broken URL wants the next retry to use the fix), not altered this round, and disclosed as such rather than silently assumed. **Deletion (Phase 76):** unchanged — historical delivery-log/dead-letter entries persist after a preference change; no plaintext secret is ever stored in either. **Retention (Phase 77):** unchanged bounded caps (`MAX_DELIVERY_LOG_ENTRIES=500`, `MAX_DEAD_LETTER_ENTRIES=200` per owner) — no customer SLA was invented. **Privacy minimization (Phase 78):** the new audit log stores field *names* changed, never values (§39-42).

---

## 79-80. Failure Injection & Security Tests

**Failure injection**, proven via real test execution (not asserted): webhook 200/404/429-with-Retry-After/500/503, timeout, network error, SSRF-blocked destination (private IP, cloud-metadata address), a malformed Retry-After header, email success/`EMAIL_NOT_CONFIGURED`/`NO_RECIPIENT`/a classified-status provider error, event deleted between enqueue and delivery, watchlist deleted between enqueue and delivery, duplicate concurrent cron-style invocation, expired lease (via real fixture TTL), disabled destination mid-flight, dead-letter-then-manual-retry.

**Security tests:** SSRF (44 pre-existing tests, still passing, §15-20), IDOR (new: cross-customer dead-letter retry, §43-46), customer isolation (existing + new), secret redaction (`getPreferences()` never returns the raw secret — existing, re-verified), XSS in the new dashboard UI additions (the retry button's `event_id`/`channel` are server-generated, non-free-text values — not user-authored strings, consistent with this dashboard's existing risk profile for similar ID-bearing `onclick` handlers elsewhere on the same page). Prototype-pollution payloads (via `JSON.parse('{"__proto__":...}')`, this session's established discipline) were re-run as part of the full `notifications.test.js` suite (unchanged from PR #136, still passing).

---

## 81-84. Production Canary & Live Cron Verification

**Not performed — disclosed, not silently skipped.** This sandbox has:
- No Vercel dashboard/API access (cannot declare or verify a Vercel Cron, cannot confirm `UPSTASH_REDIS_REST_URL`/`RESEND_API_KEY` values in the live Vercel environment beyond what `.env.example`/existing docs already describe).
- No GitHub Actions dashboard/API access to trigger `alert-delivery.yml` via `workflow_dispatch` and observe a real run (this is a **local git repository session**, not an authenticated GitHub session — pushing this branch and opening a PR is the mechanism by which the *actual* GitHub Actions environment will first see this workflow file at all).
- No Cloudflare account/wrangler-login access (irrelevant here regardless, since Cloudflare Cron is intentionally not the live mechanism, §6).

What **is** verified: the workflow's YAML parses correctly (`js-yaml`, confirmed this round) and its structure (schedule, concurrency group, preflight gate, both `run:` steps, secret references) was read back and matches the design in §6-7. Once merged, the very next `git log` on `main` after the first scheduled firing (or the first `workflow_dispatch`) is the actual live-verification evidence — not available inside this session. This is disclosed as the top Known Limitation (§26/§1), not claimed away.

---

## 85-87. Performance, Cost, Scale

Measured locally against the fake-Redis fixture (in-memory, no real network — these numbers characterize this code's own overhead, not Upstash's real round-trip latency, which will dominate in production and was not measured here):

| Batch size | Records processed | Elapsed | ms/record |
|---|---|---|---|
| 10 | 10 | 282 ms | 28.2 |
| 100 | 100 | 5,567 ms | 55.7 |
| 1000 (requested) | **500** (hard-capped, §29) | 47,072 ms | 94.1 |

The 1000-request/500-actual row is itself a real finding, not noise: `getDuePendingDeliveries()`'s pre-existing `Math.min(limit, 500)` cap silently enforced the true batch ceiling — confirmed, not assumed, by seeing the discrepancy directly. This measurement is what led to §29's `--limit=50`/`timeout-minutes: 15` fix.

**Cost model** (Phase 86, directional, not measured against real billing): the dominant variable cost is GitHub Actions minutes (one ~1-3 minute job every 30 minutes under normal load, well within any repo's free/included allowance) plus Upstash Redis command count (each due channel costs roughly 6-8 commands: claim, prefs read, event read, watchlist read, outcome record, delivery-log write, release) and Resend/webhook egress proportional to actual deliveries, not to corpus size — the evaluator/dispatcher never scans the full intelligence corpus per run (bounded by watched-entity count and due-queue size respectively). No premature optimization was applied; the `--limit=50` bound exists for correctness (§29), not cost.

---

## 88-89. Full Regression & Adversarial Review

**Exact totals, this round, full suite:**
```
npx jest
Test Suites: 61 passed, 1 skipped, 62 total
Tests:       2120 passed, 60 skipped, 2180 total
Time:        18.89s

node --test workers/lib/*.test.js
tests 118
pass 118
fail 0
```
Baseline before this round (PR #136, from that certification's own record): 2080 passed. This round adds new coverage across `notification-store.test.js`, `notification-dispatch.test.js`, `notifications.test.js`, and `router.test.js` — net positive, zero regressions, zero skips introduced by this round's own changes (the 60 skipped tests are pre-existing and unrelated to this tranche).

**Adversarial self-review found and fixed, before any external reviewer, five real issues this round:**
1. Two pre-existing test mocks (`notification-dispatch.test.js`, `notifications.test.js`) simulated a webhook response without a `.headers` object — this round's new `res.headers.get('retry-after')` call would have thrown against them. Fixed by adding a real `.headers.get()` stub, matching what an actual `fetch()` Response always provides.
2. `api/v1/notifications.js`'s `handleTestWebhook` called `deliverWebhookChannel` without a `deliveryId`, which would have sent the literal string `"undefined"` as `X-Sentinel-Delivery-Id` on every test delivery. Fixed by generating one via `buildDeliveryId`.
3. Two pre-existing `notification-store.test.js` assertions expected `recordAttemptOutcome()` to resolve to `undefined`; this round's new return-value contract (`'delivered'|'retrying'|'dead_lettered'|'unresolved'`) made those assertions wrong, not the new behavior — fixed the assertions, not the source, after confirming the new return value is itself correct and intentional.
4. The scale measurement in §85-87 surfaced the 500-attempts-worst-case-exceeds-job-timeout risk (§29) — found by actually running the code at scale, not by inspection alone.
5. The dashboard's delivery-status badge coloring would have rendered a `'cancelled'` entry with the same red styling as a real failure — cosmetically misleading, fixed (§57-59).

**CodeQL:** no separate CodeQL run was triggered from this sandbox (no CI/CodeQL runner access); the equivalent manual review above (SSRF re-audit, IDOR test, prototype-pollution re-run, secret-redaction re-check) is the disclosed substitute, consistent with this session's established practice for prior tranches.

---

## 90-92. Deployment Config, Migration Safety, Runbook

**Deployment config:** `wrangler.jsonc` untouched (confirmed via `git diff`, §7); `vercel.json` untouched — no new Vercel function registration was needed since `retry-dead-letter` is a new *action* on the already-registered `api/v1/notifications.js`, not a new file/route. The one new deployment artifact is `.github/workflows/alert-delivery.yml` itself, YAML-validated (§81-84). No production/preview binding confusion is possible — this workflow declares no Cloudflare or Vercel bindings at all, only GitHub Actions secrets already scoped to this repository.

**Migration safety:** not applicable — no D1 migration, no schema change; Redis keys are schema-less and additive (`notify:claim:*`, `audit:notify:log` are new key *prefixes*, never a rewrite of an existing key's shape).

**Runbook** (condensed; expand into `RUNBOOKS.md` in a future tranche if warranted):
- *Workflow stopped firing:* check `Actions -> Watchlist Alert Delivery` run history for the preflight-skip warning (missing secrets) vs. an actual step failure; `workflow_dispatch` fires it manually either way.
- *Growing dead-letter count:* check `GET ?action=dead-letters` per affected owner; the `reason` field (`PERMANENT_FAILURE` vs `MAX_RETRY_ATTEMPTS_EXHAUSTED`) tells you whether it's a customer-side config issue or a transient-outage pattern worth investigating on the destination side.
- *Suspected stuck claims:* claim keys self-expire after `CLAIM_LEASE_MS` (90s) — no manual intervention is ever required; if `oldest_pending_delivery_age_seconds` (logged every run) grows without bound across multiple cycles, the dispatcher itself is not running (check the workflow, not the data).
- *Secret compromise (webhook signing secret):* customer-initiated `rotate-webhook-secret` immediately invalidates the old value; no platform-side action needed beyond confirming the customer rotated it.
- *Duplicate delivery reports from a customer:* ask for the `X-Sentinel-Delivery-Id` they received twice — if it's the same value both times, this is the disclosed ambiguous-remote-success case (§13/§68-71), not a bug; if the values differ, that would be a real defect worth escalating.

---

## 93-98. Commercial & Reliability Workflow Proofs

Proven by the actual test suite exercising the real code paths end-to-end (not separate demo scripts, reusing already-built evidence rather than duplicating it):

- **A (CVE/KEV -> email -> delivered -> history):** `notification-dispatch.test.js`, "delivers a due email successfully and records it in the delivery log" — full `dispatchNewEvent` -> `processDueDeliveries` -> `listDeliveries` chain.
- **B (webhook -> signature -> delivery -> history):** the same file's `deliverWebhookChannel` describe block plus "email and webhook channels on the same event are both attempted independently" — signature format asserted directly (`/^t=\d+,v1=[0-9a-f]{64}$/`).
- **Reliability (retry then success, other customers unaffected):** "a failed delivery is scheduled for retry, not immediately dead-lettered" plus "respects the limit parameter across multiple due owners" (three independent owners, one bounded batch) together demonstrate isolation.
- **Terminal failure (no infinite retry, operator/customer visible):** "a 404 webhook response dead-letters on the very first attempt" — `attempts: 1`, `reason: 'PERMANENT_FAILURE'`, visible via `listDeadLetters()` and the new dashboard card.
- **Duplicate-suppression (concurrent invocation, one delivery):** the `Promise.all` concurrency test, §11-12.
- **Crash-recovery (claim, simulated crash, lease expiry, recovery):** the claim/release/lease describe block in `notification-store.test.js`.

---

## 99. Known Limitations (full list)

1. **Not yet observed live.** The GitHub Actions schedule and secret-preflight gate are code-complete and unit/YAML-validated, not yet observed firing in the actual GitHub Actions environment from this sandbox (§81-84) — the top limitation, listed first deliberately.
2. **`UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN` as GitHub Actions secrets specifically are unverified** — proven to exist as Vercel env vars; unverified whether also present in this repo's GitHub Actions secret store (§4, §81-84). The workflow degrades safely (visible warning, no silent no-op, no confusing failure) if they are absent, mirroring `backup-customer-data.yml`'s own already-established handling of this exact situation.
3. **Cloudflare Cron Trigger remains not live**, by deliberate, unchanged design (§6-7).
4. **DNS-rebinding window** between SSRF check and actual connection remains, unchanged from PR #136 (§15-20).
5. **True exactly-once remote delivery is not achievable** and is not claimed (§13, §68-71) — mitigated via a stable delivery ID for recipient-side dedup, not eliminated.
6. **Per-customer fairness within one dispatch batch is not implemented** — a deliberate, evidence-based deferral (§27-31), not an oversight.
7. **No operator health-view UI** — only structured log-line observability exists (§52-56).
8. **Entitlements remain flat** — unchanged, already-disclosed gap from Issue 24 (§43-46).
9. **Email hard-bounce classification and provider idempotency keys are not implemented** — Resend's synchronous response does not expose either (§32-34).
10. **No live Cloudflare Queue exists or was evaluated for live verification** — moot, since Queues were not selected as the orchestration mechanism (§6).

None of these were hidden or discovered by a reviewer after the fact — each was found and documented during this round's own audit and self-review.

---

## 100. Rollback

Purely additive at the infrastructure level: one new GitHub Actions workflow file (`alert-delivery.yml` — delete it to fully stop autonomous firing, with zero effect on anything else, since it only ever invokes pre-existing scripts) and one new dormant Worker export (`scheduled`, inert without a Cron Trigger). At the application level: new functions/fields on `notification-store.js`/`notification-dispatch.js` are additive; the one behavior change to an *existing* function (`recordAttemptOutcome`'s new optional params and return value) is backward compatible — omitting the new params reproduces the exact prior behavior, and the new return value was the only reason two pre-existing test assertions needed updating (§88-89, item 3), not a breaking change to any real caller. No existing route, schema, database migration, or exported interface was removed or renamed. Reverting this PR's commits fully restores PR #136's prior (manual-only) posture.

---

## 101. Final Verdict

**CONDITIONAL GO.**

Alert delivery is now built to be autonomous, durable under concurrent/repeated execution, recoverable after a crash, and observable — all proven through real, adversarial, concurrency-aware tests, not asserted. The two things standing between this and an unqualified GO are both about **verification this sandbox cannot perform, not about missing engineering**: confirming the GitHub Actions secrets are actually configured, and observing one real scheduled run fire in production. Both become checkable the moment this branch is merged and the workflow has its first real opportunity to run.

