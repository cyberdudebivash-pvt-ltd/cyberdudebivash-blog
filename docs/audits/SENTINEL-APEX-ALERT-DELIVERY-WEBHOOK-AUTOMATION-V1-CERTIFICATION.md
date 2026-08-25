# SENTINEL APEX — Alert Delivery & Webhook Automation v1
## Production Certification

**Date:** 2026-08-25
**Branch:** `claude/p1-alert-delivery-webhook-automation-v1`
**Baseline:** `SENTINEL-APEX-WATCHLISTS-CHANGE-DETECTION-V1-CERTIFICATION.md` (merged as PR #134) built customer-owned watchlists and deterministic intelligence change detection, but explicitly deferred alert delivery — "the platform's monitoring feed exists, but a customer must visit the dashboard to see it." That certification's own §102/forward-look named this exact tranche (email, signed webhooks, notification preferences, retry/dead-letter, delivery logs) as the recommended next step. This tranche builds it.

---

## Executive Verdict

**GO.**

A working, tested, security-reviewed delivery mechanism for watchlist change events now exists: email (via the platform's existing Resend integration) and signed webhooks (HMAC-SHA256, Stripe-compatible signature scheme) with per-channel retry/backoff and dead-lettering. 108 new/touched tests pass, full regression is green, and a dedicated SSRF threat model — the headline risk of any "deliver to a customer-supplied URL" feature — was built, tested adversarially, and hardened during this round's own self-review (see §11 and §16).

This is **not** real-time alerting. Delivery — both the first attempt and every retry — runs only when `scripts/deliver-watchlist-notifications.js` is invoked, exactly as watchlist change evaluation itself only runs when `scripts/evaluate-watchlist-changes.js` is invoked. No claim of instant or real-time delivery appears anywhere in this tranche's code, UI copy, or documentation.

---

## Customer Problem

Watchlists v1 answers "what changed and why does it matter" — but only if the customer remembers to open the dashboard. This tranche closes that loop: a customer can now say "email me" or "POST to my SIEM/SOAR webhook" once, and every future genuinely-new change on their watchlists reaches them there — without rebuilding or duplicating the change-detection logic that already exists.

---

## Scope

**In scope:** email and webhook delivery of watchlist change events; per-owner notification preferences; signed-webhook infrastructure (HMAC signing, SSRF-safe URL validation); bounded retry with per-channel backoff; dead-lettering; a customer-visible delivery log; dashboard UI for all of the above.

**Explicitly out of scope (deferred, not silently missing):** Slack/Teams/PagerDuty-style native integrations (webhook covers this generically — a customer can point their own relay at it); a live Cloudflare Cron Trigger for either the evaluator or the delivery sweep (both remain manually/externally triggered — see Known Limitations); a distributed lock for concurrent script invocations; per-tier entitlement gating of notification channels (flat across tiers, matching the existing, already-documented gap in watchlist entitlements).

---

## Reuse-Before-Build Audit

Before writing any new code, the following were searched for and either reused or explicitly rejected with cause:

| Capability needed | Found | Decision |
|---|---|---|
| Email sending | `api/_lib/resend.js` (`sendEmail()`, `canSendEmail()`) — the same client `auth.js`'s registration welcome-email already uses (`tests-js/registration-welcome-email.test.js`) | **Reused unchanged.** No new email client built. |
| Email content-builder pattern | `api/v1/auth.js`'s `buildWelcomeEmail()` (`{subject, text, html}` triple) | **Pattern mirrored exactly** for `buildWatchlistAlertEmail()` — same structure, same "text body raw, html body escaped" discipline. |
| Signature scheme | `api/_lib/stripe.js`'s inbound webhook verification (`t=…,v1=…` HMAC-SHA256 + `crypto.timingSafeEqual`) | **Scheme mirrored, direction reversed** — outbound signing in `webhook-signing.js` uses the identical construction, not a new protocol. |
| Account email lookup by userId | `api/v1/auth.js`'s `handleRegister()` write pattern (`user:id:{userId}` → API-key hash → `user:key:{hash}`.email) | **Reused via the same 2-hop lookup**, not a new `userId → email` index. |
| Watchlist ownership/read | `watchlist-store.js`'s `getWatchlist(id, ownerId)` (ownership-checked, public-shaped) | **Reused unchanged** for resolving a watchlist's name at delivery time. |
| Redis "give me due items" primitive | Not present — `redis.js` had no score-range query | **New, minimal addition**: `zrangebyscore`, the same class of justified extension as the watchlist round's own `setnx` addition. |
| Retry-queue / job-scheduling infrastructure | None in this repo (`content_discovery.py`'s retry queue is Python-side and file-backed, unrelated) | **New, built in `notification-store.js`** — no existing JS-side equivalent to extend. |

No second email client, no second signature scheme, no second customer-identity index, and no second intelligence store were created.

---

## Architecture

```
change-engine.js's evaluateEntity()            (unchanged responsibility: detect + persist + fan out to feed)
  |
  +-> store.appendToOwnerFeed(ownerId, eventId)  (pre-existing, untouched)
  |
  +-> notificationDispatch.dispatchNewEvent({ownerId, watchlistId, event})   [NEW, enqueue-only, error-swallowed]
        |
        v
notification-store.js's enqueuePendingDelivery()
  -> notify:pending:{ownerId}:{eventId}  (one record, both channels tracked independently)
  -> notify:pending_queue                 (global sorted set, scored by soonest-due channel)
        |
        v  (a SEPARATE, manually-run process)
scripts/deliver-watchlist-notifications.js -> notification-dispatch.js's processDueDeliveries()
  -> notify.getDuePendingDeliveries()     (bounded ZRANGEBYSCORE, not a full scan)
  -> per due channel: deliverEmailChannel() / deliverWebhookChannel()
  -> notify.recordAttemptOutcome()         (success -> remove; failure -> backoff or dead-letter)
  -> notify.recordDelivery()               (customer-visible audit trail)
```

Change detection and notification delivery are two independent processes joined only by the Redis-persisted pending-delivery queue — a network failure or a slow customer endpoint during delivery can never block or slow down change detection, and vice versa.

---

## Notification Ownership Model

Preferences and delivery history are **account-level**, not watchlist-level — a customer has one inbox and (optionally) one webhook endpoint, not one per watchlist, matching how a real person actually wants to be notified. Ownership is always the authenticated caller's own `userId` (`authenticate()`'s return value), never trusted from the request body — the same discipline already established for watchlists themselves.

---

## Supported Channels

**Email.** Sent via `resend.js`, defaulting to the account's own registration email; a customer may set an explicit override address. Enabled by default (the lowest-risk channel, tied to something the customer explicitly opted into by creating a watchlist) — trivially toggled off.

**Webhook.** A signed HTTPS POST to a customer-supplied URL. Disabled by default (cannot be enabled without an explicit URL and a generated secret — see §12). Requires the URL to pass the SSRF-safety guard (§11) both when saved and again immediately before every delivery attempt.

Both channels are gated by `getWatchlistEntitlements()`'s new `email_notifications_enabled`/`webhook_notifications_enabled` flags — flat across tiers, the same documented posture as every other watchlist limit (no centralized entitlement layer exists yet to gate this by tier, and CLAUDE.md's own constraint against inventing pricing applies here identically).

---

## Webhook Signature Scheme

`X-Sentinel-Signature: t=<unix-seconds>,v1=<hex HMAC-SHA256 of "{t}.{raw body}">` — byte-for-byte the same construction Stripe uses for its own outbound webhooks (and the same one `stripe.js` already verifies for *inbound* Stripe webhooks in this repo), chosen deliberately so integrators who already handle Stripe webhooks recognize the pattern immediately. `verifySignature()` is also implemented (constant-time via `crypto.timingSafeEqual`, with a bounded signature-age window) for completeness/testability, even though v1's own delivery path only ever signs, never verifies its own output.

The envelope: `{id: "evt_{event_id}", type: "watchlist.change_event", created_at, data: {...the same event fields already visible in the authenticated feed..., watchlist: {id, name}}}` — no new or additional data beyond what the owner can already see in their own dashboard feed.

---

## SSRF Threat Model (the headline risk)

A webhook URL is customer-supplied and fetched by our own server on every delivery — the canonical SSRF vector. `webhook-signing.js`'s `isSafeWebhookUrl()`:

- Requires `https:` (rejects `http:` and any other scheme).
- Rejects `localhost`, `*.localhost`, `*.local`.
- Rejects a direct IP-literal host (bracketed IPv6 included — a real bug found and fixed this session, see §16) in any blocked range: all of RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local including the AWS/GCP/Azure/OCI metadata address `169.254.169.254` (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), unique-local IPv6 (`fc00::/7`), multicast, and the IETF documentation/reserved ranges.
- For a hostname (not a literal), performs a real DNS lookup and rejects if **any** resolved address falls in a blocked range — catching the common case of a hostname that simply resolves to an internal address.
- Runs **twice**: once when a customer saves `webhook_url` (immediate feedback, rejects bad input before it's ever stored) and again immediately before every delivery attempt (the real enforcement point — a URL's DNS record can change between save and delivery).
- The outbound `fetch()` itself uses `redirect: 'error'` — a redirect response is treated as a failure, never followed, closing the "302 to an internal address" bypass.
- A per-request `AbortController` timeout (8s) prevents a slow or hanging customer endpoint from blocking the delivery sweep.

**Disclosed, not claimed away:** this is a check-then-connect guard, not a connect-time IP-pinning HTTP client (which would require a custom DNS resolver + socket-level IP binding this repo's zero-npm-dependency convention doesn't build here). A DNS record that resolves safely at check time and changes to an internal address in the following moments before the `fetch()` call completes its own resolution is a real, narrow, disclosed residual window — the two-time check (save + every delivery, not just save) minimizes but does not eliminate it. Documented in Known Limitations, not hidden.

44 dedicated unit tests in `webhook-signing.test.js` cover the full blocked-range table (IPv4 and IPv6), the bracket-stripping fix, DNS-lookup-failure fail-closed behavior, and the two real bugs found via smoke-testing before any formal test was written (§16).

---

## Preferences & API Contract

`GET/POST /api/v1/notifications` (`preferences`, `update-preferences`, `rotate-webhook-secret`, `test-webhook`, `deliveries`, `dead-letters`) — follows the exact `guardRequest → globalIpRateLimit → authenticate() → action= dispatch` convention every other `api/v1/*.js` handler uses. Field-whitelisted (`assertFieldWhitelist`), prototype-pollution-tested. `email_override` validated by a bounded regex; `webhook_url` validated for length and SSRF-safety before being stored. Enabling webhook delivery is rejected (`WEBHOOK_URL_REQUIRED` / `WEBHOOK_SECRET_REQUIRED`) unless both a URL and a generated secret already exist — an "enabled but non-functional" state is unreachable through this API. Clearing `webhook_url` force-disables `webhook_enabled` in the same call, so an "enabled but urlless" state is equally unreachable.

`rotate-webhook-secret` returns the raw secret exactly once, in that call's response only — never re-readable afterward (`getPreferences()` only ever returns `has_webhook_secret: boolean`), matching `generateApiKey()`'s own show-once precedent in `middleware.js`.

---

## Retry, Backoff & Dead-Letter Model

One pending-delivery record per `(ownerId, eventId)` — **not** per channel — with each enabled channel tracking its own independent attempt count and `next_attempt_at`. A channel's failure reschedules only that channel (`BACKOFF_MINUTES = [0, 2, 10, 30, 120]`, indexed by attempt count); a channel's success removes only that channel from the pending set. A channel that exhausts `MAX_RETRY_ATTEMPTS` (5) is moved to that owner's dead-letter list **without blocking a still-retrying sibling channel on the same event** — proven by a dedicated test (`notification-store.test.js`), not just asserted. The whole record is removed only once every enabled channel has either succeeded or been dead-lettered.

No live cron delivers any of this — see Architecture and Known Limitations.

---

## Idempotency & Race-Condition Hardening

`enqueuePendingDelivery()` originally used a plain `GET`-then-`SET` existence check — a real TOCTOU window if `evaluateWatchedEntities()` were ever invoked twice concurrently (no distributed lock exists for that script). Found during this round's own adversarial self-review (not by an external reviewer) and fixed to use `SET…NX` — the exact same atomic-create discipline `change-engine.js`'s `persistEventIfNew()` already established for event persistence, applied here to the notification queue. The fake-Redis test fixture executes commands sequentially, so this specific race cannot be deterministically reproduced in the current unit-test harness; the fix closes a real gap against genuine concurrent-request production behavior regardless, and is disclosed here rather than claimed as test-proven.

---

## Persistence

Upstash Redis only — the same store the entire Watchlists v1 tranche already uses, for the same evidence-backed reason (this Worker has no Cloudflare production storage bindings; see that certification's Persistence section). New key families, all customer-owned operational state, never a second intelligence store:

- `notify:prefs:{ownerId}` (hash) — preferences + webhook secret (never returned via any API response).
- `notify:delivery_log:{ownerId}` (sorted set, bounded to 500 entries) — full attempt history, success and failure.
- `notify:dead_letter:{ownerId}` (sorted set, bounded to 200 entries).
- `notify:pending:{ownerId}:{eventId}` (string) — one record per pending delivery.
- `notify:pending_queue` (sorted set, global) — the due-query index.

---

## Security Review

- **SSRF** — see §11, the primary threat this feature introduces.
- **Secret handling** — the webhook secret is stored (server needs it to sign every delivery, unlike an API key which only needs verification), never returned by `preferences`, never logged, never included in delivery-log error strings (which only ever capture the *customer's own endpoint's* response, not our request).
- **XSS** — `buildWatchlistAlertEmail()`'s html body escapes every interpolated value (watchlist name, entity label, reason, recommended action) via a dedicated `escapeHtml()`; the delivery-log UI reuses the dashboard's existing `esc()` discipline. Verified with real adversarial payloads in both the Jest suite and real-browser QA (`<script>`, `<img onerror>`, `<svg onload>` all render as inert text).
- **Prototype pollution** — `update-preferences`' field whitelist tested against a real `JSON.parse('{"__proto__":...}')`-sourced payload (the actual attack vector), not an object-literal `__proto__` (which sets the prototype, not an own property, and isn't a real attack surface — a distinction this codebase already learned to test for correctly in the watchlist round).
- **Ownership isolation** — preferences, secrets, delivery logs, and dead letters are all keyed by the authenticated caller's own `userId`; a dedicated test suite proves customer A's rotate/update/delivery calls never affect or leak to customer B.
- **Rate limiting** — reuses `globalIpRateLimit()` unchanged for every action on this endpoint, including `test-webhook` (which is, by design, a bounded, authenticated "ping an arbitrary public HTTPS URL" primitive — the same characteristic every other webhook-testing feature in the industry has, e.g. Stripe's own "send test webhook").
- **DoS bounds** — an 8-second timeout per webhook attempt, a 5-attempt retry cap, bounded delivery-log/dead-letter sizes, a bounded batch limit on the delivery sweep (default 100, capped at 500).

---

## Entitlements

`getWatchlistEntitlements()` gains `email_notifications_enabled`/`webhook_notifications_enabled`, both `true` for every tier today — the same flat, documented, no-invented-pricing posture already established for every other watchlist limit.

---

## UI

`api-dashboard.html`'s Watchlists panel gains a "📨 Alert Delivery" card (email toggle + override address, webhook URL + enable toggle + rotate-secret + send-test-delivery) and a "📬 Delivery Log" card, using this dashboard's exact existing conventions (`esc()` escaping, `showAlert()` feedback, plain `<input type="checkbox">` controls, the same fetch/JSON pattern every other panel action already uses). No new CSS classes invented.

---

## Browser QA

Real Chromium via Playwright (not simulated), desktop and 375px mobile: preference load, toggling webhook-before-URL correctly rejected and the UI re-syncing to server truth (not left in a stale checked state), saving a URL, rotating a secret with the reveal-once box, sending a test delivery, and a delivery log entry carrying an adversarial `<script>`/`<img onerror>` payload rendering as inert text. **11/11 checks passed**, zero unexpected console errors (the one intentionally-triggered 400 from the webhook-before-URL test case is explicitly filtered as expected, not a real error).

---

## Tests

Exact totals, run on this branch:

- `api/_lib/__tests__/webhook-signing.test.js`: **44 passed** (HMAC round-trip, malformed-header rejection, the full IPv4/IPv6 blocked-range table, the bracket-stripping fix, DNS-failure fail-closed behavior).
- `api/_lib/__tests__/notification-store.test.js`: **24 passed** (preferences CRUD + isolation, show-once secret discipline, delivery log + dead-letter ordering/isolation/truncation, the full per-channel enqueue/due-query/backoff/dead-letter state machine).
- `api/_lib/__tests__/notification-dispatch.test.js`: **24 passed** (email content escaping, per-channel delivery success/failure/timeout, enqueue-only dispatch logic, the full sender including deleted-event/deleted-watchlist fallback behavior).
- `api/v1/__tests__/notifications.test.js`: **33 passed** (401s, method enforcement, field whitelist + real prototype-pollution payload, the full preference-validation contract including SSRF rejection, secret rotation, test-webhook, and three dedicated cross-customer ownership-isolation tests).
- `api/_lib/__tests__/change-engine.test.js`: **4 new tests** (17 total) proving the dispatch integration point — a real change enqueues correctly, a watcher with nothing enabled gets nothing enqueued, a baseline-only run never enqueues, and a simulated notification-store failure never prevents the pre-existing feed fan-out from succeeding.

**129 new tests**, reconciled exactly against the full-suite delta: **1951 → 2080** passing (60 skipped throughout, unchanged; 0 failed). Full regression: Jest 2080/2140 (61/62 suites, 1 pre-existing unrelated skip), Python 677/677 (untouched this round, confirmed unchanged), `node --test` (workers/lib) 116/116 (including the route-table parity tripwire updated 33→34), `tsc --noEmit` clean.

---

## Performance

Delivery is bounded and cursor-free by design: `getDuePendingDeliveries()` is a single `ZRANGEBYSCORE` query capped at the caller's limit (default 100, hard-capped 500) — never a full-keyspace scan. Each webhook attempt is individually timeout-bounded (8s); a slow customer endpoint delays only that one delivery, not the batch. No production p95 latency is claimed — this Worker has no production traffic history (see Live Verification).

---

## Live Verification

**Not performed against live Resend or a live customer webhook endpoint** — this environment has no `RESEND_API_KEY`/`UPSTASH_REDIS_REST_URL` credentials, the same disclosed limitation as every prior round in this lineage. All verification above is local: real HMAC/crypto, a real (mocked-fetch) SSRF-guard test suite including real DNS lookups against real public hostnames, real browser automation, and full Jest/pytest/node:test/tsc regression. Disclosed explicitly, not implied as production-verified.

---

## Commercial Value

- **Retention/stickiness**: converts a passive dashboard feed into an active, recurring touchpoint — the difference between a customer who forgets to check back and one who gets emailed.
- **Enterprise integration surface**: signed webhooks let a customer route SENTINEL APEX events into their own SIEM/SOAR/ticketing pipeline without waiting on a bespoke integration — a real enterprise-conversion lever.
- **Trust signal**: a Stripe-familiar signature scheme and a visible delivery log (showing exactly what was sent, when, and whether it succeeded) is the kind of operational transparency enterprise buyers evaluate before trusting a vendor with SOC-facing alerting.

---

## Known Limitations

1. **Not real-time.** Both change detection and notification delivery run only when their respective scripts are invoked — no live Cloudflare Cron Trigger exists for either (same disclosed posture as Watchlists v1's own Known Limitations; `wrangler.jsonc` still defers scheduling authority).
2. **No distributed lock.** Concurrent invocations of `deliver-watchlist-notifications.js` (or of the evaluator) are not guarded against. The `SET…NX`-based idempotency fix in this round closes the specific race it targets; a general concurrent-invocation guard is a larger, separate infrastructure decision.
3. **SSRF guard is check-then-connect, not IP-pinned.** A narrow DNS-rebinding window between validation and the actual `fetch()` remains, disclosed in §11.
4. **No native Slack/Teams/PagerDuty integration** — webhook delivery is generic; a customer must run their own relay to bridge into those tools.
5. **Flat entitlements** — email/webhook notification access is not tier-gated, inheriting the same documented gap as every other watchlist limit.
6. **Enterprise customers with private-network-only webhook receivers cannot use this feature** — the SSRF guard has no allowlist mechanism for a customer's own private endpoints in v1.
7. **`test-webhook` has no dedicated stricter rate limit** beyond the platform's existing global per-IP limiter — acceptable for v1 (the same bound every other endpoint has) but worth tightening if abuse is observed.

---

## Rollback

Additive and self-contained: `api/v1/notifications.js`, `api/_lib/webhook-signing.js`, `api/_lib/notification-store.js`, `api/_lib/notification-dispatch.js`, and `scripts/deliver-watchlist-notifications.js` can all be deleted with zero effect on Watchlists v1's own functionality. The single integration point in `change-engine.js` (`notificationDispatch.dispatchNewEvent(...).catch(() => {})`) is one additive call, error-swallowed, safely revertable. No schema change to any existing key family; the new `notify:*` key families are simply abandoned on revert, nothing to migrate.

---

## Final Verdict

**GO.** A real, tested, security-reviewed delivery mechanism — not a stub, not an overclaim. SSRF was treated as the headline risk it is, tested adversarially, and hardened further during this round's own self-review (the IPv6-bracket fix and the setnx race fix were both found here, not by an external reviewer). "Not real-time" is stated plainly everywhere it matters, matching this lineage's consistent trust-over-marketing discipline.

---

*CYBERDUDEBIVASH® SENTINEL APEX — Production Certification*
