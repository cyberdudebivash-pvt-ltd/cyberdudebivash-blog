# SENTINEL APEX — Cloudflare Live Cutover v1 — Certification

**Tranche:** P0 Production Activation — Cloudflare Live Cutover, Cron
Certification & Legacy Scheduler Retirement v1
**Branch:** `claude/p0-cloudflare-live-cutover-v1`
**Verdict: CONDITIONAL GO** — see §29.

---

## 1. Executive Verdict

This tranche attempted to prove the Cloudflare-native monitoring runtime
(D1-backed watchlists/change-detection/alert-delivery, built across PR
#137/#138/#139) **live in production** and retire the GitHub Actions
scheduler bridge once proven. **It could not** — `wrangler whoami`
reports "not authenticated" in this sandbox, the same blocker disclosed
in every certification in this lineage since PR #137. Per this
mandate's own Phase 3 instruction, no production mutation was attempted
once that was confirmed: no D1 migration was applied to a real database,
no Worker was deployed to a real account, no Cron Trigger was activated,
and the GitHub Actions scheduler was **not** touched — it remains the
only genuinely-proven-live scheduler for this subsystem. What this
tranche *did* accomplish: a real, previously-undiscovered Workers-runtime
compatibility bug was found and fixed (§19), every command in the new
runbook was verified against Cloudflare's current documentation or local
emulation, and a `wrangler deploy --dry-run` succeeded without
authentication, proving the Worker bundles and its bindings resolve.

## 2. Baseline

Verified against fresh `main` (`git fetch && git checkout main && git
pull`), not trusted from conversation history: PR #138
(`9009ced9`, Cloudflare-Only Alert Runtime v1) and PR #139 (`e26097d6`,
Cloudflare-Only Runtime Completion v2) both merged. `wrangler.jsonc`
carries the `sentinel-apex-core` D1 binding and `triggers.crons:
["*/30 * * * *"]`, both marked in the file's own header comment as
"code-complete configuration, not a live trigger." `workers/entry.js`
exports `async scheduled(controller, env, ctx)`. `.github/workflows/
alert-delivery.yml` runs both evaluate and deliver steps on a `schedule:
'*/30 * * * *'` trigger, gated on both `redis_ready` and `d1_ready`
(the gating fix from PR #139, unchanged).

## 3. Production Architecture

Unchanged from the target state PR #138/#139 already built:
`Canonical Intelligence → Watchlist Match (D1) → Semantic Change (D1) →
Delivery Job (D1) → Cron/GitHub bridge → scheduled()/GitHub Actions
step → Atomic Claim → Email/Signed Webhook → Retry/Terminal → D1
History`. This tranche did not alter this architecture — it attempted to
activate the Cloudflare-native half of it (Worker + Cron) in place of the
GitHub Actions bridge, and could not, for the reason in §1.

## 4. D1 Live Verification

**Not performed — blocked.** No `wrangler d1 create`, no
`wrangler d1 migrations apply --remote`, no `wrangler d1 execute
--remote` was run against a real database; all require authentication
this sandbox does not have. `migrations/0001_notification_delivery.sql`
and `migrations/0002_watchlists_change_detection.sql` remain verified
only via local emulation (`wrangler d1 execute --local`), as established
in their respective prior-round certifications — unchanged this round.

## 5. Worker Deployment

**Not performed — blocked** (requires authentication). What *was*
verified: `node scripts/build-cloudflare-assets.js` succeeds (10,574
files built to `dist-public/`), and `npx wrangler deploy --dry-run`
succeeds cleanly without authentication — output confirmed: `Total
Upload: 17871.19 KiB / gzip: 3012.92 KiB`, binding table showing
`env.DB (sentinel-apex-core)` as a D1 Database binding and `env.ASSETS`
as an Assets binding, exit code 0, no warnings. This proves the Worker
bundle compiles and its declared bindings resolve syntactically — it does
**not** prove a real deploy would succeed (dry-run does not exercise
account-level authorization, quota, or the actual upload).

## 6. Cron Configuration

`wrangler.jsonc`'s `triggers.crons: ["*/30 * * * *"]` is valid
configuration, unchanged this round. Verified against Cloudflare's
current documentation (fetched live, not recalled): Cron Trigger changes
"should be exclusively managed through the Wrangler configuration file"
for a Wrangler-managed Worker, and take effect only on `wrangler deploy`
— propagation "may take several minutes (up to 15 minutes)." This detail
is new evidence this round (not previously documented in this lineage)
and is now recorded in the runbook §8 so a future operator doesn't
mistake normal propagation delay for activation failure.

## 7. Manual Canary

**Not performed against a real deployment** (requires a live Worker).
Cloudflare's documented local-testing mechanism
(`curl "http://localhost:8787/cdn-cgi/handler/scheduled"` against
`wrangler dev --local`) was identified and recorded in the runbook, but
not exercised against the full application this round — the DNS-behavior
probe (§19) used a minimal standalone scratch Worker instead, a more
targeted test for the specific question that round needed answered.

## 8. Real Cron Proof

**Not obtained.** No live Cloudflare Cron Trigger invocation has been
observed at any point in this lineage (PR #137 through this tranche) —
this sandbox has never had authenticated Cloudflare account access. This
is the single fact that keeps this certification at CONDITIONAL GO
rather than GO, per this mandate's own Phase 60 rule: "If real Cron
cannot be observed: remain CONDITIONAL GO. Do not promote based only on
configuration."

## 9. Scheduler Cutover

**Not performed.** Per this mandate's own Phase 28-29 sequencing (cutover
only after real Cron proof) and the platform's standing "never leave a
period with zero working scheduler" rule, the GitHub Actions
`schedule:` trigger in `alert-delivery.yml` was **not modified this
round** — touching it without §8's proof first would itself be the
violation this rule exists to prevent.

## 10. GitHub Retirement

**Not performed, correctly.** `.github/workflows/alert-delivery.yml`
remains exactly as PR #139 left it: `schedule: '*/30 * * * *'`, gated on
both `redis_ready` and `d1_ready`. The dependency guard
(`tests/governance-cloudflare-runtime.test.js`) already asserts this
gating shape and continues to pass (§24) — this round added no guard
against the `schedule:` trigger itself, since asserting its absence would
be actively wrong while it remains the only proven-live scheduler.

## 11. Watchlist Integrity

No watchlist code was modified this round (only `webhook-signing.js`,
§19). `api/_lib/watchlist-store.js`'s D1 schema and contract are
unchanged from PR #139's certification. No production data exists to
compare before/after, since no production D1 database has ever been
provisioned in this lineage (confirmed again, §4).

## 12. Change-Event Integrity

Same as §11 — `api/_lib/change-engine.js` unmodified this round, no
production data to compare.

## 13. Alert Delivery

`api/_lib/notification-dispatch.js` and `api/_lib/notification-store.js`
unmodified this round. Re-verified via code reading (not rebuilt): bounded
batch (`processDueDeliveries({ limit = 100 })`, default 100 — the
GitHub Actions bridge separately passes `--limit=50` for its own
worst-case-timeout reasoning, unchanged), atomic claim/lease
(`claimDeliveryChannel`/`releaseDeliveryChannel`, unchanged from PR
#137/#138), retryable-vs-terminal classification (`recordAttemptOutcome`'s
`retryable` parameter and fast-path dead-letter for `retryable === false`,
unchanged).

## 14. Email

Not exercised this round — no `RESEND_API_KEY`-backed live send was
attempted (no production credentials exist in this sandbox to test with,
and this mandate explicitly forbids sending real customer alerts as a
test). Per Phase 39's own instruction, this does not block Cron/webhook
certification — email is classified separately, unproven live, same as
every prior round.

## 15. Webhooks

Signature scheme (`signPayload`/`verifySignature`, HMAC-SHA256,
`t=<ts>,v1=<hex>` header format) and delivery headers
(`X-Sentinel-Signature`, `X-Sentinel-Event`, `X-Sentinel-Delivery-Id`)
confirmed unchanged and complete via direct source read of
`notification-dispatch.js` — every field a receiver needs to verify
signature, check the timestamp window, and deduplicate by `delivery_id`
is present in both the headers and the payload body (`id`, `delivery_id`,
`schema_version`). No change was needed here (Phase 38's own "no need to
change if already correct" applies). The SSRF guard itself changed —
see §19.

## 16. Idempotency

Unchanged from PR #139: `owner_feed`'s composite PK
`(owner_id, event_id)` with `ON CONFLICT DO NOTHING`, `change_events`'
PK on `event_id`, `watchlist_entities`' composite PK — all proven via
real `Promise.all` concurrency tests in PR #139's own test suite
(`watchlist-store.test.js`, `change-engine.test.js`), re-run this round
as part of the full regression (§24) with no change in behavior.

## 17. Lease Recovery

Unchanged from PR #138: `notification-store.js`'s `claimDeliveryChannel`
uses a `claim_token`/`lease_expires_at` column pair, proven via that
round's own stale-lease-reclaim test. Not re-derived this round (no
code touched it); re-confirmed passing in the full regression (§24).

## 18. Retry

`MAX_RETRY_AFTER_SECONDS = 3600` bounds a malicious or misconfigured
endpoint's `Retry-After` header (confirmed via direct source read,
unchanged from PR #136/#137). 429/5xx/timeout → retryable; permanent
4xx/invalid/disabled destination → terminal via the `retryable === false`
fast path — both unchanged, both covered by existing tests re-run this
round.

## 19. SSRF — Critical, Re-Verified Under Workers Runtime (real finding this round)

**This is the substantive finding of this tranche.** Cloudflare's own
current Workers runtime-APIs documentation (fetched live while
researching this certification, not recalled) states: *"All `node:dns`
functions are available, except `lookup`, `lookupService`, and `resolve`
which throw 'Not implemented' errors when called"* under `nodejs_compat`.
`api/_lib/webhook-signing.js`'s `isSafeWebhookUrl()` — the SSRF guard
gating every outbound webhook delivery — called exactly
`dns.promises.lookup()`. Under the documented real Workers runtime, this
call would throw, which `isSafeWebhookUrl`'s own `try/catch` converts to
`{ safe: false, reason: 'DNS_LOOKUP_FAILED' }` — a **fail-closed**
outcome from a security standpoint, but a **full functional regression**
for the webhook channel: every hostname-based webhook URL (the
overwhelming majority of real-world webhook endpoints; only a literal-IP
URL would bypass the DNS path entirely) would be rejected as unsafe on a
real deployed Worker, even though the exact same code passes all 44
existing Jest tests (which run under real Node.js, not workerd, and so
never exercise this gap).

**Empirically probed, not just doc-cited**: a minimal standalone scratch
Worker was built and run under this exact repository's pinned wrangler
version (`4.123.0`) via `wrangler dev --local` (no Cloudflare
authentication required for local emulation). Surprisingly, this local
probe's `dns.promises.lookup('example.com', { all: true })` call
**succeeded**, returning real-looking Cloudflare edge addresses —
contradicting the official docs for this specific case. This is recorded
explicitly as a **known discrepancy between local Miniflare/wrangler-dev
emulation and Cloudflare's documented live-Workers behavior**, and per
this platform's own "never claim live proof from local emulation"
discipline, the documented behavior (not the more permissive local
result) is the one trusted for a production fix.

**Fixed**: `isSafeWebhookUrl()` rewritten to resolve `dns.promises.
resolve4()` and `dns.promises.resolve6()` in parallel instead of
`dns.promises.lookup()` — both are confirmed supported by the same
Cloudflare docs, and both were independently confirmed working in the
same local `wrangler dev` probe. Each address family is resolved
independently so a host with only an A record (or only AAAA — the common
case) is not treated as a failure just because the other family has no
records. All 44 pre-existing `webhook-signing.test.js` tests pass
unchanged against the rewrite, including a real end-to-end DNS
resolution test over the network. A new governance guard
(`tests/governance-cloudflare-runtime.test.js`) now asserts
`webhook-signing.js` never reintroduces `dns.lookup`/`dns.promises.
lookup`.

**Still unproven**: this fix has not been verified against a real
deployed Cloudflare Worker — only against real Node (Jest, over a real
network DNS call) and local `wrangler dev` emulation (which, per the
above, is already known to diverge from documented live behavior for the
*old* code — its agreement with the *new* code's expected behavior is
reassuring but not conclusive proof). This is the clearest concrete
argument in this entire certification for why live deployment
verification (§8) is not optional busywork — this exact class of bug is
undetectable without it.

All previously-covered SSRF ranges (localhost, RFC1918, link-local
including the cloud metadata address, CGNAT, IPv6 loopback/ULA,
bracketed-IPv6 literals, unsafe schemes) remain blocked, unchanged in
logic, re-verified passing.

## 20. Signature Validation

Unchanged, re-verified via source read (§15) — no live test webhook was
sent (requires a live Worker + controlled receiving endpoint, neither
available this round).

## 21. Customer Isolation

No customer-isolation-relevant code was touched this round. PR #139's
`getOwnedWatchlist()` ownership-gate finding stands unchanged.

## 22. Observability

`workers/lib/router.js`'s `handleScheduled()` logs a structured
`[SCHEDULED]` JSON summary (`evaluation`, `delivery`, `elapsed_ms`) on
every invocation — confirmed via source read, unchanged. This is
observable via `wrangler tail` (real-time) or the dashboard's Trigger
Events (100 most recent) / Workers Logs (longer retention), per
Cloudflare's own documentation researched this round. **Disclosed gap,
not fixed**: there is no dedicated D1-backed health-signal column (e.g.
`last_cron_invocation_at`, `cron_failures`) for the application itself to
self-report staleness (mandate Phase 45-46) — today's observability is
entirely Cloudflare's own log/dashboard mechanism, which is a legitimate
Cloudflare-native answer but means staleness detection requires an
operator to actually look at those logs, not a self-contained API
endpoint. Building dedicated D1 tracking for this was judged out of this
tranche's coherent scope (production activation, not new observability
features) and is recorded as an open item rather than silently addressed
or silently ignored.

## 23. SLO

Unchanged: 30-minute Cron/GitHub-Actions cadence, "an eligible job should
ordinarily receive an attempt within one cron interval plus processing
allowance" — no customer-facing contractual SLA implied, consistent with
every prior round's framing. New this round: Cloudflare's own
documentation notes cron *configuration changes* (not invocation cadence)
may take up to 15 minutes to propagate after a deploy — recorded in the
runbook so this isn't mistaken for a cadence violation during a future
real cutover.

## 24. Tests

Full regression re-run this round, exact totals:

| Runner | Passed | Failed | Skipped |
|---|---|---|---|
| Jest | 2158 | 0 | 60 |
| pytest | 658 | 0 | 0 |
| node:test (`tests-js/`) | 208 | 0 | 0 |
| node:test (`Sentinel-APEX/renderer/tests/`) | 64 | 0 | 0 |
| node:test (`Sentinel-APEX/engine-node/tests/`) | 106 | 0 | 0 |
| node:test (`workers/lib/`) | 120 | 0 | 0 |
| **Total** | **3314** | **0** | **60** |

(2 more than PR #139's 3312 total: the 2 new governance tests added this
round for the DNS-compatibility guard, §19.) 63/64 Jest suites pass; the
1 skipped suite is the pre-existing e2e suite requiring a live server,
unchanged and unrelated to this round.

## 25. CodeQL

Not run locally this round (CodeQL requires the GitHub Actions
environment) — will run automatically as a required check once this
branch's PR is opened, per this repository's standard CI. No new
dependency, no new external input-handling code was introduced this
round (the DNS fix replaces one Node built-in call with two others in
the same module, no new attack surface) — no CodeQL finding is
anticipated, but this is not a substitute for the actual CI run.

## 26. Production Evidence

None obtained beyond what's listed in §5-8: a successful unauthenticated
`wrangler deploy --dry-run` (bundle/binding validation only) and a local
`wrangler dev --local` DNS-behavior probe (local emulation, explicitly
not equated with live production per §19's own caveat). No D1 database,
no deployed Worker, no Cron invocation, no delivery attempt has occurred
against real Cloudflare infrastructure at any point in this tranche.

## 27. Known Limitations

- **No live Cloudflare account access** — the root cause of every other
  limitation below, unchanged since PR #137.
- **GitHub Actions scheduler not retired** — correctly blocked by the
  above, per this mandate's own sequencing rule.
- **The SSRF DNS fix (§19) is unverified against a real deployed
  Worker** — the single highest-value next step for a future session
  with real credentials, precisely because this exact bug class evaded
  both Node/Jest testing and local Workers emulation.
- **No dedicated cron-health D1 tracking** (§22) — Cloudflare's own
  log/dashboard mechanism is the current, legitimate, but
  operator-attention-dependent answer.
- **Email channel unproven live** — unchanged, out of this round's
  ability to test safely.
- **`migrate-watchlists-redis-to-d1.js` still has no dedicated test
  file** — a PR #139 disclosed gap, unchanged, not addressed this round
  (out of this tranche's scope).

## 28. Rollback

Documented in full in `docs/runbooks/CLOUDFLARE-ALERT-RUNTIME-CUTOVER.md`
§13. Summary: since no production mutation occurred this round, there is
**nothing to roll back** from this tranche specifically. The runbook's
rollback guidance (revert the GitHub Actions schedule-trigger removal via
`git revert`, never re-enable Redis, D1 remains canonical regardless of
which scheduler transport is active) is prepared for the *future* cutover
this tranche could not yet perform.

## 29. Final Verdict

**CONDITIONAL GO.**

GO on: the runbook is complete and verified against current Cloudflare
documentation; `wrangler deploy --dry-run` proves the Worker bundles and
its bindings resolve; a real, previously-undiscovered Workers-runtime
compatibility bug in the SSRF guard was found, fixed, and covered by a
new regression guard, with zero test regressions elsewhere (3,314/3,314
passing); every governance guard from PR #139 continues to hold.

CONDITIONAL on: §8's absence — no real Cloudflare Cron invocation has
been observed, at any point in this lineage, because no session in this
lineage has had authenticated Cloudflare account access. Per this
mandate's own Phase 60, this alone caps the verdict at CONDITIONAL GO
regardless of how much configuration/code readiness work is complete.
**This certification does not claim**: a live Worker deployment, a live
D1 database, a live Cron invocation, GitHub scheduler retirement, or
platform-wide Cloudflare-only status. The next required action is
entirely environmental, not further engineering: an operator with real
Cloudflare credentials must run `docs/runbooks/CLOUDFLARE-ALERT-RUNTIME-
CUTOVER.md` end to end.

*CYBERDUDEBIVASH® SENTINEL APEX — Cloudflare Live Cutover v1*
*Certified by evidence, not assertion. No claim above exceeds what was
actually run, read, or fetched this tranche.*
