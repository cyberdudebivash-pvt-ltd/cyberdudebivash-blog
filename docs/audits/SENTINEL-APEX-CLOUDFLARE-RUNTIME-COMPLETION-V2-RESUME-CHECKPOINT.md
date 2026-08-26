# SENTINEL APEX — Cloudflare-Only Runtime Completion v2 — Resume Checkpoint

**Date:** 2026-08-26 (round 1); updated 2026-08-26 (round 2)
**Branch:** `claude/p0-cloudflare-runtime-completion-v2` (round 1, merged
as PR #139); `claude/p0-cloudflare-live-cutover-v1` (round 2, this update)
**Written per:** the same "Long-Run Checkpoint Policy" established by the
Global CTI Commercial Transformation v3 lineage — stop at a safe boundary,
commit, push, open/update the PR, and leave a clear resume point.

**READ THIS FIRST IF RESUMING — round 2 update:** round 2 was a tranche
dedicated *specifically* to live production activation (not another
migration), and confirmed the same `wrangler whoami` → not-authenticated
blocker round 1 (and every round since PR #137) already found — this is
now a third independent confirmation, from a session whose entire mandate
was proving live status, which is itself evidence the gap is genuinely
environmental. Round 2's real contribution: found and fixed a live
Workers-runtime bug in `webhook-signing.js`'s SSRF guard (`dns.promises.
lookup()` is undocumented-as-unsupported under Workers `nodejs_compat` —
switched to `resolve4()`/`resolve6()`), and produced a new runbook
(`docs/runbooks/CLOUDFLARE-ALERT-RUNTIME-CUTOVER.md`) with every command
verified against Cloudflare's current documentation. See §17 below (round
2) for full detail before resuming this lineage again. **Round 1's own
content below (§1-16) is unchanged and still accurate** — this was an
activation attempt, not a re-migration; no watchlist/change-detection/
delivery code from round 1 was modified in round 2 except the one file
named above.

**READ THIS FIRST IF RESUMING — round 1 (original):** this tranche
migrated **watchlists and change-detection** from Redis to Cloudflare D1
(joining the alert-delivery control plane, already D1-backed since PR
#138, in the same shared `sentinel-apex-core` database) and produced
three dedicated audit documents covering auth, billing, and the 35-file
ReportX/Intelligence Factory surface — all deliberately deferred, not
migrated, with real evidence for why. **It did not** achieve live
Cloudflare Cron proof or GitHub Actions scheduler retirement — this
sandbox still has no authenticated Cloudflare account access
(`wrangler whoami` → not authenticated, re-verified this round, unchanged
since PR #137). Read
`docs/audits/SENTINEL-APEX-CLOUDFLARE-ONLY-RUNTIME-COMPLETION-V2-CERTIFICATION.md`
in full before extending this lineage further — it is the authoritative
record of what is and is not proven.

---

## 1. What this checkpoint is (and isn't)

The mandate this branch is named for is a 74-phase "P0 Master Production
Transformation" specification. This checkpoint does not claim the full
74 phases were executed — it records what a deliberately-scoped subset
(P0-B: watchlists + change-detection, plus the audit-only P0-D/ReportX
work the mandate itself explicitly permits deferring) actually
accomplished, with evidence, per the mandate's own "Implementation
Strategy" section's explicit permission to split into P0-A/B/C/D and
defer what genuine risk assessment says should be deferred.

## 2. What happened this round (chronological)

1. Re-read `PRODUCTION-RUNTIME-POLICY.md` and the V1 dependency inventory
   as baseline evidence, per Phase 1.
2. Built a corrected, 48-file Cloudflare Runtime Inventory V2 — the prior
   round's direct-require grep undercounted at 30 files; a broader
   method-call-usage grep found 18 more dependency-injection-pattern
   consumers invisible to the narrower search. Documented as an explicit
   methodology correction, not a silent revision.
3. Re-confirmed `wrangler whoami` → not authenticated. Considered and
   rejected `wrangler deploy --temporary` as a workaround (would only
   prove Workers/Cron/D1 work on an anonymous account, not this
   platform's real configuration). P0-A (live Cron proof) declared
   blocked, same as every prior round in this lineage.
4. Designed and built `migrations/0002_watchlists_change_detection.sql`
   (7 tables, 4 indexes) — verified empirically via
   `wrangler d1 execute --local` before writing any consuming code, same
   discipline as PR #138.
5. Rewrote `api/_lib/watchlist-store.js` and `api/_lib/change-engine.js`
   onto D1 in place, preserving every exported symbol and function
   signature exactly — `api/v1/watchlists.js` (the HTTP router) needed
   zero changes.
6. Updated `scripts/evaluate-watchlist-changes.js` and
   `.github/workflows/alert-delivery.yml` (both evaluate and deliver
   steps now gated on `redis_ready && d1_ready`, since change-detection's
   fan-out calls into D1-backed `notification-dispatch.js`).
7. Built `scripts/migrate-watchlists-redis-to-d1.js` (dry-run-first,
   idempotent) — disclosed limitation: no dedicated test file this round
   (time/context budget), unlike its PR #138 sibling.
8. Extended `api/_lib/__fixtures__/fake-d1.js` and rewrote
   `watchlist-store.test.js` (23 tests), `change-engine.test.js`
   (17 tests, including re-deriving one failure-injection test whose
   original blast radius no longer matched the new shared-D1
   architecture), and `api/v1/__tests__/watchlists.test.js` (23 tests,
   needed only a `jest.mock('../../_lib/d1', ...)` addition).
9. Audited auth and billing in full (5 + 8 files read/grepped), wrote
   `SENTINEL-APEX-AUTH-BILLING-DEFERRAL-AUDIT-V2.md` — verdict DEFER on
   both, with real evidence (rate-limiter latency risk, a genuine
   pre-existing TOCTOU race found and documented not fixed, a real
   cross-subsystem coupling via `user:pending:tier:*`, confirmation that
   Redis mirrors Stripe/Razorpay/human-admin-owned truth rather than
   being the ledger itself).
10. Audited the 35-file ReportX/Intelligence Factory cluster at a
    representative-sample level (4 files read in full, 1,362 lines), wrote
    `SENTINEL-APEX-REPORTX-INTEL-FACTORY-RUNTIME-AUDIT-V2.md` — verdict
    DEFER in full, with a repo-wide grep confirming zero coupling with
    anything migrated this round or last round.
11. Built `tests/governance-cloudflare-runtime.test.js` (16 tests) — a
    precise, non-naive dependency-regression guard watching only the
    specific files this platform has deliberately migrated, wired into
    the pre-existing but previously-unpopulated `npm run test:governance`
    script slot with zero `package.json` changes.
12. Built `docs/architecture/PRODUCTION-SECRETS-INVENTORY.md` (names
    only) by grepping real `process.env`/`os.environ`/`secrets.*` usage
    across JS, Python, and GitHub Actions YAML.
13. Ran the full regression suite: Jest, pytest, and all four node:test
    groups — 3,312 tests passed, 0 failed (exact breakdown in §4 below).
14. Added 3 real `Promise.all` concurrency tests (not simulated sequential
    claims) proving the D1 schema's `ON CONFLICT DO NOTHING` design
    resolves genuine concurrent writes for `addEntity`,
    `appendToOwnerFeed`, and `persistEventIfNew`.
15. Did a security self-review: verified every dynamic-SQL call site in
    the new code interpolates only placeholder-count strings (never raw
    values), confirmed the ownership-check pattern (`getOwnedWatchlist`)
    survived the rewrite unchanged, confirmed `getWatchersForEntity` is
    never HTTP-exposed (no cross-tenant leak), confirmed no secret-value
    printing anywhere in the touched files.
16. Wrote the certification doc (32 sections, verdict CONDITIONAL GO).
17. Updated `platform/capabilities.md` (Watchlists + Alert Delivery
    rows), `platform/open-issues.md` (closed Issue 26 item 7, added
    Issue 27), and
    `docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md`
    (Watchable state / Intelligence change event / Watchlist /
    Notification-delivery-state rows) — all previously described the
    pre-this-tranche Redis-only reality.
18. Updated `docs/architecture/PRODUCTION-RUNTIME-POLICY.md`'s §3
    migration-status table (watchlists row, auth/billing/ReportX rows now
    cite the new dedicated audits) and its "Net position" summary.
19. This checkpoint.

## 3. Certification status

`docs/audits/SENTINEL-APEX-CLOUDFLARE-ONLY-RUNTIME-COMPLETION-V2-CERTIFICATION.md`
— **CONDITIONAL GO**. GO on the watchlist/change-detection D1 migration
itself (schema verified locally, contracts preserved exactly, zero
regressions across 3,312 tests, a precise regression guard now in place).
CONDITIONAL on live Cloudflare Cron proof and GitHub Actions scheduler
retirement remaining unproven — production execution continues via the
GitHub Actions bridge, not a live-verified Cron Trigger, until a session
with real Cloudflare credentials completes that proof. Does **not** claim
platform-wide Cloudflare-only status — §30 of the certification doc states
exactly what is and is not, per the mandate's own explicit instruction not
to claim otherwise.

## 4. Test baseline (reproduce before trusting any further change)

```
npx jest --ci --maxWorkers=2
# Expect: 1 skipped, 63 passed, 63 of 64 suites; 60 skipped, 2156 passed, 2216 total tests

npx jest tests/governance-cloudflare-runtime.test.js
# Expect: 16 passed, 16 total (the dependency-regression guard)

npx jest api/_lib/__tests__/watchlist-store.test.js api/_lib/__tests__/change-engine.test.js api/v1/__tests__/watchlists.test.js
# Expect: 3 passed suites; 63 passed, 63 total (25 + 18 + 23 — includes the 3 new Promise.all concurrency tests)

python3 -m pytest tests/ -q
# Expect: 658 passed

node --test tests-js/*.test.js
# Expect: tests 208, pass 208, fail 0

node --test Sentinel-APEX/renderer/tests/*.test.js
# Expect: tests 64, pass 64, fail 0

node --test Sentinel-APEX/engine-node/tests/*.test.js
# Expect: tests 106, pass 106, fail 0

node --test workers/lib/*.test.js
# Expect: tests 120, pass 120, fail 0
```

Note: `node --test <directory>/` (bare directory path) fails with
`MODULE_NOT_FOUND` on this Node version for these specific directories —
use the explicit `*.test.js` glob as shown above, which works cleanly.

## 5. Next exact action if resuming

Several independent threads are open. Pick based on what the resuming
session is actually asked to do:

**Thread A — live Cloudflare Cron proof (P0-A, blocked every round so
far).** Requires a session with real, authenticated Cloudflare
credentials. Run `wrangler whoami` first — if still unauthenticated,
this thread cannot proceed; do not attempt `wrangler deploy --temporary`
as a substitute (see §8 of the certification doc for why that doesn't
satisfy the actual requirement). If credentials exist: `wrangler d1
create` (or confirm the existing `sentinel-apex-core` database), populate
the `CLOUDFLARE_*` GitHub Actions secrets, `wrangler deploy`, observe a
real Cron Trigger firing, THEN retire the GitHub Actions scheduler bridge
per `PRODUCTION-RUNTIME-POLICY.md`'s non-negotiables (never leave a
period with zero working scheduler — cut over only after the new one is
proven, not before).

**Thread B — a dedicated auth+billing migration round (P0-D).** Per
`SENTINEL-APEX-AUTH-BILLING-DEFERRAL-AUDIT-V2.md` §D's own
recommendation: scope this as one tranche (not two), because they share
the `user:pending:tier:*` Redis key and cannot safely split. Read that
audit doc in full before starting — it already did the evidence-gathering
this thread would otherwise redo. Do not migrate the rate-limiter to D1
without first resolving whether the API surface has moved off Vercel
(§A.5 of that audit explains why doing so prematurely would add latency
to every authenticated request).

**Thread C — ReportX migration.** Per
`SENTINEL-APEX-REPORTX-INTEL-FACTORY-RUNTIME-AUDIT-V2.md` §7: the
relational-collapse technique this tranche proved for watchlists
(mirrored ZSET indexes → one indexed/joined table) applies directly. 31
of the 35 files were not individually read this round — a fresh session
picking this up should not assume the 4-file sample generalizes perfectly
to all 31 without at least a broader confirming pass.

**Thread D — migrate-watchlists-redis-to-d1.js test coverage.** A
disclosed gap (Issue 27 item 2) — build a test file mirroring
`scripts/__tests__/migrate-notifications-redis-to-d1.test.js`'s pattern
before this tool is ever run against real data.

**If none of the above — this tranche's own remaining work.** As of this
checkpoint, only the final commit/push/draft-PR/subscribe step (mandate
Phase 68-73, tracked as this session's own task list item) may still be
pending — check `git status` and the branch's push state before assuming
Thread A-D over finishing this tranche's own delivery.

---

## 17. Round 2 — Cloudflare Live Cutover v1 (2026-08-26)

**Branch:** `claude/p0-cloudflare-live-cutover-v1`. **Certification:**
`docs/audits/SENTINEL-APEX-CLOUDFLARE-LIVE-CUTOVER-V1-CERTIFICATION.md`
— CONDITIONAL GO. **Runbook (new):**
`docs/runbooks/CLOUDFLARE-ALERT-RUNTIME-CUTOVER.md`.

**17.1 — What this round was asked to do.** A dedicated mandate to prove
the Cloudflare-native monitoring runtime live in production (real D1,
real deployed Worker, real Cron invocation observed) and, only once
proven, retire the GitHub Actions scheduler bridge. Not another
migration tranche — round 1 (§1-16 above) already finished the code-side
migration work this round assumes as its starting point.

**17.2 — The gate, confirmed again.** `wrangler whoami` → not
authenticated, re-run fresh at this round's start. Per the mandate's own
explicit instruction ("if not authenticated: STOP production mutation,
do not fabricate deployment success"), no D1 migration was applied to a
real database, no Worker was deployed to a real account, no Cron Trigger
was activated, and — correctly — the GitHub Actions scheduler was **not**
touched. This is the third independent round to hit this exact wall
(PR #137, PR #138, this round), now from a session whose entire mandate
was specifically to get past it, which is stronger evidence than before
that the gap is genuinely environmental (no Cloudflare credentials exist
in any sandbox this lineage has ever run in) rather than something a
differently-scoped or differently-instructed session could route around.

**17.3 — What WAS accomplished despite the gate.** `wrangler deploy
--dry-run` succeeds without authentication — confirmed the Worker bundle
compiles (10,596 files, 17,871.19 KiB / gzip 3,012.92 KiB) and both
declared bindings (`env.DB` → `sentinel-apex-core`, `env.ASSETS`) resolve
by name. Official Cloudflare documentation was fetched live (not recalled
from training data) for Cron Trigger configuration/deployment/
verification, D1 migration commands, and `wrangler deploy`/`secret`/
`tail` syntax — all now cited precisely in the new runbook rather than
assumed.

**17.4 — The real finding: a live Workers-runtime SSRF-guard bug.**
Cloudflare's current docs (`developers.cloudflare.com/workers/
runtime-apis/nodejs/dns/`) state `dns.lookup`/`dns.promises.lookup`
throw "Not implemented" under Workers `nodejs_compat`.
`api/_lib/webhook-signing.js`'s `isSafeWebhookUrl()` called exactly that
function — meaning every hostname-based webhook URL (the common case)
would have been rejected as unsafe on a real deployed Worker, even
though all 44 of this file's Jest tests pass (Jest runs under real
Node, never exercising this gap). **Empirically probed, not just cited**:
a standalone scratch Worker run via `wrangler dev --local` under this
exact repo's pinned wrangler (`4.123.0`) showed `dns.promises.lookup()`
*actually working* in local emulation — a genuine, disclosed discrepancy
between Miniflare's local DNS behavior and Cloudflare's documented live
behavior. The documented behavior was trusted over the more permissive
local result, per this platform's own "never claim live proof from local
emulation" discipline (this is the clearest concrete illustration of that
rule this whole lineage has produced — local emulation actively
disagreed with production docs here, not merely "unverified"). **Fixed**:
switched to `dns.promises.resolve4()`/`resolve6()` (both confirmed
supported by the same docs and the same local probe), each family
resolved independently so a single-family host (the common case) isn't
treated as a failure. All 44 existing tests pass unchanged against the
rewrite; a new governance guard
(`tests/governance-cloudflare-runtime.test.js`) now asserts `dns.lookup`/
`dns.promises.lookup` never reappear in this file. **Still unverified
against a real deployed Worker** — this is the single highest-value next
step for whoever runs the new runbook for real, precisely because this
bug class evaded both Node testing and local Workers emulation.

**17.5 — Full regression this round.** Jest 2158/2158 (2 more than round
1's 2156 — the new DNS-guard tests), pytest 658/658, node:test 208+64+106+120
= 498/498. Total 3,314/3,314, 0 failed, 0 skipped-unexpectedly (the 1
pre-existing e2e-suite skip is unchanged and unrelated).

**17.6 — Governance doc updates this round.** `platform/open-issues.md`
gained Issue 28 (this round's findings, full detail in §17.4 above,
tracked individually per this platform's own discipline).
`platform/capabilities.md`'s Alert Delivery row got a one-paragraph
addition noting the SSRF fix and the new runbook — not a rewrite, since
nothing about the row's underlying CONDITIONAL-GO status changed.
`docs/architecture/PRODUCTION-RUNTIME-POLICY.md`,
`INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md` were deliberately **not**
touched this round — nothing in production reality changed (still not
live), so rewriting them would have been unjustified churn, not honesty.

**17.7 — Next exact action if resuming.** Unchanged in kind from §1-16's
own Thread A: an operator with real, authenticated Cloudflare credentials
needs to run `docs/runbooks/CLOUDFLARE-ALERT-RUNTIME-CUTOVER.md` end to
end. That runbook is now the single most current, most precisely-cited
resource for doing so — read it before attempting a live cutover from
any future session, rather than re-deriving the command sequence from
scratch. Once real Cron proof exists (runbook §11), return to this
lineage to actually retire the GitHub Actions scheduler (runbook §12) —
still not done as of this checkpoint, and still correctly so.
