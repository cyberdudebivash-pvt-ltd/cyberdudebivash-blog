# SENTINEL APEX — Cloudflare Alert Runtime: Live Cutover Runbook

**Scope:** the watchlist/change-detection/alert-delivery monitoring
pipeline only (`workers/entry.js`'s `scheduled` export → D1 →
email/webhook delivery). Not auth, billing, ReportX, or the Intel Factory
content pipeline — those are explicitly out of scope (see
`docs/audits/SENTINEL-APEX-AUTH-BILLING-DEFERRAL-AUDIT-V2.md` and
`SENTINEL-APEX-REPORTX-INTEL-FACTORY-RUNTIME-AUDIT-V2.md`).

**Who this is for:** an operator with real, authenticated Cloudflare
account access. Every command below was verified either against
Cloudflare's own current documentation (fetched live while writing this
runbook, not recalled from training data) or empirically against this
exact repository and wrangler version (`4.123.0`) in local emulation. No
step in this runbook has been run against a real Cloudflare account —
that is precisely the gap this runbook exists to close.

**No secret values appear anywhere in this document**, per this
platform's own security policy — only secret *names*, referenced from
`docs/architecture/PRODUCTION-SECRETS-INVENTORY.md`.

---

## 0. Before you start

Run once, from the repository root, before any `wrangler` command:

```bash
node scripts/build-cloudflare-assets.js
```

This builds `dist-public/`, the asset directory `wrangler.jsonc`'s
`assets.directory` points at. It is not committed and is not an npm
script — invoke the file directly. Skipping this step means `wrangler
deploy`/`--dry-run` will bundle a stale or missing asset tree.

## 1. Authenticate

```bash
npx wrangler whoami
```

If this reports "You are not authenticated", **stop here**. Do not
proceed with any step below. Authenticate with:

```bash
npx wrangler login
```

This opens an OAuth flow in a browser. For a headless/CI environment,
use an API token instead: set `CLOUDFLARE_API_TOKEN` in the environment
(Cloudflare's own documented mechanism, superseding the deprecated
`wrangler config` command). Re-run `wrangler whoami` to confirm before
continuing.

## 2. Verify account, Worker, and environment

```bash
npx wrangler whoami          # confirms account
npx wrangler deployments list  # confirms which Worker/environment you're about to touch, if any prior deploy exists
```

Confirm the account and Worker name shown match the intended production
account for `blog.cyberdudebivash.in` / `cti.cyberdudebivash.in` — **do
not proceed if this resolves to a dev/preview/personal account.**
`wrangler.jsonc`'s `name` field (`cyberdudebivash-blog`) is the Worker
name this will deploy as; there is deliberately no `routes` or
`custom_domains` entry yet (see that file's own header comment) — this
tranche does not claim a production hostname, only the D1/Cron backend.

## 3. Verify / create the production D1 database

```bash
npx wrangler d1 list
```

Look for `sentinel-apex-core`. If it does not exist:

```bash
npx wrangler d1 create sentinel-apex-core
```

This prints a `database_id` (a UUID) — **add it to `wrangler.jsonc`'s
`d1_databases[0].database_id` field** (currently omitted deliberately,
since the schema marks it "not required" until a real database exists —
see that file's header comment). Commit this change; it is configuration,
not a secret.

If `sentinel-apex-core` already exists (e.g. a prior operator session
created it), do **not** create a second database — reuse it. Confirm its
ID with:

```bash
npx wrangler d1 info sentinel-apex-core --json
```

## 4. Apply migrations to the production database

Record the current state first (idempotent — safe to run repeatedly):

```bash
npx wrangler d1 migrations list sentinel-apex-core --remote
```

This shows which of `migrations/0001_notification_delivery.sql` and
`migrations/0002_watchlists_change_detection.sql` are already applied.
Before applying, record current row counts for comparison after (see §5).
Apply pending migrations:

```bash
npx wrangler d1 migrations apply sentinel-apex-core --remote
```

`--remote` targets the real production database; omitting it (or using
`--local`) targets only local emulation and proves nothing about
production. Migration state is tracked in a `d1_migrations` table inside
the database itself — Cloudflare's own migration tooling, not a custom
mechanism this platform built.

**No destructive migration exists in this repository's `migrations/`
directory today** — both files are additive `CREATE TABLE IF NOT EXISTS`
statements. If a future migration ever needs to alter or drop a column,
require the same evidence bar as any other production schema change
(this repo's Architecture Preservation Rule) before writing it.

## 5. D1 data sanity check

```bash
npx wrangler d1 execute sentinel-apex-core --remote --command "SELECT COUNT(*) FROM watchlists"
npx wrangler d1 execute sentinel-apex-core --remote --command "SELECT COUNT(*) FROM watchlist_entities"
npx wrangler d1 execute sentinel-apex-core --remote --command "SELECT COUNT(*) FROM change_events"
npx wrangler d1 execute sentinel-apex-core --remote --command "SELECT COUNT(*) FROM notification_delivery_jobs"
npx wrangler d1 execute sentinel-apex-core --remote --command "SELECT COUNT(*) FROM notification_delivery_log"
npx wrangler d1 execute sentinel-apex-core --remote --command "SELECT COUNT(*) FROM notification_dead_letters"
```

All-zero counts are expected and fine if this is the first real
provisioning of this database (no production traffic has used D1 yet —
the GitHub Actions bridge and any prior manual runs may have been
targeting a database that was never actually created, per every prior
round's disclosed "no live Cloudflare account access" limitation). If
counts are unexpectedly non-zero in a way that doesn't match known
migration-tool `--apply` runs, stop and determine why before proceeding
(wrong database? a `migrate-*-redis-to-d1.js --apply` run this runbook
doesn't know about?) rather than assuming.

## 6. Verify Worker bindings resolve

```bash
npx wrangler deploy --dry-run
```

Confirm the printed binding table shows `env.DB (sentinel-apex-core)` as
a D1 Database binding and `env.ASSETS` as an Assets binding, with no
warnings about an unresolvable binding. `--dry-run` compiles and bundles
the Worker without deploying — verified in this exact repository to
succeed even without authentication (it does not need to resolve
`database_id` to bundle, only to actually deploy), but a full `wrangler
whoami`-authenticated dry-run is the one to trust before a real deploy.

## 7. Verify required secrets are set

```bash
npx wrangler secret list
```

Cross-reference against `docs/architecture/PRODUCTION-SECRETS-INVENTORY.md`
§5 (email) and §10 (internal auth/admin) for the names this subsystem
needs: `RESEND_API_KEY` (email channel — optional; its absence degrades
email delivery gracefully per `notification-dispatch.js`'s own design,
it does not block webhook delivery or Cron certification, see Phase 39 of
the governing mandate). Webhook signing secrets
(`whsec_*`) are generated and stored per-customer in D1
(`notification_preferences`), not as Worker-level secrets — nothing to
set here for those. Set any missing Worker-level secret with:

```bash
npx wrangler secret put RESEND_API_KEY
```

(interactive prompt — never pass the value as a command-line argument,
which would leak it into shell history).

## 8. Deploy

```bash
npx wrangler deploy
```

Record, without any secret values: the deployment output's Worker
version ID, the Worker name, and the timestamp. Cloudflare's own
documentation notes Cron Trigger configuration changes may take **up to
15 minutes to propagate** after a deploy — do not conclude Cron
activation failed if the first invocation doesn't appear within minutes
of deploying.

## 9. Verify the Worker is live

```bash
npx wrangler deployments list
```

Confirm the new deployment is listed as active. If the Worker has been
given a route/custom domain (not the case as of this runbook — see §2),
also verify the HTTP endpoint responds. Confirm the deployed version's
source corresponds to the current `main`/cutover-branch commit SHA — do
not rely on the CLI's own "deployed successfully" message alone as proof
of correctness; cross-check against `git log` for the SHA that was
actually built and uploaded.

## 10. Manual scheduled-path canary (before waiting for real Cron)

Local emulation (`wrangler dev --local`) can invoke the same `scheduled`
export via:

```bash
curl "http://localhost:8787/cdn-cgi/handler/scheduled"
```

(Cloudflare's own documented local-testing endpoint.) This proves the
handler runs and D1 is reachable, but is **local emulation, not
production proof** — do not cite this alone as evidence of a live Cron
invocation (§13 below covers that). For a canary against the real
deployed Worker without waiting for the schedule, use `wrangler tail` (see
§11) while triggering the same code path through its normal HTTP entry
points (e.g. an authenticated call to `deliver-watchlist-notifications.js`
functionality via the notifications API) — never send a real test alert
to a real customer; use an internal/controlled destination only.

## 11. Observe real Cron invocations

```bash
npx wrangler tail
```

Live-tails the deployed Worker's logs. `workers/lib/router.js`'s
`handleScheduled()` logs a structured `[SCHEDULED]` JSON summary
(`evaluation`, `delivery`, `elapsed_ms`) on every invocation — this is
the line to watch for. Alternatively, via the dashboard: **Workers &
Pages → (select Worker) → Settings → Trigger Events → View events**
(stores the 100 most recent invocations) or **Workers Logs** for longer
retention and filtering. A cron cycle with zero due jobs is still valid
proof of execution — an empty, successful `[SCHEDULED]` log line is not
a failure.

## 12. Retire the GitHub Actions scheduler bridge — only after §11 proof

Do not do this step until at least one real Cloudflare Cron invocation
has been directly observed (§11), per this platform's own "never leave a
period with zero working scheduler" rule. Once proven:

Edit `.github/workflows/alert-delivery.yml` — replace the `schedule:`
trigger with `workflow_dispatch:` only (preserves manual/CI diagnostic
capability, removes production scheduling). Do not delete the workflow
entirely — it remains useful for manual runs and as a documented
fallback (see §13 of this runbook).

## 13. Post-cutover verification and rollback

Observe at least one more Cron cycle after the GitHub schedule is
disabled (§11 again), confirming delivery no longer depends on GitHub
Actions. Re-run §5's row counts and compare — no unexpected drop is
acceptable.

**Rollback**, if Cloudflare Cron misbehaves immediately after cutover:
revert `.github/workflows/alert-delivery.yml` to restore its `schedule:`
trigger (git revert the specific commit, not a manual re-edit, to avoid
drift). This restores the scheduler transport only. **D1 remains the
canonical store regardless — do not reintroduce Redis as a fallback
under any circumstance.** If Cloudflare Cron is disabled, GitHub Actions
resumes reading/writing the exact same D1 database it always has since
PR #138/#139; there is no split-brain risk in this rollback because
storage was never part of what changed at cutover.

---

*CYBERDUDEBIVASH® SENTINEL APEX — Cloudflare Alert Runtime Cutover Runbook*
*Every command above is cited to either Cloudflare's own current
documentation or this repository's own verified local behavior — see
`docs/audits/SENTINEL-APEX-CLOUDFLARE-LIVE-CUTOVER-V1-CERTIFICATION.md`
for the evidence trail.*
