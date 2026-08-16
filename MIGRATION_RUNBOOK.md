# Vercel Account Migration Runbook

For migrating this project from the inaccessible Vercel account (login and
password-reset both confirmed failing) to a new Vercel account/team with
full access. Read `VERCEL_MIGRATION_INVENTORY.md` and
`ENVIRONMENT_VARIABLE_MATRIX.md` first — this runbook assumes their
findings and doesn't repeat the evidence, only the actions.

**Model**: `DISCOVER → BACKUP → RECONSTRUCT → STAGE → VERIFY → CUT OVER →
OBSERVE → RETIRE`. Every step before "CUT OVER" is safe and reversible —
nothing touches the live domain or the old account. **Do not skip ahead to
CUT OVER until STAGE + VERIFY are both green.**

Every step below that needs a Vercel/DNS/payment-provider dashboard is
marked **[YOU]** — none of it is something an AI session can do; it
needs your hands on those consoles. Steps marked **[EITHER]** can be done
from your local clone or by asking whoever's driving this session to do
the git-side half.

---

## Phase 0 — Try account recovery in parallel (don't block on it)

**[YOU]** Before or alongside everything below, open a support case
directly with Vercel: **https://vercel.com/help**. "Lost login + password
reset also fails" is exactly the class of issue their account-recovery
support handles, separately from the self-service password reset that's
already failed. Two reasons to try this in parallel rather than skip it:

1. If it succeeds, you get the *existing* account back — including
   whatever undeclared config only lives there (the Vercel Cron schedule
   for `/api/cron/dispatch-intel`, the domain's existing SSL/verification
   state, deployment history).
2. Even if it doesn't resolve in time, a support ticket creates a paper
   trail that may help later (e.g., disputing unauthorized access if this
   was a compromise, not just a forgotten credential).

Do not wait for a response before starting Phase 1 — proceed in parallel.

---

## Phase 1 — DISCOVER

Done. See `VERCEL_MIGRATION_INVENTORY.md` (deployment model, `vercel.json`,
`.vercelignore`, the undeclared cron, the 19-workflow audit) and
`ENVIRONMENT_VARIABLE_MATRIX.md` (all ~43 Vercel env vars + 13 separate
GitHub Actions secrets, classified). Both are committed to this repo —
they're now the authoritative source of what the new project needs.

---

## Phase 2 — BACKUP (of what's actually recoverable)

There is no dashboard export to take — the old account can't be logged
into. What's "backed up" is entirely what's already git-visible (Phase 1)
plus real secret *values* recovered from **other services' own
dashboards** — Vercel losing your login doesn't mean these are lost too,
they're separate accounts:

| Value | Check this dashboard (separate login from Vercel) |
|---|---|
| `UPSTASH_REDIS_REST_URL` / `_TOKEN` | https://console.upstash.com — same database, just re-view/regenerate the REST token |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_*` | https://dashboard.stripe.com |
| `RAZORPAY_KEY_ID` / `_SECRET`, webhook secret | https://dashboard.razorpay.com |
| `RESEND_API_KEY`, `RESEND_AUDIENCE_ID` | https://resend.com |
| `NVD_API_KEY`, `OTX_API_KEY`, `ANTHROPIC_API_KEY`, etc. | each provider's own console |

**[YOU]** For every value in that table, sign into the *provider's own*
dashboard (not Vercel) and either copy the existing value or regenerate
it there. If any of these logins were *also* only accessible via the same
compromised credentials as Vercel, treat that value as needing rotation
at the source, not just at Vercel.

For everything else — `ADMIN_SECRET_KEY`, `DOWNLOAD_TOKEN_SECRET`,
`CRON_SECRET`, `BACKUP_ENCRYPTION_KEY`, `APEX_BRIDGE_SECRET` — these are
**self-issued** secrets with no external state tied to them (except
`BACKUP_ENCRYPTION_KEY`, and per `RUNBOOKS.md` that one was never actually
provisioned before this incident, so there's nothing it needs to stay
compatible with). Don't try to recover the old values — generate fresh
ones in Phase 3. This is forced rotation, which is the *safe* outcome
here, not a loss: per `MIGRATION_RUNBOOK.md`'s companion doc (Section 10
of the original governance request), any secret that lived exclusively in
an account you've now lost control of should be rotated regardless of
whether this migration was voluntary.

---

## Phase 3 — RECONSTRUCT (new Vercel project)

**[YOU]** All of this phase happens in the Vercel dashboard/CLI.

1. **Create the new account as a Team, not a personal account**, even if
   you're the only member today. This is the structural fix for the root
   cause of this incident: a Team supports multiple owners/members, so
   losing one person's login doesn't lock everyone out again. Use a
   durable, organization-controlled email (not a personal one that could
   itself become unreachable), enable 2FA, and **this time, actually save
   the recovery codes somewhere durable and separate from the account
   itself** (a password manager, not a note only accessible via the same
   login).

2. **Connect GitHub**: authorize the Vercel GitHub App for
   `cyberdudebivash-pvt-ltd/cyberdudebivash-blog`. This requires GitHub
   org-admin rights (or at least repo-admin) to approve a new App
   installation.

3. **Import the project** with these exact settings (all sourced from the
   git-committed `vercel.json`/`package.json`, per `VERCEL_MIGRATION_INVENTORY.md`
   §2, §4):
   - Framework Preset: **Other** (no framework — confirmed, no `next`/`vite`/etc. dependency)
   - Root Directory: `./` (repo root)
   - Build Command: **leave disabled/empty** — there is no build step
   - Output Directory: default (repo root serves static files as-is)
   - Install Command: default (`npm install` — `package-lock.json` is committed for reproducible installs)
   - Production Branch: `main`

4. **`vercel.json`'s `ignoreCommand`, headers, rewrites, redirects, and
   per-function memory/duration settings apply automatically** — they're
   read from the repo at build time, not a dashboard setting. Nothing to
   re-enter for those.

5. **Set every environment variable** from the newly-completed
   `.env.example` (this repo's own copy is now the checklist — it
   documents all ~43, not the 13 it did before this migration). For each:
   - Real values recovered in Phase 2, for the provider-backed ones.
   - Freshly generated values (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`) for the self-issued ones.
   - Leave `NODE_ENV` **unset** (or explicitly `production`) — never `development`, see the warning in `.env.example` about `api/_lib/middleware.js`'s dev-auth bypass.
   - Set each for Production **and** Preview environments (Development is optional, only relevant if you deploy preview branches you want fully functional too).

6. **Recreate the Vercel Cron** for `/api/cron/dispatch-intel`: Project →
   Settings → Cron Jobs → Add. The original schedule was never committed
   to git and isn't recoverable — a reasonable starting point is every 30
   minutes (`*/30 * * * *`), matching `sentinel-apex.yml`'s own cadence,
   but this is your call, not a recovered fact.

7. **Do not add the production domain yet.** Stop here — you now have a
   working project on an auto-generated `https://<something>.vercel.app`
   URL. That's the point of the next two phases.

---

## Phase 4 — STAGE

**[YOU]** Trigger the first deploy (importing the project in step 3 above
should have already done this automatically). Confirm it succeeds and
note the `*.vercel.app` URL Vercel assigns.

If the build fails, check the deploy log — with no build step configured,
failures here would almost always mean a misconfigured Root Directory or
a missing env var a function needs at cold-start, not a code problem
(this exact code deploys cleanly today on the old account).

---

## Phase 5 — VERIFY (against the staging URL — never test in Phase 6+)

**[EITHER]** Adapt `OPERATIONS.md` §3's probes to the staging URL:

```bash
STAGING=https://your-project-name.vercel.app
curl -s -o /dev/null -w 'homepage        %{http_code}\n' "$STAGING/"
curl -s -o /dev/null -w 'newsletter OPT  %{http_code}\n' -X OPTIONS "$STAGING/api/v1/newsletter"   # expect 204
curl -s -o /dev/null -w 'billing         %{http_code}\n' "$STAGING/api/v1/billing"                  # expect 400
curl -s -o /dev/null -w 'auth            %{http_code}\n' "$STAGING/api/v1/auth"                     # expect 400
curl -sI "$STAGING/" | grep -iE "^(strict-transport-security|x-frame-options|content-security-policy):"
```

**[YOU]** Beyond the automated probes, exercise each revenue system
end-to-end against staging before this becomes real production traffic:

- **Newsletter**: submit a real signup, confirm it lands in your Resend
  audience (or the Redis-stored lead if Resend isn't configured yet).
- **Redis**: confirm `/api/v1/auth` registration issues a working API key
  and that it authenticates against `/api/v1/intel/*`.
- **Admin**: confirm `/api/v1/admin/*` accepts the *new* `ADMIN_SECRET_KEY`
  via the `X-Admin-Key` header and rejects everything else.
- **Payments**: use each processor's test/sandbox mode first — do not run
  a real charge against staging. Confirm order creation, signature
  verification, and the webhook endpoints respond correctly to a
  processor-sent test event (Stripe CLI's `stripe trigger`, or Razorpay's
  test-mode webhook resend).
- **Cron**: manually trigger `/api/cron/dispatch-intel` once (with the
  correct `CRON_SECRET` header) and confirm it successfully dispatches to
  GitHub Actions.

Do not proceed to Phase 6 until every one of these is confirmed on
staging, not assumed.

---

## Phase 6 — CUT OVER (DNS)

**Not yet determined**: which registrar/DNS provider controls
`cyberdudebivash.in` today. That is a separate account from Vercel and
this session has no visibility into it — check wherever the domain was
originally purchased, or a DNS provider like Cloudflare if one is in
front of it.

**[YOU]**
1. In the **new** Vercel project: Settings → Domains → Add
   `blog.cyberdudebivash.in`. Vercel will display the exact A/CNAME
   record(s) to create.
2. Log into whatever controls DNS for `cyberdudebivash.in` and update
   those records to point at the new project.
3. Wait for DNS propagation (can take minutes to hours depending on the
   previous record's TTL) and Vercel's automatic SSL certificate
   issuance for the domain.
4. Re-run Phase 5's probes, this time against
   `https://blog.cyberdudebivash.in` itself, to confirm the cutover
   actually took effect and isn't still serving the old deployment from
   cache.

This is the only step in this runbook that affects live customer traffic.
Everything before it is safe to redo or abandon with zero customer
impact.

---

## Phase 7 — OBSERVE

Follow `RUNBOOKS.md`'s existing monitoring guidance for the first
observation window: 4xx/5xx rates, function failures, Redis
connectivity, cron execution, feed freshness, auth success rate, webhook
delivery. `smoke-test.yml` already runs automatically on every push to
`main` and will flag critical page failures.

If anything critical breaks and can't be fixed forward quickly, DNS can
be pointed back at nothing (or you can leave the domain on the new
project and roll the *code* back via `git revert`, per `RUNBOOKS.md`
"Rollback" — the new Vercel project is not going away, so this isn't an
all-or-nothing cutover).

---

## Phase 8 — RETIRE (old account)

Since the old account can't be logged into, there is nothing to
proactively revoke *from inside it*. What you can still do:

1. **[YOU]** If the Phase 0 support ticket eventually resolves and you
   regain access, revoke its GitHub App installation, delete/pause the
   old Vercel project, and remove the old domain binding — but only
   after confirming the new project has been stable in production for a
   real observation period, not immediately.
2. **[YOU]** Rotate every credential in the table in Phase 2 regardless
   of whether you regain old-account access, if there's any chance the
   lockout was a compromise rather than a forgotten password — a lost
   password you can't reset is also the symptom of a takeover.
3. State plainly to anyone who asks (customers, team): if access is never
   recovered, that's the honest answer — don't claim the old account was
   "deleted" or "secured" if it's genuinely just unreachable.

---

## Post-migration cleanup (not urgent, do after Phase 7 is stable)

- `OPERATIONS.md` and `RUNBOOKS.md` both casually assume Vercel dashboard
  access is available — once the new account is the real one, no doc
  changes are strictly required (they were accurate again the moment
  Phase 6 completes), but it's worth a note in `platform/open-issues.md`
  recording this incident happened, when, and what changed, matching this
  repo's own convention for durable institutional memory.
- Consider whether the R2/AWS product-download dead code (flagged in
  `ENVIRONMENT_VARIABLE_MATRIX.md`) is worth fixing now that env vars are
  being re-provisioned from scratch anyway, or worth dropping entirely if
  it's not actually planned to be used.
