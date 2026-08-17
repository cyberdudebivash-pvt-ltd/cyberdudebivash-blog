# Rollback Runbook

Rollback procedure for the first isolated `workers.dev` staging deployment
described in `STAGING-DEPLOYMENT-PLAN.md`. Written in advance, per Stage 4
Section 25 — not exercised by this task (no deployment has been made).

## Why this rollback is inherently low-risk

**Production DNS was never touched.** `blog.cyberdudebivash.in` continues
to resolve to Vercel throughout the entire lifecycle of the staging
Worker — before, during, and after. Rolling back the staging deployment
therefore requires no DNS change, no propagation wait, and carries zero
risk to live production traffic at any point. This is a direct consequence
of `STAGING-DEPLOYMENT-PLAN.md`'s scope (`workers.dev` only, no custom
domain, no route).

## Rollback options, in order of preference

### 1. Remove the staging Worker entirely

```bash
npx wrangler delete cyberdudebivash-blog
```

Deletes the Worker script and its `*.workers.dev` subdomain assignment.
Use this if the staging deployment should be fully withdrawn (e.g. a
serious defect is found, or staging is being paused indefinitely).

### 2. Revert to a previous Worker version

Cloudflare Workers retains deployment history natively. If a *later*
staging deploy introduces a regression relative to an earlier one still
worth keeping live:

```bash
npx wrangler deployments list --name cyberdudebivash-blog
npx wrangler rollback --name cyberdudebivash-blog [--message "reason"]
```

`wrangler rollback` reverts to the immediately-previous deployment by
default; pass a specific deployment ID (from `deployments list`) to target
a non-adjacent version.

### 3. Redeploy from a known-good commit

If the Worker's code itself needs to move backward (not just its most
recent deployment):

```bash
git checkout <known-good-sha> -- .
rm -rf dist-public && node scripts/build-cloudflare-assets.js
npx wrangler deploy
git checkout <original-branch-or-sha> -- .   # restore working tree
```

Prefer option 2 (`wrangler rollback`) when the target state is simply
"the previous deploy" — it's faster and doesn't require a local checkout
dance. Use option 3 only when reverting further back than Cloudflare's
retained deployment history covers.

## What remains untouched by any rollback option above

- **Vercel** — the live production origin for `blog.cyberdudebivash.in`,
  completely unaffected by any action in this runbook.
- **DNS** — no record ever pointed at the staging Worker; there is
  nothing to revert.
- **Any other Worker/KV/R2/D1 resource on the target Cloudflare
  account** — the staging deployment binds only `env.ASSETS`; no shared
  resource is ever touched (see `COMPLETE-CLOUDFLARE-INVENTORY.md` and
  the Wrangler Config Safety Audit — zero KV/D1/R2/Queue bindings exist
  in `wrangler.jsonc`).
- **Secrets** — none were ever set (see
  `ENVIRONMENT-MIGRATION-MATRIX.md` — the first staging deployment
  requires none), so there's nothing to rotate or revoke as part of a
  rollback either.

## Evidence/logs to retain before rolling back

If the rollback is defect-driven rather than routine:
1. `npx wrangler deployments list --name cyberdudebivash-blog` output
   (deployment history, timestamps).
2. `npx wrangler tail --name cyberdudebivash-blog` output captured during
   the incident window, if the Worker was actively receiving traffic.
3. The specific failing request/response (method, path, status, headers)
   that motivated the rollback.
4. A copy of `dist-public/`'s build manifest at the time of the bad
   deploy (regenerate via the same commit: `git log` to find the commit
   the bad deploy was built from, `git show <sha>:scripts/build-cloudflare-assets.js`
   if the build script itself changed between deploys).

Retain these against the eventual production-cutover postmortem/decision
record, even though this rollback itself carries no production risk.

## Post-rollback verification

1. Confirm the Worker (if kept, per option 2/3) serves its expected
   version: `curl https://cyberdudebivash-blog.<subdomain>.workers.dev/`
   and spot-check against the known-good behavior.
2. Confirm `blog.cyberdudebivash.in` is unaffected (Vercel, unchanged) —
   expected to be trivially true given no DNS was ever touched, but worth
   a spot-check for completeness.
3. If the Worker was deleted (option 1): confirm
   `npx wrangler deployments list --name cyberdudebivash-blog` returns a
   "not found"/empty result, and that re-running `STAGING-DEPLOYMENT-PLAN.md`
   from scratch is the intended path back to a staging environment, not an
   assumption that state persisted.
