# CYBERDUDEBIVASH SENTINEL APEX — Operations & Revenue Activation Runbook

This document covers how the platform deploys, and — more importantly — the
**revenue systems that are already built and deployed but switched off**,
waiting on environment configuration. Activating them is the single highest-
leverage revenue action available today: the code path exists and is verified;
it just needs credentials set in Vercel.

Last verified: 2026-07-05.

---

## 1. Deployment (Vercel)

The site is a static + serverless deployment on Vercel, auto-deploying on every
push to `main`. Two GitHub Actions also commit to `main` on a schedule:

| Workflow | Schedule | Commits |
|---|---|---|
| `sentinel-apex.yml` | `0,30 * * * *` (:00, :30) | intel data refresh |
| `blogger-syndication.yml` | `15,45 * * * *` (:15, :45) | new blog posts |

They are **interleaved on purpose** so pushes to `main` land every ~15 min.

### 1.1 Deploy starvation — cause and the permanent fix

**Symptom:** nothing publishes for a long time even though commits land on `main`.

**Cause:** the Vercel build for this repo takes ~10–13 minutes (measured). When
pushes to `main` arrive faster than that, each new push **cancels the previous
in-flight deploy**, so no deploy ever finishes and production freezes on the
last one that happened to complete in a quiet gap. This is why the two content
workflows were interleaved to a 15-minute cadence (longer than the build).

**Belt-and-suspenders fix (recommended, ~30 seconds, one time):**
The intel-refresh commits are already tagged with `[skip ci]`. Tell Vercel to
skip deploying those commits so only real content changes deploy:

> Vercel → Project → Settings → Git → **Ignored Build Step** → set to:
> ```
> bash -c '[[ "$VERCEL_GIT_COMMIT_MESSAGE" != *"[skip ci]"* ]]'
> ```

With this set, you can safely return `sentinel-apex.yml` to a faster cadence
(e.g. `*/5`) for real-time intel freshness — those commits will refresh the
data files without triggering a deploy, while syndication/content/SEO commits
(which are **not** tagged `[skip ci]`) deploy normally.

---

## 2. Revenue Activation Checklist

Every system below is **coded, deployed, and endpoint-live**. Status is what was
verified in production on the date above. Set the env vars in
**Vercel → Project → Settings → Environment Variables**, redeploy, then verify.

| System | Purpose (revenue) | Env vars required | Verified status |
|---|---|---|---|
| **Resend** | Newsletter → owned email audience + nurture (the content→SaaS funnel) | `RESEND_API_KEY`, `RESEND_AUDIENCE_ID` | ❌ **not configured** (`esp_status: not_configured`) |
| **Upstash Redis** | Lead storage, API keys, rate limiting, billing state | `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | ⚠️ verify (lead endpoint returns "captured") |
| **Stripe** | USD card subscriptions (SOC Pro, Enterprise) | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_ENTERPRISE` | ⚠️ verify |
| **Razorpay** | INR payments (primary processor) | `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` | ⚠️ verify |

### 2.1 Newsletter → Resend (highest-leverage, do this first)

The entire capture pipeline exists: forms tagged `data-email-capture` are wired
by `email-engine.js` to `POST /api/v1/newsletter`, which stores the lead in
Redis and adds the contact to your Resend audience — the API key never touches
the browser. Right now `email-engine.js` has `provider: 'formsubmit'`, so
signups are emailed to `bivash@cyberdudebivash.com` instead of building a list.

**Activate:**
1. Create a Resend account, an Audience, and an API key.
2. In Vercel set `RESEND_API_KEY` and `RESEND_AUDIENCE_ID`; redeploy.
3. Verify (should return `esp_status: "subscribed"`):
   ```
   curl -s -X POST https://blog.cyberdudebivash.in/api/v1/newsletter \
     -H 'Content-Type: application/json' \
     -d '{"email":"you@example.com","segment":"general","source":"activation_test"}'
   ```
4. In `email-engine.js` change `provider: 'formsubmit'` → `provider: 'resend'`
   and deploy. (Do this **after** step 3 succeeds — flipping before Resend is
   configured would route leads into storage instead of your inbox.)

Once live, every SEO visitor who subscribes becomes an owned, segmentable
contact (segments supported: `general`, `cve-alerts`, `ai-security`, `mssp`,
`enterprise`, `webinar`) with a 7-touch nurture sequence already scripted in
`email-engine.js`.

### 2.2 Payments — verify and reconcile

Verify each processor responds configured (endpoints are already live at
`/api/v1/billing`). Then confirm the **price actually charged matches the price
displayed** ($18/mo SOC Pro after the pricing-consistency fix).

> ⚠️ **Known mismatch to check:** `api/_lib/stripe.js` documents
> `STRIPE_PRICE_PRO` as "monthly $49", but the site now displays **$18/mo**.
> If Stripe is activated, create/point `STRIPE_PRICE_PRO` at an **$18** price
> object, or the customer is shown $18 and charged $49 — a chargeback and
> trust risk. Razorpay (INR ₹1,499 ≈ $18) is the canonical price.

---

## 3. Quick verification probes

```
BASE=https://blog.cyberdudebivash.in
# API layer alive (400/405 = deployed & validating; 404 = not deployed)
curl -s -o /dev/null -w 'newsletter %{http_code}\n' -X OPTIONS $BASE/api/v1/newsletter   # expect 204
curl -s -o /dev/null -w 'billing    %{http_code}\n' $BASE/api/v1/billing                  # expect 400
curl -s -o /dev/null -w 'auth       %{http_code}\n' $BASE/api/v1/auth                     # expect 400
# Data + brand surfaces
curl -s -o /dev/null -w 'EVI json   %{http_code}\n' $BASE/data/exploitation-velocity-index.json  # 200
curl -s -o /dev/null -w 'favicon    %{http_code}\n' $BASE/favicon.ico                     # 200
```

---

## 4. Revenue system inventory (what's built)

- **Content → audience:** SEO (3,000+ posts, favicon/entity-graph live), research
  hub + Exploitation Velocity Index (linkable data asset), detection packs
  (lead magnets) → newsletter capture (`/api/v1/newsletter`, needs Resend).
- **Audience → revenue:** SOC Pro subscription (Stripe/Razorpay), Enterprise
  (contact + Calendly opportunity), API access (keys via `/api/v1/auth`),
  detection-pack storefront (`products.html` → `/api/v1/billing`).
- **Trust layer (done):** verifiable sourcing + corrections policy, legal pages,
  consistent pricing, primary-source citations — the prerequisites enterprise
  procurement checks before any of the above can convert.

The infrastructure is in place. The gating item for measurable revenue is
**switching on the env-configured systems above** — code changes cannot do this;
they require account credentials set in Vercel.

---

## 5. Build Orchestrator, Observability & Rollback

Added alongside the Phase 4 platform-maturity work. See `docs/build-system.md`
(auto-generated) for the full generator registry.

### 5.1 Running a generator on demand

Six generators already run on independent schedules (see `docs/build-system.md`
for the current list and cadence). To re-run one manually without waiting for
its cron — e.g. after fixing a bug, or to backfill after an outage — use the
`workflow_dispatch`-only **Build Orchestrator** workflow (GitHub → Actions →
"🛰 SENTINEL APEX — Build Orchestrator (manual)" → Run workflow), or locally:

```
node orchestrator/build-orchestrator.js --discover        # list generators + dependencies
node orchestrator/build-orchestrator.js --run cve-pages    # run one
node orchestrator/build-orchestrator.js --run-all --incremental  # run all, skipping unchanged
```

This never replaces or reschedules any of the six existing workflows — it is a
manual/on-demand tool only.

### 5.2 Checking platform health

`ops/health/index.html` (regenerated every 30 min by `observability.yml`, and
on every push to `orchestrator/**`) shows, for all six generators: freshness
status, last successful output timestamp, and — for the Blogger syndication
pipeline specifically — a real trend of the last 30 runs' publish/fail counts,
since a run can commit state and exit non-zero-only-sometimes while still
publishing nothing (see `automation/main.py`'s exit logic: only `failed > 0
and published == 0` is treated as a hard failure). This page is intentionally
**not** linked from public navigation or included in `sitemap.xml` — it's an
operator view, not a content surface.

If the dashboard shows the Blogger syndication trend below ~50% healthy,
re-check the failure signature first — `HTTP 429 rate limited` matches the
OAuth/rate-limit incident this platform has hit before (see the root-cause
analysis in the `fix: surface Blogger syndication pipeline failures` and
`fix: throttle-guard the external dispatcher` commits).

### 5.3 Rollback

There is no automated rollback pipeline (see `CHANGELOG.md` for the tagging
convention used to identify known-good points). To roll back a bad production
deploy today:

1. **Identify the last good commit** — check `git log --oneline main` and/or
   the version tags in `CHANGELOG.md` for the most recent tagged release known
   to be healthy.
2. **Revert forward, don't force-push** — `git revert <bad-commit>` (or a
   range) and push a new commit to `main`. Force-pushing `main` is not
   recommended: the six generator workflows commit to `main` on their own
   schedules and a force-push can silently drop or conflict with one of those
   in-flight commits.
3. **Vercel dashboard fallback** — Vercel keeps prior deployments; from the
   Vercel dashboard, "Promote to Production" on the last known-good deployment
   gives an immediate rollback while the `git revert` above lands properly in
   history. Use this for anything user-facing and urgent; still follow up with
   the git revert so `main` and production stay in sync.
4. **Bot-commit throttle interaction** — remember `vercel-ignore-build.sh`
   (see §1.1) only allows bot commits (`SENTINEL APEX`/`syndication:
   auto-published` messages) to trigger a build in the first 10 minutes of
   each even UTC hour. A revert commit authored by a human (or with a
   different message prefix) always builds immediately regardless of that
   gate.
