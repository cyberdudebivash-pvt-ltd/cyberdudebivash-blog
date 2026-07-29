# CYBERDUDEBIVASH SENTINEL APEX — Operations & Revenue Activation Runbook

This document covers how the platform deploys, and — more importantly — the
**revenue systems that are already built and deployed but switched off**,
waiting on environment configuration. Activating them is the single highest-
leverage revenue action available today: the code path exists and is verified;
it just needs credentials set in Vercel.

Last verified: 2026-07-05. Section 2.2's Stripe warning updated 2026-07-28
(GEORP v1) — see that section for what changed. For incident/outage
procedures (not covered here), see `RUNBOOKS.md`.

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

> **Update (2026-07-28, GEORP v1):** the code-level $49/$18 mismatch this
> warning originally flagged is fixed — `api/_lib/stripe.js`'s own header
> comment now correctly states the canonical amount (₹1,499/≈$18) and
> explicitly warns that a code change here cannot confirm what the live
> Stripe dashboard Price object actually points at. That residual risk is
> real and current, and now applies to **three** tiers, not just Pro:
> Starter was also repriced (₹2,499/$29 → ₹999/$12, `docs/PRICING.md`,
> GCDOM v1) and has never had a Stripe Price object created for it at any
> price. **Before ever activating Stripe live**, verify all three —
> `STRIPE_PRICE_STARTER` ($12), `STRIPE_PRICE_PRO` ($18),
> `STRIPE_PRICE_ENTERPRISE` ($60) — against `api/_lib/payment-utils.js`'s
> `PLANS` directly in the Stripe dashboard. Razorpay (INR-denominated,
> matching `PLANS` directly) remains the canonical, verified-in-production
> processor.
>
> **Separately (verified live, 2026-07-28):** `GET
> /api/v1/billing?action=plans` on the actual production site still
> returns Starter at the *old* price (2499), not the reordered ₹999. The
> Starter/Pro reorder fix (`platform/open-issues.md` Issue 10, GCDOM v1) is
> merged and tested on `claude/cti-platform-standards-f64l5x` but was never
> merged to `main`, so it has not deployed — the customer-facing pricing
> defect that fix addresses is still live today. This is a real gap in the
> deployment cadence, not just a historical note: fixes are accumulating on
> a feature branch across multiple sprints without reaching production.

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
