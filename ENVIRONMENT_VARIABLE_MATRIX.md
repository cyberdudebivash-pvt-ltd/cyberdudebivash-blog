# Environment Variable Matrix

Authoritative, evidence-based inventory of every environment variable this
platform's code actually reads — derived from source, not from
`.env.example` (which, see below, covers less than a third of them). No
secret *values* appear anywhere in this document, only names, usage sites,
and classification. Produced 2026-08-16 on
`transformation/vercel-recovery-production-hardening`. Two independent
research passes converged on the same secret-sweep conclusion (none
committed); citations are file:line against that branch.

**Classification legend** (per the recovery program's own vocabulary):
`KNOWN` = default/fallback value is visible in code, or the value is
non-secret by design (e.g. a public GA4 ID). `NOT VERIFIED` = this session
has no way to know the real production value. `ROTATION REQUIRED` =
security-sensitive credential that should be reissued given the account
that held it is reported lost. `DEPRECATED` = do not carry forward as-is.
`OPTIONAL` = feature degrades gracefully without it.

---

## Two separate credential domains

This is the single most important structural fact in this document:
**there are two independent secret stores, not one.**

1. **Vercel Project Environment Variables** — consumed by `process.env.*`
   in the serverless app under `api/`. 42 distinct variables, catalogued
   in full below.
2. **GitHub Actions Repository Secrets** — consumed by workflow-run
   scripts. Overlaps partially with (1) (workflows pass some of the same
   names to `fetch-live-intel.js`/`ai-security-intel-engine.js`), **plus an
   entirely separate set of 13 variables** read only by the Python
   Blogger-syndication pipeline via `os.environ.get()` in
   `automation/config.py:81-97`, which never touch `process.env` and were
   easy to miss: `BLOGGER_CLIENT_ID`, `BLOGGER_CLIENT_SECRET`,
   `BLOGGER_REFRESH_TOKEN`, `BLOGGER_BLOG_ID`, `GROQ_API_KEY`,
   `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`, `ALIENVAULT_OTX_KEY`,
   `GOOGLE_SEARCH_CONSOLE_KEY`, `TWITTER_API_KEY`, `TWITTER_API_SECRET`,
   `TWITTER_ACCESS_TOKEN`, `TWITTER_ACCESS_SECRET`.

**Naming inconsistency, flag before recovery**: the Node pipeline reads
`OTX_API_KEY` (`fetch-live-intel.js:87`, sourced from GitHub secret
`OTX_API_KEY` per `.github/workflows/sentinel-apex.yml:109`) while the
Python pipeline reads `ALIENVAULT_OTX_KEY` (`automation/config.py:90`,
sourced from GitHub secret `ALIENVAULT_OTX_KEY` per
`.github/workflows/blogger-syndication.yml:130`) — confirm with AlienVault
whether these were meant to be the same underlying API key stored under
two different secret names, or are genuinely two separate keys, before
deciding whether one or two need recovering.

**Priority order for recovery, by blast radius** (not just by what this
program originally assumed): Redis (Upstash) is read by 45 files across
~415 call sites and backs *everything* — auth, billing, rate limiting,
product delivery, the entire intelligence/workbench API. Recovering
**Upstash account access and GitHub repository-secrets access** matters
at least as much as Vercel account recovery itself, and per
`RUNBOOKS.md:94-97`, if Redis access is lost *before* a working backup
exists, registered customers' API keys are stated as unrecoverable — see
"Urgent, independent of Vercel" below.

---

## Vercel Project Environment Variables (JS/serverless app)

### Redis (highest blast radius — everything depends on this)

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `UPSTASH_REDIS_REST_URL` | `api/_lib/redis.js:8,12` (45 files transitively) | Upstash Redis REST API base URL | De facto required — every Redis call throws if unset | Vercel (Production) | No (URL, not secret alone) | NOT VERIFIED | ROTATION REQUIRED |
| `UPSTASH_REDIS_REST_TOKEN` | `api/_lib/redis.js:9,12` | Bearer token for the same API | De facto required | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |

### Payments — Stripe

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `STRIPE_SECRET_KEY` | `api/_lib/stripe.js:15`; `api/v1/billing.js:444`; **also** an independent second direct-fetch use in `api/v1/billing/webhook.js:164` | Bearer auth to Stripe REST API | Optional at load; 503 if unset at subscribe endpoint | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |
| `STRIPE_WEBHOOK_SECRET` | `api/_lib/stripe.js:16,51,61` | HMAC verification of `Stripe-Signature` | Webhook always rejected if unset | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |
| `STRIPE_PRICE_STARTER` | `api/_lib/stripe.js:17` | Stripe Price ID, Starter plan | Checkout throws if unset | Vercel (Production) | No (identifier) | NOT VERIFIED | KNOWN gap — per `RUNBOOKS.md:107-108`, may never have had a Price object created in Stripe at all; verify in dashboard before reuse, don't assume recovery = done |
| `STRIPE_PRICE_PRO` | `api/_lib/stripe.js:18` | Stripe Price ID, Pro plan | Same | Vercel (Production) | No | NOT VERIFIED | Verify amount matches `api/_lib/payment-utils.js` `PLANS` before reactivating |
| `STRIPE_PRICE_ENTERPRISE` | `api/_lib/stripe.js:19` | Stripe Price ID, Enterprise plan | Same | Vercel (Production) | No | NOT VERIFIED | Same verification requirement |

### Payments — Razorpay (per `OPERATIONS.md`, the canonical/primary processor)

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `RAZORPAY_KEY_ID` | `api/_lib/razorpay.js:10`; echoed to client in `payment-flow.js:510` (by design — Razorpay's checkout.js needs it client-side) | Basic-auth username; public-by-design once issued to client | Optional; gates Razorpay features | Vercel (Production) | Semi (not secret once issued, but rotation still coordinated) | NOT VERIFIED | ROTATION REQUIRED |
| `RAZORPAY_KEY_SECRET` | `api/_lib/razorpay.js:11` | Basic-auth password; HMAC key for checkout success-callback verification | Optional; gates features | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |
| `RAZORPAY_WEBHOOK_SECRET` | `api/_lib/razorpay.js:12,84,86` | HMAC verification of `X-Razorpay-Signature` | Webhook rejected if unset | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |

### Manual payment display config (not secrets)

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `ADMIN_SECRET_KEY` | `api/_lib/payment-utils.js:133`; `api/_lib/security.js:379` (duplicated check in both) | Gates `X-Admin-Key` on `/api/v1/admin/*`, timing-safe compare | Fails closed (deny) if unset or <16 chars | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |
| `UPI_ID` | `api/_lib/payment-utils.js:48` | Displayed UPI payment ID | Optional, fallback `cyberdudebivash@upi` | Vercel (Production) | No | KNOWN (fallback visible; real value NOT VERIFIED) | KNOWN/OPTIONAL |
| `UPI_NAME` | `api/_lib/payment-utils.js:49` | Displayed UPI payee name | Optional, fallback shown in code | Vercel (Production) | No | KNOWN (fallback) | OPTIONAL |
| `BANK_NAME` / `BANK_ACCOUNT` / `BANK_IFSC` / `BANK_LABEL` | `api/_lib/payment-utils.js:54-57` | Displayed bank-transfer details | Optional, fallbacks shown in code | Vercel (Production) | `BANK_ACCOUNT`/`BANK_IFSC` are sensitive display data, not auth secrets | KNOWN (fallbacks) | OPTIONAL — verify real values are current, not a security rotation |

### Digital-product delivery

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `DOWNLOAD_TOKEN_SECRET` | `api/_lib/product-delivery.js:147`; `api/v1/customer/download.js:33` | HMAC signs/verifies download tokens | `product-delivery.js` throws if unset; `download.js` 503s | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |
| `PRODUCTS_BUCKET` | `api/v1/customer/download.js:58` | S3/R2 bucket name | Optional, fallback `cyberdudebivash-products` | Vercel (Production) | No | KNOWN (fallback) | See DEPRECATED note below |
| `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | `api/v1/customer/download.js:95-101` | Cloudflare R2 (S3-compatible) credentials | **Dead code as shipped** — `aws-sdk` is `require()`'d here but is not a declared dependency and is absent from `node_modules`; this branch always fails regardless of these vars | Vercel (Production) | Yes (if ever wired up) | NOT VERIFIED | **DEPRECATED** — either add `aws-sdk` as a real dependency and fix this path, or remove the dead branch; do not spend recovery effort re-provisioning R2 credentials for code that can't use them today |
| `AWS_ACCESS_KEY_ID` / `AWS_REGION` / `AWS_SECRET_ACCESS_KEY` | `api/v1/customer/download.js:111-117` | Alternate (non-R2) S3 credentials | Same dead-code caveat | Vercel (Production) | Yes | NOT VERIFIED | DEPRECATED, same reasoning |

### Email — Resend

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `RESEND_API_KEY` | `api/_lib/resend.js:8` | Bearer auth, Resend REST API | Optional, degrades gracefully | Vercel (Production) | Yes | NOT VERIFIED | ROTATION REQUIRED |
| `RESEND_AUDIENCE_ID` | `api/_lib/resend.js:9` | Newsletter audience ID | Optional | Vercel (Production) | No (identifier) | NOT VERIFIED | KNOWN gap — see note below |
| `RESEND_FROM_EMAIL` | `api/_lib/resend.js:10-11` | From-address | Optional, fallback `noreply@cyberdudebivash.com` | Vercel (Production) | No | KNOWN (fallback) | OPTIONAL |

**Note**: `email-engine.js:21` currently sets `provider: 'resend'` in code
(i.e. code has switched away from the `formsubmit` fallback), but
`OPERATIONS.md` (self-dated 2026-07-05/07-28, not independently re-verified
live this session) last recorded `esp_status: not_configured` in the
actual Vercel environment. **This is a real discrepancy to resolve during
recovery, not just during this document's writing**: confirm whether
Resend env vars are actually set before assuming the code's `resend`
provider selection is currently functioning in production.

### GitHub integration / Cron

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `CRON_SECRET` | `api/cron/dispatch-intel.js:48-49` | Timing-safe bearer check on Vercel Cron's call to this endpoint | 401 if unset/wrong | Vercel (Production) | Yes | NOT VERIFIED — **undocumented in `.env.example`** | ROTATION REQUIRED |
| `GITHUB_DISPATCH_TOKEN` | `api/cron/dispatch-intel.js:87,89,99` | Fine-grained GitHub PAT (comment: scoped to `Actions:write` on this repo only), triggers `workflow_dispatch` | 503 if unset | Vercel (Production) | Yes | NOT VERIFIED — **undocumented in `.env.example`** | ROTATION REQUIRED |
| `GITHUB_REPO_OWNER` / `GITHUB_REPO_NAME` | `api/cron/dispatch-intel.js:23-24` | GitHub API URL segments | Optional, fallbacks `cyberdudebivash`/`cyberdudebivash-blog` | Vercel (Production) | No | KNOWN (fallback) | OPTIONAL |
| `GITHUB_TOKEN` | `fetch-live-intel.js:86,324` | Optional Bearer auth to GitHub Security Advisories API (raises rate limit) | Fully optional | GitHub Actions (repo secret) | Yes | NOT VERIFIED | ROTATION REQUIRED — distinct from GitHub's own auto-issued Actions token used by `secrets.GITHUB_TOKEN` in ~15 workflow files for checkout/push, which needs no manual recovery |

### Content-pipeline enrichment (Node)

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `NVD_API_KEY` | `fetch-live-intel.js:85` | NVD CVE feed rate-limit key | Optional, empty fallback | GitHub Actions (repo secret) | Yes | NOT VERIFIED | ROTATION REQUIRED |
| `OTX_API_KEY` | `fetch-live-intel.js:87` | AlienVault OTX feed key | Optional, empty fallback | GitHub Actions (repo secret) | Yes | NOT VERIFIED | ROTATION REQUIRED — see naming-inconsistency note above |
| `SENTINEL_APEX_API_KEY` | `fetch-live-intel.js:88` | Own comment: "optional — endpoints are public" | Explicitly optional | GitHub Actions (repo secret) | Marginal | NOT VERIFIED | OPTIONAL |
| `ANTHROPIC_API_KEY` | `ai-security-intel-engine.js:57` | Claude API key, optional "LLM analyst" enrichment stage | Optional — pipeline runs fully without it per workflow comment | GitHub Actions (repo secret) | Yes | NOT VERIFIED | ROTATION REQUIRED if in use |
| `AISEC_ANALYST` | `ai-security-intel-engine.js:38` | Feature flag gating the analyst stage | Optional | GitHub Actions (repo secret) | No | KNOWN (boolean flag) | OPTIONAL |
| `APEX_API_BASE` | `api/v1/billing.js:51,656` | Base URL of the separate `intel.cyberdudebivash.com` service, called post-payment to provision a cross-service API key | Optional, fallback `https://intel.cyberdudebivash.com`; failure is caught, non-fatal | Vercel (Production) | No (URL) | KNOWN (fallback) | **Security note, not just migration**: this outbound call sends no auth header/secret at all (`api/v1/billing.js` ~line 651-662) — see "Urgent" section below |

### Backup/restore

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `BACKUP_ENCRYPTION_KEY` | `scripts/backup-customer-data.js:124-129`; `scripts/restore-customer-data.js:57-60` | AES key encrypting the Redis backup snapshot | **Hard `process.exit(1)` if unset**, in both scripts | GitHub Actions (repo secret) | Yes | NOT VERIFIED — **per `RUNBOOKS.md:18-27`, was never provisioned as of that writing** | ROTATION REQUIRED / **provision for the first time** — see "Urgent" section below |

### Site config / misc

| Variable | Used By | Purpose | Required? | Environment | Secret? | Current Value Known? | Migration Action |
|---|---|---|---|---|---|---|---|
| `NEXT_PUBLIC_BASE_URL` | `api/_lib/product-delivery.js:151`; `api/v1/billing.js:450`; `.env.example:71` | Base site URL for links/redirect URLs | Optional, fallback `https://blog.cyberdudebivash.in` | Vercel (Production) | No | KNOWN | KNOWN |
| `NODE_ENV` | `api/_lib/middleware.js:113` (**security-relevant**, see "Urgent" below); `jest.setup.ts:4` (test harness only) | If Redis is unreachable AND this equals the literal string `'development'`, auth returns a fake pro-tier bypass user instead of failing closed | Optional; only the exact string `'development'` triggers the bypass | Vercel (Production should never set this) | No | KNOWN behavior; real deployment value NOT VERIFIED | **Must be confirmed absent/`production` on the new Vercel project — see "Urgent"** |

---

## GitHub Actions Repository Secrets — Blogger/Python pipeline only

Read exclusively via `os.environ.get()` in `automation/config.py:81-97`.
Never touch `process.env` — a separate credential surface from everything
above, easy to overlook if recovery focuses only on the Vercel dashboard.

| Variable | Purpose (from `automation/config.py` context) | Migration Action |
|---|---|---|
| `BLOGGER_CLIENT_ID` / `BLOGGER_CLIENT_SECRET` / `BLOGGER_REFRESH_TOKEN` | OAuth credentials for Blogger API syndication | ROTATION REQUIRED |
| `BLOGGER_BLOG_ID` | Target Blogger blog identifier | KNOWN (identifier, not secret) |
| `GROQ_API_KEY` / `DEEPSEEK_API_KEY` / `OPENROUTER_API_KEY` | LLM provider keys for the Blogger content pipeline | ROTATION REQUIRED |
| `ALIENVAULT_OTX_KEY` | AlienVault OTX key (Python side — see naming-inconsistency note) | ROTATION REQUIRED |
| `GOOGLE_SEARCH_CONSOLE_KEY` | Search Console API access | ROTATION REQUIRED |
| `TWITTER_API_KEY` / `TWITTER_API_SECRET` / `TWITTER_ACCESS_TOKEN` / `TWITTER_ACCESS_SECRET` | Twitter/X API credentials | ROTATION REQUIRED |

---

## `.env.example` coverage gap

`.env.example` (root, 94 lines, placeholders only — no real secrets;
verified twice) documents **13 of the 42** JS-side variables. It is not a
reliable checklist for recovery. Missing entirely: `CRON_SECRET`,
`GITHUB_DISPATCH_TOKEN`, `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`,
`GITHUB_TOKEN`, `DOWNLOAD_TOKEN_SECRET`, `PRODUCTS_BUCKET`, `R2_ACCOUNT_ID`,
`R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`,
`AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, `NVD_API_KEY`, `OTX_API_KEY`,
`SENTINEL_APEX_API_KEY`, `ANTHROPIC_API_KEY`, `AISEC_ANALYST`,
`APEX_API_BASE`, `BACKUP_ENCRYPTION_KEY`, `NODE_ENV`, `RESEND_FROM_EMAIL`
(all 13 Python-only variables above are, naturally, also absent — this file
was never meant to cover them, but that's worth stating explicitly so no
one assumes it does). **Recommended P1 fix**: regenerate `.env.example`
from this document once real recovery is complete, so it stops
undercounting by two-thirds.

---

## Committed-secret sweep — result: none found

Two independent passes, same conclusion. Checked: high-confidence key
prefixes (`sk_live_`, `sk_test_`, `rzp_live_`, `rzp_test_`, `whsec_`,
`re_[A-Za-z0-9]{16,}`, `ghp_`, `gho_`, `github_pat_`, `xox[baprs]-`,
`AKIA[0-9A-Z]{16}`, `AIza...`), PEM/private-key headers, Twilio SID
patterns, any `*SECRET*/*KEY*/*TOKEN*/*PASSWORD*` identifier assigned a
quoted literal ≥20 chars outside `process.env`, `.pem`/`.key`/`.pfx`/`.p12`
files, and `git log --all` across every local/remote branch (40+) for any
commit that ever added a `.env`/`.env.local`/`.env.production` file. Zero
hits beyond `.env.example`'s placeholders.

---

## Urgent findings — independent of the Vercel-account-loss narrative

These surfaced from this inventory and matter regardless of how the
Vercel recovery itself proceeds:

1. **`api/_lib/middleware.js:108-118` fails open under a specific
   misconfiguration.** If Redis is unreachable *and* `NODE_ENV` is exactly
   `'development'`, `authenticate()` returns a synthetic
   `{tier:'pro', userId:'dev', ...}` user instead of denying the request.
   Vercel does not set `NODE_ENV=development` on Production/Preview
   deployments by default, so this should not fire today — but it is
   exactly the kind of variable a recovery/migration process could
   accidentally introduce while reconstructing a new Vercel project's
   environment variables. **Recommendation**: either remove this bypass
   entirely, or gate it on a second, explicit flag that can never be
   Vercel's own default (e.g. `ALLOW_DEV_AUTH_BYPASS=true`) so `NODE_ENV`
   alone can never trigger it. This is a code change, not an infra change
   — safe for this session to make once past the forensic phase.
2. **`api/v1/billing.js` calls `APEX_API_BASE` (`intel.cyberdudebivash.com`)
   with no authentication header at all** when provisioning a cross-service
   API key after payment verification (~lines 651-662). Worth a decision:
   either that endpoint is intentionally unauthenticated (document why),
   or it's missing a shared-secret/signature check.
3. **`BACKUP_ENCRYPTION_KEY` and the other two backup-related GitHub
   secrets were, per `RUNBOOKS.md:18-27`, never provisioned** as of that
   document's writing. If that is still true, **no encrypted backup of
   Redis customer data (API keys, tier assignments, payment audit log)
   exists at all**. Combined with the Vercel-account-loss scenario, if
   Redis access were also lost before this is fixed, `RUNBOOKS.md:94-97`
   states registered customers' API keys would be unrecoverable. This is
   arguably the single highest-priority action in this entire program,
   independent of Vercel: provision the three backup secrets and run one
   real backup, now, while Redis access is confirmed still working.
