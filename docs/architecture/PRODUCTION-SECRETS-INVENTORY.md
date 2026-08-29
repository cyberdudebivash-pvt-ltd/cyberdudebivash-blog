# SENTINEL APEX — Production Secrets Inventory

**Purpose:** A complete, names-only inventory of every environment
variable / secret this platform's production code references, across
JavaScript (Vercel + Cloudflare Workers runtime), Python (Intel Factory
automation pipeline), and GitHub Actions workflows. Built by grepping the
real source (`process.env.*` in `api/`, `scripts/`, `workers/`;
`os.environ` in `automation/`; `secrets.*` in `.github/workflows/`) —
not from memory or assumption.

**This document contains names only. No values, no partial values, no
hints about actual configured values, ever.** Populating or rotating any
secret named here happens in the relevant platform's own secret store
(Vercel project settings, Cloudflare Workers secrets, GitHub Actions
repository secrets) — never in this repository.

---

## 1. Cloudflare (production runtime target)

| Name | Used by |
|---|---|
| `CLOUDFLARE_ACCOUNT_ID` | `api/_lib/d1.js` (REST transport), GitHub Actions D1 bridge steps |
| `CLOUDFLARE_D1_DATABASE_ID` | Same |
| `CLOUDFLARE_API_TOKEN` | Same |

## 2. Redis / Upstash (LEGACY — active for auth, billing, ReportX; retired for alert-delivery and watchlists/change-detection as of this and the prior tranche)

| Name | Used by |
|---|---|
| `UPSTASH_REDIS_REST_URL` | `api/_lib/redis.js`, GitHub Actions alert-delivery bridge |
| `UPSTASH_REDIS_REST_TOKEN` | Same |

## 3. Payment processors (external SaaS — Stripe, Razorpay own financial truth; see the Auth & Billing Deferral Audit)

| Name | Used by |
|---|---|
| `STRIPE_SECRET_KEY` | `api/_lib/stripe.js`, `api/v1/billing/webhook.js` |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signature verification |
| `STRIPE_PRICE_STARTER` / `STRIPE_PRICE_PRO` / `STRIPE_PRICE_ENTERPRISE` | Stripe Checkout price IDs |
| `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` | `api/_lib/razorpay.js` |
| `RAZORPAY_WEBHOOK_SECRET` | Razorpay webhook signature verification |

## 4. Manual payment instructions (semi-public account details, env-configurable with defaults — not secrets in the credential sense, inventoried for completeness)

| Name | Used by |
|---|---|
| `UPI_ID` / `UPI_NAME` | `api/_lib/payment-utils.js` |
| `BANK_NAME` / `BANK_ACCOUNT` / `BANK_IFSC` / `BANK_LABEL` | Same |

## 5. Email delivery

| Name | Used by |
|---|---|
| `RESEND_API_KEY` | `api/_lib/resend.js`, alert-delivery and auth welcome emails |
| `RESEND_AUDIENCE_ID` | Newsletter audience targeting |
| `RESEND_FROM_EMAIL` | Sender address |

## 6. LLM / AI providers (Intel Factory content generation)

| Name | Used by |
|---|---|
| `ANTHROPIC_API_KEY` | `automation/llm_client.py` |
| `DEEPSEEK_API_KEY` | Same (fallback provider) |
| `GROQ_API_KEY` | Same |
| `OPENROUTER_API_KEY` | Same |

## 7. Threat intelligence sources (Intel Factory)

| Name | Used by |
|---|---|
| `NVD_API_KEY` | `automation/` NVD source fetcher |
| `ALIENVAULT_OTX_KEY` | `automation/threat_feeds` OTX source |
| `OTX_API_KEY` | Referenced in `.github/workflows/*` — appears to be an alias/legacy name alongside `ALIENVAULT_OTX_KEY`; not resolved in this audit (out of scope — a Redis/D1 runtime audit, not a secrets-naming cleanup), flagged here so it isn't lost |

## 8. Social syndication

| Name | Used by |
|---|---|
| `TWITTER_API_KEY` / `TWITTER_API_SECRET` / `TWITTER_ACCESS_TOKEN` / `TWITTER_ACCESS_SECRET` | `automation/social_amplifier.py` |

## 9. Blogger publication (Intel Factory → cti.cyberdudebivash.in)

| Name | Used by |
|---|---|
| `BLOGGER_BLOG_ID` | `automation/blogger_publisher.py` |
| `BLOGGER_CLIENT_ID` / `BLOGGER_CLIENT_SECRET` / `BLOGGER_REFRESH_TOKEN` | OAuth credentials for the Blogger API |
| `GOOGLE_SEARCH_CONSOLE_KEY` | Search Console indexing API |

## 10. Internal auth / admin / cron

| Name | Used by |
|---|---|
| `ADMIN_SECRET_KEY` | `api/_lib/security.js verifyAdminKey`, `api/_lib/payment-utils.js isAdminAuthorized` (duplicated — see Auth & Billing Deferral Audit §A.7) |
| `ANALYST_KEYS` | `api/_lib/analyst-auth.js` — JSON array of `{id, name, role, key}` |
| `CRON_SECRET` | Cron-triggered endpoint authorization |
| `APEX_BRIDGE_SECRET` | Cross-service bridge authorization |
| `DOWNLOAD_TOKEN_SECRET` | `api/v1/customer/download.js` signed download links |
| `GITHUB_DISPATCH_TOKEN` | `workflow_dispatch` trigger authorization from application code |
| `ALLOW_DEV_AUTH_BYPASS` | `api/_lib/middleware.js` — dev-only auth bypass gate, requires `NODE_ENV=development` too (see A.5 caution in the Auth audit) |
| `SENTINEL_APEX_API_KEY` | Referenced in GitHub Actions — internal API self-authentication for scheduled jobs |

## 11. AWS / R2 storage

| Name | Used by |
|---|---|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` | Legacy/alternate storage path |
| `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | Cloudflare R2 (S3-compatible) — product/report artifact storage |
| `PRODUCTS_BUCKET` | Bucket name for digital product delivery |
| `BACKUP_ENCRYPTION_KEY` | Backup artifact encryption |

## 12a. SIEM connector credential encryption (Controlled SIEM Deployment Gateway v1)

| Name | Used by |
|---|---|
| `CONNECTOR_CREDENTIAL_MASTER_KEY` | `api/_lib/connector-crypto.js` — AES-256-GCM envelope encryption of `siem_connectors.credential_ciphertext` (e.g. a Microsoft Sentinel service principal's client secret). Connector credential save/rotate/decrypt hard-refuses without it. |
| `CONNECTOR_CREDENTIAL_MASTER_KEY_PREVIOUS` | Same file — set only during a master-key rotation window so previously-encrypted credentials remain decryptable until re-encrypted under the new key. |

## 12. Non-secret configuration (inventoried for completeness — public values, not credentials)

| Name | Used by |
|---|---|
| `NODE_ENV` | Standard Node environment flag |
| `NEXT_PUBLIC_BASE_URL` | Public base URL |
| `PUBLIC_CTI_URL` | Public Intel Factory site URL (cti.cyberdudebivash.in) |
| `NEWSLETTER_SIGNUP_URL` | Public newsletter signup link |
| `MAX_POSTS_PER_RUN` | Intel Factory pipeline batch size |
| `GITHUB_REPO_NAME` / `GITHUB_REPO_OWNER` | Repo self-reference for automation |
| `GITHUB_TOKEN` | GitHub Actions' own auto-provided token, not a repository-configured secret |

---

## 13. Cross-reference — Cloudflare-Only Runtime Completion v2 relevance

Per the GitHub Actions workflow gating fix made this tranche
(`alert-delivery.yml`), the `redis_ready`/`d1_ready` preflight now checks
`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` AND
`CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_D1_DATABASE_ID` +
`CLOUDFLARE_API_TOKEN` before running either the evaluate or deliver step
— both steps now depend on both stores (watchlists/change-detection moved
to D1 this tranche; delivery state moved to D1 last tranche; the
`getOwnerAccountEmail()` customer-identity lookup remains the one
legitimate Redis call in the D1-backed delivery path). This is
unverified/likely not yet configured as real GitHub Actions repository
secrets in production — this sandbox has no live Cloudflare account
access to confirm (`wrangler whoami` → not authenticated), consistent
across every round of this multi-tranche effort.

*CYBERDUDEBIVASH® SENTINEL APEX — Production Secrets Inventory*
*Phase 45-48 deliverable, Cloudflare-Only Runtime Completion v2*
*Names only. No values. Rotate/populate secrets in each platform's own store, never in this repository.*
