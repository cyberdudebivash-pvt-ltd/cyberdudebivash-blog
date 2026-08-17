# Environment Migration Matrix

Stage 4 Section 9's environment/`process.env` final certification. Builds
directly on `ENVIRONMENT_VARIABLE_MATRIX.md` (the pre-existing, extensive
42-variable inventory from the Vercel-account-recovery program) rather than
re-deriving it — reconciled with two real code-vs-doc discrepancies found
this session, plus the Cloudflare-specific classification that document
never needed to make.

## The bridging mechanism — the one fact that changes everything else

**No explicit bridging code exists anywhere in this repository.** A
full-codebase grep for `process.env` inside `workers/**` returns zero
matches. The ported `api/**` handlers keep calling `process.env.XXX`
directly, completely unaware they're running in a Worker.

This works because `wrangler.jsonc`'s `compatibility_flags: ["nodejs_compat"]`
causes the Workers runtime to auto-populate the global `process.env`
object from whatever `vars`/`secrets` are bound to the Worker — a
platform-level implicit bridge, not anything this repository's code does.

**This session upgraded that claim from INFERRED to CLAUDE-VERIFIED**:
a synthetic `ADMIN_SECRET_KEY` was placed in a local, gitignored
`.dev.vars`, and a live request against a real `wrangler dev` instance
sent that exact value as an `X-Admin-Key` header. The admin-key check
passed (a different, later failure occurred — the synthetic Redis URL
being unreachable — not the 401 a broken/absent bridge would produce),
proving `process.env.ADMIN_SECRET_KEY` genuinely reached the handler.

**Practical consequence for staging**: `wrangler.jsonc` currently declares
**no `vars` and no `secrets` section at all** — deliberately, per that
file's own trailing comment. As committed, every one of the 44 variables
below resolves to `undefined` inside a deployed Worker. Variables with a
`|| 'fallback'` silently use their hardcoded default; variables with no
fallback trigger each handler's own fail-closed path (401/503/thrown,
matching the "unset" behavior already documented for Vercel). Before any
staging deployment can exercise authenticated/paid functionality, the
minimum secret set below (see "Minimum secrets for first staging") must
be provisioned via `wrangler secret put` or the dashboard — this
document does not perform that provisioning, and per Section 28's
Absolute Remote Cloudflare Safety Rule, could not from this task even if
it wanted to.

## Concurrency safety (Stage 4 Section 13's specific requirement)

**No application code anywhere writes to `process.env` at runtime.** A
full-codebase grep for assignment patterns
(`process\.env\.[A-Za-z_]+\s*=`, `process\.env\[.*\]\s*=`,
`Object.assign(process.env, ...)`) found exactly two hits, both confined
to test-harness setup code (`api/_lib/__tests__/stripe-webhook-verify.test.js`,
`tests-js/middleware-dev-auth-bypass.test.js`) — never executed during
real request handling. Combined with the bridge itself being static
per-isolate (populated once from deploy-time bindings, not derived from
any per-request input), there is no mechanism by which one request could
observe another's environment state. Verified by construction, not by a
synthetic concurrency stress test — the exhaustive grep is dispositive
here since there is nothing for a race to corrupt.

## Complete variable inventory (44 variables, source-derived)

Full per-variable file:line citations, load-time/request-time
classification, and secret/public determination live in
`ENVIRONMENT_VARIABLE_MATRIX.md` — reused here, not duplicated. This table
adds the two columns that document didn't need: Cloudflare target type and
staging requirement.

**Cloudflare target type key**: `VAR` (non-secret config) ·
`SECRET` (Wrangler secret) · `EXTERNAL_DEPENDENCY` (a third-party
service's own credential, still a Wrangler secret, called out separately
because rotation is coordinated with that provider) · `DEPRECATED`
(dead code, do not provision) · `NOT_MIGRATED` (Python/GitHub-Actions-only,
never reaches a Worker).

| Variable | Cloudflare target type | Staging required? | Production required? | Note |
|---|---|---|---|---|
| `UPSTASH_REDIS_REST_URL` | SECRET | No¹ | Yes | Highest blast radius — backs auth, billing, rate limiting, workbench |
| `UPSTASH_REDIS_REST_TOKEN` | SECRET | No¹ | Yes | Same |
| `STRIPE_SECRET_KEY` | EXTERNAL_DEPENDENCY | No¹ | Yes | |
| `STRIPE_WEBHOOK_SECRET` | EXTERNAL_DEPENDENCY | No¹ | Yes | |
| `STRIPE_PRICE_STARTER`/`PRO`/`ENTERPRISE` | VAR | No¹ | Yes | Identifiers, not secrets |
| `RAZORPAY_KEY_ID` | EXTERNAL_DEPENDENCY (semi-public) | No¹ | Yes | Echoed client-side by design |
| `RAZORPAY_KEY_SECRET` | EXTERNAL_DEPENDENCY | No¹ | Yes | |
| `RAZORPAY_WEBHOOK_SECRET` | EXTERNAL_DEPENDENCY | No¹ | Yes | |
| `ADMIN_SECRET_KEY` | SECRET | No¹ | Yes | Gates `/api/v1/admin/*` |
| `UPI_ID`/`UPI_NAME`/`BANK_*` | VAR | No | Yes | Display-only, fallbacks in code |
| `DOWNLOAD_TOKEN_SECRET` | SECRET | No¹ | Yes | |
| `PRODUCTS_BUCKET` | VAR | No | No | Feeds dead-code path (see below) |
| `R2_ACCOUNT_ID`/`R2_ACCESS_KEY_ID`/`R2_SECRET_ACCESS_KEY` | **DEPRECATED** | No | No | `getS3Client()` is confirmed dead code — `aws-sdk` not a declared dependency, always fails regardless |
| `AWS_ACCESS_KEY_ID`/`AWS_REGION`/`AWS_SECRET_ACCESS_KEY` | **DEPRECATED** | No | No | Same dead-code branch |
| `RESEND_API_KEY` | EXTERNAL_DEPENDENCY | No | No¹ | Degrades gracefully |
| `RESEND_AUDIENCE_ID`/`RESEND_FROM_EMAIL` | VAR | No | No¹ | |
| `CRON_SECRET` | SECRET | No | Only if `/api/cron/dispatch-intel` is ever exposed via this Worker | See `wrangler.jsonc`'s explicit non-goal: no Cron trigger this stage |
| `GITHUB_DISPATCH_TOKEN` | SECRET | No | Same conditional | |
| `GITHUB_REPO_OWNER`/`GITHUB_REPO_NAME` | VAR | No | Same conditional | Fallbacks in code |
| `GITHUB_TOKEN` | NOT_MIGRATED | No | No | Only read by `fetch-live-intel.js`, a standalone CLI script run by GitHub Actions, never by a Worker request |
| `NVD_API_KEY`/`OTX_API_KEY`/`SENTINEL_APEX_API_KEY`/`ANTHROPIC_API_KEY`/`AISEC_ANALYST` | NOT_MIGRATED | No | No | Content-pipeline CLI scripts, GitHub Actions only |
| `APEX_API_BASE` | VAR | No | Yes | URL, fallback in code |
| `APEX_BRIDGE_SECRET` | SECRET | No | Yes | **Missing from `ENVIRONMENT_VARIABLE_MATRIX.md`'s table** — see Discrepancies below |
| `NEXT_PUBLIC_BASE_URL` | VAR | No | Yes | Fallback in code |
| `NODE_ENV` | VAR | No | Yes (must be absent or `production`, never `development`) | Security-relevant — see "Urgent findings" below |
| `ALLOW_DEV_AUTH_BYPASS` | VAR | No | Yes (must be absent/`false`) | **Missing from `ENVIRONMENT_VARIABLE_MATRIX.md`'s table** — see Discrepancies below |
| `BACKUP_ENCRYPTION_KEY` | NOT_MIGRATED | No | No | `scripts/backup-customer-data.js`/`restore-customer-data.js`, CLI scripts run by GitHub Actions, never by a Worker request |
| 13 Python-only Blogger-pipeline variables | NOT_MIGRATED | No | No | `automation/config.py`, `os.environ.get()`, never touches `process.env` at all |

¹ *"No" for staging* reflects this migration's own "hosting migration
first" scoping: the first isolated `workers.dev` staging deployment is
meant to prove static hosting + the compatibility shim work, not to
exercise live payment/Redis/webhook functionality against real external
services from an unauthenticated, unapproved environment. A later,
separately-scoped staging pass that specifically wants to exercise those
flows would provision the relevant subset then.

## Discrepancies found this session against `ENVIRONMENT_VARIABLE_MATRIX.md`

That document (self-dated 2026-08-16, produced on a different branch —
`transformation/vercel-recovery-production-hardening`) is comprehensive
and remains the authoritative per-variable citation source, but two real
gaps were found by cross-checking it against current code:

1. **`APEX_BRIDGE_SECRET`** exists in code (`api/v1/billing.js:669,671`,
   an HMAC-signing guard for the cross-service call to
   `intel.cyberdudebivash.com`) and is documented in `.env.example`, but
   does not appear in the matrix's table. Notably, the matrix's own
   "Urgent findings" §2 describes the *problem* this variable solves
   (an unauthenticated outbound call) as if still open — the code already
   has the fix, the matrix was never updated to reflect it.
2. **`ALLOW_DEV_AUTH_BYPASS`** exists in code
   (`api/_lib/middleware.js:119`) and is documented in `.env.example`'s
   prose, but also does not appear in the matrix's table. The matrix's
   "Urgent findings" §1 *recommends* adding exactly this flag — the code
   now implements that recommendation.
3. **The matrix's claim that `.env.example` covers only "13 of 42"
   variables is stale.** Git history shows `.env.example` was rewritten
   to be comprehensive in a later commit (`2a71980f8`, "docs: Vercel
   account migration runbook + complete .env.example (#74)") than the one
   that produced the matrix (`e512140a1`) — the matrix's own recommended
   fix appears to have been carried out, but the descriptive text was
   never revised to match. Current `.env.example` covers essentially all
   44 variables.

Recommendation: `ENVIRONMENT_VARIABLE_MATRIX.md` should get a small
revision pass adding these two rows and correcting the coverage claim —
noted here rather than silently fixed, since that document belongs to a
different, prior investigation and editing it is outside this Cloudflare
migration task's scope.

## Urgent findings carried forward (still open, not Cloudflare-specific)

From `ENVIRONMENT_VARIABLE_MATRIX.md`'s own "Urgent findings" section,
restated here because they affect what "production required" means above:

1. `NODE_ENV === 'development'` (combined with Redis being unreachable)
   triggers a synthetic pro-tier auth bypass — now also gated on the
   second, explicit `ALLOW_DEV_AUTH_BYPASS` flag per the matrix's own
   recommendation (implemented in code, per Discrepancy #2 above). Both
   must be confirmed absent/false in any staging or production Cloudflare
   environment variable set.
2. `BACKUP_ENCRYPTION_KEY` and its sibling backup secrets were, per
   `RUNBOOKS.md`, never provisioned as of that document's writing — not
   something this Cloudflare migration can or should fix (it's a GitHub
   Actions secret, `NOT_MIGRATED` above), but worth carrying forward as a
   live cross-cutting risk independent of this migration's own scope.

## Minimum secrets for first staging deployment

Per this migration's own scoping (footnote ¹ above): **none.** The first
isolated `workers.dev` staging deployment (see
`STAGING-DEPLOYMENT-PLAN.md`) exercises static hosting, routing, header
parity, and the compatibility shim's own logic — none of which requires a
single real secret. Every `process.env.X` read resolving to `undefined`
and each handler failing closed exactly as documented is the *expected,
correct* staging behavior for this stage, not a blocker.
