# Pre-Migration Forensics — Vercel → Cloudflare

Phase 0 deliverable for the Vercel-elimination / Cloudflare-migration program.
Produced 2026-08-16 on branch `claude/cyberdudebivash-state-recovery-iewq2g`,
repo `cyberdudebivash-pvt-ltd/cyberdudebivash-blog`. Every claim below is
anchored to a file path (and line number where useful) as it exists in this
repository at the time of writing. Nothing here was inferred from a
Cloudflare dashboard, API, or CLI session — see §1.

**Relationship to existing documents** (Single Source of Truth — this doc
does not repeat their content, it references it):
- `VERCEL_MIGRATION_INVENTORY.md` is the canonical, already-complete
  inventory of `vercel.json`, `.vercelignore`, `vercel-ignore-build.sh`, the
  serverless function surface, and the un-declared cron gap. Read that
  document first; this one assumes it.
- `ENVIRONMENT_VARIABLE_MATRIX.md` is the canonical inventory of all ~43
  environment variables, their consumers, and secret-domain split
  (Vercel project vars vs. GitHub Actions secrets).
- This document's unique contribution: **what specifically must change in
  the application code and CI to run on Cloudflare Workers/Pages instead of
  Vercel**, and **what this session can and cannot verify about the target
  Cloudflare environment**.

---

## 1. Session capability boundary — read this first

This session has **zero Cloudflare access**, confirmed directly rather than
assumed:

- `npx wrangler whoami` → `You are not authenticated.` No cached OAuth
  session, no `CLOUDFLARE_API_TOKEN`, no `CLOUDFLARE_ACCOUNT_ID` in the
  environment (`env | grep -i cloudflare` and `env | grep -i '^CF_'` both
  empty).
- No Cloudflare/Workers/Pages/Wrangler MCP tool is registered in this
  session (checked via tool search — none found).

**Consequence**: every fact in this document about the *target* Cloudflare
account — what Workers/Pages projects already exist there, what routes or
custom domains are already bound, current plan tier, existing DNS records,
whether a Worker or route name would collide with another CYBERDUDEBIVASH
platform — is `NOT VERIFIED` and cannot become verified without one of:

1. Cloudflare API credentials (scoped API token + account ID) provided to
   this session, or
2. The user running the equivalent inventory commands themselves and
   sharing the output back into this repo/conversation.

Everything else in this document is git-verifiable and does not depend on
that access.

---

## 2. Runtime dependency compatibility (`package.json`)

Six declared runtime dependencies, all reviewed for Workers-runtime
(V8 isolate, no native addons, no real filesystem) compatibility:

| Package | Version | Compatible as-is? | Notes |
|---|---|---|---|
| `zod` | `^3.22.0` | Yes | Pure JS, no I/O |
| `uuid` | `^9.0.0` | Yes | Pure JS |
| `js-yaml` | `5.2.2` | Yes | Pure JS |
| `marked` | `18.0.7` | Yes | Pure JS |
| `satori` | `0.29.0` | Yes | Zero declared dependencies (verified via `npm view satori dependencies`); designed for edge use |
| `@resvg/resvg-js` | `2.6.2` | **No** | Native Rust addon via napi-rs — cannot load in a Workers isolate |

**De-risking finding**: `@resvg/resvg-wasm@2.6.2` exists as a real,
same-maintainer, same-version, WASM-compiled sibling package (confirmed via
`npm view`). It is the direct drop-in replacement for the Workers port —
this is not a dead end requiring a different rendering library entirely,
just an import swap plus WASM-instantiation handling. Scope of the actual
call site is narrow: `api/og.js` uses exactly three calls —
`new Resvg(svg, { fitTo: { mode: 'width', value: 1200 } })` →
`.render()` → `.asPng()` (around lines 154–165).

`api/og.js` also does filesystem font loading that has no Workers
equivalent and must be re-architected, not just swapped:

```
api/og.js:25   const fs = require('fs');
api/og.js:26   const path = require('path');
api/og.js:28   const FONT_DIR = path.join(__dirname, '_lib', 'fonts');
```

Workers have no runtime filesystem. Fonts must instead be bundled as
imported binary assets (or served through the Workers Static Assets /
`ASSETS` binding and fetched at request time) — this is a known, standard
pattern for Workers + Satori, not a novelty, but it is a real code change
to `api/og.js`, not a config change.

---

## 3. Node-specific request/response API surface

Grep sweep of every file under `api/` (excluding `__tests__`), counting
usage of Node's `IncomingMessage`/`ServerResponse`-style API that Vercel's
Node runtime exposes as `req`/`res`, versus the Web-standard `Request`/
`Response` objects Cloudflare Workers' `fetch` handler uses instead:

| Pattern | Occurrences |
|---|---|
| `req.body` | 202 |
| `req.method` | 153 |
| `req.query` | 122 |
| `req.url` | 20 |
| `req.headers` | 18 |
| `req.on` (stream events) | 6 |
| `req.socket` | 2 |
| `req.destroy` | 1 |
| `res.setHeader(` | 101 |
| `res.status(` | 88 |
| `res.json(` | 15 |
| `res.end(` | 3 |
| `res.send(` | 2 |
| `res.set(` | 1 |

(A handful of these are false-positive matches on unrelated local variables
named `res`; the counts above are the raw grep totals, not a filtered
audit — treat as an upper-bound scale indicator, not an exact API-call
count.)

**Interpretation**: the volume (`req.body`/`req.query`/`res.status`/
`res.json` in the hundreds) means a full manual rewrite of every handler to
native `Request`/`Response` is not the right approach — the correct pattern
is a thin **compatibility shim** at the Worker entry point that constructs
a Node-`req`/`res`-shaped object from the incoming Web `Request` (populating
`.body`, `.query`, `.method`, `.headers` as plain objects/strings, and a
`res` object whose `.status()`/`.json()`/`.setHeader()`/`.end()` methods
accumulate into a real `Response` returned to the Workers runtime) and
hands that to the *existing, unmodified* handler functions. This preserves
Level 4 (Reuse) and Level 5 (Minimal Change Surface) from the Engineering
Decision Order — it means the ~30 route handlers under `api/v1/**` and
`api/og.js`/`api/cron/dispatch-intel.js` do not need to be individually
rewritten, only wrapped.

## 4. Filesystem / Node-global usage outside `api/og.js`

Nine files reference `fs`, `path`, `__dirname`, or `__filename`:

- `api/og.js` (fonts — see §2)
- `api/_lib/detection-rules.js`
- `api/_lib/customer-deliverables-engine.js`
- `api/_lib/pipeline-health-certification.js`
- `api/_lib/intelligence-hub.js`
- `api/_lib/threat-graph.js`
- `api/_lib/campaign-engine.js`
- `api/_lib/ioc-canonical.js`
- `api/_lib/intel.js`

`NOT VERIFIED` in this pass: whether each of these reads static data
(candidate for bundled-import or `ASSETS`-binding replacement) or writes/
appends (e.g. `pipeline-health-certification.js` — recall
`pipeline-health-history.json` is `.gitignore`'d, suggesting local
disk-state that has no Workers equivalent at all and may need a KV/R2-backed
rewrite, not just an import swap). Each of these 9 files needs individual
review before the Phase 4/5 porting work is scoped precisely; this document
identifies them, it does not yet classify them.

## 5. Raw-body stream reads (webhook HMAC verification)

The Node `IncomingMessage` stream-event pattern
(`req.on('data'/'end'/'error')`) — fundamentally incompatible with
Workers' `Request.text()`/`.arrayBuffer()` Web Streams model — is not
scattered across the codebase. It is centralized in exactly one helper:

```
api/_lib/security.js:348   function readRawBody(req, maxBytes = 262144) { ... }
api/_lib/security.js:368   exports.readRawBody = readRawBody;
```

with exactly two call sites, both webhook signature-verification handlers:

```
api/v1/billing/webhook.js:26            rawBody = await sec.readRawBody(req);
api/v1/billing/razorpay-webhook.js:32   rawBody = await sec.readRawBody(req);
```

This narrows the Phase 4 req/res-adapter risk considerably: the adapter
does not need to emulate Node stream events generally — it only needs
`readRawBody` itself reimplemented (or branched) to call
`await request.text()` / `await request.arrayBuffer()` when running under
the Workers shim, since raw, unparsed bytes are required for HMAC
signature verification and must not be JSON-parsed first. Both call sites
already isolate this correctly (raw body read before any JSON parsing),
which is what makes a localized fix possible instead of a rewrite.

## 6. Routing and header complexity (`vercel.json`)

Already fully inventoried in `VERCEL_MIGRATION_INVENTORY.md` §2. The
Cloudflare-specific risk this document adds: **Cloudflare Pages' native
`_redirects`/`_headers` file syntax is materially simpler than Vercel's
`vercel.json` and cannot express query-string-producing rewrites**
(e.g. `/api/v1/intel/live` → `/api/v1/intel?action=live`, one of ~20 such
rules). Cloudflare's `_redirects` supports path-to-path rewrites and
splats, but not composing a new query string from a path segment the way
`vercel.json`'s `rewrites` does.

**Consequence**: the 27-rule rewrite table cannot be ported as static
config. It needs to become routing logic inside a Worker (or Pages
Function) that inspects the incoming path and either (a) dispatches
directly to the already-existing handler with a constructed `query` object
— consistent with the req/res-shim approach in §3, so this is additive to
that work, not a separate mechanism — or (b) issues an internal
`fetch`/subrequest. The 8 header blocks (CORS, CSP, HSTS, cache-control,
per-path) likewise need to be applied by the same Worker rather than a
static `_headers` file, because several are path-pattern-scoped in ways
that mirror the routing logic already being built.

**Security-relevant behavior that must be preserved exactly, not
approximately** (flagging per Section 9 of the Engineering Constitution —
these are functional security controls, not cosmetic):
- The `blocked-404` rewrites for `/CLAUDE.md`, `/Sentinel-APEX/:path*`,
  `/eito/:path*`, `/platform/:path*`, `/prompts/:path*`, and three named
  `.md` files. `VERCEL_MIGRATION_INVENTORY.md` §3 records that two of
  these paths were previously live and Google-indexed before this
  protection existed — regressing this in the port would be a repeat of a
  known prior incident, not a new risk.
- The path-scoped CSP/CORS/security-header sets in `vercel.json:17-113`
  (`default-src 'none'` on the API surface; the explicit script/connect-src
  allowlists on HTML pages).
- HMAC webhook signature verification (§5) — must verify against
  byte-identical raw body pre-parse on both Stripe and Razorpay paths.

## 7. CI/CD touchpoints referencing Vercel (6 of 19 workflows)

| Workflow | Reference | Action needed for full elimination |
|---|---|---|
| `security-audit.yml:103-111` | Parses `vercel.json` directly to validate security headers exist | Must be repointed at wherever headers live post-migration (Worker source or a new config file), or it will silently stop validating anything real |
| `smoke-test.yml:28,31,83` | Waits ~90s for "Vercel deployment" to settle; error message points at Vercel logs | Update wait strategy and error message for Cloudflare's (typically faster) propagation model |
| `sentinel-apex.yml:5` | Comment: 15-min interleave chosen relative to Vercel's measured build time | Cadence itself is a bot-content-freshness decision, not a technical constraint under Cloudflare — flagging as a possible future relaxation, not changing it in this pass (would be a behavior change requiring separate authorization) |
| `blogger-syndication.yml:13` | Comment: cadence reduced specifically to conserve Vercel deployment quota | Same as above — the underlying constraint (Vercel Hobby 100 deploys/day) goes away on Cloudflare, but relaxing cadence is out of scope unless explicitly requested |
| `ai-security-intel.yml:6-8` | Comment: cron aligned to `vercel-ignore-build.sh`'s deploy window | `vercel-ignore-build.sh` itself becomes dead code once Vercel is fully decommissioned (Phase 15) — deprecate per the repo's Deprecation Instead of Deletion policy, do not delete silently |
| `backup-customer-data.yml:14,18` | Comment: required secrets "exist today only as Vercel [project env vars]" | Already tracked in `ENVIRONMENT_VARIABLE_MATRIX.md` — these need a Cloudflare-side secret store equivalent (Workers secrets / `wrangler secret put`) as part of Phase 3 environment migration |

No workflow calls the Vercel CLI or API directly — deployment itself is
100% Vercel's native git-push auto-deploy (confirmed in
`VERCEL_MIGRATION_INVENTORY.md` §1/§4). This means CI changes for the
migration are about **validation and timing assumptions**, not about
removing deploy-trigger logic — there is no Vercel deploy step in any
workflow to delete.

---

## 8. What remains unknown, and why

Everything below requires either Cloudflare account access this session
does not have, or a decision only the account owner can make:

- Whether a Worker or Pages project named `cyberdudebivash-blog` (or any
  colliding name/route) already exists on the target Cloudflare account.
- Current plan tier and its limits (Workers request/CPU-time limits,
  concurrent script count, KV/R2 usage against any existing platforms on
  the same account) — directly relevant to whether the 8
  `vercel.json`-declared functions' `maxDuration`/`memory` budgets
  (10–20s, 128–512MB) fit inside Workers' CPU-time model, which is billed
  and limited differently than Vercel's wall-clock/memory model.
  `NOT VERIFIED` without account access.
  - **Known-risk exception, verifiable without account access**: PNG
    generation (`api/og.js`, currently `memory: 512, maxDuration: 15`) is
    the one route whose workload profile (image rasterization) is large
    enough relative to typical Workers CPU-time limits to warrant explicit
    load testing once staging exists — flagging now so Phase 6 scopes a
    real test for this route specifically rather than assuming parity.
- Existing DNS configuration for `blog.cyberdudebivash.in` and every other
  CYBERDUDEBIVASH domain sharing the account, needed to prove the
  "infrastructure collision report" the migration program's Phase 1
  requires — cannot be honestly produced from this repository alone.
- Whether other CYBERDUDEBIVASH platforms already deployed to this
  Cloudflare account use Workers, Pages, or both, and what routing pattern
  they occupy (needed to pick an isolated route/subdomain for staging that
  provably does not collide).

## 9. Recommended immediate next step

This document completes the repo-side half of Phase 0. The account-side
half (Cloudflare inventory) is blocked on §1 and needs an explicit decision
on how this session obtains — or does not obtain — Cloudflare account
visibility before Phase 1 (infrastructure collision report) can be produced
honestly rather than guessed. See the accompanying chat response for the
proposed options.
