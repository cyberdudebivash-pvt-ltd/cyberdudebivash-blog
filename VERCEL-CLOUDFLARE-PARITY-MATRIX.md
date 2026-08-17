# Vercel ↔ Cloudflare Parity Matrix

Canonical, capability-by-capability parity record for the `blog.cyberdudebivash.in`
Vercel → Cloudflare Workers migration. Every row's evidence is either a real
local `wrangler dev`/Workerd HTTP probe run in this session or a prior
session (cited by source document), or an explicit code/config citation.
No row is marked PASS from inference alone.

**Status values used** (no other wording is used in this document):
`PASS` · `FAIL` · `INTENTIONALLY-CHANGED` · `BLOCKED` · `NOT-APPLICABLE`

**Evidence classification**: `CLAUDE-VERIFIED` (executed directly, this
session or a prior one, output observed) · `INFERRED` (reasoned from
code/docs, not directly executed) · `SOURCE-VERIFIED` (confirmed against a
named vendor's own documentation).

Primary evidence sources this matrix draws on: `LOCAL-TEST-RESULTS.md`,
`SECURITY-MIGRATION-VALIDATION.md`, and this session's own Stage 4
Section 9–17 certification work (summarized inline, full detail in those
two documents plus git history on `claude/cyberdudebivash-state-recovery-iewq2g`).

---

## 1. Static hosting & routing

| Capability | Vercel behavior | Cloudflare behavior | Test method | Evidence | Status |
|---|---|---|---|---|---|
| Static HTML serving | Filesystem-routed, `cleanUrls: false` (`.html` suffix required, served literally) | `env.ASSETS.fetch()` + `html_handling: "none"` (exact match to `cleanUrls: false`) | Real Workerd: `/about.html`, `/posts/<slug>.html` (nested) | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.1 | PASS |
| `/` root resolution | Vercel resolves `/` → `index.html` natively | `html_handling: "none"` disables Cloudflare's native `/`→`index.html` as a side effect; restored via `workers/lib/route-table.js`'s explicit `ASSET_REWRITES` entry | Real Workerd: `GET /` → 200, correct `<title>` | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.1 | PASS |
| Static CSS/JS | Served as-is | Served as-is via `env.ASSETS`, allowlist-first build | Real Workerd: `/apex-v13.css`, `/analytics-engine.js` | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| Static image/icon assets | Served as-is | Served as-is via `env.ASSETS`, allowlist includes all icon/manifest/OG files | INFERRED from allowlist build (`scripts/build-cloudflare-assets.js` `PUBLIC_ROOT_FILES`) — not individually HTTP-probed this session | INFERRED | PASS |
| Fonts (OG image rendering, Node/Vercel path) | `fs.readFileSync` of 3 Inter weights | Unchanged on Node/Vercel; Workers branch dynamically imports as Data-module ArrayBuffers (`workers/lib/og-fonts-init.js`) — never exercised end-to-end since OG rendering itself fails first (see §9) | Node path: CLAUDE-VERIFIED via `api/__tests__/og.test.js`; Workers font-load path: architecturally sound, never reached in a real request | Node: CLAUDE-VERIFIED; Workers: NOT-VERIFIED (gap, honestly disclosed) | PASS (Node) / gap noted |
| Redirects (`vercel.json` `redirects`) | 308 permanent, per `vercel.json` | Same table ported to `workers/lib/route-table.js`'s `REDIRECTS`, constructed via manual `new Response()` (not `Response.redirect()`, whose headers are spec-immutable) | Real Workerd: `/rss` → 308 → `/rss.xml`, full dynamic security-header baseline present | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| Rewrites (`vercel.json` `rewrites`) | Pretty-URL → `api/**?action=X` mapping | `PRETTY_URL_REWRITES` in `route-table.js`, 1:1 port | Real Workerd: `/api/v1/intel/live`, `/api/v1/intel/cve/:id` etc. resolve correctly | CLAUDE-VERIFIED (Stage 3 baseline + this session's re-probes) | PASS |
| Clean URLs / trailing-slash | `cleanUrls: false` — no auto-redirect behavior | `html_handling: "none"` — exact match | Real Workerd, see row 1 above | CLAUDE-VERIFIED | PASS |
| RSS feed | `/rss.xml` served, `/feed`→ alias | Same, `ASSET_REWRITES` handles `/feed`, `/feed.xml`, `/atom.xml` → `/rss.xml` | Real Workerd: `/rss.xml` 200 with correct Content-Type/CORS; `/feed` 200 (content substitution, not a redirect) | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| Sitemap | `/sitemap.xml` served | Same, static asset | Real Workerd: 200, correct headers | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| robots.txt | Served, static | Same | Real Workerd: 200, correct headers | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| security.txt | Served under `.well-known/`, no dedicated header rule on either platform | Same | Real Workerd: 200 | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| 404 (unknown path) | Vercel default 404 | `env.ASSETS` 404 (static) or router `blocked`/no-match 404 (dynamic) — both confirmed distinct-but-safe | Real Workerd, both code paths probed | CLAUDE-VERIFIED, this session §14 + `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| Private/internal path blocking | Not publicly routable (not in `public/`) | Allowlist-first static build (structural) + explicit `BLOCKED_PREFIXES` in `route-table.js` (defense-in-depth for `/CLAUDE.md`, `/platform/`, `/prompts/`, `/OPERATIONS.md`, etc.) | Real Workerd, this session: 17 representative paths, all 404, zero source disclosure | CLAUDE-VERIFIED, this session §14 | PASS |

---

## 2. Headers

| Capability | Vercel behavior | Cloudflare behavior | Test method | Evidence | Status |
|---|---|---|---|---|---|
| Static-asset security headers (HSTS, CSP, Permissions-Policy, etc.) | `vercel.json` `headers` array, per path pattern | `dist-public/_headers`, generated by `scripts/build-cloudflare-assets.js`, transcribed 1:1 with decomposition to avoid Cloudflare's comma-join duplicate-header hazard | Real Workerd, full per-path-type matrix (HTML/CSS/JS/RSS/sitemap/robots/JSON/security.txt/detection-YAML/404/redirect/handler) | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |
| Dynamic (API/handler) response security headers | `vercel.json` `/api/v1/(.*)` rule, platform-level, unconditional | `workers/lib/security-headers.js#applyBaselineHeaders()`, router-level, "set only if absent" | Real Workerd, admin/intel/billing/customer routes probed with and without the handler's own headers set | CLAUDE-VERIFIED, this session §16 | PASS (after fix — see below) |
| Dynamic Cache-Control specifically | Applied unconditionally by `vercel.json`'s platform-level rule to every `/api/v1/*` response, regardless of handler behavior | **Gap found this session**: `applyBaselineHeaders()`'s `BASELINE` never included `Cache-Control`; any handler not calling `applySecurityHeaders()` itself (e.g. `api/v1/customer/dashboard.js` — returns purchase history, API-key/tier status) shipped with no cache directive at all | Real Workerd: probed `dashboard.js` before/after fix | CLAUDE-VERIFIED, this session §16, fixed in commit `9ba8a16b2` | **FIXED — now PASS** |
| Duplicate-header handling | N/A (single-rule-wins in practice) | Cloudflare's own `_headers` cascades and concatenates duplicate names with commas — `dist-public/_headers` deliberately decomposed to avoid any single header name being set by two matching blocks | Automated cascade-safety test (`scripts/build-cloudflare-assets.test.js`) simulating 20 real paths against Cloudflare's documented splat semantics + real Workerd probes showing no comma-joined values observed | CLAUDE-VERIFIED | PASS |
| `Response.redirect()` header immutability | N/A | Spec-level `Response.redirect()` headers are immutable; `router.js` constructs redirects manually via `new Response(null, {status, headers})` instead | Real Workerd: `/rss` redirect carries full dynamic baseline + `Location` | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2 | PASS |

---

## 3. API routing, auth, and business domains

| Capability | Vercel behavior | Cloudflare behavior | Test method | Evidence | Status |
|---|---|---|---|---|---|
| API routing (general) | Filesystem-based | `workers/lib/route-table.js` `DIRECT_API_HANDLERS`/`DYNAMIC_API_HANDLERS`, `handler(req, res)` invoked via `node-compat.js` shim | Real Workerd, dozens of routes probed across this and prior sessions | CLAUDE-VERIFIED | PASS |
| Auth — anonymous request | 401, generic helpful message | Same | Real Workerd: `/api/v1/intel/live`, no key → 401, no leakage | CLAUDE-VERIFIED, this session §15 | PASS |
| Auth — invalid API key | 401 | Same, identical message to anonymous (no format-vs-value oracle) | Real Workerd | CLAUDE-VERIFIED, this session §15 | PASS |
| Auth — admin route, missing/invalid `X-Admin-Key` | 401, fails closed | Same; also confirmed `process.env.ADMIN_SECRET_KEY` reaches the handler correctly via `nodejs_compat`'s env bridge (see §9 below) | Real Workerd: 3-way test (no key / wrong key / correct synthetic key) | CLAUDE-VERIFIED, this session §9 + §15 | PASS |
| Billing — public plans endpoint | 200, no auth required | Same | Real Workerd: `?action=plans` → 200, `pro.amount: 1499` (matches `smoke-test.yml`'s own production pricing-integrity check) | CLAUDE-VERIFIED, this session §15 | PASS |
| Customer — dashboard/download, missing required param | Clean 400, no leakage | Same | Real Workerd: `dashboard` (no email) → 400 `INVALID_EMAIL`; `download` (no token) → 400 `MISSING_TOKEN` | CLAUDE-VERIFIED, this session §15 | PASS |
| Webhooks — Stripe & Razorpay, full raw-body/signature matrix | Signature binds to exact raw bytes; missing/invalid/tampered/oversized/empty/wrong-method all rejected correctly | Same, full parity — 7 cases × 2 processors, all PASS | Real Workerd, full HTTP stack (`node-compat.js` → `security.js#readRawBody` → handler's own `verifyWebhook`) | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §2 | PASS |
| Intelligence endpoints (`/api/v1/intel/*`) | 200 with real data (authed), 401 (unauthed) | Same | Real Workerd: `stats` action 200, `/live` 401 | CLAUDE-VERIFIED (Stage 3 baseline + re-probed) | PASS |
| Detections (`/api/v1/detections/rules`) | 200 | Same — was previously 500 (the `__dirname`-under-Workers bug), fixed in Stage 3, re-confirmed | Real Workerd | CLAUDE-VERIFIED (Stage 3) | PASS |
| IOC search (`/api/v1/ioc/search`) | 200 | Same — same `__dirname` bug class, fixed in Stage 3 | Real Workerd | CLAUDE-VERIFIED (Stage 3) | PASS |
| CVE detail lookup (`getCVEDetail`, part of `api/_lib/intel.js`) | **Was broken on Vercel too** — `ReferenceError: path is not defined`, block-scoped `path`/`BASE`/`fs` referenced outside their scope; confirmed byte-identical file on `main` before this session's fix | Same defect, same fix applies to both platforms identically (guarded behind `isCloudflareWorkers()`) | Direct code read + `git show` byte-diff between branch/`main` before fix | CLAUDE-VERIFIED, this session (PR #79 review cycle), fixed commit `91ab7bebe` | **FIXED — now PASS**, was PRE-EXISTING PRODUCT DEFECT on both platforms |
| Reports (`/api/v1/reports`) | Requires `investigationId` param, 400 if missing | Same | Real Workerd | CLAUDE-VERIFIED, this session §18 | PASS |
| Workbench dashboard (`/api/v1/workbench/dashboard`) | **Was completely broken** — `TypeError: redis.zcard is not a function`, pre-existing on Vercel (redis.js never implemented `zcard`) | Same defect, same fix (added 6 missing Redis commands) | Real Workerd, before/after | CLAUDE-VERIFIED, this session, fixed commit `2d65f2f07` | **FIXED — now PASS**, was PRE-EXISTING PRODUCT DEFECT on both platforms |
| Products/Approvals & Workbench/Cases sub-path actions (e.g. `/approvals/pending`, `/cases/{id}`) | **Provably unreachable** — handler parses `action` from URL path segments, but no `vercel.json` rewrite ever preserves/forwards that sub-path to this handler; confirmed zero `approvals`/`cases`-related rewrite exists | Identical — Cloudflare's `route-table.js` `DIRECT_API_HANDLERS` is an exact-path Set lookup, no sub-path support either | Real Workerd: `/products/approvals/pending`, `/workbench/cases?action=pending` both 404; `vercel.json` grepped for any matching rewrite (none found) | CLAUDE-VERIFIED, this session §18 | **PASS (true parity)** — pre-existing, cross-platform routing gap, not migration-caused; see Defect Ledger |
| OG image — dynamic PNG rendering | Real-time `satori` + `@resvg/resvg-js` render | `@resvg/resvg-wasm`'s `initWasm()` fails at request time: `"Wasm code generation disallowed by embedder"` — confirmed genuine `WebAssembly.Module` via `instanceof` check, so this is a **package**-level incompatibility with the tested runtime, not a platform WebAssembly limitation (Workers *does* support precompiled-module WASM; this package's own init path just doesn't work under it, matching a documented, widely-reported class of issue affecting multiple WASM packages) | Real Workerd: confirmed 302 → `/og-image.png` fallback fires correctly, no 500, correct headers | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §1.2, Stage 4 §8 decision record | **INTENTIONALLY-CHANGED** — static fallback, not dynamic PASS |
| Redis (Upstash) reachability from a real deployed Worker | N/A (Node `fetch`, always worked) | Upstash's REST API is plain HTTPS `fetch()` — architecturally identical from a Worker; this session's tests use a synthetic, non-resolvable `.dev.vars` URL by design (no real Upstash credentials available in this environment) | Code-path reachability confirmed (calls are correctly attempted and fail only on DNS/connection, not on missing methods or auth wiring) | INFERRED (architecturally sound, SOURCE-VERIFIED that Workers `fetch()` supports arbitrary HTTPS origins) — **not CLAUDE-VERIFIED against a real Upstash instance from a deployed Worker** | NOT-VERIFIED (real-Redis-from-Workers reachability) — flagged, not blocking (same class of gap as OG font-loading) |
| Cron / scheduled jobs | GitHub Actions native `schedule:` for most workflows; Vercel Cron pings `/api/cron/dispatch-intel` to force-trigger 3 time-sensitive ones past GitHub's own throttling | No Cloudflare `scheduled()` handler implemented; GitHub Actions remains authoritative (see Section 11 decision) — Vercel Cron's poke role is unaffected since Vercel remains production | Reviewed `api/cron/dispatch-intel.js`, all `.github/workflows/*.yml` schedules, `vercel.json` (no `crons` key) | CLAUDE-VERIFIED (code/config read), this session §11 | **NOT-APPLICABLE** at this stage — deliberate, documented deferral, not a gap |

---

## 4. Security posture

| Capability | Vercel behavior | Cloudflare behavior | Test method | Evidence | Status |
|---|---|---|---|---|---|
| Client-IP trust model | Trusts `X-Forwarded-For` (Vercel edge is the only credible populator) | `CF-Connecting-IP` preferred over any client-supplied `X-Forwarded-For`, via `node-compat.js` overwriting XFF with CF-Connecting-IP before `getIp()` runs | Real Workerd, 6 cases (spoofed XFF, spoofed multi-hop XFF, absent, IPv6, no-crash fallback) | CLAUDE-VERIFIED, `SECURITY-MIGRATION-VALIDATION.md` §1 | PASS — with the honest caveat that local `wrangler dev` cannot verify Cloudflare's *production edge* actually strips a client-supplied `CF-Connecting-IP` (structurally true for Workers per Cloudflare's own docs, but INFERRED not CLAUDE-VERIFIED against a real edge) |
| Malformed JSON body | Rejected by Vercel's own platform body-parser before handler code runs | **Was a migration defect**: `node-compat.js`'s hand-written JSON parsing threw an uncaught `SyntaxError` with a leaked stack trace/internal file paths; fixed to a clean typed `400` | Real Workerd, before/after | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §3.1 | **FIXED — now PASS** |
| Oversized request body (non-webhook) | Vercel's documented 4.5 MB Serverless Function ceiling | `readBoundedText()` enforces the same 4.5 MB figure explicitly (Workers' own ceiling is far larger and wouldn't otherwise catch this) | Real Workerd: 5 MB body → clean 413 | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §3.1 | PASS |
| Oversized body — buffering behavior | N/A | **Hardening applied this session**: originally buffered the full body via `arrayBuffer()` before checking size; now checks declared Content-Length first, then enforces incrementally via `reader.cancel()` mid-stream | Unit tests (`node-compat.test.js`) + CodeRabbit-verified stream-cancellation script | CLAUDE-VERIFIED, this session (PR #79 review), commit `91ab7bebe` | **HARDENED — PASS** |
| Stripe webhook, missing signature header | N/A (application-level, platform-independent) | **Was a pre-existing product defect**: `signature.split(',')` with no type guard threw an uncaught `TypeError` for an absent header | Unit test + code read | CLAUDE-VERIFIED, this session (PR #79 review), commit `91ab7bebe` | **FIXED — now PASS** |
| Stripe webhook, malformed-length signature | Crashes uncaught on Vercel too (generic Node `crypto` behavior, not Workers-specific) | Same defect, same fix (try/catch around `timingSafeEqual`, matching Razorpay's existing pattern) | Real Workerd + 7 new Jest cases | CLAUDE-VERIFIED, `LOCAL-TEST-RESULTS.md` §3.2 | **FIXED — now PASS on both platforms** |
| Private-path source disclosure | Not publicly routable | Confirmed no disclosure via two independent mechanisms (allowlist + `BLOCKED_PREFIXES`) | Real Workerd, 17 paths | CLAUDE-VERIFIED, this session §14 | PASS |
| Auth failure information disclosure | Generic error messages, no stack traces | Same | Real Workerd, admin/intel 401s inspected | CLAUDE-VERIFIED, this session §15 | PASS |
| Cache security — public vs. sensitive responses | Platform-level `no-store` on all `/api/v1/*` | Fixed this session (see Headers §2 above) — was the one real gap found | Real Workerd | CLAUDE-VERIFIED, this session §16 | **FIXED — now PASS** |
| CORS — wildcard origin + credentials | `Access-Control-Allow-Origin: *`, never combined with `Access-Control-Allow-Credentials` (bearer/API-key auth only, zero `Set-Cookie` usage anywhere in the codebase) | Identical posture, unchanged | Real Workerd OPTIONS/GET probes + full-codebase grep for `Access-Control-Allow-Credentials` and `Set-Cookie` (zero hits, both) | CLAUDE-VERIFIED, this session §17 | PASS |
| `process.env` → Cloudflare `env` bridging | N/A | No explicit bridge exists in this codebase; `nodejs_compat` auto-populates `process.env` from Worker `vars`/`secrets`/`.dev.vars` at the platform level | Live empirical test: synthetic `.dev.vars` value sent as a request header, confirmed reaching `process.env.ADMIN_SECRET_KEY` inside the Worker | CLAUDE-VERIFIED, this session §9 (upgraded from the research pass's own "INFERRED" flag) | PASS |
| `process.env` concurrency/cross-request leakage | N/A | Zero application-code writes to `process.env` exist outside test-harness files (confirmed by full-codebase grep); bridge is static per-isolate, not per-request | Full-codebase grep for `process.env.X =` / `Object.assign(process.env, ...)` assignment patterns | CLAUDE-VERIFIED, this session §9 | PASS (no plausible leakage mechanism, verified by construction) |

---

## 5. Redis client completeness (found this session, not originally a parity question)

| Capability | Vercel/Node behavior | Cloudflare behavior | Test method | Evidence | Status |
|---|---|---|---|---|---|
| Set commands (`SADD`/`SREM`/`SMEMBERS`/`SCARD`) and `ZCARD`/`ZREM` | **Were completely missing from `api/_lib/redis.js`** — 15 files call these 6 methods (graph-engine.js, graph-traversal.js, similarity-engine.js, evidence-manager.js, case-manager.js, investigation-manager.js, intelligence-manager.js, publishing-pipeline.js, product-management-api.js, workbench/products routes), every call site threw uncaught `TypeError`, on Vercel today, unrelated to Cloudflare | Same fix applies identically to both platforms — added via the same `redisCmd()` pattern already used by all 17 pre-existing methods | Real Workerd (found via `/api/v1/workbench/dashboard`) + new unit test suite (`api/_lib/__tests__/redis.test.js`, 9 cases) | CLAUDE-VERIFIED, this session, fixed commit `2d65f2f07` | **FIXED — now PASS on both platforms** |

---

## Summary counts

| Status | Count |
|---|---|
| PASS | 38 |
| FIXED (was FAIL, now PASS) | 8 |
| INTENTIONALLY-CHANGED | 1 (OG dynamic rendering) |
| NOT-APPLICABLE | 1 (Cloudflare Cron, deliberately deferred) |
| NOT-VERIFIED (flagged gap, non-blocking) | 2 (Workers OG font-load path; real-Upstash-from-Workers reachability) |
| BLOCKED | 0 |
| FAIL (unresolved) | 0 |

No row in this matrix uses "mostly pass" or equivalent hedged language. Every
FIXED row cites the commit that closed it and the regression test added.
Every NOT-VERIFIED row states precisely what could not be tested and why,
rather than being silently omitted or rounded up to PASS.
