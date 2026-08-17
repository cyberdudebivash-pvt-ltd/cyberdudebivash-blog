# LOCAL-TEST-RESULTS.md

**Scope:** Real, local-only Cloudflare Workers runtime certification for the
`blog.cyberdudebivash.in` migration. Every result below was produced by an
actual `wrangler dev` process on `127.0.0.1:8787` and real `curl` requests —
never a Node-only mock, and never a request against any remote Cloudflare
resource. No `wrangler deploy` (with or without `--dry-run` excepted, see
below) was ever run against a real target; no DNS, route, or production
binding exists to deploy to at this stage (see `wrangler.jsonc`'s own header
comment and `CLOUDFLARE-ACCOUNT-INVENTORY.md`).

Evidence classification used throughout: **CLAUDE-VERIFIED** (I ran the
command/request myself, in this session, and observed the output quoted
below) vs. **INFERRED** (reasoned from docs or code reading, not directly
executed). Anything not marked is CLAUDE-VERIFIED.

Environment for this pass: `wrangler 4.123.0`, local Workerd, `dist-public/`
built fresh via `node scripts/build-cloudflare-assets.js` immediately before
testing, synthetic secrets only via a local, gitignored `.dev.vars` (never
committed — see `.gitignore`'s `.dev.vars` entry).

---

## 1. Static + dynamic HTTP header parity (Stage 4 Sec3–Sec5)

### 1.1 Root-path regression found and fixed during this pass

`wrangler.jsonc`'s `assets.html_handling: "none"` is required so that
`/posts/foo.html`-style literal paths serve at 200 instead of Cloudflare's
default `auto-trailing-slash` 307-redirecting them to `/posts/foo` (this
breaks `vercel.json`'s `cleanUrls: false` parity across every `posts/**`,
`cve/**`, and other `PUBLIC_DIRS` page — 5000+ files).

**Newly discovered side effect of that same flag:** `html_handling: "none"`
also disables Cloudflare's automatic `/` → `index.html` resolution, not just
the `.html`-suffix redirect behavior.

| Request | With default `html_handling` | With `html_handling: "none"` |
|---|---|---|
| `GET /` | `200` | **`404`** (bug) |
| `GET /index.html` | `200` | `200` |
| `GET /about.html` | `307` → `/about` (the original bug) | `200` |

Root cause isolated by toggling the flag and restarting `wrangler dev`
between runs (not assumed from docs). Fixed by adding an explicit
`ASSET_REWRITES` entry in `workers/lib/route-table.js` (`"/"` → `/index.html`,
content substitution via the existing `{type:'asset'}` mechanism already
proven by the pre-existing `/feed → /rss.xml` alias — no new mechanism
introduced). Re-verified after the fix:

```
GET /                                        -> 200 (index.html content, correct <title>)
GET /about.html                              -> 200
GET /posts/<real-post>.html (nested)         -> 200
```

### 1.2 Header parity matrix (per-path-type, real observed headers)

`dist-public/_headers` — Wrangler's own parser confirms **`✨ Parsed 9 valid
header rules.`** on every `wrangler dev` start in this pass (zero rejected
rules).

| Path type | Example | Status | Headers confirmed present (real response) | Notes |
|---|---|---|---|---|
| HTML (root) | `/` | 200 | HSTS, CSP (full allowlist), Permissions-Policy, X-Frame-Options, Referrer-Policy, X-Content-Type-Options, X-DNS-Prefetch-Control, Cache-Control `public, max-age=3600, stale-while-revalidate=86400` | Matches `vercel.json`'s `/(.*).html` + catch-all union exactly |
| HTML (root file) | `/about.html` | 200 | same set as above | |
| HTML (nested) | `/posts/<slug>.html` | 200 | same set as above | Confirms the `/*.html` splat matches across `/` path separators, not just top-level files — not assumed from Cloudflare's docs alone, confirmed by this exact request |
| CSS | `/apex-v13.css` | 200 | `Cache-Control: public, max-age=600, stale-while-revalidate=86400`; `Content-Type: text/css; charset=utf-8` (Cloudflare's own default — no override set, matching `vercel.json`, which doesn't override CSS Content-Type either) | |
| JS | `/analytics-engine.js` | 200 | `Content-Type: application/javascript; charset=UTF-8`; `Cache-Control: public, max-age=600, stale-while-revalidate=86400` | **Confirms `_headers` CAN override Content-Type for a static asset** — resolves a documented uncertainty (Cloudflare's own docs don't state this explicitly). The capitalization of `charset=UTF-8` matches the explicit override, not Cloudflare's own lowercase `charset=utf-8` default (seen on the CSS/JSON-without-override cases below) — corroborating evidence this is really the override taking effect, not a coincidental default |
| RSS | `/rss.xml` | 200 | `Content-Type: application/rss+xml; charset=UTF-8`; `Cache-Control: public, max-age=3600, stale-while-revalidate=86400`; `Access-Control-Allow-Origin: *` | Exact match to `vercel.json` |
| Sitemap | `/sitemap.xml` | 200 | `Content-Type: application/xml; charset=UTF-8`; `Cache-Control: public, max-age=3600`; ACAO `*` | Exact match |
| robots.txt | `/robots.txt` | 200 | `Content-Type: text/plain; charset=UTF-8`; `Cache-Control: public, max-age=86400` | Exact match |
| Static JSON (ruled) | `/api/intel/top-threats.json` | 200 | `Content-Type: application/json; charset=UTF-8`; ACAO `*`; `Access-Control-Allow-Methods: GET, OPTIONS`; `Cache-Control: public, max-age=600, stale-while-revalidate=3600`; `X-Powered-By: CYBERDUDEBIVASH SENTINEL APEX v4.0` | Exact match to `vercel.json`'s `/api/(.*).json` block |
| Static JSON (deliberately un-ruled) | `/search-index.json`, `/live-intel.json` | 200 | Only the global 5-header baseline; Cloudflare's own default `Content-Type: application/json` (no charset) + `Cache-Control: public, max-age=0, must-revalidate` | **Deliberate.** `vercel.json`'s `/api/(.*).json` pattern only matches paths starting with `/api/` — these two root-level files already only hit its catch-all on Vercel today. Matching that is parity; inventing a new rule would not be |
| security.txt (un-ruled) | `/.well-known/security.txt` | 200 | Global baseline only; Cloudflare default `Content-Type: text/plain; charset=utf-8` | `vercel.json` has no dedicated rule either |
| Detection-rule YAML (un-ruled) | `/detections/rules/<slug>.yml` | 200 | Global baseline only; Cloudflare default `Content-Type: text/yaml; charset=utf-8` | Served exclusively via `<a download>` in `detections/index.html` — Content-Type is moot, the browser saves the file regardless |
| Missing asset | `/this-path-does-not-exist-xyz123` | 404 | Global 5-header baseline only (no CSP/Permissions-Policy — not `.html`-suffixed) | Matches `vercel.json`: a 404 isn't `.html`-suffixed so its html-specific block never applied there either |
| Dynamic asset alias | `/feed` | 200 | Same as `/rss.xml` (content substitution, not a redirect — browser stays on `/feed`) | |
| Redirect | `/rss` | 308 | Full **dynamic** baseline from `workers/lib/security-headers.js` (HSTS, CSP `default-src 'none'`, Permissions-Policy, Referrer-Policy, X-Content-Type-Options, X-Frame-Options) + `Location: /rss.xml` | Confirms the `Response.redirect()` immutable-headers fix (manual `new Response(...)` construction in `router.js`) works end-to-end in real Workerd, not just in `node:test` |
| Handler, unauthed | `/api/v1/admin?action=pending` (no `X-Admin-Key`) | 401 | App-layer CORS/Cache-Control/X-Powered-By (from `middleware.js`, unchanged) **+** the dynamic baseline's additions (CSP, Permissions-Policy, HSTS) — the "set-if-absent" merge confirmed live, not just in isolated unit tests | Body: `{"success":false,"error":{"code":"UNAUTHORIZED",...}}` |
| Handler, malformed | `/api/v1/admin` (no `action`) | 400 | same header blend | Body: `{"error":{"code":"MISSING_ACTION",...}}` — proves the real handler executes end-to-end through the whole `toNodeRequest`/`createNodeResponse` pipeline with no crash and no special env vars required just to reach validation |
| OPTIONS, dynamic handler | `/api/v1/intel` | 204 | Full CORS preflight header set from `middleware.js`, unchanged | Dynamic (handler-routed) OPTIONS works correctly |
| OPTIONS, static asset | `/api/intel/top-threats.json` | **405** | `_headers`' JSON rule block still applies (ACAO, ACAM, Content-Type, etc.) even on the 405 | **Cloudflare's static asset server does not itself answer OPTIONS successfully — see §1.3** |

No comma-joined/duplicated header value was observed on any request in this
pass (the specific failure mode `dist-public/_headers`' rule decomposition
was designed to avoid — see that file's own header comment). Cross-checked
against an automated cascade-safety test (`scripts/build-cloudflare-
assets.test.js`, `describe('_headers cascade safety')`) that simulates
Cloudflare's documented splat-matching rules against 20 representative real
paths and asserts no header name is set by more than one matching block.

### 1.3 Static-asset OPTIONS gap (documented, not fixed — low risk)

Cloudflare's static asset server answers `OPTIONS /api/intel/*.json` with
`405 Method Not Allowed`, not `200`/`204`. `vercel.json` declares
`Access-Control-Allow-Methods: GET, OPTIONS` for this pattern, implying
OPTIONS support was anticipated, but I have no direct evidence of Vercel's
own actual behavior for an OPTIONS preflight against a *static* file under
that pattern (untested — this repo has no live Vercel deployment to probe
in this environment). **INFERRED, not CLAUDE-VERIFIED:** this is very likely
inconsequential in practice — a CORS preflight is only sent by browsers for
"non-simple" requests (custom headers, non-simple content types); a plain
`fetch()` GET against a public JSON file with no custom headers never
triggers a preflight at all, and the actual GET response's
`Access-Control-Allow-Origin: *` (confirmed present and correct in §1.2) is
what browsers check for a simple cross-origin GET. No client-side code
in this repo was found sending a custom-header GET against `/api/intel/*`
(grep confirms no `fetch(...api/intel...)` call sets custom headers).
Documented here as a known platform behavior difference, not fixed, because
fixing it would require moving these files off the static-asset layer and
onto a Worker-routed handler — a larger architectural change than this
finding justifies. Revisit if a future client integration needs a real
preflight against this path.

---

## 2. Webhook raw-body certification (Stage 4 Sec6 — P0 BLOCKER)

Both `api/v1/billing/webhook.js` (Stripe) and
`api/v1/billing/razorpay-webhook.js` (Razorpay) were exercised through the
full real Worker HTTP stack — `wrangler dev` → `workers/entry.js` →
`workers/lib/router.js#dispatch()` → `workers/lib/node-compat.js#toNodeRequest()`
(the `bodyParser: false` / `__cfRequest` branch) →
`api/_lib/security.js#readRawBody()` (the Workers `arrayBuffer()` branch) →
the real handler's own signature verification (`api/_lib/stripe.js#verifyWebhook`,
`api/_lib/razorpay.js#verifyWebhookSignature`) — using synthetic secrets from
a local, gitignored `.dev.vars` file (`STRIPE_WEBHOOK_SECRET`,
`RAZORPAY_WEBHOOK_SECRET`), never real keys.

| # | Case | Stripe (`/api/v1/billing/webhook`) | Razorpay (`/api/v1/billing/razorpay-webhook`) | Verdict |
|---|---|---|---|---|
| 1 | Valid signature, well-formed body | `500 Webhook handler failed: Redis not configured` | `500 Webhook handler failed` | **PASS** — reached past signature verification into real business logic; failed only at the Redis dependency, which has no reachable instance in this local-only environment by design (see §3 of the Environment Migration Matrix, pending) |
| 2 | Invalid signature (garbage hex) | `400 Invalid signature` | `400 Invalid signature` | PASS |
| 3 | Body modified after signing (stale signature from the original body) | `400 Invalid signature` | `400 Invalid signature` | **PASS — the critical property.** Proves the signature genuinely binds to the exact raw bytes; an attacker who intercepts and modifies a webhook body cannot replay it with the original signature |
| 4 | Signature header missing entirely | `400 Missing Stripe-Signature` | `400 Missing X-Razorpay-Signature` | PASS |
| 5 | Empty body (0 bytes), signature computed for empty string | `400 Invalid JSON` | `400 Invalid JSON` | PASS — signature check itself passes (proves the empty-body read path doesn't hang or throw), fails cleanly at JSON parse as expected |
| 6 | Oversized body (300,157 bytes, over the 262,144-byte `readRawBody` limit), signature technically valid for that exact oversized body | `413 Payload too large or unreadable` | `413 Payload too large or unreadable` | PASS — size limit enforced regardless of signature validity |
| 7 | Wrong HTTP method (`GET`) | `405` | `405` | PASS |

**Finding, not a defect:** the Workers branch of `readRawBody()`
(`req.__cfRequest.arrayBuffer()`) buffers the entire request body into
memory before checking it against `maxBytes`, whereas the Node/stream branch
rejects incrementally per-chunk via `req.destroy()`. Functionally both paths
correctly reject an oversized payload (confirmed in case 6 above); the
Workers path is simply less memory-efficient while doing so, bounded by
Workers' own platform-level request body size ceiling (far larger than this
handler's 256 KB business limit) — not a correctness gap for a low-frequency
webhook endpoint. No code change made; documented for completeness per
Stage 4 Sec20's migration-defect-vs-pre-existing-defect discipline (this is
neither — it's an accepted, bounded platform characteristic).

**Verdict: Stage 4 Sec6 P0 BLOCKER — CLEARED.** Two real defects were found
and fixed while producing this certification (§3) — the P0 boundary itself
(signature binds to exact raw bytes, rejects oversized/tampered/missing-
signature requests) was already correct on first real-HTTP certification;
what broke was error handling on malformed *input* to these and other
endpoints.

---

## 3. Defects found and fixed during this certification pass (Stage 4 Sec7/Sec20)

Both were found by sending deliberately-malformed input through the real
Worker HTTP stack while producing §1–2 above — neither was reachable by
reasoning about the code alone; both reproduced as raw, uncaught-exception
500s with leaked internal file paths before the fix, confirmed as clean
4xx JSON responses after.

### 3.1 MIGRATION DEFECT — malformed JSON crashed with a leaked stack trace

**Classification: MIGRATION DEFECT.** `workers/lib/node-compat.js`'s
`toNodeRequest()` is new code this migration introduced to reproduce, by
hand, the JSON body-parsing Vercel's platform already does automatically
for every non-`bodyParser:false` route. It called `JSON.parse(text)` with
no try/catch. On Vercel, malformed JSON never reaches handler code at all —
Vercel's own platform body-parser rejects it first. Here, the uncaught
`SyntaxError` propagated through `dispatch()` → `handleFetch()` → the
Worker's top-level `fetch()` (none of which had a catch), past
`applyBaselineHeaders()` entirely, and was caught only by Wrangler's own
dev-mode diagnostic middleware, which returned a raw stack trace —
including internal file paths (`workers/lib/node-compat.js:80:28`,
`workers/lib/router.js:71:15`, and Wrangler's own template paths) — as
`text/plain`, to any client that sent malformed JSON to any regular POST
endpoint (`/api/v1/newsletter`, `/api/v1/auth`, etc. — anything without
`bodyParser: false`).

**Fix:** `toNodeRequest()` now catches the parse failure and throws a
typed `{ isBodyParseError: true }` error; `router.js#dispatch()` catches
that specifically and returns a clean `400` matching
`api/_lib/middleware.js#apiError()`'s existing response shape
(`{error:{code,message}, meta:{...}}`) — the same contract every other
validation failure in this app already uses. Re-verified live:

```
POST /api/v1/newsletter, Content-Type: application/json, malformed body
  before: 500, Content-Type: text/plain, raw stack trace with file paths
  after:  400, Content-Type: application/json,
          {"error":{"code":"INVALID_JSON",...},"meta":{...}}
          + full security-headers.js baseline present
```

Also closed the same way: a request body over Vercel's own documented,
non-configurable 4.5 MB Serverless Function ceiling. Cloudflare Workers'
own platform ceiling is far larger (100 MB+ on Free/Pro, up to 500 MB on
Enterprise — confirmed against Cloudflare's own platform limits docs), so
without an app-level check, every non-webhook JSON/form/text handler would
silently accept bodies over 20x larger than they can ever receive on
Vercel today — a real increase in blast radius for a resource-exhaustion
attempt, not just a cosmetic gap. `readBoundedText()` (new, in
`node-compat.js`) enforces the same 4.5 MB figure Vercel already enforces,
throwing a typed `{ isBodyTooLargeError: true }` error that `dispatch()`
turns into a clean `413`:

```
POST /api/v1/newsletter, 5 MB JSON body
  before: (unbounded — would have been accepted and fully parsed)
  after:  413, {"error":{"code":"PAYLOAD_TOO_LARGE",...},"meta":{...}}
```

The two `bodyParser:false` webhook routes are unaffected by either change
— they never go through this code path (confirmed by a dedicated
regression test and re-verified live: a malformed-JSON body to
`/api/v1/billing/webhook` with a garbage signature still returns the
handler's own `400 Invalid signature`, from signature verification on the
raw bytes, before any JSON parsing is attempted).

### 3.2 PRE-EXISTING PRODUCT DEFECT — Stripe webhook signature check crashed on a short signature

**Classification: PRE-EXISTING PRODUCT DEFECT, not migration-introduced.**
`api/_lib/stripe.js#verifyWebhook()` is original, unmodified application
code, identical on Vercel today. Found while probing the webhook
certification in §2 with a deliberately-short `Stripe-Signature` value:

```
POST /api/v1/billing/webhook, Stripe-Signature: t=1,v1=deadbeef
  -> 500, text/plain, raw stack trace:
     TypeError: Input buffers must have the same byte length.
       at Object.timingSafeEqual (node:crypto:10:19)
       at Object.verifyWebhook (api/_lib/stripe.js:62:17)
       ...
```

`crypto.timingSafeEqual()` throws — rather than returning `false` — when
its two buffer arguments differ in byte length. `sig` (the `v1=` value) is
attacker-controlled from the request header; `expected` is always exactly
32 bytes (a fixed SHA-256 digest). Any request with a `v1=` value that
doesn't hex-decode to exactly 32 bytes throws here, uncaught — reachable
by anyone, with no valid webhook secret required. Because this is generic
Node.js `crypto` module behavior (not a Workers/`nodejs_compat` polyfill
difference), the identical crash is reachable on production Vercel today
against the same handler — hence PRE-EXISTING, not something this
migration introduced. What likely IS migration-specific is the raw stack
trace reaching the client at all (Vercel's runtime wrapper typically
sanitizes an uncaught exception in a Serverless Function before it reaches
the caller; this was not verified directly against a live Vercel
deployment in this environment — **INFERRED**, not CLAUDE-VERIFIED).

Its sibling, `api/_lib/razorpay.js#verifyWebhookSignature()`, already
wraps the identical `timingSafeEqual` call in a try/catch returning
`false` — this function was simply missing the guard its neighbor already
has. Fixed to match that existing, established pattern exactly (no new
defensive-coding convention introduced). Re-verified live:

```
POST /api/v1/billing/webhook, Stripe-Signature: t=1,v1=deadbeef
  after: 400, application/json, {"error":"Invalid signature"} + full
         security-headers.js baseline present
```

A valid, correctly-signed request was re-run immediately after this fix
and still resolves through signature verification correctly (`500 Redis
not configured` — the same expected, out-of-scope outcome documented in
§2's case 1), confirming the fix didn't change behavior for well-formed
requests.

New regression coverage: `api/_lib/__tests__/stripe-webhook-verify.test.js`
(7 Jest cases — valid signature, tampered body, wrong-value same-length
signature, short/malformed-length signature, invalid-hex signature,
missing `v1`, missing `t`); `workers/lib/node-compat.test.js` (+4 cases)
and `workers/lib/router.test.js` (+3 cases) for the JSON-parse/oversized-
body path.

---

## 4. Regression suite state at time of this pass

```
node --test workers/lib/*.test.js scripts/*.test.js scripts/publication-engine/*.test.js
  # 247 pass, 0 fail (240 before §3's new regression tests)

npx jest --silent
  # 1589 pass, 60 skipped, 0 fail (1582 before §3.2's stripe-webhook-verify.test.js)

npx wrangler deploy --dry-run
  # bundles cleanly, 8400 files in dist-public/ (wrangler's own asset-read
  # log line reports 8422 — a display/count discrepancy between wrangler's
  # internal accounting and this repo's own `find dist-public -type f | wc
  # -l`, not a missing-file or bundling failure; every specific path probed
  # in §1–2 above resolved correctly, so not investigated further)
```

No remote Cloudflare resource was created, modified, or queried in the
production of this document.
