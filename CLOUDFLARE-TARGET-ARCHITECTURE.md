# Cloudflare Target Architecture

What the Cloudflare Workers implementation of `blog.cyberdudebivash.in`
actually is, structurally — required by Stage 4 Section 19. Describes the
architecture as built and CLAUDE-VERIFIED through Stages 3–4, not a
proposal.

## High-level shape

```
Request
  │
  ▼
Cloudflare edge (Worker isolate)
  │
  ▼
workers/entry.js  ── thin ESM entry, wrangler.jsonc's `main`
  │  - static top-level `import wasmModule from '@resvg/resvg-wasm/index_bg.wasm'`
  │    (must be top-level for Wrangler's bundler to resolve it to a real
  │    precompiled WebAssembly.Module — see wrangler.jsonc's CompiledWasm rule)
  │  - passes (request, env) straight to workers/lib/router.js
  ▼
workers/lib/router.js#handleFetch(request, env)
  │
  ├─► workers/lib/route-table.js#resolveRoute(pathname)
  │     classifies the request as one of:
  │       - blocked            (BLOCKED_PREFIXES match → dynamic 404)
  │       - redirect           (REDIRECTS table → manual Response, not
  │                              Response.redirect(), whose headers are
  │                              spec-immutable)
  │       - asset               (ASSET_REWRITES → env.ASSETS.fetch() on a
  │                              rewritten path, e.g. /feed → /rss.xml,
  │                              / → /index.html)
  │       - handler (pretty)   (PRETTY_URL_REWRITES → a DIRECT_API_HANDLERS
  │                              entry with synthesized query params)
  │       - handler (direct)   (DIRECT_API_HANDLERS / DYNAMIC_API_HANDLERS
  │                              exact-path lookup)
  │       - no match           → passthrough to env.ASSETS.fetch()
  │                              (genuinely static content, or a static 404)
  │
  ├─► workers/lib/node-compat.js  (only for the `handler` branches)
  │     - toNodeRequest(request, handlerConfig): builds a Node-shaped
  │       {method, url, headers, query, body} from the Web-standard Request
  │       - bodyParser !== false: JSON/form/text parsing with a typed
  │         isBodyParseError, and MAX_BODY_BYTES=4.5MB (Vercel-parity)
  │         enforced incrementally via the body's own ReadableStream reader
  │       - bodyParser === false (the 2 webhook routes): raw bytes only,
  │         signature verification happens against the exact untouched
  │         payload
  │       - cf-connecting-ip overwrites x-forwarded-for before the
  │         unmodified app-layer getIp() ever runs (client-IP trust model)
  │     - createNodeResponse(): the reverse direction — collects
  │       res.status()/json()/send()/end()/setHeader() calls into a real
  │       Web-standard Response
  │
  ├─► the ORIGINAL, UNMODIFIED api/** handler
  │     `module.exports = async (req, res) => {...}` — Vercel's own
  │     calling convention, completely unaware it's running in a Worker.
  │     This is the core of the migration's compatibility strategy: port
  │     the platform boundary, not the application code.
  │
  └─► workers/lib/security-headers.js#applyBaselineHeaders(response)
        Applied to every response router.js itself produces (handler
        dispatch, redirects, blocked-404) — NOT to the ASSETS-passthrough
        case, which gets its headers from dist-public/_headers instead.
        "Set only if absent": HSTS, X-Content-Type-Options, Referrer-
        Policy, Permissions-Policy, Cache-Control (added this session —
        see VERCEL-CLOUDFLARE-PARITY-MATRIX.md §2), and CSP+X-Frame-
        Options together (only if the handler set neither).
```

## Static assets

`env.ASSETS` binding → `dist-public/`, built by
`scripts/build-cloudflare-assets.js` (allowlist-first — see
`STATIC-ASSET-MANIFEST.md`). `wrangler.jsonc`'s `assets.html_handling:
"none"` matches `vercel.json`'s `cleanUrls: false`; the resulting loss of
Cloudflare's native `/`→`index.html` resolution is restored at the
route-table level (`ASSET_REWRITES`), not by reverting the flag (which
would reintroduce a much larger regression across 5,000+ `.html` pages).

## Runtime detection

`api/_lib/runtime-env.js#isCloudflareWorkers()` — the single shared check
(`navigator.userAgent === 'Cloudflare-Workers'`, Cloudflare's own
documented detection idiom) every fs/`__dirname`-dependent module branches
on: `api/_lib/intel.js`, `workers/lib/threat-graph.js`,
`api/_lib/ioc-canonical.js`, `api/_lib/detection-rules.js`. Workers branch:
build-time `require('*.json')` (esbuild bundles it, no fs call, no TTL
cache needed — already-parsed data). Node/Vercel branch: unchanged
`fs.readFileSync`.

## OG image rendering

`workers/lib/resvg-wasm-init.js` + `workers/lib/og-fonts-init.js`:
platform-branched WASM/font initialization. Both platforms use
`@resvg/resvg-wasm` (not the native `@resvg/resvg-js`, whose `.node`
binaries cannot be bundled for Workers at all — confirmed via a real
`wrangler deploy --dry-run` failure). Workers-specific: the WASM module
comes from `workers/entry.js`'s top-level import; `@resvg/resvg-wasm`'s
own `initWasm()` fails at request time regardless
(`VERCEL-CLOUDFLARE-PARITY-MATRIX.md`'s OG row) — `api/og.js`'s existing
render-failure fallback (302 → `/og-image.png`) handles this correctly.

## `process.env` / secrets

No explicit bridging code exists anywhere in this repository (confirmed by
a full-codebase grep, zero `process.env` references in `workers/**`).
`nodejs_compat` (`wrangler.jsonc`'s `compatibility_flags`) auto-populates
`process.env` from whatever `vars`/`secrets` are bound to the Worker —
confirmed empirically this session via a live synthetic-secret round-trip
test, not just inferred from Cloudflare's docs. See
`ENVIRONMENT-MIGRATION-MATRIX.md` for the full variable inventory.

## What is deliberately absent from this architecture today

- Any GitHub Actions workflow step that runs `wrangler deploy` — confirmed
  zero matches for `wrangler|cloudflare` across every `.github/workflows/*.yml`.
  Cloudflare deployment is 100% local/human-triggered at this stage.
- Any `wrangler.jsonc` `routes`, `custom_domains`, KV/D1/R2/Queue bindings,
  or `triggers.crons` — see `wrangler.jsonc`'s own trailing comment and the
  Wrangler Config Safety Audit in the final readiness report.
- A `scheduled()` handler — GitHub Actions remains the authoritative
  scheduler; see Section 11's decision, carried into
  `VERCEL-CLOUDFLARE-PARITY-MATRIX.md`.

## Why this design (not a rewrite)

The alternative — rewriting every `api/**` handler against Cloudflare's
native `fetch(request, env)` signature — would have meant re-verifying
correctness for the entire application surface (auth, billing, webhooks,
intelligence, workbench) simultaneously with the platform migration
itself. The compatibility-shim approach (`node-compat.js`) instead keeps
100% of the original, already-production-tested handler code unmodified,
confining the migration's actual risk surface to the shim layer itself —
which is exactly what Stages 3–4's real-Workerd testing has been
certifying end-to-end.
