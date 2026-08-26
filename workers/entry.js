/**
 * Cloudflare Worker entry point. wrangler.jsonc's `main` points here.
 *
 * Deliberately thin: Wrangler needs an ES module (`export default { fetch
 * }`) to recognize a Module Worker, but that syntax can't be require()'d
 * by plain Node — so it can't live in a file this repo's own node:test
 * suite needs to load directly. All real routing/dispatch logic lives in
 * workers/lib/router.js (CommonJS) instead, tested there. This file is
 * bundled by Wrangler/esbuild, which resolves the require() below and
 * the ESM export together — not run under Node's CJS loader in
 * production.
 *
 * The top-level `import` of the .wasm file lives here rather than behind
 * a require()/dynamic import() in a CommonJS module — this is the file
 * Wrangler's bundler resolves it from into a real precompiled
 * WebAssembly.Module (wrangler.jsonc's `rules` entry is required for
 * this — Data/Text/CompiledWasm module types have no zero-config
 * default, confirmed against Cloudflare's own docs after a real
 * `wrangler dev` failure without it).
 *
 * PLATFORM SUPPORT vs. PACKAGE COMPATIBILITY — do not conflate these.
 * Workers DOES support WebAssembly: the supported model is a precompiled
 * WebAssembly.Module resolved at build time (exactly what the static
 * import above produces and what workers/lib/resvg-wasm-init.js's
 * setWasmModule() receives — verified directly via an
 * `instanceof WebAssembly.Module` check, not assumed, before ruling out
 * an import-mechanism bug). What Workers restricts is *compiling* new
 * Wasm from raw bytes at request time, which is a deliberate, documented
 * platform security boundary, not a missing feature.
 *
 * The actual finding is narrower: @resvg/resvg-wasm's own initWasm()
 * still fails at request time — "Wasm code generation disallowed by
 * embedder" — even when handed a genuine precompiled Module. That is a
 * PACKAGE-level incompatibility with the tested Workers execution model
 * (this specific package's internal init path, on the version pinned
 * here), not evidence that Workers can't run WebAssembly generally.
 * Other WASM packages hit the same symptom for their own internal
 * reasons (github.com/cloudflare/workers-sdk#1366,
 * cloudflare/next-on-pages#704, prisma#28657) — cited as prior art that
 * this class of failure is real and known, not as proof this package's
 * specific cause is identical to theirs.
 *
 * Decision for this migration: B — INTENTIONAL STATIC OG FALLBACK, not
 * further experimentation toward dynamic rendering. api/og.js's existing
 * render-failure fallback (302 to the static /og-image.png) already
 * handles this correctly — verified via a real local Workerd HTTP
 * request: 302 status, correct Location, correct Cache-Control, no 500.
 * Dynamic OG rendering is classified INTENTIONALLY-CHANGED in
 * VERCEL-CLOUDFLARE-PARITY-MATRIX.md, not PASS. Revisit only if
 * @resvg/resvg-wasm ships a fix verified against this exact runtime, or
 * a different renderer is evaluated — not by continuing to retry this
 * one.
 */
const { handleFetch, handleScheduled } = require('./lib/router');
const { setWasmModule } = require('./lib/resvg-wasm-init');
import wasmModule from '@resvg/resvg-wasm/index_bg.wasm';

setWasmModule(wasmModule);

export default {
  async fetch(request, env) {
    return handleFetch(request, env);
  },
  // wrangler.jsonc's triggers.crons entry is now populated (Cloudflare-
  // Only Alert Runtime tranche -- see handleScheduled()'s own doc in
  // lib/router.js for the full authorization trail). Still not provably
  // LIVE from this codebase's own evidence: this export only actually
  // gets invoked once an operator with real Cloudflare credentials runs
  // `wrangler deploy` from an authenticated account, which this sandbox
  // does not have (`wrangler whoami` -> not authenticated). Exporting it
  // costs nothing at runtime either way; Cloudflare simply never calls it
  // until that deploy happens.
  async scheduled(controller, env, ctx) {
    return handleScheduled(controller, env, ctx);
  },
};
