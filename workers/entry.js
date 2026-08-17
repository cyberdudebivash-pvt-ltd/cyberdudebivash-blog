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
 * KNOWN LIMITATION, verified via a diagnostic instanceof check then
 * removed: even though `wasmModule` here genuinely is a
 * WebAssembly.Module (not raw bytes), @resvg/resvg-wasm's initWasm()
 * still fails at request time with "Wasm code generation disallowed by
 * embedder". This is a documented, widely-reported Cloudflare Workers
 * platform restriction affecting multiple WASM packages generally
 * (github.com/cloudflare/workers-sdk#1366, cloudflare/next-on-pages#704,
 * prisma#28657), not specific to this import mechanism, and not resolved
 * as of this writing. api/og.js's existing render-failure fallback (a
 * 302 to the static /og-image.png) already handles this gracefully and
 * correctly — verified via a real local Workerd HTTP request, not
 * assumed — which is an explicitly acceptable outcome for this stage,
 * not a bug to keep chasing blindly. Revisit if @resvg/resvg-wasm ships
 * a Workers-specific fix, or evaluate an alternative renderer, before
 * treating OG images as fully at parity on Cloudflare.
 */
const { handleFetch } = require('./lib/router');
const { setWasmModule } = require('./lib/resvg-wasm-init');
import wasmModule from '@resvg/resvg-wasm/index_bg.wasm';

setWasmModule(wasmModule);

export default {
  async fetch(request, env) {
    return handleFetch(request, env);
  },
};
