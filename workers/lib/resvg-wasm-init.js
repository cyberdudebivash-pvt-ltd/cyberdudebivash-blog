'use strict';

/**
 * Lazily initializes @resvg/resvg-wasm exactly once per isolate/process
 * and returns its Resvg class. Used unconditionally by api/og.js on both
 * platforms during the migration window — @resvg/resvg-wasm's Resvg API
 * (new Resvg(svg, opts).render().asPng()) is identical to the native
 * @resvg/resvg-js this replaces (confirmed against its .d.ts), so this is
 * the one runtime dependency swap the OG-image route needs, not a
 * rewrite. Native @resvg/resvg-js cannot be used at all under Workers —
 * its .node binaries have no loader and can't be bundled (confirmed via
 * a real `wrangler deploy --dry-run` failure, not assumed).
 *
 * initWasm() may only be called once per process — a second call throws
 * "Already initialized". A Worker isolate is reused across requests, so
 * this must be memoized, not called per-request.
 *
 * Node reads the .wasm file directly off the real disk in node_modules
 * (no equivalent under Workers — no filesystem). Workers needs a genuine
 * WebAssembly.Module, supplied via setWasmModule() before the first
 * request — workers/entry.js's own top-level `import wasmModule from
 * '@resvg/resvg-wasm/index_bg.wasm'` is what Wrangler's bundler resolves
 * to a real precompiled Module (that import can't live in this
 * CommonJS file — it would break Node's require() of it).
 *
 * KNOWN LIMITATION even with a genuine Module supplied here: see
 * workers/entry.js's comment. initWasm() still fails at request time
 * under Workers with "Wasm code generation disallowed by embedder" — a
 * documented, widely-reported platform restriction (not specific to
 * this file's import mechanism, confirmed by directly checking
 * `instanceof WebAssembly.Module` before ruling that out), not yet
 * resolved. getResvg() below still throws in that case, on purpose —
 * api/og.js's caller already has a correct, verified fallback for
 * exactly this failure mode, so this file does not need its own.
 */

const { initWasm, Resvg } = require('@resvg/resvg-wasm');
const { isCloudflareWorkers } = require('../../api/_lib/runtime-env');

let workersWasmModule = null;
let initPromise = null;

function setWasmModule(mod) {
  workersWasmModule = mod;
}

async function getResvg() {
  if (!initPromise) {
    initPromise = isCloudflareWorkers()
      ? initWasm(workersWasmModule)
      : initWasm(require('fs').readFileSync(require.resolve('@resvg/resvg-wasm/index_bg.wasm')));
  }
  await initPromise;
  return Resvg;
}

module.exports = { getResvg, setWasmModule, isCloudflareWorkers };
