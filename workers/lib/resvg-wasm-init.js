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
 * The two branches below load the same .wasm bytes through the only
 * mechanism that actually works in each environment: Wrangler's bundler
 * resolves a require()'d .wasm file to a WebAssembly.Module at build
 * time (Cloudflare's documented pattern), which Node has no equivalent
 * for without --experimental-wasm-modules; Node instead reads the file
 * directly off the real disk in node_modules, which Workers has no
 * equivalent for (no filesystem). Both requires are string literals so
 * each bundler/loader can see them — see api/og.js's caller for why this
 * lives in its own CommonJS file rather than using a top-level ESM
 * import directly.
 */

const { initWasm, Resvg } = require('@resvg/resvg-wasm');

let initPromise = null;

function isCloudflareWorkers() {
  return typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';
}

async function getResvg() {
  if (!initPromise) {
    initPromise = isCloudflareWorkers()
      ? initWasm(require('@resvg/resvg-wasm/index_bg.wasm'))
      : initWasm(require('fs').readFileSync(require.resolve('@resvg/resvg-wasm/index_bg.wasm')));
  }
  await initPromise;
  return Resvg;
}

module.exports = { getResvg, isCloudflareWorkers };
