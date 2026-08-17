'use strict';

/**
 * Loads api/og.js's 3 Inter font weights, branching on the same
 * isCloudflareWorkers() check as resvg-wasm-init.js, for the same
 * reason: the loading MECHANISM genuinely differs per platform, not just
 * the byte source. Workers has no filesystem, so fs.readFileSync (the
 * existing, unchanged Vercel/Node path) cannot run there. Getting the
 * bytes on Workers needs a static ESM import of each .woff file (which
 * wrangler.jsonc's `rules` maps to a Data module, resolved to an
 * ArrayBuffer at build time) — a CommonJS require('*.woff') looks
 * equivalent but produces a runtime require() call Workers can't
 * satisfy, same failure mode confirmed for the .wasm loader in
 * resvg-wasm-init.js. That static import lives in the sibling
 * og-fonts-bytes.mjs, reached here via a dynamic import() (valid inside
 * CommonJS) only on the Workers branch — which makes this function
 * async on both platforms now, so api/og.js must await it.
 */

const { isCloudflareWorkers } = require('../../api/_lib/runtime-env');

let cache = null;

async function loadFontsForRuntime() {
  if (cache) return cache;

  if (isCloudflareWorkers()) {
    const bytes = (await import('./og-fonts-bytes.mjs')).default;
    cache = [
      { name: 'Inter', data: bytes.interRegular, weight: 400, style: 'normal' },
      { name: 'Inter', data: bytes.interBold, weight: 700, style: 'normal' },
      { name: 'Inter', data: bytes.interExtraBold, weight: 800, style: 'normal' },
    ];
  } else {
    const fs = require('fs');
    const path = require('path');
    const FONT_DIR = path.join(__dirname, '..', '..', 'api', '_lib', 'fonts');
    cache = [
      { name: 'Inter', data: fs.readFileSync(path.join(FONT_DIR, 'Inter-Regular.woff')), weight: 400, style: 'normal' },
      { name: 'Inter', data: fs.readFileSync(path.join(FONT_DIR, 'Inter-Bold.woff')), weight: 700, style: 'normal' },
      { name: 'Inter', data: fs.readFileSync(path.join(FONT_DIR, 'Inter-ExtraBold.woff')), weight: 800, style: 'normal' },
    ];
  }

  return cache;
}

module.exports = { loadFontsForRuntime };
