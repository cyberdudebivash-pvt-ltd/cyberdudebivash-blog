'use strict';

/**
 * Loads api/og.js's 3 Inter font weights, branching on the same
 * isCloudflareWorkers() check as resvg-wasm-init.js, for the same
 * reason: the loading MECHANISM genuinely differs per platform, not just
 * the byte source. Workers has no filesystem, so fs.readFileSync (the
 * existing, unchanged Vercel/Node path) cannot run there — but a plain
 * require('*.woff') can't run under Node either (no loader for that
 * extension), so this can't be unified into one require() call either.
 * Wrangler's [[rules]] config (wrangler.jsonc) maps .woff to a Data
 * module, so require()'ing one under a Workers bundle resolves to an
 * ArrayBuffer at build time — satori's fonts option accepts that
 * directly, same shape as the Buffer fs.readFileSync already returns.
 */

const { isCloudflareWorkers } = require('./resvg-wasm-init');

let cache = null;

function loadFontsForRuntime() {
  if (cache) return cache;

  if (isCloudflareWorkers()) {
    cache = [
      { name: 'Inter', data: require('../../api/_lib/fonts/Inter-Regular.woff'), weight: 400, style: 'normal' },
      { name: 'Inter', data: require('../../api/_lib/fonts/Inter-Bold.woff'), weight: 700, style: 'normal' },
      { name: 'Inter', data: require('../../api/_lib/fonts/Inter-ExtraBold.woff'), weight: 800, style: 'normal' },
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
