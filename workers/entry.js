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
 */
const { handleFetch } = require('./lib/router');

export default {
  async fetch(request, env) {
    return handleFetch(request, env);
  },
};
