'use strict';

/**
 * All Worker routing/dispatch logic, kept in plain CommonJS specifically
 * so it's requireable and unit-testable under plain Node (node:test)
 * without going through Wrangler/esbuild. workers/entry.js is a thin ESM
 * wrapper around handleFetch() below — Wrangler needs an ES module entry
 * (export default { fetch }) to recognize a Module Worker, but that
 * syntax can't be require()'d by Node directly, so the real logic lives
 * here instead of in the file Wrangler points main at.
 */

const { toNodeRequest, createNodeResponse } = require('./node-compat');
const { resolveRoute } = require('./route-table');
const { applyBaselineHeaders } = require('./security-headers');

// Static require() map, not a dynamic require(computedPath) — esbuild
// must see each module reference at build time to bundle it; a
// runtime-computed string would silently fail to bundle. Keys must be
// exactly route-table.js's DIRECT_API_HANDLERS ∪ DYNAMIC_API_HANDLERS
// handler paths — enforced by router.test.js's parity check against
// route-table.js, not just by hand-matching here.
const HANDLER_MODULES = {
  'api/og': () => require('../../api/og'),
  'api/cron/dispatch-intel': () => require('../../api/cron/dispatch-intel'),
  'api/v1/admin': () => require('../../api/v1/admin'),
  'api/v1/analysis/assessments': () => require('../../api/v1/analysis/assessments'),
  'api/v1/analysis/findings': () => require('../../api/v1/analysis/findings'),
  'api/v1/auth': () => require('../../api/v1/auth'),
  'api/v1/billing': () => require('../../api/v1/billing'),
  'api/v1/billing/razorpay-webhook': () => require('../../api/v1/billing/razorpay-webhook'),
  'api/v1/billing/webhook': () => require('../../api/v1/billing/webhook'),
  'api/v1/customer/dashboard': () => require('../../api/v1/customer/dashboard'),
  'api/v1/customer/download': () => require('../../api/v1/customer/download'),
  'api/v1/detections/rules': () => require('../../api/v1/detections/rules'),
  'api/v1/detections/rules/[id]': () => require('../../api/v1/detections/rules/[id]'),
  'api/v1/intel': () => require('../../api/v1/intel'),
  'api/v1/watchlists': () => require('../../api/v1/watchlists'),
  'api/v1/intelligence/confidence': () => require('../../api/v1/intelligence/confidence'),
  'api/v1/intelligence/correlations': () => require('../../api/v1/intelligence/correlations'),
  'api/v1/intelligence/graph': () => require('../../api/v1/intelligence/graph'),
  'api/v1/intelligence/objects': () => require('../../api/v1/intelligence/objects'),
  'api/v1/intelligence/publish': () => require('../../api/v1/intelligence/publish'),
  'api/v1/intelligence/similarity': () => require('../../api/v1/intelligence/similarity'),
  'api/v1/ioc/[id]': () => require('../../api/v1/ioc/[id]'),
  'api/v1/ioc/search': () => require('../../api/v1/ioc/search'),
  'api/v1/newsletter': () => require('../../api/v1/newsletter'),
  'api/v1/products/approvals': () => require('../../api/v1/products/approvals'),
  'api/v1/products/export': () => require('../../api/v1/products/export'),
  'api/v1/products/index': () => require('../../api/v1/products/index'),
  'api/v1/quality/index': () => require('../../api/v1/quality/index'),
  'api/v1/reports/index': () => require('../../api/v1/reports/index'),
  'api/v1/workbench/cases': () => require('../../api/v1/workbench/cases'),
  'api/v1/workbench/dashboard': () => require('../../api/v1/workbench/dashboard'),
  'api/v1/workbench/investigations': () => require('../../api/v1/workbench/investigations'),
  'api/v1/workbench/search': () => require('../../api/v1/workbench/search'),
};

async function dispatch(handlerPath, request, routeQuery) {
  const load = HANDLER_MODULES[handlerPath];
  if (!load) {
    // route-table.js resolved a handler this map doesn't know about — a
    // real bug (see router.test.js's parity check), not a client error.
    // Fail closed rather than guess.
    return new Response('Not Found', { status: 404 });
  }

  const handlerModule = load();
  const handler = typeof handlerModule === 'function' ? handlerModule : handlerModule.default;
  const handlerConfig = handlerModule.config;

  let req;
  try {
    req = await toNodeRequest(request, handlerConfig);
  } catch (err) {
    // Both branches match api/_lib/middleware.js#apiError()'s response
    // shape exactly -- the shared helper most handlers already use for
    // every other 4xx -- so these get the same contract as any other
    // validation failure instead of a platform-specific error page.
    if (err && err.isBodyParseError) {
      return applyBaselineHeaders(new Response(JSON.stringify({
        error: { code: 'INVALID_JSON', message: 'Request body is not valid JSON.' },
        meta:  { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      }), { status: 400, headers: { 'content-type': 'application/json' } }));
    }
    if (err && err.isBodyTooLargeError) {
      return applyBaselineHeaders(new Response(JSON.stringify({
        error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds the maximum allowed size.' },
        meta:  { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      }), { status: 413, headers: { 'content-type': 'application/json' } }));
    }
    throw err; // genuinely unexpected -- surface it, don't mask a real bug
  }
  req.query = { ...req.query, ...routeQuery };

  const { res, response } = createNodeResponse();
  await handler(req, res);
  return applyBaselineHeaders(await response);
}

/**
 * @param {Request} request
 * @param {{ ASSETS: { fetch(req: Request): Promise<Response> } }} env
 */
async function handleFetch(request, env) {
  const url = new URL(request.url);
  const route = resolveRoute(url.pathname);

  // Static-asset paths (no route match, or an explicit alias to another
  // static file) never pass through applyBaselineHeaders() — those are
  // genuinely static responses and get their security headers from
  // dist-public/_headers instead, not duplicated here. See security-
  // headers.js's header comment for why the two must stay separate.
  if (!route) {
    return env.ASSETS.fetch(request);
  }

  switch (route.type) {
    case 'blocked':
      return applyBaselineHeaders(new Response('Not Found', { status: 404 }));

    case 'redirect': {
      // Not Response.redirect(): per the Fetch spec, the Headers on a
      // Response.redirect() result have an "immutable" guard, so
      // applyBaselineHeaders()'s .set() calls throw on it (confirmed via
      // a real test failure, not assumed). Constructing the Response
      // directly gives a normal, mutable Headers object instead.
      const destination = new URL(route.to, url);
      return applyBaselineHeaders(new Response(null, {
        status: route.status,
        headers: { Location: destination.toString() },
      }));
    }

    case 'asset': {
      const assetUrl = new URL(route.path, url);
      return env.ASSETS.fetch(new Request(assetUrl, request));
    }

    case 'handler':
      return dispatch(route.handlerPath, request, route.query);

    default:
      return applyBaselineHeaders(new Response('Not Found', { status: 404 }));
  }
}

module.exports = { handleFetch, dispatch, HANDLER_MODULES };
