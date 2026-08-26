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
  'api/v1/notifications': () => require('../../api/v1/notifications'),
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

/**
 * Cloudflare Cron Trigger entry point (workers/entry.js's `scheduled`
 * export calls this). wrangler.jsonc's `triggers.crons` entry now exists
 * (Cloudflare-Only Alert Runtime tranche -- the operator has explicitly
 * authorized Cloudflare Workers as the production alert-delivery runtime,
 * see docs/audits/SENTINEL-APEX-CLOUDFLARE-ONLY-ALERT-RUNTIME-V1-
 * CERTIFICATION.md), superseding this comment's own prior "scheduling
 * authority is undecided" framing for this subsystem specifically. Still
 * not LIVE from this codebase's own evidence, though: this sandbox has no
 * authenticated Cloudflare account access (`wrangler whoami` -> not
 * authenticated, confirmed before writing this), so the config exists but
 * takes effect only once an operator with real credentials runs `wrangler
 * deploy` -- exactly the "code-complete configuration, not a live
 * trigger" distinction wrangler.jsonc's own header comment makes. The
 * real, already-live autonomous trigger today remains
 * .github/workflows/alert-delivery.yml's native GitHub Actions schedule
 * -- see that workflow's header for the retirement sequencing.
 *
 * Calls the exact same evaluateWatchedEntities()/processDueDeliveries()
 * functions the Node CLI scripts call -- one implementation of "what a
 * scheduled run does," reused here, not reimplemented for this runtime.
 * Bounded (each call's own internal batch/limit defaults apply) and
 * idempotent-safe (processDueDeliveries()'s atomic D1 claim/lease makes
 * this safe to invoke even if it somehow overlapped the GitHub Actions
 * path or another scheduled() invocation -- both paths read/write the
 * same D1 database, so there is one source of delivery truth regardless
 * of which trigger fires).
 *
 * The 4th `deps` param is a test-only seam (default {} in every real
 * call site, including workers/entry.js's) so router.test.js can inject
 * fakes instead of requiring real Redis/D1-backed modules under plain
 * node:test -- never populated in production.
 */
async function handleScheduled(controller, env, ctx, deps = {}) {
  const { evaluateWatchedEntities } = deps.changeEngine || require('../../api/_lib/change-engine');
  const { processDueDeliveries } = deps.notificationDispatch || require('../../api/_lib/notification-dispatch');
  const { setD1Binding } = deps.d1 || require('../../api/_lib/d1');

  // env.DB is Cloudflare's native D1 binding (wrangler.jsonc's
  // d1_databases entry), only ever available once a real invocation
  // hands us `env` -- unlike workers/entry.js's setWasmModule() call at
  // module load time, this can't happen any earlier. Registering it here
  // (not in dispatch()/handleFetch()) is a deliberate, disclosed scope
  // boundary: this scheduled handler is the one Cloudflare-triggered
  // entry point this tranche activates, so it's the one place that gets
  // the zero-latency native-binding fast path. The HTTP-triggered
  // api/v1/notifications.js routes reached via dispatch() do NOT get env
  // threaded to them (dispatch() calls `handler(req, res)` with no env
  // param -- confirmed by reading it fresh before this migration began)
  // and so fall back to d1.js's REST API transport even when running
  // under Cloudflare Workers -- correct, just one HTTP round trip slower
  // than the native binding would be. Widening dispatch()'s signature to
  // thread env through ~30 unrelated Vercel-style (req,res) handlers is a
  // materially larger architectural change than this tranche's actual
  // scope (migrating alert orchestration specifically, per the Cloudflare
  // Runtime Dependency Inventory's own §0) -- revisit only with its own
  // evidence and justification, not as a side effect of this change.
  if (env && env.DB) setD1Binding(env.DB);

  const startedAt = Date.now();
  const evaluation = await evaluateWatchedEntities();
  const delivery = await processDueDeliveries();
  const summary = {
    trigger: 'cloudflare_cron', cron: controller && controller.cron,
    elapsed_ms: Date.now() - startedAt, evaluation, delivery,
  };
  console.log('[SCHEDULED]', JSON.stringify(summary));
  return summary;
}

module.exports = { handleFetch, dispatch, handleScheduled, HANDLER_MODULES };
