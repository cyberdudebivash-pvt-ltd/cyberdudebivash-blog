'use strict';

/**
 * Data-only transcription of vercel.json's rewrites/redirects (as read for
 * PRE-MIGRATION-FORENSICS.md / VERCEL_MIGRATION_INVENTORY.md), plus
 * Vercel's own filesystem-routing convention for api/** (any .js file
 * under api/, except api/_lib/** and api/intel/**, is a routable
 * function — see VERCEL_MIGRATION_INVENTORY.md Sec5 for the enumerated
 * 32-function list this was transcribed from). Kept as pure data + a pure
 * matching function, independent of any Cloudflare-specific dispatch code,
 * so it's fully unit-testable without a Workers runtime.
 *
 * resolveRoute() expects a bare pathname (no query string).
 */

const BLOCKED_PREFIXES = [
  '/CLAUDE.md',
  '/Sentinel-APEX/',
  '/eito/',
  '/platform/',
  '/prompts/',
  '/BUSINESS-TRANSFORMATION-ROADMAP-2026.md',
  '/AUDIT-REPORT-2026-05-28.md',
  '/OPERATIONS.md',
];

// [pattern, handlerPath, buildQuery(match)] — 1:1 with vercel.json's
// `rewrites` array. handlerPath is the api/** file (no extension) Vercel's
// own filesystem convention already routes the *destination* path to.
const PRETTY_URL_REWRITES = [
  [/^\/api\/v1\/intel\/live$/, 'api/v1/intel', () => ({ action: 'live' })],
  [/^\/api\/v1\/intel\/top-threats$/, 'api/v1/intel', () => ({ action: 'top' })],
  [/^\/api\/v1\/intel\/cve\/([^/]+)$/, 'api/v1/intel', m => ({ action: 'cve', id: m[1] })],
  [/^\/api\/v1\/intel\/iocs$/, 'api/v1/intel', () => ({ action: 'iocs' })],
  [/^\/api\/v1\/intel\/ransomware$/, 'api/v1/intel', () => ({ action: 'ransomware' })],
  [/^\/api\/v1\/intel\/search$/, 'api/v1/intel', () => ({ action: 'search' })],
  [/^\/api\/v1\/intel\/graph$/, 'api/v1/intel', () => ({ action: 'graph' })],
  [/^\/api\/v1\/intel\/campaigns$/, 'api/v1/intel', () => ({ action: 'campaigns' })],
  [/^\/api\/v1\/intel\/campaign\/([^/]+)$/, 'api/v1/intel', m => ({ action: 'campaign', id: m[1] })],
  [/^\/api\/v1\/intel\/top-actors$/, 'api/v1/intel', () => ({ action: 'top-actors' })],

  [/^\/api\/v1\/auth\/register$/, 'api/v1/auth', () => ({ action: 'register' })],
  [/^\/api\/v1\/auth\/me$/, 'api/v1/auth', () => ({ action: 'me' })],
  [/^\/api\/v1\/keys\/usage$/, 'api/v1/auth', () => ({ action: 'usage' })],

  [/^\/api\/v1\/billing\/create-intent$/, 'api/v1/billing', () => ({ action: 'create-intent' })],
  [/^\/api\/v1\/billing\/submit-payment$/, 'api/v1/billing', () => ({ action: 'submit-payment' })],
  [/^\/api\/v1\/billing\/payment-status$/, 'api/v1/billing', () => ({ action: 'status' })],
  [/^\/api\/v1\/billing\/subscribe$/, 'api/v1/billing', () => ({ action: 'subscribe' })],
  [/^\/api\/v1\/billing\/razorpay\/order$/, 'api/v1/billing', () => ({ action: 'create-razorpay-order' })],
  [/^\/api\/v1\/billing\/razorpay\/verify$/, 'api/v1/billing', () => ({ action: 'verify-razorpay-payment' })],
  [/^\/api\/v1\/billing\/products\/checkout$/, 'api/v1/billing', () => ({ action: 'create-product-checkout' })],

  [/^\/api\/v1\/admin\/payments\/pending$/, 'api/v1/admin', () => ({ action: 'pending' })],
  [/^\/api\/v1\/admin\/payments\/approve$/, 'api/v1/admin', () => ({ action: 'approve' })],
  [/^\/api\/v1\/admin\/payments\/reject$/, 'api/v1/admin', () => ({ action: 'reject' })],
  [/^\/api\/v1\/admin\/payments\/audit$/, 'api/v1/admin', () => ({ action: 'audit' })],
  [/^\/api\/v1\/admin\/payments\/razorpay-orders$/, 'api/v1/admin', () => ({ action: 'razorpay-orders' })],
  [/^\/api\/v1\/admin\/payments\/product-orders$/, 'api/v1/admin', () => ({ action: 'product-orders' })],
];

// vercel.json rewrites these to the literal static file /rss.xml — served
// by Cloudflare's static asset layer, not a handler.
const ASSET_REWRITES = [
  [/^\/feed$/, '/rss.xml'],
  [/^\/feed\.xml$/, '/rss.xml'],
  [/^\/atom\.xml$/, '/rss.xml'],
];

// [pattern, destination, status] — vercel.json's `redirects` (permanent: true → 308).
const REDIRECTS = [
  [/^\/rss$/, '/rss.xml', 308],
];

// Every routable api/** function reachable at its own literal path via
// Vercel's filesystem convention (i.e. not through one of the pretty-URL
// rewrites above). api/_lib/** (underscore-prefixed) and api/intel/**
// (.json data) are deliberately excluded — see route-table.test.js for a
// cross-check against VERCEL_MIGRATION_INVENTORY.md's count.
const DIRECT_API_HANDLERS = new Set([
  'api/og',
  'api/cron/dispatch-intel',
  'api/v1/admin',
  'api/v1/auth',
  'api/v1/billing',
  'api/v1/intel',
  'api/v1/newsletter',
  'api/v1/analysis/assessments',
  'api/v1/analysis/findings',
  'api/v1/billing/webhook',
  'api/v1/billing/razorpay-webhook',
  'api/v1/customer/dashboard',
  'api/v1/customer/download',
  'api/v1/detections/rules',
  'api/v1/intelligence/confidence',
  'api/v1/intelligence/correlations',
  'api/v1/intelligence/graph',
  'api/v1/intelligence/objects',
  'api/v1/intelligence/publish',
  'api/v1/intelligence/similarity',
  'api/v1/ioc/search',
  'api/v1/products/approvals',
  'api/v1/products/export',
  'api/v1/products/index',
  'api/v1/quality/index',
  'api/v1/reports/index',
  'api/v1/workbench/cases',
  'api/v1/workbench/dashboard',
  'api/v1/workbench/investigations',
  'api/v1/workbench/search',
]);

// The 2 known [id]-style dynamic segments. api/v1/ioc/search (static) is
// checked ahead of the api/v1/ioc/[id] pattern by resolveRoute() below, so
// "search" itself is never swallowed as an id.
const DYNAMIC_API_HANDLERS = [
  [/^\/api\/v1\/detections\/rules\/([^/]+)$/, 'api/v1/detections/rules/[id]'],
  [/^\/api\/v1\/ioc\/([^/]+)$/, 'api/v1/ioc/[id]'],
];

/**
 * @param {string} pathname bare path, no query string (e.g. url.pathname)
 * @returns {null
 *   | { type: 'blocked' }
 *   | { type: 'redirect', to: string, status: number }
 *   | { type: 'asset', path: string }
 *   | { type: 'handler', handlerPath: string, query: Record<string,string> }}
 */
function resolveRoute(pathname) {
  if (BLOCKED_PREFIXES.some(p => pathname === p || pathname.startsWith(p))) {
    return { type: 'blocked' };
  }

  for (const [pattern, to, status] of REDIRECTS) {
    if (pattern.test(pathname)) return { type: 'redirect', to, status };
  }

  for (const [pattern, to] of ASSET_REWRITES) {
    if (pattern.test(pathname)) return { type: 'asset', path: to };
  }

  for (const [pattern, handlerPath, buildQuery] of PRETTY_URL_REWRITES) {
    const m = pathname.match(pattern);
    if (m) return { type: 'handler', handlerPath, query: buildQuery(m) };
  }

  const directPath = pathname.replace(/^\//, '').replace(/\/$/, '');
  if (DIRECT_API_HANDLERS.has(directPath)) {
    return { type: 'handler', handlerPath: directPath, query: {} };
  }
  // Vercel drops a trailing /index from the routable URL — api/v1/products/
  // index.js is reached at /api/v1/products, not /api/v1/products/index.
  if (DIRECT_API_HANDLERS.has(`${directPath}/index`)) {
    return { type: 'handler', handlerPath: `${directPath}/index`, query: {} };
  }

  for (const [pattern, handlerPath] of DYNAMIC_API_HANDLERS) {
    const m = pathname.match(pattern);
    if (m) return { type: 'handler', handlerPath, query: { id: m[1] } };
  }

  return null; // not an API route — defer to the static asset layer
}

module.exports = {
  BLOCKED_PREFIXES,
  PRETTY_URL_REWRITES,
  ASSET_REWRITES,
  REDIRECTS,
  DIRECT_API_HANDLERS,
  DYNAMIC_API_HANDLERS,
  resolveRoute,
};
