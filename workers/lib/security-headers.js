'use strict';

/**
 * Centralized dynamic-response security header baseline for everything
 * router.js itself returns (handler dispatch, redirects, blocked-404).
 * Not applied to the passthrough-to-ASSETS case (unmatched paths, feed
 * aliases) — those are genuinely static-asset responses and get their
 * headers from dist-public/_headers instead (see scripts/build-
 * cloudflare-assets.js). Cloudflare's own _headers mechanism only covers
 * static asset responses, not Worker-produced ones, so the two have to
 * be enforced separately — this file is the dynamic half.
 *
 * "Set only if absent", never unconditional overwrite: api/_lib/
 * middleware.js's applySecurityHeaders()/respond() already set
 * Content-Type, CORS (Access-Control-*), and X-Powered-By correctly for
 * every handler that calls them, and Section 4's own requirement is not
 * to duplicate/fight that existing, already-correct app-layer contract.
 * This baseline exists for headers the app layer generally does NOT set
 * (HSTS, nosniff, referrer-policy, permissions-policy, cache-control) and
 * as a safety net for any response path that reaches router.js without
 * having gone through middleware.js at all (redirects, blocked-404, an
 * unexpected handler that forgets to call guardRequest).
 *
 * Cache-Control is deliberately included here, unlike the other app-layer
 * headers this baseline defers to: on Vercel, vercel.json's own
 * `/api/v1/(.*)` rule applies `Cache-Control: no-store, no-cache,
 * must-revalidate` to every response at the platform level, unconditionally
 * -- regardless of whether the handler itself calls
 * applySecurityHeaders(). Found via a real Workerd probe of
 * api/v1/customer/dashboard.js (which returns purchase history and API-key/
 * tier status, and does not call applySecurityHeaders()): its Cloudflare
 * response had every other baseline header but no Cache-Control at all,
 * because router.js has no equivalent platform-level safety net for
 * dynamic responses. Every response this function ever applies to is an
 * API/JSON/redirect/404 (see the comment below) -- never something that
 * should be shared-cacheable -- so adding it here is safe unconditionally,
 * not just a narrow fix for this one handler.
 */

const BASELINE = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'no-store, no-cache, must-revalidate',
};

// API/JSON/redirect/404 responses only — router.js never returns HTML
// directly (HTML is always served by the ASSETS binding before the
// Worker runs at all, or via the explicit 'asset' route type, neither of
// which calls this function), so a strict CSP is always safe here. It
// would NOT be safe applied to HTML, which needs the permissive
// script-src allowlist vercel.json's /(.*).html block already documents
// — that one belongs in _headers, not here.
const DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'";

/**
 * Mutates and returns `response` with baseline headers applied wherever
 * the response doesn't already set them. Response headers are mutable
 * in place for a same-origin Response object constructed by this
 * codebase (node-compat.js/router.js), so no cloning is required.
 */
function applyBaselineHeaders(response) {
  for (const [key, value] of Object.entries(BASELINE)) {
    if (!response.headers.has(key)) response.headers.set(key, value);
  }
  if (!response.headers.has('Content-Security-Policy') && !response.headers.has('X-Frame-Options')) {
    // Only add both together, and only if the handler set neither —
    // a handler that explicitly set one but not the other made a
    // deliberate choice this baseline shouldn't second-guess.
    response.headers.set('Content-Security-Policy', DEFAULT_CSP);
    response.headers.set('X-Frame-Options', 'DENY');
  }
  return response;
}

module.exports = { applyBaselineHeaders, BASELINE, DEFAULT_CSP };
