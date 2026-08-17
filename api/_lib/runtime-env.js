'use strict';

/**
 * Single source of truth for "am I running in a Cloudflare Worker or in
 * Node (Vercel/local dev/tests)". Lives under api/_lib (not workers/lib)
 * because api/_lib modules need it directly — workers/ is an adapter
 * layer around api/, not the other way around, so api/_lib shouldn't
 * depend on workers/lib for something this basic.
 *
 * navigator.userAgent === 'Cloudflare-Workers' is Cloudflare's own
 * documented runtime-detection convention, not a guess:
 * https://developers.cloudflare.com/workers/runtime-apis/web-standards/
 */
function isCloudflareWorkers() {
  return typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';
}

module.exports = { isCloudflareWorkers };
