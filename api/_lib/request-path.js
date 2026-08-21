'use strict';

/**
 * Resolve a request's logical path segments for handlers that do their own
 * sub-resource routing (workbench/investigations.js, workbench/cases.js,
 * intelligence/graph.js).
 *
 * These files were written assuming Vercel would deliver the full original
 * request path via req.url for any sub-path under their mount point --
 * true only for the file's own bare base path (Vercel's default
 * file-to-route mapping, e.g. `/api/v1/workbench/investigations` ->
 * investigations.js with no rewrite needed). No vercel.json rewrite ever
 * existed for anything deeper (`/investigations/{id}`, `/{id}/timeline`,
 * ...), so every one of those requests 404'd at Vercel's routing layer
 * before this code ever ran -- confirmed by vercel.json carrying zero
 * `/api/v1/workbench/*` or `/api/v1/intelligence/*` rewrites, while the
 * only other multi-action router in this same file (admin.js) needs one
 * explicit rewrite per action to be reachable at all.
 *
 * The fix: a single wildcard rewrite per mount point
 * (`/mountPath/:apexSubpath*` -> `/mountPath?apexSubpath=:apexSubpath*`)
 * carries the sub-path through as a query param instead. This function
 * reconstructs the exact same absolute segment array the handlers'
 * existing routing logic already expects, from whichever the request
 * actually carries: the query param (once the rewrite is live) or a
 * literal req.url (kept as a fallback -- not because query-param delivery
 * is uncertain, but because it costs nothing and means the base-path case,
 * which already worked with zero rewrite, keeps working unchanged even if
 * something about the rewritten request shape ever surprises this
 * function).
 */
function resolvePathParts(req, mountPath) {
  const rawSubpath = req.query && req.query.apexSubpath;
  if (rawSubpath !== undefined) {
    const segments = Array.isArray(rawSubpath) ? rawSubpath : String(rawSubpath).split('/');
    return [...mountPath.split('/').filter(Boolean), ...segments.filter(Boolean)];
  }
  return (req.url || '').split('?')[0].split('/').filter(Boolean);
}

module.exports = { resolvePathParts };
