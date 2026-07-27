/**
 * SENTINEL APEX — Internal Path Blocker
 *
 * Serves a plain 404 for internal governance/architecture/strategy paths
 * that must never be publicly reachable (CLAUDE.md, Sentinel-APEX/, eito/,
 * platform/, prompts/, and the root strategy docs). Added because
 * .vercelignore alone was verified (via direct HTTP checks against the live
 * deployment, including a fresh cache-MISS request) not to stop these paths
 * from being served on this project -- routing through an explicit
 * rewrite to a function that returns 404 is a mechanism already proven to
 * work on this deployment (every api/v1/* endpoint depends on the same
 * rewrite mechanism), unlike the unverified .vercelignore behavior.
 */
'use strict';

module.exports = (req, res) => {
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end('Not Found');
};
