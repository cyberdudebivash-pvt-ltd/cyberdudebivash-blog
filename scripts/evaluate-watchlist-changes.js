#!/usr/bin/env node
/**
 * SENTINEL APEX — Watchlist Change Evaluation
 *
 * Thin CLI wrapper around api/_lib/change-engine.js's evaluateWatchedEntities().
 * Runs on a real autonomous schedule as of Alert Orchestration v1:
 * .github/workflows/alert-delivery.yml's native GitHub Actions
 * `schedule:` trigger (every 30 minutes, immediately followed by
 * scripts/deliver-watchlist-notifications.js in the same run — see that
 * workflow's header for the cadence reasoning and why GitHub Actions
 * rather than a Cloudflare Cron Trigger, which wrangler.jsonc still
 * explicitly defers pending separate operator authorization). Still safe
 * to run manually or via any other external scheduler too — this
 * function's own idempotent/replay-safe event creation (see change-
 * engine.js) does not depend on any particular caller.
 *
 * Usage:
 *   UPSTASH_REDIS_REST_URL=... UPSTASH_REDIS_REST_TOKEN=... \
 *     node scripts/evaluate-watchlist-changes.js [--batch=200]
 *
 * Bounded and cursor-resumable (see change-engine.js's own header): a run
 * only processes up to --batch watched entities before persisting its
 * cursor and exiting, so repeated invocations sweep the full watched set
 * over time without ever scanning the full intelligence corpus.
 */
'use strict';

function parseBatchArg(argv) {
  const match = argv.find(a => a.startsWith('--batch='));
  if (!match) return undefined;
  const n = parseInt(match.split('=')[1], 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

async function main() {
  if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
    console.error('[WATCHLIST-EVAL] UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN must be set.');
    process.exit(1);
    return;
  }

  const { evaluateWatchedEntities } = require('../api/_lib/change-engine');
  const batchLimit = parseBatchArg(process.argv.slice(2));

  const startedAt = Date.now();
  const results = await evaluateWatchedEntities(batchLimit ? { batchLimit } : {});
  const elapsedMs = Date.now() - startedAt;

  console.log('[WATCHLIST-EVAL] Run complete.');
  console.log(`[WATCHLIST-EVAL]   watched entities total: ${results.watched_entities_total}`);
  console.log(`[WATCHLIST-EVAL]   evaluated this run:      ${results.evaluated}`);
  console.log(`[WATCHLIST-EVAL]   baseline established:    ${results.baseline}`);
  console.log(`[WATCHLIST-EVAL]   unchanged:               ${results.unchanged}`);
  console.log(`[WATCHLIST-EVAL]   changed:                 ${results.changed}`);
  console.log(`[WATCHLIST-EVAL]   events created:          ${results.events_created}`);
  console.log(`[WATCHLIST-EVAL]   load failures (skipped): ${results.load_failed}`);
  console.log(`[WATCHLIST-EVAL]   watchlists touched:      ${results.watchlists_touched}`);
  console.log(`[WATCHLIST-EVAL]   elapsed: ${elapsedMs}ms`);
}

if (require.main === module) {
  main().catch(err => {
    console.error('[WATCHLIST-EVAL] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { parseBatchArg };
