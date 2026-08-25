#!/usr/bin/env node
/**
 * SENTINEL APEX — Watchlist Notification Delivery
 *
 * Thin CLI wrapper around api/_lib/notification-dispatch.js's
 * processDueDeliveries(). Runs on a real autonomous schedule as of Alert
 * Orchestration v1: .github/workflows/alert-delivery.yml's native GitHub
 * Actions `schedule:` trigger (every 30 minutes -- see that workflow's
 * header for why that cadence, and why GitHub Actions rather than a
 * Cloudflare Cron Trigger, which wrangler.jsonc still explicitly defers
 * pending separate operator authorization). Still safe to run manually
 * or via any other external scheduler too -- processDueDeliveries()'s
 * atomic claim/lease makes concurrent/repeated invocations safe by
 * construction, not just by convention. Run AFTER evaluate-watchlist-
 * changes.js in the same cycle (the scheduled workflow already does this
 * in order) — it only ever processes already-enqueued pending
 * deliveries, it does not detect changes itself.
 *
 * Usage:
 *   UPSTASH_REDIS_REST_URL=... UPSTASH_REDIS_REST_TOKEN=... \
 *   RESEND_API_KEY=... \
 *     node scripts/deliver-watchlist-notifications.js [--limit=100]
 *
 * RESEND_API_KEY is optional here in the sense that the script still runs
 * without it — email deliveries will simply fail with EMAIL_NOT_CONFIGURED
 * (logged and retried/dead-lettered like any other failure) rather than
 * the script refusing to start; webhook deliveries need no email
 * configuration at all.
 */
'use strict';

function parseLimitArg(argv) {
  const match = argv.find(a => a.startsWith('--limit='));
  if (!match) return undefined;
  const n = parseInt(match.split('=')[1], 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

async function main() {
  if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
    console.error('[NOTIFY-DELIVER] UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN must be set.');
    process.exit(1);
    return;
  }

  const { processDueDeliveries } = require('../api/_lib/notification-dispatch');
  const { getOldestPendingAgeSeconds } = require('../api/_lib/notification-store');
  const limit = parseLimitArg(process.argv.slice(2));

  const startedAt = Date.now();
  const results = await processDueDeliveries(limit ? { limit } : {});
  const oldestPendingAgeSeconds = await getOldestPendingAgeSeconds().catch(() => null);
  const elapsedMs = Date.now() - startedAt;

  console.log('[NOTIFY-DELIVER] Run complete.');
  console.log(`[NOTIFY-DELIVER]   pending records processed: ${results.records_processed}`);
  console.log(`[NOTIFY-DELIVER]   channels claimed:          ${results.claimed}`);
  console.log(`[NOTIFY-DELIVER]   skipped (claimed elsewhere): ${results.skipped_claimed_elsewhere}`);
  console.log(`[NOTIFY-DELIVER]   cancelled (channel disabled): ${results.cancelled}`);
  console.log(`[NOTIFY-DELIVER]   delivery attempts:         ${results.attempts}`);
  console.log(`[NOTIFY-DELIVER]   delivered:                 ${results.delivered}`);
  console.log(`[NOTIFY-DELIVER]   scheduled for retry:       ${results.retried}`);
  console.log(`[NOTIFY-DELIVER]   dead-lettered:             ${results.dead_lettered}`);
  console.log(`[NOTIFY-DELIVER]   oldest pending age (sec):  ${oldestPendingAgeSeconds === null ? 'n/a (queue empty)' : oldestPendingAgeSeconds}`);
  console.log(`[NOTIFY-DELIVER]   elapsed: ${elapsedMs}ms`);

  // Compact structured run summary (orchestration mandate Phase 55) --
  // one machine-parseable line, no secrets, safe to grep out of GitHub
  // Actions logs or pipe into whatever external monitoring is wired up
  // later without needing to reformat the human-readable lines above.
  console.log('[NOTIFY-DELIVER-SUMMARY]', JSON.stringify({
    records_processed: results.records_processed,
    claimed: results.claimed,
    skipped_claimed_elsewhere: results.skipped_claimed_elsewhere,
    cancelled: results.cancelled,
    attempts: results.attempts,
    delivered: results.delivered,
    retrying: results.retried,
    terminal: results.dead_lettered,
    oldest_pending_delivery_age_seconds: oldestPendingAgeSeconds,
    elapsed_ms: elapsedMs,
  }));
}

if (require.main === module) {
  main().catch(err => {
    console.error('[NOTIFY-DELIVER] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { parseLimitArg };
