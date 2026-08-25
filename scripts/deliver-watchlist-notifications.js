#!/usr/bin/env node
/**
 * SENTINEL APEX — Watchlist Notification Delivery (manual/scheduled-fallback run)
 *
 * Thin CLI wrapper around api/_lib/notification-dispatch.js's
 * processDueDeliveries(). Same posture as scripts/evaluate-watchlist-
 * changes.js (see that script's own header): run manually today, not
 * wired to a Cloudflare Cron Trigger — wrangler.jsonc's own header
 * explicitly defers scheduling authority, and this is exactly that kind
 * of infrastructure decision. Run this AFTER evaluate-watchlist-changes.js
 * in the same cycle (or any time after) — it only ever processes
 * already-enqueued pending deliveries, it does not detect changes itself.
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
  const limit = parseLimitArg(process.argv.slice(2));

  const startedAt = Date.now();
  const results = await processDueDeliveries(limit ? { limit } : {});
  const elapsedMs = Date.now() - startedAt;

  console.log('[NOTIFY-DELIVER] Run complete.');
  console.log(`[NOTIFY-DELIVER]   pending records processed: ${results.records_processed}`);
  console.log(`[NOTIFY-DELIVER]   delivery attempts:         ${results.attempts}`);
  console.log(`[NOTIFY-DELIVER]   delivered:                 ${results.delivered}`);
  console.log(`[NOTIFY-DELIVER]   scheduled for retry:       ${results.retried}`);
  console.log(`[NOTIFY-DELIVER]   dead-lettered:             ${results.dead_lettered}`);
  console.log(`[NOTIFY-DELIVER]   elapsed: ${elapsedMs}ms`);
}

if (require.main === module) {
  main().catch(err => {
    console.error('[NOTIFY-DELIVER] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { parseLimitArg };
