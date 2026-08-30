#!/usr/bin/env node
/**
 * SENTINEL APEX — Detection Version Snapshot Backfill
 *
 * One-time tool for the Detection Performance Intelligence v1 tranche:
 * snapshots the CURRENT content of every rule already in the canonical
 * detection store (api/_lib/detection-rules.js) into detection_versions
 * (migrations/0006_detection_performance_intelligence.sql), so every
 * existing rule has at least one immutable, content-addressed version
 * row before detection-rules.js#storeRule()'s new fire-and-forget hook
 * starts capturing future versions live.
 *
 * Honest limitation, not fixed by this tool: content for a rule's PAST
 * versions (e.g. 1.0.0-1.0.8 of a rule now at 1.0.9) was already
 * destroyed by storeRule()'s pre-existing overwrite-in-place behavior,
 * long before this tool or the hook existed. This script snapshots only
 * the CURRENT row of each rule, tagged snapshot_source='BACKFILL_CURRENT_
 * STATE' — it never invents or reconstructs unavailable historic content.
 * The live history[] array (unchanged) remains the only record that
 * those earlier versions existed at all; the version-history API marks
 * them content-unavailable rather than fabricating anything.
 *
 * Idempotent: safe to run more than once. snapshotVersion()'s own
 * ON CONFLICT(detection_id, version) DO NOTHING means a repeat run against
 * unchanged rules inserts nothing new.
 *
 * Usage:
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_D1_DATABASE_ID=... CLOUDFLARE_API_TOKEN=... \
 *     node scripts/backfill-detection-version-snapshots.js [--apply] [--verbose]
 *
 * Without --apply: reports what would be snapshotted, writes nothing to D1.
 */
'use strict';

const detectionRules = require('../api/_lib/detection-rules');
const versionStore = require('../api/_lib/detection-version-store');

async function main() {
  const args = process.argv.slice(2);
  const apply = args.includes('--apply');
  const verbose = args.includes('--verbose');

  const store = detectionRules.loadCanonical();
  const rules = store.rules || [];

  console.log(`[BACKFILL] Found ${rules.length} rule(s) in the canonical store.`);
  for (const rule of rules) {
    const existing = apply ? await versionStore.getVersionSnapshot(rule.id, rule.governance.version) : null;
    if (verbose || !apply) {
      console.log(`  - ${rule.id} (${rule.technique_id}) v${rule.governance.version} -- status=${rule.governance.status}, history entries=${(rule.history || []).length}${existing ? ' [already snapshotted]' : ''}`);
    }
  }

  if (!apply) {
    console.log(`[BACKFILL] Dry run only -- ${rules.length} rule(s) would be snapshotted. Re-run with --apply to write to D1.`);
    return;
  }

  const result = await versionStore.backfillCurrentVersions(rules);
  console.log('[BACKFILL] Complete:', JSON.stringify(result, null, 2));
  if (result.failed.length) {
    console.error(`[BACKFILL] ${result.failed.length} rule(s) failed to snapshot -- see above.`);
    process.exitCode = 1;
  }
}

main().catch(err => {
  console.error('[BACKFILL] Fatal error:', err.message);
  process.exitCode = 1;
});
