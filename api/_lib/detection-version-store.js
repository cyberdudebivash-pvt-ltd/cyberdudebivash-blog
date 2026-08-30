'use strict';
/**
 * SENTINEL APEX — Detection Version Snapshot Store
 *
 * D1-backed store for detection_versions (migrations/0006_detection_
 * performance_intelligence.sql). See that migration's header for the full
 * evidence trail (real, already-occurred content loss for 3 of 5 real
 * canonical detection rules) that makes this table necessary.
 *
 * This module is intentionally ignorant of WHEN it is called — it only
 * ever inserts an immutable, content-addressed row for whatever rule
 * object it is handed, and does so idempotently (a second snapshotVersion()
 * call for a version that already has a row is a safe no-op, never an
 * overwrite). Two real callers use it very differently:
 *
 *   - detection-rules.js#storeRule() calls it fire-and-forget (not
 *     awaited) on every version bump, because storeRule() itself must
 *     stay synchronous (see that file's own comment for why — its one
 *     production caller, fetch-live-intel.js's genMultiPlatformDetections(),
 *     is a non-async function called in a loop, and making storeRule()
 *     async would cascade an async signature through that function's own
 *     callers, a materially larger blast radius than this tranche's
 *     scope). The residual risk this accepts — the host process exits
 *     before the fire-and-forget write completes — is strictly no worse
 *     than today's guaranteed, unconditional content loss on every
 *     version bump, and is explicitly disclosed in the certification doc
 *     rather than hidden.
 *
 *   - scripts/backfill-detection-version-snapshots.js awaits it directly,
 *     once, to capture the CURRENT content of every pre-existing
 *     canonical rule as its own immutable snapshot (source:
 *     BACKFILL_CURRENT_STATE) — the one-time migration path. This never
 *     invents content for versions that predate the backfill; see that
 *     script and the migration file for the honest disclosure of what
 *     remains unrecoverable.
 */

const crypto = require('crypto');
const d1 = require('./d1');

const SNAPSHOT_SOURCES = ['LIVE_CAPTURE', 'BACKFILL_CURRENT_STATE'];

/**
 * Deterministic semantic hash over exactly the fields that define a
 * version's actual defensive content — never over governance/timestamps/
 * history, which change independently of content and would make the hash
 * unstable for genuinely identical query logic.
 */
function computeContentHash(rule) {
  const canonical = {
    technique_id: rule.technique_id || null,
    title: rule.title || null,
    level: rule.level || null,
    description: rule.description || null,
    data_source: rule.data_source || null,
    platforms: {
      sigma: (rule.platforms && rule.platforms.sigma) || null,
      kql: (rule.platforms && rule.platforms.kql) || null,
      splunk: (rule.platforms && rule.platforms.splunk) || null,
      osquery: (rule.platforms && rule.platforms.osquery) || null,
    },
    suricata: rule.suricata || [],
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

/**
 * Idempotent: a repeat call for a version that already has a row is a
 * silent no-op (ON CONFLICT DO NOTHING on the (detection_id, version)
 * primary key) — never an overwrite. Returns true if a new row was
 * inserted, false if one already existed.
 */
async function snapshotVersion(rule, { source, reason, author } = {}) {
  if (!rule || !rule.id || !rule.governance || !rule.governance.version) {
    throw new Error('snapshotVersion requires a stored rule with id and governance.version');
  }
  if (!SNAPSHOT_SOURCES.includes(source)) {
    throw new Error(`snapshotVersion requires source to be one of: ${SNAPSHOT_SOURCES.join(', ')}`);
  }
  const contentHash = computeContentHash(rule);
  const changes = await d1.runMutationWithChanges(
    `INSERT INTO detection_versions
      (detection_id, version, title, technique_id, level, description, data_source,
       platforms_json, suricata_json, governance_status_at_snapshot, confidence_at_snapshot,
       content_hash, snapshot_source, snapshot_reason, snapshot_author, snapshotted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(detection_id, version) DO NOTHING`,
    [
      rule.id, rule.governance.version, rule.title, rule.technique_id, rule.level || null,
      rule.description || null, rule.data_source || null,
      JSON.stringify(rule.platforms || {}), JSON.stringify(rule.suricata || []),
      rule.governance.status || null, rule.governance.confidence || null,
      contentHash, source, reason || null, author || null, new Date().toISOString(),
    ]
  );
  return changes > 0;
}

function toPublicSnapshot(row) {
  return {
    detection_id: row.detection_id,
    version: row.version,
    title: row.title,
    technique_id: row.technique_id,
    level: row.level || null,
    description: row.description || null,
    data_source: row.data_source || null,
    platforms: JSON.parse(row.platforms_json || '{}'),
    suricata: JSON.parse(row.suricata_json || '[]'),
    governance_status_at_snapshot: row.governance_status_at_snapshot,
    confidence_at_snapshot: row.confidence_at_snapshot || null,
    content_hash: row.content_hash,
    snapshot_source: row.snapshot_source,
    snapshot_reason: row.snapshot_reason || null,
    snapshot_author: row.snapshot_author || null,
    snapshotted_at: row.snapshotted_at,
  };
}

async function getVersionSnapshot(detectionId, version) {
  const rows = await d1.query('SELECT * FROM detection_versions WHERE detection_id = ? AND version = ?', [detectionId, version]);
  return rows.length ? toPublicSnapshot(rows[0]) : null;
}

async function listVersionSnapshots(detectionId) {
  const rows = await d1.query('SELECT * FROM detection_versions WHERE detection_id = ? ORDER BY snapshotted_at ASC', [detectionId]);
  return rows.map(toPublicSnapshot);
}

/**
 * One-time migration helper: snapshots the CURRENT content of every
 * supplied canonical rule as a BACKFILL_CURRENT_STATE row. Safe to call
 * more than once (idempotent per snapshotVersion's own contract) — a
 * second run against unchanged rules inserts nothing new. Never invents
 * content for versions before the current one; see this file's header.
 */
async function backfillCurrentVersions(rules) {
  const results = { attempted: 0, inserted: 0, already_present: 0, failed: [] };
  for (const rule of rules || []) {
    results.attempted += 1;
    try {
      const didInsert = await snapshotVersion(rule, { source: 'BACKFILL_CURRENT_STATE', reason: 'One-time backfill of current canonical content prior to this migration.', author: 'detection-version-backfill' });
      if (didInsert) results.inserted += 1; else results.already_present += 1;
    } catch (err) {
      results.failed.push({ detection_id: rule.id, version: rule.governance && rule.governance.version, error: err.message });
    }
  }
  return results;
}

module.exports = {
  SNAPSHOT_SOURCES,
  computeContentHash,
  snapshotVersion,
  getVersionSnapshot,
  listVersionSnapshots,
  backfillCurrentVersions,
};
