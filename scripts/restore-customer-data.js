#!/usr/bin/env node
/**
 * SENTINEL APEX — Customer Data Restore (GEORP v1 / Phase 3)
 *
 * Companion to backup-customer-data.js. Decrypts a snapshot and replays it
 * into Redis. Defaults to a dry run (prints what WOULD be restored) --
 * requires an explicit --confirm flag to actually write, since replaying
 * data into production Redis should be a deliberate human decision (a
 * "break glass" action performed during an actual incident), never
 * scheduled or triggered automatically the way the backup itself is.
 *
 * Usage:
 *   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file>            # dry run
 *   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file> --confirm   # writes
 *
 * See RUNBOOKS.md "Redis Outage / Data Loss" for the full procedure this
 * script is one step of.
 */
'use strict';

const fs = require('fs');
const { decryptSnapshot } = require('./backup-customer-data');

/** Replay a decrypted snapshot into a live redis client. Pure with respect
 *  to the snapshot itself; the only side effect happens through the
 *  passed-in `redis` client, so this is directly testable with a fake
 *  client instead of live Redis. Skips null/undefined string values
 *  (a key that existed with no value at backup time) rather than writing
 *  the literal string "null"/"undefined" into Redis. */
async function applySnapshot(redis, snapshot) {
  let hashesWritten = 0;
  let stringsWritten = 0;

  for (const [key, fields] of Object.entries(snapshot.hashes || {})) {
    if (fields && typeof fields === 'object') {
      await redis.hmset(key, fields);
      hashesWritten++;
    }
  }
  for (const [key, value] of Object.entries(snapshot.strings || {})) {
    if (value !== null && value !== undefined) {
      await redis.set(key, value);
      stringsWritten++;
    }
  }

  return { hashesWritten, stringsWritten };
}

async function main() {
  const [, , snapshotPath, flag] = process.argv;
  if (!snapshotPath) {
    console.error('Usage: node restore-customer-data.js <snapshot-file> [--confirm]');
    process.exit(1);
    return;
  }
  const encryptionKey = process.env.BACKUP_ENCRYPTION_KEY;
  if (!encryptionKey) {
    console.error('[RESTORE] BACKUP_ENCRYPTION_KEY is not set — cannot decrypt.');
    process.exit(1);
    return;
  }

  const encrypted = fs.readFileSync(snapshotPath, 'utf8');
  const snapshot = decryptSnapshot(encrypted, encryptionKey);

  const userCount = Object.keys(snapshot.hashes || {}).length;
  const stringCount = Object.keys(snapshot.strings || {}).length;
  console.log(`[RESTORE] Snapshot from ${snapshot.createdAt}: ${userCount} user record(s), ${stringCount} lookup key(s), ${(snapshot.auditLog || []).length} audit entries.`);

  if (flag !== '--confirm') {
    console.log('[RESTORE] Dry run only — no data written. Re-run with --confirm to actually restore into Redis.');
    return;
  }

  const redis = require('../api/_lib/redis');
  const { hashesWritten, stringsWritten } = await applySnapshot(redis, snapshot);
  console.log(`[RESTORE] Wrote ${hashesWritten} hash(es), ${stringsWritten} string key(s) into Redis.`);
}

if (require.main === module) {
  main().catch(err => {
    console.error('[RESTORE] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { applySnapshot };
