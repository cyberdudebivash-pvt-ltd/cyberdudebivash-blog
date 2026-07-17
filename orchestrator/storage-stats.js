/**
 * SENTINEL APEX — Storage Growth Stats
 *
 * Lightweight, read-only file-count/size snapshot for the directories
 * that grow continuously as the pipeline ingests content — useful for
 * spotting runaway growth (e.g. logs/ has accumulated 3,700+ files with
 * no rotation policy) before it becomes a real operational problem.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { ROOT } = require('./generator-sdk');

const TRACKED_DIRS = ['logs', 'posts', 'api/intel/products', 'api/intel/cve', 'data'];

function dirStats(relDir) {
  const full = path.join(ROOT, relDir);
  let fileCount = 0;
  let totalBytes = 0;
  (function walk(p) {
    let entries;
    try {
      entries = fs.readdirSync(p, { withFileTypes: true });
    } catch (_) {
      return;
    }
    for (const entry of entries) {
      const entryPath = path.join(p, entry.name);
      if (entry.isDirectory()) {
        walk(entryPath);
      } else if (entry.isFile()) {
        fileCount += 1;
        try {
          totalBytes += fs.statSync(entryPath).size;
        } catch (_) {
          // File removed between readdir and stat — skip it.
        }
      }
    }
  })(full);
  return { dir: relDir, fileCount, totalBytes, totalMB: Math.round((totalBytes / (1024 * 1024)) * 10) / 10 };
}

function computeStorageStats(dirs = TRACKED_DIRS) {
  return dirs.map(dirStats);
}

module.exports = { computeStorageStats, dirStats, TRACKED_DIRS };
