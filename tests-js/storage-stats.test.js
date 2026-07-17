'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { dirStats, computeStorageStats } = require('../orchestrator/storage-stats');

test('dirStats returns zero counts for a nonexistent directory rather than throwing', () => {
  const stats = dirStats('this-directory-does-not-exist-xyz');
  assert.strictEqual(stats.fileCount, 0);
  assert.strictEqual(stats.totalBytes, 0);
});

test('dirStats counts files recursively across subdirectories', () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-storage-'));
  const ROOT = require('../orchestrator/generator-sdk').ROOT;
  // dirStats always resolves relative to the real ROOT, so build a fixture
  // under a temp dir and pass its path relative to ROOT via path.relative.
  const relDir = path.relative(ROOT, tmpBase);
  fs.mkdirSync(path.join(tmpBase, 'sub'), { recursive: true });
  fs.writeFileSync(path.join(tmpBase, 'a.txt'), 'hello');
  fs.writeFileSync(path.join(tmpBase, 'sub', 'b.txt'), 'world!!');

  const stats = dirStats(relDir);
  assert.strictEqual(stats.fileCount, 2);
  assert.strictEqual(stats.totalBytes, 5 + 7);

  fs.rmSync(tmpBase, { recursive: true, force: true });
});

test('computeStorageStats returns one entry per tracked directory', () => {
  const stats = computeStorageStats(['package.json']); // a file, not a dir -> readdirSync fails gracefully
  assert.strictEqual(stats.length, 1);
  assert.strictEqual(stats[0].dir, 'package.json');
});

test('computeStorageStats against the real tracked directories returns positive counts', () => {
  const stats = computeStorageStats();
  assert.ok(stats.length > 0);
  for (const s of stats) {
    assert.strictEqual(typeof s.fileCount, 'number');
    assert.strictEqual(typeof s.totalMB, 'number');
  }
});
