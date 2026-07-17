'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { summarizeRuns } = require('../orchestrator/run-log-stats');

test('summarizeRuns against the real repo returns a well-formed summary shape', () => {
  const s = summarizeRuns(5);
  assert.strictEqual(typeof s.sampledRuns, 'number');
  assert.strictEqual(typeof s.healthyRuns, 'number');
  assert.ok(Array.isArray(s.runs));
  assert.ok(s.healthyRuns <= s.sampledRuns);
});

test('summarizeRuns returns zero-value shape for an empty logs directory', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runlog-empty-'));
  const s = summarizeRuns(10, tmpDir);
  assert.strictEqual(s.sampledRuns, 0);
  assert.strictEqual(s.successRate, null);
  assert.strictEqual(s.mostRecent, null);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('a run with failed>0 and published==0 is marked unhealthy; most recent sorts first', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runlog-'));
  fs.writeFileSync(path.join(tmpDir, 'run-20260101-000000.json'), JSON.stringify({
    run_start: '2026-01-01T00:00:00Z', run_end: '2026-01-01T00:01:00Z',
    discovered: 5, published: 0, failed: 5, skipped: 0,
  }));
  fs.writeFileSync(path.join(tmpDir, 'run-20260101-010000.json'), JSON.stringify({
    run_start: '2026-01-01T01:00:00Z', run_end: '2026-01-01T01:01:00Z',
    discovered: 5, published: 3, failed: 2, skipped: 0,
  }));

  const s = summarizeRuns(10, tmpDir);
  assert.strictEqual(s.sampledRuns, 2);
  assert.strictEqual(s.healthyRuns, 1);
  assert.strictEqual(s.mostRecent.published, 3); // newest filename (010000) sorts first
  assert.strictEqual(s.mostRecent.healthy, true);
  assert.strictEqual(s.successRate, 50);
  assert.strictEqual(s.totalPublished, 3);
  assert.strictEqual(s.totalFailed, 7);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('a run with failed==0 counts as healthy even with zero published', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runlog-'));
  fs.writeFileSync(path.join(tmpDir, 'run-20260101-000000.json'), JSON.stringify({
    run_start: '2026-01-01T00:00:00Z', run_end: '2026-01-01T00:01:00Z',
    discovered: 0, published: 0, failed: 0, skipped: 0,
  }));
  const s = summarizeRuns(10, tmpDir);
  assert.strictEqual(s.mostRecent.healthy, true);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('malformed JSON log files are skipped rather than crashing', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runlog-'));
  fs.writeFileSync(path.join(tmpDir, 'run-20260101-000000.json'), '{not valid json');
  const s = summarizeRuns(10, tmpDir);
  assert.strictEqual(s.sampledRuns, 0);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
