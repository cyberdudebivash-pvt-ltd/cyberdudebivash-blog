'use strict';
/**
 * SENTINEL APEX — Detection Performance Intelligence v1: proves detection-
 * rules.js#storeRule()'s new fire-and-forget version-snapshot hook is
 * actually wired up correctly, WITHOUT ever touching the real, committed
 * data/detection-rules-canonical.json file (fs is fully mocked here --
 * this file must never leave a diff in that production data file).
 *
 * loadCanonical()/saveCanonical() re-read/re-write via fs on every single
 * call (no module-level caching) -- so the module under test only needs
 * to be required once; per-test isolation comes from resetting the fake
 * in-memory "disk" in beforeEach, not from re-requiring the module.
 */

jest.mock('fs', () => ({
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
  renameSync: jest.fn(),
  unlinkSync: jest.fn(),
}));
jest.mock('../detection-version-store', () => ({
  SNAPSHOT_SOURCES: ['LIVE_CAPTURE', 'BACKFILL_CURRENT_STATE'],
  snapshotVersion: jest.fn(() => Promise.resolve(true)),
}));

const fs = require('fs');
const versionStore = require('../detection-version-store');
const detectionRules = require('../detection-rules');

let fakeDisk;

beforeEach(() => {
  jest.clearAllMocks();
  fakeDisk = { meta: { version: '1.0.0', generated: '2020-01-01T00:00:00.000Z', total_rules: 0 }, rules: [] };
  fs.readFileSync.mockImplementation(() => JSON.stringify(fakeDisk));
  fs.writeFileSync.mockImplementation((_path, content) => { fakeDisk = JSON.parse(content); });
  fs.renameSync.mockImplementation(() => {});
  versionStore.snapshotVersion.mockImplementation(() => Promise.resolve(true));
});

describe('storeRule() — additive fire-and-forget version snapshot hook', () => {
  test('a brand-new rule triggers exactly one snapshotVersion() call for version 1.0.0', async () => {
    const rule = detectionRules.storeRule({ technique_id: 'T1059.001', title: 'Test Rule', level: 'high', sigma: 'title: x' }, { confidence: 'HIGH' });

    expect(rule.governance.version).toBe('1.0.0');
    // Fire-and-forget -- allow the floating microtask to run before asserting.
    await new Promise(process.nextTick);
    expect(versionStore.snapshotVersion).toHaveBeenCalledTimes(1);
    const [snapshottedRule, opts] = versionStore.snapshotVersion.mock.calls[0];
    expect(snapshottedRule.id).toBe(rule.id);
    expect(snapshottedRule.governance.version).toBe('1.0.0');
    expect(opts.source).toBe('LIVE_CAPTURE');
  });

  test('storeRule() itself never throws or blocks even when snapshotVersion() rejects', async () => {
    versionStore.snapshotVersion.mockImplementationOnce(() => Promise.reject(new Error('D1 not configured')));
    expect(() => detectionRules.storeRule({ technique_id: 'T1059.001', title: 'Test Rule', level: 'high', sigma: 'title: x' })).not.toThrow();
    await new Promise(process.nextTick); // let the rejection settle into the internal .catch() without an unhandled rejection
  });

  test('updating an existing rule snapshots the NEW incremented version, not the old one', async () => {
    const spec = { technique_id: 'T1059.001', title: 'Test Rule', level: 'high', sigma: 'title: x' };
    detectionRules.storeRule(spec, {});
    await new Promise(process.nextTick);
    versionStore.snapshotVersion.mockClear();

    const updated = detectionRules.storeRule({ ...spec, sigma: 'title: x (updated)' }, { change: 'Refined selection logic' });
    expect(updated.governance.version).toBe('1.0.1');
    await new Promise(process.nextTick);
    expect(versionStore.snapshotVersion).toHaveBeenCalledTimes(1);
    const [snapshottedRule, opts] = versionStore.snapshotVersion.mock.calls[0];
    expect(snapshottedRule.governance.version).toBe('1.0.1');
    expect(opts.reason).toBe('Refined selection logic');
  });

  test('never writes to the real filesystem -- fs itself is fully mocked, so every write lands on the in-memory fake disk only', () => {
    detectionRules.storeRule({ technique_id: 'T1059.001', title: 'Test Rule', level: 'high', sigma: 'title: x' }, {});
    expect(fs.writeFileSync).toHaveBeenCalled();
    expect(fakeDisk.rules.length).toBe(1); // proves the write actually landed on the fake disk, not silently discarded
  });
});
