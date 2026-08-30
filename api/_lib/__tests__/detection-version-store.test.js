'use strict';
/**
 * SENTINEL APEX — Detection Performance Intelligence v1: detection-version-store.js
 *
 * Proves the immutability contract that closes the real, already-occurred
 * content-loss defect in detection-rules.js#storeRule(): a version, once
 * snapshotted, is never overwritten by a later snapshotVersion() call for
 * that same (detection_id, version) -- only a genuinely new version number
 * ever produces a new row.
 */

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const versionStore = require('../detection-version-store');

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

function makeRule(overrides = {}) {
  return {
    id: 'det_abc123',
    technique_id: 'T1059.001',
    title: 'Suspicious PowerShell Execution',
    level: 'high',
    description: 'Detects suspicious PowerShell invocation patterns.',
    data_source: 'process_creation',
    platforms: { sigma: 'title: test\nlogsource: {product: windows}\ndetection: {sel: {a: b}, condition: sel}', kql: null, splunk: null, osquery: null },
    suricata: [],
    governance: { status: 'GENERATED', confidence: 'MEDIUM', version: '1.0.0' },
    ...overrides,
  };
}

describe('computeContentHash', () => {
  test('identical content produces the identical hash', () => {
    const a = versionStore.computeContentHash(makeRule());
    const b = versionStore.computeContentHash(makeRule());
    expect(a).toBe(b);
  });

  test('different query content produces a different hash', () => {
    const a = versionStore.computeContentHash(makeRule());
    const b = versionStore.computeContentHash(makeRule({ platforms: { sigma: 'title: different', kql: null, splunk: null, osquery: null } }));
    expect(a).not.toBe(b);
  });

  test('governance/timestamps do not affect the hash -- only content fields do', () => {
    const a = versionStore.computeContentHash(makeRule({ governance: { status: 'GENERATED', version: '1.0.0' } }));
    const b = versionStore.computeContentHash(makeRule({ governance: { status: 'RELEASED', version: '9.9.9' } }));
    expect(a).toBe(b);
  });
});

describe('snapshotVersion — idempotent, immutable insert', () => {
  test('a first snapshot for a (detection_id, version) inserts a new row', async () => {
    const inserted = await versionStore.snapshotVersion(makeRule(), { source: 'LIVE_CAPTURE' });
    expect(inserted).toBe(true);
    const row = await versionStore.getVersionSnapshot('det_abc123', '1.0.0');
    expect(row.title).toBe('Suspicious PowerShell Execution');
    expect(row.snapshot_source).toBe('LIVE_CAPTURE');
  });

  test('a repeat snapshot for the SAME (detection_id, version) is a no-op -- never overwrites', async () => {
    await versionStore.snapshotVersion(makeRule({ title: 'Original Title' }), { source: 'LIVE_CAPTURE' });
    const secondInsert = await versionStore.snapshotVersion(makeRule({ title: 'A Different Title Attempting To Overwrite' }), { source: 'LIVE_CAPTURE' });
    expect(secondInsert).toBe(false);
    const row = await versionStore.getVersionSnapshot('det_abc123', '1.0.0');
    expect(row.title).toBe('Original Title'); // proves the row was NOT overwritten
  });

  test('a genuinely new version number for the same detection creates a SEPARATE row, leaving the old one untouched', async () => {
    await versionStore.snapshotVersion(makeRule({ governance: { status: 'GENERATED', version: '1.0.0' } }), { source: 'LIVE_CAPTURE' });
    await versionStore.snapshotVersion(makeRule({ title: 'Updated Title', governance: { status: 'GENERATED', version: '1.0.1' } }), { source: 'LIVE_CAPTURE' });
    const v1 = await versionStore.getVersionSnapshot('det_abc123', '1.0.0');
    const v2 = await versionStore.getVersionSnapshot('det_abc123', '1.0.1');
    expect(v1.title).toBe('Suspicious PowerShell Execution');
    expect(v2.title).toBe('Updated Title');
  });

  test('rejects an unknown snapshot_source', async () => {
    await expect(versionStore.snapshotVersion(makeRule(), { source: 'NOT_A_REAL_SOURCE' })).rejects.toThrow();
  });

  test('rejects a rule missing governance.version', async () => {
    await expect(versionStore.snapshotVersion({ id: 'x' }, { source: 'LIVE_CAPTURE' })).rejects.toThrow();
  });
});

describe('getVersionSnapshot / listVersionSnapshots', () => {
  test('getVersionSnapshot returns null for a version that was never snapshotted', async () => {
    const row = await versionStore.getVersionSnapshot('det_never_seen', '1.0.0');
    expect(row).toBeNull();
  });

  test('listVersionSnapshots returns every version for one detection, ordered, isolated from other detections', async () => {
    await versionStore.snapshotVersion(makeRule({ governance: { status: 'GENERATED', version: '1.0.0' } }), { source: 'LIVE_CAPTURE' });
    await versionStore.snapshotVersion(makeRule({ governance: { status: 'GENERATED', version: '1.0.1' } }), { source: 'LIVE_CAPTURE' });
    await versionStore.snapshotVersion(makeRule({ id: 'det_other', governance: { status: 'GENERATED', version: '1.0.0' } }), { source: 'LIVE_CAPTURE' });

    const history = await versionStore.listVersionSnapshots('det_abc123');
    expect(history.length).toBe(2);
    expect(history.map(v => v.version)).toEqual(['1.0.0', '1.0.1']);
  });
});

describe('backfillCurrentVersions — one-time migration helper', () => {
  test('snapshots the current content of every supplied rule', async () => {
    const rules = [makeRule({ id: 'det_1' }), makeRule({ id: 'det_2', governance: { status: 'RELEASED', version: '2.0.0' } })];
    const result = await versionStore.backfillCurrentVersions(rules);
    expect(result.attempted).toBe(2);
    expect(result.inserted).toBe(2);
    expect(result.already_present).toBe(0);
    expect(result.failed).toEqual([]);

    const row1 = await versionStore.getVersionSnapshot('det_1', '1.0.0');
    const row2 = await versionStore.getVersionSnapshot('det_2', '2.0.0');
    expect(row1.snapshot_source).toBe('BACKFILL_CURRENT_STATE');
    expect(row2.governance_status_at_snapshot).toBe('RELEASED');
  });

  test('is safe to run twice -- the second run inserts nothing new', async () => {
    const rules = [makeRule({ id: 'det_1' })];
    await versionStore.backfillCurrentVersions(rules);
    const second = await versionStore.backfillCurrentVersions(rules);
    expect(second.inserted).toBe(0);
    expect(second.already_present).toBe(1);
  });

  test('a per-rule failure is reported without aborting the rest of the batch', async () => {
    const rules = [makeRule({ id: 'det_ok' }), { id: 'det_bad' } /* missing governance.version */, makeRule({ id: 'det_ok_2' })];
    const result = await versionStore.backfillCurrentVersions(rules);
    expect(result.attempted).toBe(3);
    expect(result.inserted).toBe(2);
    expect(result.failed.length).toBe(1);
    expect(result.failed[0].detection_id).toBe('det_bad');
  });
});
