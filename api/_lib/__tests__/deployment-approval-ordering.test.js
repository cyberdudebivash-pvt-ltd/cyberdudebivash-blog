'use strict';

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForApprovalOrderingTest = instance;
  return instance;
});

const deploymentStore = require('../deployment-store');

beforeEach(() => {
  global.__fakeD1ForApprovalOrderingTest._reset();
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('latest approval remains deterministic when wall clock does not advance', async () => {
  const fixedMs = Date.parse('2026-09-01T09:00:00.000Z');
  jest.spyOn(Date, 'now').mockReturnValue(fixedMs);

  const base = {
    detectionVersion: '1.0.0',
    connectorId: 'conn_test',
    targetConfigHash: 'target-hash',
    enabledRequested: false,
  };

  await deploymentStore.recordApproval('dep_test', 'usr_a', {
    ...base,
    approvedHash: 'hash-v1',
  });
  await deploymentStore.recordApproval('dep_test', 'usr_a', {
    ...base,
    detectionVersion: '2.0.0',
    approvedHash: 'hash-v2',
  });
  await deploymentStore.recordApproval('dep_test', 'usr_a', {
    ...base,
    detectionVersion: '1.0.0',
    approvedHash: 'hash-rollback-v1',
  });

  const rows = global.__fakeD1ForApprovalOrderingTest._dump().deploymentApprovals;
  expect(rows).toHaveLength(3);
  expect(Date.parse(rows[1].created_at)).toBeGreaterThan(Date.parse(rows[0].created_at));
  expect(Date.parse(rows[2].created_at)).toBeGreaterThan(Date.parse(rows[1].created_at));

  const latest = await deploymentStore.getLatestApproval('dep_test');
  expect(latest.approved_hash).toBe('hash-rollback-v1');
  expect(latest.detection_version).toBe('1.0.0');
});
