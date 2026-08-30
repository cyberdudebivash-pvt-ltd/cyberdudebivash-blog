'use strict';
/**
 * SENTINEL APEX — Detection Performance Intelligence v1: deployment-
 * store.js#countDeploymentsByDetection() only. deployment-store.js's own
 * pre-existing CRUD surface is already exercised end-to-end through
 * deployment-engine.test.js/deployments.test.js -- this file adds
 * coverage for exactly the one new, additive function this tranche
 * introduces, not a re-test of everything else in the module.
 */

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const deploymentStore = require('../deployment-store');

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

async function seedDeployment(ownerId, detectionId, state) {
  await deploymentStore.createDraftDeployment(ownerId, {
    connectorId: 'conn_1', detectionId, detectionVersion: '1.0.0', entityType: 'cve', entityId: 'CVE-2024-0001', format: 'kql',
  });
  const [row] = await deploymentStore.listDeployments(ownerId);
  await deploymentStore.updateDeployment(row.deployment_id, { state });
  return row.deployment_id;
}

describe('countDeploymentsByDetection — GLOBAL, count-only, cross-tenant safe', () => {
  test('counts distinct owners with a LIVE deployment of this detection, ignoring other detections', async () => {
    await seedDeployment('usr_a', 'det_x', 'DEPLOYED');
    await seedDeployment('usr_b', 'det_x', 'VERIFIED');
    await seedDeployment('usr_c', 'det_other', 'DEPLOYED');

    const result = await deploymentStore.countDeploymentsByDetection('det_x');
    expect(result.total).toBe(2);
    expect(result.distinct_owners).toBe(2);
  });

  test('excludes terminal (non-live) states -- a disabled/failed deployment does not count as currently affected', async () => {
    await seedDeployment('usr_a', 'det_y', 'DEPLOYED');
    await seedDeployment('usr_b', 'det_y', 'DISABLED');

    const result = await deploymentStore.countDeploymentsByDetection('det_y');
    expect(result.total).toBe(1);
    expect(result.distinct_owners).toBe(1);
  });

  test('returns zero counts, never throws, for a detection with no deployments at all', async () => {
    const result = await deploymentStore.countDeploymentsByDetection('det_never_deployed');
    expect(result).toEqual({ total: 0, distinct_owners: 0 });
  });

  test('never returns an owner_id or any per-deployment identifying field -- counts only', async () => {
    await seedDeployment('usr_a', 'det_z', 'DEPLOYED');
    const result = await deploymentStore.countDeploymentsByDetection('det_z');
    expect(Object.keys(result).sort()).toEqual(['distinct_owners', 'total']);
    expect(JSON.stringify(result)).not.toContain('usr_a');
  });
});
