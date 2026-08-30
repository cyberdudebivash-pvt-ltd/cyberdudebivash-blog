'use strict';
/**
 * SENTINEL APEX — Controlled Read-Only SIEM Hunting: hunt-query-store.js
 *
 * Pure persistence tests against fake-d1, mirroring hunt-store.test.js's
 * exact conventions. Orchestration (readiness/bounds/connector dispatch)
 * is covered separately in hunt-query-engine.test.js.
 */

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const store = require('../hunt-query-store');

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

const OWNER_A = 'usr_a';
const OWNER_B = 'usr_b';

function fixtureArgs(overrides = {}) {
  return {
    huntId: 'hunt_1', queryId: 'hq_1', connectorId: 'conn_1', detectionId: 'det_1', detectionVersion: '1.0.0',
    format: 'kql', timeStart: '2026-08-01T00:00:00Z', timeEnd: '2026-08-02T00:00:00Z', rowLimit: 50,
    ...overrides,
  };
}

describe('createExecution / getExecution', () => {
  test('creates a RUNNING row with no result yet', async () => {
    const executionId = await store.createExecution(OWNER_A, fixtureArgs());
    const execution = await store.getExecution(OWNER_A, executionId);
    expect(execution.state).toBe('RUNNING');
    expect(execution.result_row_count).toBeNull();
    expect(execution.completed_at).toBeNull();
    expect(execution.hunt_id).toBe('hunt_1');
  });

  test('another owner cannot read this execution (tenant isolation)', async () => {
    const executionId = await store.createExecution(OWNER_A, fixtureArgs());
    expect(await store.getExecution(OWNER_B, executionId)).toBeNull();
  });

  test('an unknown execution_id returns null, not an error', async () => {
    expect(await store.getExecution(OWNER_A, 'hqx_does_not_exist')).toBeNull();
  });
});

describe('completeExecution', () => {
  test('moves a RUNNING row to its terminal state with a result count', async () => {
    const executionId = await store.createExecution(OWNER_A, fixtureArgs());
    await store.completeExecution(executionId, { state: 'SUCCEEDED', resultRowCount: 3 });
    const execution = await store.getExecution(OWNER_A, executionId);
    expect(execution.state).toBe('SUCCEEDED');
    expect(execution.result_row_count).toBe(3);
    expect(execution.completed_at).toBeTruthy();
  });

  test('records error_code/error_classification on a failure', async () => {
    const executionId = await store.createExecution(OWNER_A, fixtureArgs());
    await store.completeExecution(executionId, { state: 'FAILED', resultRowCount: null, errorCode: 'QUERY_REJECTED', errorClassification: 'QUERY_DEFECT' });
    const execution = await store.getExecution(OWNER_A, executionId);
    expect(execution.state).toBe('FAILED');
    expect(execution.result_row_count).toBeNull();
    expect(execution.error_code).toBe('QUERY_REJECTED');
    expect(execution.error_classification).toBe('QUERY_DEFECT');
  });
});

describe('listExecutionsForHunt', () => {
  test('lists only this owner\'s executions for the given hunt, newest first', async () => {
    const id1 = await store.createExecution(OWNER_A, fixtureArgs());
    await new Promise((r) => setTimeout(r, 2));
    const id2 = await store.createExecution(OWNER_A, fixtureArgs());
    const executions = await store.listExecutionsForHunt(OWNER_A, 'hunt_1');
    expect(executions.map((e) => e.execution_id)).toEqual([id2, id1]);
  });

  test('another owner\'s executions for the same hunt_id are never returned (tenant isolation)', async () => {
    await store.createExecution(OWNER_B, fixtureArgs());
    const executions = await store.listExecutionsForHunt(OWNER_A, 'hunt_1');
    expect(executions).toEqual([]);
  });

  test('a different hunt_id for the same owner is excluded', async () => {
    await store.createExecution(OWNER_A, fixtureArgs({ huntId: 'hunt_other' }));
    const executions = await store.listExecutionsForHunt(OWNER_A, 'hunt_1');
    expect(executions).toEqual([]);
  });
});
