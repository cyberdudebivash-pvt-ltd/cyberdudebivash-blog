'use strict';

jest.mock('../../d1', () => {
  const { createFakeD1 } = require('../../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const connector = require('../mock-siem-connector');

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

function fixtureIntent(overrides = {}) {
  return {
    remote_resource_name: 'sentinelapex-abc123', detection_id: 'det_1', detection_version: '1.0.0',
    title: 'Test Rule', description: 'desc', technique_id: 'T1490', severity_raw: 'high',
    format: 'kql', query: 'DeviceProcessEvents | where 1 == 1', enabled: false,
    ...overrides,
  };
}

describe('testConnection', () => {
  test('CONNECTED by default', async () => {
    const result = await connector.testConnection({ target_config: {} });
    expect(result.result).toBe('CONNECTED');
  });
  for (const [sim, expected] of [['AUTH_FAILED', 'AUTH_FAILED'], ['PERMISSION_DENIED', 'INSUFFICIENT_PERMISSION'], ['TARGET_NOT_FOUND', 'TARGET_NOT_FOUND'], ['UNAVAILABLE', 'UNAVAILABLE']]) {
    test(`simulate=${sim} -> ${expected}`, async () => {
      const result = await connector.testConnection({ target_config: { simulate: sim } });
      expect(result.result).toBe(expected);
    });
  }
});

describe('deploy / readBack idempotency', () => {
  test('deploying twice with the same intent updates the same remote resource, not a duplicate', async () => {
    const c = { id: 'conn_1', target_config: {} };
    const intent = fixtureIntent();
    const first = await connector.deploy(c, intent);
    const second = await connector.deploy(c, intent);
    expect(first.remote_resource_id).toBe(second.remote_resource_id);

    const dump = global.__fakeD1ForTest._dump();
    expect(dump.mockSiemResources.size).toBe(1);
  });

  test('readBack reflects exactly what was deployed, in canonical shape', async () => {
    const c = { id: 'conn_1', target_config: {} };
    const intent = fixtureIntent({ enabled: true });
    await connector.deploy(c, intent);
    const back = await connector.readBack(c, intent.remote_resource_name);
    expect(back.found).toBe(true);
    expect(back.observed).toEqual({ query: intent.query, severity: 'high', enabled: true, techniques: ['T1490'] });
  });

  test('readBack on a never-deployed resource reports not found, not an error', async () => {
    const c = { id: 'conn_1', target_config: {} };
    const back = await connector.readBack(c, 'sentinelapex-does-not-exist');
    expect(back.found).toBe(false);
    expect(back.observed).toBeNull();
  });
});

describe('failure simulation', () => {
  test('RATE_LIMITED deploy throws a retryable ConnectorError with no resource created', async () => {
    const c = { id: 'conn_1', target_config: { simulate: 'RATE_LIMITED' } };
    await expect(connector.deploy(c, fixtureIntent())).rejects.toMatchObject({ code: 'RATE_LIMITED', retryable: true, httpStatus: 429 });
    const dump = global.__fakeD1ForTest._dump();
    expect(dump.mockSiemResources.size).toBe(0);
  });

  test('SERVER_ERROR deploy throws a retryable ConnectorError', async () => {
    const c = { id: 'conn_1', target_config: { simulate: 'SERVER_ERROR' } };
    await expect(connector.deploy(c, fixtureIntent())).rejects.toMatchObject({ code: 'REMOTE_ERROR', retryable: true });
  });

  test('TIMEOUT deploy throws before writing anything', async () => {
    const c = { id: 'conn_1', target_config: { simulate: 'TIMEOUT' } };
    await expect(connector.deploy(c, fixtureIntent())).rejects.toMatchObject({ code: 'TIMEOUT', retryable: true });
    const dump = global.__fakeD1ForTest._dump();
    expect(dump.mockSiemResources.size).toBe(0);
  });

  test('TIMEOUT_AFTER_CREATE deploy throws AFTER the resource is actually written — the reconciliation scenario', async () => {
    const c = { id: 'conn_1', target_config: { simulate: 'TIMEOUT_AFTER_CREATE' } };
    await expect(connector.deploy(c, fixtureIntent())).rejects.toMatchObject({ code: 'TIMEOUT', retryable: true });
    const back = await connector.readBack({ id: 'conn_1', target_config: {} }, fixtureIntent().remote_resource_name);
    expect(back.found).toBe(true); // the write DID happen despite the thrown error
  });
});

describe('disable / delete', () => {
  test('disable sets enabled:false without deleting the resource', async () => {
    const c = { id: 'conn_1', target_config: {} };
    const intent = fixtureIntent({ enabled: true });
    await connector.deploy(c, intent);
    const result = await connector.disable(c, intent.remote_resource_name);
    expect(result.ok).toBe(true);
    const back = await connector.readBack(c, intent.remote_resource_name);
    expect(back.found).toBe(true);
    expect(back.observed.enabled).toBe(false);
  });

  test('deleteRemote actually removes the resource', async () => {
    const c = { id: 'conn_1', target_config: {} };
    const intent = fixtureIntent();
    await connector.deploy(c, intent);
    await connector.deleteRemote(c, intent.remote_resource_name);
    const back = await connector.readBack(c, intent.remote_resource_name);
    expect(back.found).toBe(false);
  });
});

describe('out-of-band drift simulation helper', () => {
  test('_simulateOutOfBandChange mutates the stored resource directly, independent of deploy()', async () => {
    const c = { id: 'conn_1', target_config: {} };
    const intent = fixtureIntent();
    await connector.deploy(c, intent);
    await connector._simulateOutOfBandChange('conn_1', intent.remote_resource_name, { query: 'admin edited this' });
    const back = await connector.readBack(c, intent.remote_resource_name);
    expect(back.observed.query).toBe('admin edited this');
  });
});

describe('connector isolation by connector_id', () => {
  test('two different connectors deploying the same resource name do not collide', async () => {
    const intent = fixtureIntent();
    await connector.deploy({ id: 'conn_A', target_config: {} }, intent);
    await connector.deploy({ id: 'conn_B', target_config: {} }, { ...intent, query: 'different query for B' });
    const backA = await connector.readBack({ id: 'conn_A', target_config: {} }, intent.remote_resource_name);
    const backB = await connector.readBack({ id: 'conn_B', target_config: {} }, intent.remote_resource_name);
    expect(backA.observed.query).toBe(intent.query);
    expect(backB.observed.query).toBe('different query for B');
  });
});
