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

describe('testHuntQueryConnection', () => {
  test('CONNECTED by default', async () => {
    const result = await connector.testHuntQueryConnection({ target_config: {} });
    expect(result.result).toBe('CONNECTED');
  });
  for (const [sim, expected] of [['AUTH_FAILED', 'AUTH_FAILED'], ['PERMISSION_DENIED', 'INSUFFICIENT_PERMISSION'], ['TARGET_NOT_FOUND', 'TARGET_NOT_FOUND'], ['UNAVAILABLE', 'UNAVAILABLE']]) {
    test(`simulate=${sim} -> ${expected}`, async () => {
      const result = await connector.testHuntQueryConnection({ target_config: { simulate: sim } });
      expect(result.result).toBe(expected);
    });
  }
});

describe('executeHuntQuery — connector-level failures', () => {
  const c = { id: 'conn_1', target_config: {} };
  const bounds = { query: 'DeviceProcessEvents | take 10', format: 'kql', timeStart: '2026-08-29T00:00:00Z', timeEnd: '2026-08-30T00:00:00Z', rowLimit: 50 };

  for (const [sim, code, retryable] of [
    ['AUTH_FAILED', 'AUTH_FAILED', false],
    ['PERMISSION_DENIED', 'PERMISSION_DENIED', false],
    ['RATE_LIMITED', 'RATE_LIMITED', true],
    ['SERVER_ERROR', 'REMOTE_ERROR', true],
    ['TIMEOUT', 'TIMEOUT', true],
  ]) {
    test(`simulate=${sim} throws ConnectorError code=${code}`, async () => {
      await expect(connector.executeHuntQuery({ id: 'conn_1', target_config: { simulate: sim } }, bounds))
        .rejects.toMatchObject({ code, retryable });
    });
  }

  test('rejects a non-positive rowLimit as QUERY_REJECTED, never silently unbounded', async () => {
    await expect(connector.executeHuntQuery(c, { ...bounds, rowLimit: 0 })).rejects.toMatchObject({ code: 'QUERY_REJECTED' });
    await expect(connector.executeHuntQuery(c, { ...bounds, rowLimit: -5 })).rejects.toMatchObject({ code: 'QUERY_REJECTED' });
  });

  test('rejects a missing time range as QUERY_REJECTED, never an unbounded historical query', async () => {
    await expect(connector.executeHuntQuery(c, { ...bounds, timeStart: null })).rejects.toMatchObject({ code: 'QUERY_REJECTED' });
    await expect(connector.executeHuntQuery(c, { ...bounds, timeEnd: undefined })).rejects.toMatchObject({ code: 'QUERY_REJECTED' });
  });
});

describe('executeHuntQuery — deterministic result-shape scenarios', () => {
  const c = { id: 'conn_1', target_config: {} };
  const bounds = { format: 'kql', timeStart: '2026-08-29T00:00:00Z', timeEnd: '2026-08-30T00:00:00Z', rowLimit: 50 };
  const { HUNT_SIMULATE_MARKER, HUNT_SIMULATE } = connector;

  test('no marker -> zero rows (NO_SIGNAL), never fabricated activity', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, query: 'DeviceProcessEvents | take 10' });
    expect(result.rows).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  test('ZERO_RESULTS marker -> zero rows', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.ZERO_RESULTS}` });
    expect(result.rows).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  test('ONE_RESULT marker -> exactly one row', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.ONE_RESULT}` });
    expect(result.rows.length).toBe(1);
    expect(result.truncated).toBe(false);
  });

  test('HUNDRED_RESULTS marker -> exactly 100 rows, within a 50 rowLimit stays bounded', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, rowLimit: 50, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.HUNDRED_RESULTS}` });
    expect(result.rows.length).toBe(50);
    expect(result.truncated).toBe(true);
  });

  test('HUNDRED_RESULTS marker fits entirely under a 200 rowLimit -> not truncated', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, rowLimit: 200, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.HUNDRED_RESULTS}` });
    expect(result.rows.length).toBe(100);
    expect(result.truncated).toBe(false);
  });

  test('OVER_LIMIT marker -> the app stays bounded at rowLimit and reports truncated', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, rowLimit: 25, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.OVER_LIMIT}` });
    expect(result.rows.length).toBe(25);
    expect(result.truncated).toBe(true);
  });
});

describe('executeHuntQuery — simulated genuine query defect', () => {
  const c = { id: 'conn_1', target_config: {} };
  const bounds = { format: 'kql', timeStart: '2026-08-29T00:00:00Z', timeEnd: '2026-08-30T00:00:00Z', rowLimit: 50 };
  const { HUNT_SIMULATE_MARKER, HUNT_SIMULATE } = connector;

  test('QUERY_ERROR marker throws a non-retryable QUERY_REJECTED, the one code the feedback router treats as a genuine detection defect', async () => {
    await expect(connector.executeHuntQuery(c, { ...bounds, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.QUERY_ERROR}` }))
      .rejects.toMatchObject({ code: 'QUERY_REJECTED', retryable: false });
  });
});

describe('normalizeResults — malformed schema and hostile fields', () => {
  const c = { id: 'conn_1', target_config: {} };
  const bounds = { format: 'kql', timeStart: '2026-08-29T00:00:00Z', timeEnd: '2026-08-30T00:00:00Z', rowLimit: 50 };
  const { HUNT_SIMULATE_MARKER, HUNT_SIMULATE } = connector;

  test('a malformed vendor response is normalized without throwing, dropping what cannot be safely interpreted', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.MALFORMED_SCHEMA}` });
    expect(() => connector.normalizeResults(c, result.rows)).not.toThrow();
    const normalized = connector.normalizeResults(c, result.rows);
    // 'not-an-object' and null are structurally dropped; the object row
    // survives with zero usable fields (its only field's value was itself
    // an object, never carried through) -- observable, not silently lost.
    expect(normalized).toEqual([{ fields: {}, source_row_index: 0 }]);
  });

  test('hostile field values (XSS string, __proto__/constructor field names, a real own "__proto__" data property) normalize to inert primitives with dangerous keys stripped, and never pollute Object.prototype', async () => {
    const result = await connector.executeHuntQuery(c, { ...bounds, query: `q ${HUNT_SIMULATE_MARKER}${HUNT_SIMULATE.HOSTILE_FIELDS}` });
    const normalized = connector.normalizeResults(c, result.rows);
    expect(normalized.length).toBe(1);
    const { fields } = normalized[0];
    expect(fields.host).toBe('<script>alert(1)</script>'); // carried through as inert data -- rendering layer is responsible for escaping
    expect(fields.user).toBe('__proto__'); // a *value* of "__proto__" is harmless data, only the *key* is dangerous
    expect(fields.detail).toBe('"; DROP TABLE hunt_observations; --');
    expect(Object.prototype.hasOwnProperty.call(fields, '__proto__')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(fields, 'constructor')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(fields, 'prototype')).toBe(false);
    expect(({}).polluted).toBeUndefined(); // global Object.prototype was never touched
  });

  test('non-array input normalizes to an empty array rather than throwing', () => {
    expect(connector.normalizeResults(c, null)).toEqual([]);
    expect(connector.normalizeResults(c, 'not-an-array')).toEqual([]);
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
