'use strict';
/**
 * Unit tests for microsoft-sentinel-connector.js against a mocked
 * global.fetch — this proves the connector's REQUEST/RESPONSE handling
 * (URL construction, auth flow, error classification, severity mapping,
 * deterministic ruleId derivation) matches the documented Microsoft API
 * contract. It does NOT and cannot prove live Azure execution — see the
 * file's own header and the certification doc's "Vendor sandbox
 * verification" section for that honest limitation.
 */

const connector = require('../microsoft-sentinel-connector');

function jsonResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300, status,
    headers: { get: (k) => headers[k.toLowerCase()] || null },
    text: async () => JSON.stringify(body),
  };
}

const FIXTURE_CONNECTOR = {
  id: 'conn_1',
  target_config: { tenant_id: 't1', subscription_id: 's1', resource_group: 'rg1', workspace_name: 'ws1', client_id: 'c1' },
  credential: { client_secret: 'shh' },
};

beforeEach(() => {
  global.fetch = jest.fn();
});
afterEach(() => {
  delete global.fetch;
});

function mockTokenThenArm(armResponse) {
  global.fetch.mockImplementationOnce(async () => jsonResponse(200, { access_token: 'fake-token' }));
  global.fetch.mockImplementationOnce(async () => armResponse);
}

describe('deriveRuleId', () => {
  test('is deterministic for the same input', () => {
    expect(connector.deriveRuleId('sentinelapex-abc')).toBe(connector.deriveRuleId('sentinelapex-abc'));
  });
  test('differs for different input', () => {
    expect(connector.deriveRuleId('sentinelapex-abc')).not.toBe(connector.deriveRuleId('sentinelapex-xyz'));
  });
  test('looks like a UUID', () => {
    expect(connector.deriveRuleId('sentinelapex-abc')).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe('mapSeverity', () => {
  test.each([
    ['critical', 'High'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'],
    ['informational', 'Informational'], ['something-unrecognized', 'Medium'], [undefined, 'Medium'],
  ])('%s -> %s', (input, expected) => {
    expect(connector.mapSeverity(input)).toBe(expected);
  });
});

describe('testConnection', () => {
  test('CONNECTED on a successful token + list call', async () => {
    mockTokenThenArm(jsonResponse(200, { value: [] }));
    const result = await connector.testConnection(FIXTURE_CONNECTOR);
    expect(result.result).toBe('CONNECTED');
  });

  test('AUTH_FAILED when Azure AD rejects the credential', async () => {
    global.fetch.mockImplementationOnce(async () => jsonResponse(401, { error: 'invalid_client' }));
    const result = await connector.testConnection(FIXTURE_CONNECTOR);
    expect(result.result).toBe('AUTH_FAILED');
  });

  test('INSUFFICIENT_PERMISSION on a 403 from ARM', async () => {
    mockTokenThenArm(jsonResponse(403, { error: { code: 'AuthorizationFailed' } }));
    const result = await connector.testConnection(FIXTURE_CONNECTOR);
    expect(result.result).toBe('INSUFFICIENT_PERMISSION');
  });

  test('TARGET_NOT_FOUND on a 404 from ARM', async () => {
    mockTokenThenArm(jsonResponse(404, { error: { code: 'ResourceNotFound' } }));
    const result = await connector.testConnection(FIXTURE_CONNECTOR);
    expect(result.result).toBe('TARGET_NOT_FOUND');
  });

  test('never issues a mutating call — only ever GETs the collection', async () => {
    mockTokenThenArm(jsonResponse(200, { value: [] }));
    await connector.testConnection(FIXTURE_CONNECTOR);
    const armCall = global.fetch.mock.calls[1];
    expect(armCall[1].method === undefined || armCall[1].method === 'GET').toBe(true);
  });
});

describe('deploy', () => {
  test('PUTs the mapped payload and returns the remote id/etag', async () => {
    mockTokenThenArm(jsonResponse(201, { id: '/subscriptions/s1/.../alertRules/abc', etag: '"etag1"', properties: {} }));
    const intent = { remote_resource_name: 'sentinelapex-abc', detection_id: 'det_1', detection_version: '1.0.0', title: 'Rule', description: 'd', technique_id: 'T1490', severity_raw: 'high', query: 'X | where Y', enabled: false };
    const result = await connector.deploy(FIXTURE_CONNECTOR, intent);
    expect(result.remote_resource_id).toContain('/alertRules/');
    expect(result.remote_etag).toBe('"etag1"');
    const armCall = global.fetch.mock.calls[1];
    expect(armCall[1].method).toBe('PUT');
    const body = JSON.parse(armCall[1].body);
    expect(body.kind).toBe('Scheduled');
    expect(body.properties.query).toBe('X | where Y');
    expect(body.properties.enabled).toBe(false);
    expect(body.properties.techniques).toEqual(['T1490']);
  });

  test('a 429 from ARM is a retryable RATE_LIMITED error', async () => {
    mockTokenThenArm(jsonResponse(429, { error: { code: 'TooManyRequests' } }));
    const intent = { remote_resource_name: 'sentinelapex-abc', detection_id: 'det_1', detection_version: '1.0.0', title: 'Rule', description: 'd', technique_id: 'T1490', severity_raw: 'high', query: 'X', enabled: false };
    await expect(connector.deploy(FIXTURE_CONNECTOR, intent)).rejects.toMatchObject({ code: 'RATE_LIMITED', retryable: true, httpStatus: 429 });
  });

  test('a 500 from ARM is retryable', async () => {
    mockTokenThenArm(jsonResponse(500, { error: {} }));
    const intent = { remote_resource_name: 'sentinelapex-abc', detection_id: 'det_1', detection_version: '1.0.0', title: 'Rule', description: 'd', technique_id: 'T1490', severity_raw: 'high', query: 'X', enabled: false };
    await expect(connector.deploy(FIXTURE_CONNECTOR, intent)).rejects.toMatchObject({ retryable: true });
  });
});

describe('readBack', () => {
  test('returns found:false on a 404 (not an error)', async () => {
    mockTokenThenArm(jsonResponse(404, { error: {} }));
    const result = await connector.readBack(FIXTURE_CONNECTOR, 'sentinelapex-abc');
    expect(result.found).toBe(false);
  });

  test('normalizes techniques to a sorted array for stable hashing', async () => {
    mockTokenThenArm(jsonResponse(200, { id: 'x', etag: 'e', properties: { query: 'Q', severity: 'High', enabled: true, techniques: ['T1218.005', 'T1003.001'] } }));
    const result = await connector.readBack(FIXTURE_CONNECTOR, 'sentinelapex-abc');
    expect(result.observed.techniques).toEqual(['T1003.001', 'T1218.005']);
  });
});

describe('URL construction', () => {
  test('PUT targets the exact documented ARM resource path with the pinned api-version', async () => {
    mockTokenThenArm(jsonResponse(200, { id: 'x', etag: 'e', properties: {} }));
    const intent = { remote_resource_name: 'sentinelapex-abc', detection_id: 'det_1', detection_version: '1.0.0', title: 'Rule', description: 'd', technique_id: 'T1490', severity_raw: 'high', query: 'X', enabled: false };
    await connector.deploy(FIXTURE_CONNECTOR, intent);
    const url = global.fetch.mock.calls[1][0];
    const ruleId = connector.deriveRuleId('sentinelapex-abc');
    expect(url).toBe(
      `https://management.azure.com/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=${connector.API_VERSION}`
    );
  });
});

describe('never follows redirects', () => {
  test('every outbound fetch call sets redirect: "error"', async () => {
    mockTokenThenArm(jsonResponse(200, { value: [] }));
    await connector.testConnection(FIXTURE_CONNECTOR);
    for (const call of global.fetch.mock.calls) {
      expect(call[1].redirect).toBe('error');
    }
  });
});
