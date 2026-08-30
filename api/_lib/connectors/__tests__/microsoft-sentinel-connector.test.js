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

const FIXTURE_CONNECTOR_WITH_HUNTING = {
  ...FIXTURE_CONNECTOR,
  target_config: { ...FIXTURE_CONNECTOR.target_config, workspace_id: 'ws-guid-1234' },
};

const HUNT_BOUNDS = { query: 'DeviceProcessEvents | take 10', format: 'kql', timeStart: '2026-08-29T00:00:00Z', timeEnd: '2026-08-30T00:00:00Z', rowLimit: 50 };

function mockTokenThenLogAnalytics(response) {
  global.fetch.mockImplementationOnce(async () => jsonResponse(200, { access_token: 'fake-hunt-token' }));
  global.fetch.mockImplementationOnce(async () => response);
}

function logAnalyticsTableResponse(columns, rows) {
  return jsonResponse(200, { tables: [{ name: 'PrimaryResult', columns: columns.map(name => ({ name, type: 'string' })), rows }] });
}

describe('testHuntQueryConnection', () => {
  test('UNAVAILABLE when the connector has no workspace_id configured — never attempts a call', async () => {
    const result = await connector.testHuntQueryConnection(FIXTURE_CONNECTOR);
    expect(result.result).toBe('UNAVAILABLE');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('CONNECTED on a successful token + minimal query call', async () => {
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['Column1'], [[1]]));
    const result = await connector.testHuntQueryConnection(FIXTURE_CONNECTOR_WITH_HUNTING);
    expect(result.result).toBe('CONNECTED');
  });

  test('requests a genuinely different OAuth scope than deploy/testConnection', async () => {
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['Column1'], [[1]]));
    await connector.testHuntQueryConnection(FIXTURE_CONNECTOR_WITH_HUNTING);
    const tokenCallBody = global.fetch.mock.calls[0][1].body;
    expect(tokenCallBody).toContain('scope=https%3A%2F%2Fapi.loganalytics.io%2F.default');
    expect(tokenCallBody).not.toContain('management.azure.com');
  });

  test('AUTH_FAILED when Azure AD rejects the credential', async () => {
    global.fetch.mockImplementationOnce(async () => jsonResponse(401, { error: 'invalid_client' }));
    const result = await connector.testHuntQueryConnection(FIXTURE_CONNECTOR_WITH_HUNTING);
    expect(result.result).toBe('AUTH_FAILED');
  });

  test('INSUFFICIENT_PERMISSION on a 403 (missing Reader role)', async () => {
    mockTokenThenLogAnalytics(jsonResponse(403, { error: { code: 'AuthorizationFailed' } }));
    const result = await connector.testHuntQueryConnection(FIXTURE_CONNECTOR_WITH_HUNTING);
    expect(result.result).toBe('INSUFFICIENT_PERMISSION');
  });

  test('TARGET_NOT_FOUND on a 404 (bad workspace_id)', async () => {
    mockTokenThenLogAnalytics(jsonResponse(404, { error: { code: 'WorkspaceNotFound' } }));
    const result = await connector.testHuntQueryConnection(FIXTURE_CONNECTOR_WITH_HUNTING);
    expect(result.result).toBe('TARGET_NOT_FOUND');
  });

  test('targets the workspace_id GUID, never the ARM workspace_name, in the URL', async () => {
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['Column1'], [[1]]));
    await connector.testHuntQueryConnection(FIXTURE_CONNECTOR_WITH_HUNTING);
    const url = global.fetch.mock.calls[1][0];
    expect(url).toBe('https://api.loganalytics.azure.com/v1/workspaces/ws-guid-1234/query');
  });
});

describe('executeHuntQuery — rejected before any remote call', () => {
  test('rejects a non-kql format as QUERY_REJECTED', async () => {
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, { ...HUNT_BOUNDS, format: 'splunk' }))
      .rejects.toMatchObject({ code: 'QUERY_REJECTED' });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('rejects a non-positive rowLimit as QUERY_REJECTED', async () => {
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, { ...HUNT_BOUNDS, rowLimit: 0 }))
      .rejects.toMatchObject({ code: 'QUERY_REJECTED' });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('rejects a missing time range as QUERY_REJECTED, never an unbounded historical query', async () => {
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, { ...HUNT_BOUNDS, timeStart: null }))
      .rejects.toMatchObject({ code: 'QUERY_REJECTED' });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('rejects a connector with no workspace_id configured as QUERY_REJECTED', async () => {
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR, HUNT_BOUNDS)).rejects.toMatchObject({ code: 'QUERY_REJECTED' });
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('executeHuntQuery — request construction', () => {
  test('sends query and timespan as separate native fields, never string-concatenated', async () => {
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['Column1'], [[1]]));
    await connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS);
    const body = JSON.parse(global.fetch.mock.calls[1][1].body);
    expect(body.query).toBe(HUNT_BOUNDS.query); // query text is untouched -- no time range spliced in
    expect(body.timespan).toBe(`${HUNT_BOUNDS.timeStart}/${HUNT_BOUNDS.timeEnd}`);
  });

  test('POSTs to the workspace-scoped Log Analytics query endpoint', async () => {
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['Column1'], [[1]]));
    await connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS);
    expect(global.fetch.mock.calls[1][0]).toBe('https://api.loganalytics.azure.com/v1/workspaces/ws-guid-1234/query');
    expect(global.fetch.mock.calls[1][1].method).toBe('POST');
  });
});

describe('executeHuntQuery — response handling', () => {
  test('maps columns/rows into row objects keyed by column name', async () => {
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['DeviceName', 'FileName'], [['host-1', 'evil.exe'], ['host-2', 'powershell.exe']]));
    const result = await connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS);
    expect(result.rows).toEqual([{ DeviceName: 'host-1', FileName: 'evil.exe' }, { DeviceName: 'host-2', FileName: 'powershell.exe' }]);
    expect(result.truncated).toBe(false);
  });

  test('zero rows -> empty array, never fabricated', async () => {
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['DeviceName'], []));
    const result = await connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS);
    expect(result.rows).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  test('a result set over rowLimit stays bounded and reports truncated: true', async () => {
    const rows = Array.from({ length: 300 }, (_, i) => [`host-${i}`]);
    mockTokenThenLogAnalytics(logAnalyticsTableResponse(['DeviceName'], rows));
    const result = await connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, { ...HUNT_BOUNDS, rowLimit: 50 });
    expect(result.rows.length).toBe(50);
    expect(result.truncated).toBe(true);
  });

  test('a 429 is a retryable RATE_LIMITED error', async () => {
    mockTokenThenLogAnalytics(jsonResponse(429, { error: { code: 'TooManyRequests' } }));
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS)).rejects.toMatchObject({ code: 'RATE_LIMITED', retryable: true, httpStatus: 429 });
  });

  test('a 500 is retryable', async () => {
    mockTokenThenLogAnalytics(jsonResponse(500, { error: {} }));
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS)).rejects.toMatchObject({ code: 'REMOTE_ERROR', retryable: true });
  });

  test('a 403 is a non-retryable PERMISSION_DENIED (missing Reader role)', async () => {
    mockTokenThenLogAnalytics(jsonResponse(403, { error: {} }));
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS)).rejects.toMatchObject({ code: 'PERMISSION_DENIED', retryable: false });
  });

  test('a 2xx response missing the documented {tables} shape is a REMOTE_ERROR, never silent-empty-success', async () => {
    mockTokenThenLogAnalytics(jsonResponse(200, { unexpected: true }));
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS)).rejects.toMatchObject({ code: 'REMOTE_ERROR' });
  });

  test('a 400 (invalid KQL / unknown table-column) is classified QUERY_REJECTED, not a generic provider error -- this is what lets a genuine query defect route to QUERY_ERROR detection feedback', async () => {
    mockTokenThenLogAnalytics(jsonResponse(400, { error: { code: 'BadArgumentError', message: "'Foo' does not refer to any known table" } }));
    await expect(connector.executeHuntQuery(FIXTURE_CONNECTOR_WITH_HUNTING, HUNT_BOUNDS)).rejects.toMatchObject({ code: 'QUERY_REJECTED', retryable: false });
  });
});

describe('normalizeResults', () => {
  test('delegates to the shared connector-contract envelope', () => {
    const normalized = connector.normalizeResults(FIXTURE_CONNECTOR_WITH_HUNTING, [{ DeviceName: 'host-1' }]);
    expect(normalized).toEqual([{ fields: { DeviceName: 'host-1' }, source_row_index: 0 }]);
  });

  test('strips a hostile __proto__ own-property key and never pollutes Object.prototype', () => {
    const hostileRow = { DeviceName: 'host-1' };
    Object.defineProperty(hostileRow, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true });
    const normalized = connector.normalizeResults(FIXTURE_CONNECTOR_WITH_HUNTING, [hostileRow]);
    expect(Object.prototype.hasOwnProperty.call(normalized[0].fields, '__proto__')).toBe(false);
    expect(({}).polluted).toBeUndefined();
  });
});
