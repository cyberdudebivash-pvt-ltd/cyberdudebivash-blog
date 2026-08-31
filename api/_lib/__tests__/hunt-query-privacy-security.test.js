'use strict';
/**
 * SENTINEL APEX — Controlled Read-Only SIEM Hunting Connectors v1:
 * cross-cutting privacy/security assertions not already pinned down by
 * the per-module unit suites (hunt-query-engine.test.js, mock-siem-
 * connector.test.js, microsoft-sentinel-connector.test.js,
 * hunt-query-store.test.js, api/v1/__tests__/hunts.test.js). Those suites
 * already cover tenant isolation/IDOR per store and hostile-field
 * sanitization per connector in isolation; this file proves the SAME
 * guarantees hold end-to-end through the real engine, and that the two
 * structural boundaries the mandate treats as load-bearing (no SSRF via
 * a customer-controlled hostname, no remote telemetry ever reaching the
 * GLOBAL cross-tenant feedback aggregate) actually hold.
 */

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});
jest.mock('../detection-rules');
jest.mock('../detection-intelligence');
jest.mock('../defense-compatibility');
jest.mock('../defense-profile-store');
jest.mock('../deployment-store');
jest.mock('../intel', () => ({
  getDossierAPI: jest.fn(),
  getActorDetailAPI: jest.fn(),
  getIocDetailAPI: jest.fn(),
}));

process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = 'f'.repeat(64);

const detectionRules = require('../detection-rules');
const detectionIntelligence = require('../detection-intelligence');
const defenseCompatibility = require('../defense-compatibility');
const defenseProfileStore = require('../defense-profile-store');
const huntStore = require('../hunt-store');
const huntEngine = require('../hunt-engine');
const siemConnectorStore = require('../siem-connector-store');
const feedbackStore = require('../detection-feedback-store');
const mockSiemConnector = require('../connectors/mock-siem-connector');
const sentinelConnector = require('../connectors/microsoft-sentinel-connector');
const engine = require('../hunt-query-engine');

const OWNER_A = 'usr_privacy_a';

function fixtureRawRule(overrides = {}) {
  return { id: 'det_privacy', technique_id: 'T1490', title: 'Privacy Test Detection', governance: { status: 'GENERATED', version: '1.0.0' }, ...overrides };
}
function fixtureCanonical(overrides = {}) {
  return {
    status: 'RELEASED', version: '1.0.0', name: 'Privacy Test Detection',
    formats: { kql: { content: 'DeviceProcessEvents | where 1 == 1', maturity: 'Production Ready' } },
    attack: [{ id: 'T1490', evidence_state: 'SOURCE_ATTRIBUTED' }],
    ...overrides,
  };
}

beforeEach(() => {
  global.__fakeD1ForTest._reset();
  detectionRules.getRule.mockReset().mockImplementation((id) => fixtureRawRule({ id }));
  detectionIntelligence.classifyAttackEvidence.mockReset().mockReturnValue('SOURCE_ATTRIBUTED');
  detectionIntelligence.toCanonicalDetectionObject.mockReset().mockImplementation((rawRule) => fixtureCanonical({ detection_id: rawRule.id }));
  defenseCompatibility.evaluateDetectionCompatibility.mockReset().mockReturnValue({ status: 'READY', missing_telemetry: [], explanation: 'Ready.' });
  defenseProfileStore.getProfile.mockReset().mockResolvedValue({ profile: { technologies: [], telemetry: {} } });
});

describe('Privacy boundary: remote telemetry never reaches the GLOBAL cross-tenant feedback aggregate', () => {
  test('a result row containing sensitive-looking values never appears in computeGlobalReviewMetrics/computeFeedbackSignal output', async () => {
    const hunt = await huntEngine.createHuntFromContext(OWNER_A, { detectionId: 'det_privacy', createdBy: OWNER_A });
    const marker = `${mockSiemConnector.HUNT_SIMULATE_MARKER}${mockSiemConnector.HUNT_SIMULATE.ONE_RESULT}`;
    const queryId = await huntStore.addQuery(hunt.hunt_id, {
      sourceDetectionId: 'det_privacy', sourceDetectionVersion: '1.0.0', format: 'kql',
      querySnapshot: `DeviceProcessEvents ${marker}`, validationStatus: 'STRUCTURALLY_VALID', addedBy: OWNER_A,
    });
    const created = await siemConnectorStore.createConnector(OWNER_A, 'free', { platform: 'mock-siem', name: 'Privacy Connector', target_config: {} });

    const run = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, created.connector.id, {
      timeStart: '2026-08-01T00:00:00Z', timeEnd: '2026-08-02T00:00:00Z', rowLimit: 50, actor: OWNER_A,
    });
    expect(run.results.length).toBe(1);
    // The analyst explicitly selects the row as an observation (the one path any of this data can persist through).
    await huntStore.addObservation(hunt.hunt_id, {
      queryId, summary: 'Sandbox host matched hypothesis', createdBy: OWNER_A,
      executionId: run.execution_id, selectedFields: run.results[0].fields,
    });
    // Submit ordinary detection feedback (customer-authored classification/summary only).
    await huntEngine.submitDetectionFeedback(OWNER_A, {
      detectionId: 'det_privacy', huntId: hunt.hunt_id, classification: 'TRUE_POSITIVE',
      summary: 'Confirmed via hunt observation', createdBy: OWNER_A,
    });

    const globalMetrics = await feedbackStore.computeGlobalReviewMetrics('det_privacy', '1.0.0');
    const signal = await feedbackStore.computeFeedbackSignal('det_privacy', '1.0.0');
    const serialized = JSON.stringify({ globalMetrics, signal });
    // The observation's selected field values (sandbox-host-0, sandbox-user-0, etc.) must never
    // appear anywhere in the GLOBAL, cross-tenant-visible aggregate -- only counts/classifications do.
    expect(serialized).not.toContain('sandbox-host-0');
    expect(serialized).not.toContain('sandbox-user-0');
    expect(serialized).not.toContain(OWNER_A);
    expect(globalMetrics.distinct_owners_total).toBe(1);
  });

  test('a genuine QUERY_DEFECT feedback summary never echoes raw remote row data, only the connector\'s own defect description', async () => {
    const hunt = await huntEngine.createHuntFromContext(OWNER_A, { detectionId: 'det_privacy', createdBy: OWNER_A });
    const marker = `${mockSiemConnector.HUNT_SIMULATE_MARKER}${mockSiemConnector.HUNT_SIMULATE.QUERY_ERROR}`;
    const queryId = await huntStore.addQuery(hunt.hunt_id, {
      sourceDetectionId: 'det_privacy', sourceDetectionVersion: '1.0.0', format: 'kql',
      querySnapshot: `DeviceProcessEvents ${marker}`, validationStatus: 'STRUCTURALLY_VALID', addedBy: OWNER_A,
    });
    const created = await siemConnectorStore.createConnector(OWNER_A, 'free', { platform: 'mock-siem', name: 'Privacy Connector 2', target_config: {} });
    await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, created.connector.id, {
      timeStart: '2026-08-01T00:00:00Z', timeEnd: '2026-08-02T00:00:00Z', rowLimit: 50, actor: OWNER_A,
    });
    const feedback = await feedbackStore.listFeedbackForOwner(OWNER_A, { detectionId: 'det_privacy' });
    const queryErrorRow = feedback.find((f) => f.classification === 'QUERY_ERROR');
    expect(queryErrorRow).toBeTruthy();
    expect(queryErrorRow.summary).not.toMatch(/sandbox-host|sandbox-user/);
  });
});

describe('SSRF hardening: the hunting query URL is built ONLY from fixed Microsoft hostnames + workspace_id, never a customer-controlled host', () => {
  beforeEach(() => { global.fetch = jest.fn(); });
  afterEach(() => { delete global.fetch; });

  function jsonResponse(status, body) {
    return { ok: status >= 200 && status < 300, status, headers: { get: () => null }, text: async () => JSON.stringify(body) };
  }

  test('a hostile workspace_id (containing a URL/host-like payload) is percent-encoded into the path, never interpreted as a redirect target', async () => {
    global.fetch.mockImplementation(async () => jsonResponse(200, { access_token: 'tok' }));
    const connector = {
      id: 'conn_ssrf', target_config: {
        tenant_id: 't1', subscription_id: 's1', resource_group: 'rg1', workspace_name: 'ws1', client_id: 'c1',
        workspace_id: 'evil.attacker.example/../../admin',
      },
      credential: { client_secret: 'shh' },
    };
    global.fetch.mockImplementationOnce(async () => jsonResponse(200, { access_token: 'tok' }));
    global.fetch.mockImplementationOnce(async () => jsonResponse(200, { tables: [{ name: 'PrimaryResult', columns: [{ name: 'x' }], rows: [] }] }));
    await sentinelConnector.executeHuntQuery(connector, { query: 'X | take 1', format: 'kql', timeStart: '2026-08-01T00:00:00Z', timeEnd: '2026-08-02T00:00:00Z', rowLimit: 10 });
    const calledUrl = global.fetch.mock.calls[1][0];
    expect(calledUrl.startsWith('https://api.loganalytics.azure.com/v1/workspaces/')).toBe(true);
    expect(calledUrl).not.toContain('evil.attacker.example/../../admin'); // must be percent-encoded, not a raw path segment
    expect(new URL(calledUrl).hostname).toBe('api.loganalytics.azure.com'); // the request always targets Microsoft's fixed hostname, regardless of workspace_id content
  });
});

describe('Hostile remote data survives the FULL engine pipeline (not just the connector in isolation) without polluting global state', () => {
  test('a HOSTILE_FIELDS run through the real engine never creates an own "__proto__"/"constructor" property anywhere, and never pollutes Object.prototype', async () => {
    const hunt = await huntEngine.createHuntFromContext(OWNER_A, { detectionId: 'det_privacy', createdBy: OWNER_A });
    const marker = `${mockSiemConnector.HUNT_SIMULATE_MARKER}${mockSiemConnector.HUNT_SIMULATE.HOSTILE_FIELDS}`;
    const queryId = await huntStore.addQuery(hunt.hunt_id, {
      sourceDetectionId: 'det_privacy', sourceDetectionVersion: '1.0.0', format: 'kql',
      querySnapshot: `DeviceProcessEvents ${marker}`, validationStatus: 'STRUCTURALLY_VALID', addedBy: OWNER_A,
    });
    const created = await siemConnectorStore.createConnector(OWNER_A, 'free', { platform: 'mock-siem', name: 'Hostile Connector', target_config: {} });
    const run = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, created.connector.id, {
      timeStart: '2026-08-01T00:00:00Z', timeEnd: '2026-08-02T00:00:00Z', rowLimit: 50, actor: OWNER_A,
    });
    expect(run.results.length).toBe(1);
    expect(Object.prototype.hasOwnProperty.call(run.results[0].fields, '__proto__')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(run.results[0].fields, 'constructor')).toBe(false);
    expect(({}).polluted).toBeUndefined();

    // Persisting it as an observation must be equally safe end-to-end.
    await huntStore.addObservation(hunt.hunt_id, {
      queryId, summary: 'Hostile field test', createdBy: OWNER_A,
      executionId: run.execution_id, selectedFields: run.results[0].fields,
    });
    const observations = await huntStore.listObservations(hunt.hunt_id);
    expect(Object.prototype.hasOwnProperty.call(observations[0].selected_fields_json, '__proto__')).toBe(false);
    expect(({}).polluted).toBeUndefined();
  });
});
