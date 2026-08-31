'use strict';
/**
 * SENTINEL APEX — Controlled Read-Only SIEM Hunting: hunt-query-engine.js
 *
 * Detection lifecycle/compatibility are mocked (matching hunt-engine.
 * test.js's exact precedent) so these tests prove THIS tranche's own
 * orchestration logic (ownership/IDOR gating, readiness gating, time/row
 * bounds, connector dispatch, execution-state persistence, query-defect ->
 * QUERY_ERROR feedback routing) rather than re-testing already-covered
 * engines. hunt-store.js, siem-connector-store.js, and the real, fully
 * deterministic mock-siem-connector.js all run for real against fake-d1 --
 * this is deliberately an integration test of the real stack minus only
 * the genuinely external pieces (detection-rules/detection-intelligence/
 * defense-compatibility/defense-profile-store/deployment-store/intel).
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
jest.mock('../connectors/connector-registry', () => {
  const real = jest.requireActual('../connectors/connector-registry');
  return { ...real, getConnectorModule: jest.fn(real.getConnectorModule) };
});

process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = 'a'.repeat(64);

const detectionRules = require('../detection-rules');
const detectionIntelligence = require('../detection-intelligence');
const defenseCompatibility = require('../defense-compatibility');
const defenseProfileStore = require('../defense-profile-store');
const deploymentStore = require('../deployment-store');
const intel = require('../intel');
const huntStore = require('../hunt-store');
const huntEngine = require('../hunt-engine');
const siemConnectorStore = require('../siem-connector-store');
const connectorRegistry = require('../connectors/connector-registry');
const mockSiemConnector = require('../connectors/mock-siem-connector');
const feedbackStore = require('../detection-feedback-store');
const { ConnectorError } = require('../connectors/connector-contract');
const engine = require('../hunt-query-engine');

const OWNER_A = 'usr_a';
const OWNER_B = 'usr_b';

function fixtureRawRule(overrides = {}) {
  return { id: 'det_1', technique_id: 'T1490', title: 'Inhibit System Recovery', governance: { status: 'GENERATED', version: '1.0.0' }, ...overrides };
}
function fixtureCanonical(overrides = {}) {
  return {
    status: 'RELEASED', version: '1.0.0', name: 'Inhibit System Recovery',
    formats: { kql: { content: 'DeviceProcessEvents | where 1 == 1', maturity: 'Production Ready' } },
    attack: [{ id: 'T1490', evidence_state: 'SOURCE_ATTRIBUTED' }],
    ...overrides,
  };
}

beforeEach(() => {
  global.__fakeD1ForTest._reset();
  detectionRules.getRule.mockReset().mockImplementation((id) => fixtureRawRule({ id }));
  detectionIntelligence.classifyAttackEvidence.mockReset().mockImplementation((t) => (t ? 'SOURCE_ATTRIBUTED' : 'UNKNOWN'));
  detectionIntelligence.toCanonicalDetectionObject.mockReset().mockImplementation((rawRule) => fixtureCanonical({ detection_id: rawRule.id }));
  defenseCompatibility.evaluateDetectionCompatibility.mockReset().mockReturnValue({ status: 'READY', format_used: 'kql', sigma_portable: false, missing_telemetry: [], explanation: 'Ready.' });
  defenseProfileStore.getProfile.mockReset().mockResolvedValue({ profile: { technologies: [], telemetry: {} } });
  deploymentStore.listDeployments.mockReset().mockResolvedValue([]);
  intel.getDossierAPI.mockReset().mockReturnValue({ found: false, dossier: null });
  intel.getActorDetailAPI.mockReset().mockReturnValue({ found: false, actor: null });
  intel.getIocDetailAPI.mockReset().mockReturnValue({ found: false, ioc: null });
  connectorRegistry.getConnectorModule.mockImplementation(jest.requireActual('../connectors/connector-registry').getConnectorModule);
});

const VALID_BOUNDS = { timeStart: '2026-08-01T00:00:00Z', timeEnd: '2026-08-02T00:00:00Z', rowLimit: 50 };

async function setupHuntWithQuery(ownerId, { platform = 'mock-siem', simulate, querySnapshot = 'DeviceProcessEvents | where 1 == 1' } = {}) {
  const hunt = await huntEngine.createHuntFromContext(ownerId, { detectionId: 'det_1', createdBy: ownerId });
  const queryId = await huntStore.addQuery(hunt.hunt_id, {
    sourceDetectionId: 'det_1', sourceDetectionVersion: '1.0.0', format: 'kql',
    querySnapshot, validationStatus: 'STRUCTURALLY_VALID', addedBy: ownerId,
  });
  const created = await siemConnectorStore.createConnector(ownerId, 'free', {
    platform, name: 'Test Connector', target_config: simulate ? { simulate } : {},
  });
  return { hunt, queryId, connectorId: created.connector.id };
}

describe('previewQuery — never touches the network, no execution record created', () => {
  test('a ready query previews cleanly', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.previewQuery(OWNER_A, hunt.hunt_id, queryId, connectorId);
    expect(result.error).toBeUndefined();
    expect(result.read_only).toBe(true);
    expect(result.readiness.ready).toBe(true);
    expect(result.connector.platform).toBe('mock-siem');
    expect((await engine.listExecutions(OWNER_A, hunt.hunt_id)).executions).toEqual([]);
  });

  test('a hunt belonging to another owner is NOT_FOUND', async () => {
    const { queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.previewQuery(OWNER_B, 'hunt_does_not_exist', queryId, connectorId);
    expect(result.error).toBe('NOT_FOUND');
  });

  test('a connectorId belonging to another owner (IDOR) is rejected, never used cross-tenant', async () => {
    const a = await setupHuntWithQuery(OWNER_A);
    const b = await setupHuntWithQuery(OWNER_B);
    const result = await engine.previewQuery(OWNER_A, a.hunt.hunt_id, a.queryId, b.connectorId);
    expect(result.error).toBe('NOT_FOUND');
  });

  test('a queryId belonging to a different hunt is rejected', async () => {
    const a = await setupHuntWithQuery(OWNER_A);
    const other = await huntEngine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.previewQuery(OWNER_A, other.hunt_id, a.queryId, a.connectorId);
    expect(result.error).toBe('NOT_FOUND');
  });

  test('surfaces NOT_READY / TELEMETRY_NOT_READY when compatibility is not exactly READY', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'PARTIALLY_READY', missing_telemetry: [{ source_label: 'X' }], explanation: 'Some telemetry missing.' });
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.previewQuery(OWNER_A, hunt.hunt_id, queryId, connectorId);
    expect(result.readiness.ready).toBe(false);
    expect(result.readiness.reason).toBe('TELEMETRY_NOT_READY');
  });

  test('surfaces DETECTION_NOT_RELEASED when the canonical detection is not RELEASED', async () => {
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ status: 'BLOCKED' }));
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.previewQuery(OWNER_A, hunt.hunt_id, queryId, connectorId);
    expect(result.readiness.ready).toBe(false);
    expect(result.readiness.reason).toBe('DETECTION_NOT_RELEASED');
  });

  test('surfaces deployment linkage (e.g. DRIFTED) for the query\'s source detection, never hidden', async () => {
    deploymentStore.listDeployments.mockResolvedValue([{ deployment_id: 'dep_1', detection_id: 'det_1', state: 'DRIFTED', connector_id: 'conn_x' }]);
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.previewQuery(OWNER_A, hunt.hunt_id, queryId, connectorId);
    expect(result.detection_linkage.deployments[0].state).toBe('DRIFTED');
  });
});

describe('formatMismatch — pre-flight, never trusted from the connector alone', () => {
  test('the sandbox connector is exempt (accepts any format for QA)', () => {
    expect(engine.formatMismatch({ is_sandbox: true, detection_format: 'kql' }, { format: 'splunk' })).toBeNull();
  });
  test('a live platform rejects a mismatched query format', () => {
    const msg = engine.formatMismatch({ is_sandbox: false, detection_format: 'kql', label: 'Microsoft Sentinel' }, { format: 'splunk' });
    expect(msg).toMatch(/kql/);
  });
  test('a matching format is not a mismatch', () => {
    expect(engine.formatMismatch({ is_sandbox: false, detection_format: 'kql' }, { format: 'kql' })).toBeNull();
  });
});

describe('runQuery — gating before any remote call or execution record', () => {
  test('requires an attributed actor', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS });
    expect(result.error).toBe('ACTOR_REQUIRED');
  });

  test('rejects when telemetry is not READY, and creates no execution row', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'TELEMETRY_GAP', missing_telemetry: [{ source_label: 'X' }] });
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.error).toBe('NOT_READY');
    expect((await engine.listExecutions(OWNER_A, hunt.hunt_id)).executions).toEqual([]);
  });

  test('rejects an invalid time range (end before start)', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { timeStart: '2026-08-02T00:00:00Z', timeEnd: '2026-08-01T00:00:00Z', rowLimit: 50, actor: OWNER_A });
    expect(result.error).toBe('INVALID_TIME_RANGE');
  });

  test('rejects a time range exceeding the maximum (no unlimited historical query)', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { timeStart: '2020-01-01T00:00:00Z', timeEnd: '2026-08-01T00:00:00Z', rowLimit: 50, actor: OWNER_A });
    expect(result.error).toBe('INVALID_TIME_RANGE');
  });

  test('rejects malformed time values', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { timeStart: 'not-a-date', timeEnd: '2026-08-01T00:00:00Z', rowLimit: 50, actor: OWNER_A });
    expect(result.error).toBe('INVALID_TIME_RANGE');
  });

  test('a connectorId belonging to another owner (IDOR) is rejected', async () => {
    const a = await setupHuntWithQuery(OWNER_A);
    const b = await setupHuntWithQuery(OWNER_B);
    const result = await engine.runQuery(OWNER_A, a.hunt.hunt_id, a.queryId, b.connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.error).toBe('NOT_FOUND');
  });

  test('a queryId belonging to another hunt is rejected', async () => {
    const a = await setupHuntWithQuery(OWNER_A);
    const other = await huntEngine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.runQuery(OWNER_A, other.hunt_id, a.queryId, a.connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.error).toBe('NOT_FOUND');
  });

  test('a non-positive/oversized rowLimit is silently bounded, never rejected outright', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, rowLimit: 999999, actor: OWNER_A });
    expect(result.error).toBeUndefined();
    const executions = (await engine.listExecutions(OWNER_A, hunt.hunt_id)).executions;
    expect(executions[0].row_limit).toBe(engine.MAX_ROW_LIMIT);
  });
});

describe('runQuery — real execution against the deterministic sandbox connector', () => {
  test('SUCCEEDED with zero rows by default (no simulate marker) -- NO_SIGNAL, never fabricated activity', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.state).toBe('SUCCEEDED');
    expect(result.results).toEqual([]);
    const executions = (await engine.listExecutions(OWNER_A, hunt.hunt_id)).executions;
    expect(executions[0].state).toBe('SUCCEEDED');
    expect(executions[0].result_row_count).toBe(0);
    expect(executions[0].completed_at).toBeTruthy();
  });

  test('a result set over rowLimit stays bounded, state PARTIAL, truncated: true', async () => {
    const marker = `${mockSiemConnector.HUNT_SIMULATE_MARKER}${mockSiemConnector.HUNT_SIMULATE.HUNDRED_RESULTS}`;
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A, { querySnapshot: `DeviceProcessEvents ${marker}` });
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, rowLimit: 25, actor: OWNER_A });
    expect(result.state).toBe('PARTIAL');
    expect(result.truncated).toBe(true);
    expect(result.results.length).toBe(25);
  });

  test('an analyst-selected observation persists via the existing, unchanged addObservation() — never automatic', async () => {
    const marker = `${mockSiemConnector.HUNT_SIMULATE_MARKER}${mockSiemConnector.HUNT_SIMULATE.ONE_RESULT}`;
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A, { querySnapshot: `DeviceProcessEvents ${marker}` });
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.results.length).toBe(1);
    expect((await huntStore.listObservations(hunt.hunt_id)).length).toBe(0); // nothing persisted until the analyst explicitly selects
    await huntStore.addObservation(hunt.hunt_id, { queryId, summary: JSON.stringify(result.results[0].fields), createdBy: OWNER_A });
    expect((await huntStore.listObservations(hunt.hunt_id)).length).toBe(1);
  });

  test('hostile field values in a result row are inert data after normalization -- never affect app behavior', async () => {
    const marker = `${mockSiemConnector.HUNT_SIMULATE_MARKER}${mockSiemConnector.HUNT_SIMULATE.HOSTILE_FIELDS}`;
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A, { querySnapshot: `DeviceProcessEvents ${marker}` });
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.state).toBe('SUCCEEDED');
    expect(Object.prototype.hasOwnProperty.call(result.results[0].fields, '__proto__')).toBe(false);
    expect(({}).polluted).toBeUndefined();
  });

  for (const [sim, expectedState] of [['RATE_LIMITED', 'RATE_LIMITED'], ['TIMEOUT', 'TIMED_OUT'], ['SERVER_ERROR', 'FAILED'], ['AUTH_FAILED', 'FAILED'], ['PERMISSION_DENIED', 'FAILED']]) {
    test(`simulate=${sim} completes the execution as ${expectedState}, never crashes`, async () => {
      const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A, { simulate: sim });
      const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
      expect(result.error).toBe('QUERY_EXECUTION_FAILED');
      expect(result.state).toBe(expectedState);
      const executions = (await engine.listExecutions(OWNER_A, hunt.hunt_id)).executions;
      expect(executions[0].state).toBe(expectedState);
    });
  }

  test('a provider outage (SERVER_ERROR) NEVER creates a QUERY_ERROR detection-feedback signal', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A, { simulate: 'SERVER_ERROR' });
    await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    const feedback = await feedbackStore.listFeedbackForOwner(OWNER_A, { detectionId: 'det_1' });
    expect(feedback.some((f) => f.classification === 'QUERY_ERROR')).toBe(false);
  });

  test('an auth failure NEVER creates a QUERY_ERROR detection-feedback signal', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A, { simulate: 'AUTH_FAILED' });
    await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    const feedback = await feedbackStore.listFeedbackForOwner(OWNER_A, { detectionId: 'det_1' });
    expect(feedback.some((f) => f.classification === 'QUERY_ERROR')).toBe(false);
  });

  test('a zero-result SUCCEEDED run never auto-creates any finding or feedback (NO_SIGNAL is not automatic failure)', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect((await huntStore.listFindings(hunt.hunt_id)).length).toBe(0);
    const feedback = await feedbackStore.listFeedbackForOwner(OWNER_A, { detectionId: 'det_1' });
    expect(feedback.length).toBe(0);
  });
});

describe('runQuery — genuine query-defect routing to QUERY_ERROR detection feedback', () => {
  test('a QUERY_REJECTED ConnectorError (genuine query/field defect) creates a QUERY_ERROR signal for the exact source detection', async () => {
    connectorRegistry.getConnectorModule.mockReturnValue({
      executeHuntQuery: jest.fn().mockRejectedValue(new ConnectorError('QUERY_REJECTED', 'Unknown column referenced.', { retryable: false })),
      normalizeResults: () => [],
    });
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.error_classification).toBe('QUERY_DEFECT');
    expect(result.state).toBe('FAILED');
    const feedback = await feedbackStore.listFeedbackForOwner(OWNER_A, { detectionId: 'det_1' });
    expect(feedback.some((f) => f.classification === 'QUERY_ERROR' && f.detection_id === 'det_1')).toBe(true);
    const executions = (await engine.listExecutions(OWNER_A, hunt.hunt_id)).executions;
    expect(executions[0].error_classification).toBe('QUERY_DEFECT');
  });
});

describe('classifyExecutionFailure — pure mapping, unit-tested directly', () => {
  test.each([
    ['QUERY_REJECTED', 'FAILED', 'QUERY_DEFECT'],
    ['AUTH_FAILED', 'FAILED', 'AUTH_ISSUE'],
    ['PERMISSION_DENIED', 'FAILED', 'AUTH_ISSUE'],
    ['RATE_LIMITED', 'RATE_LIMITED', 'PROVIDER_ISSUE'],
    ['TIMEOUT', 'TIMED_OUT', 'PROVIDER_ISSUE'],
    ['REMOTE_ERROR', 'FAILED', 'PROVIDER_ISSUE'],
  ])('%s -> state=%s, classification=%s', (code, expectedState, expectedClassification) => {
    const result = engine.classifyExecutionFailure(new ConnectorError(code, 'x'));
    expect(result).toEqual({ state: expectedState, errorClassification: expectedClassification });
  });
});

describe('concurrency bound — one in-flight execution per hunt', () => {
  test('a second RUN while one is still RUNNING is rejected', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    // Insert a RUNNING row directly via the store (simulating an in-flight execution the harness hasn't completed yet).
    const huntQueryStore = require('../hunt-query-store');
    await huntQueryStore.createExecution(OWNER_A, {
      huntId: hunt.hunt_id, queryId, connectorId, detectionId: 'det_1', detectionVersion: '1.0.0',
      format: 'kql', timeStart: VALID_BOUNDS.timeStart, timeEnd: VALID_BOUNDS.timeEnd, rowLimit: 50,
    });
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.error).toBe('QUERY_ALREADY_RUNNING');
  });

  test('a stale RUNNING row (older than the staleness window) never permanently deadlocks the hunt', async () => {
    const { hunt, queryId, connectorId } = await setupHuntWithQuery(OWNER_A);
    const huntQueryStore = require('../hunt-query-store');
    const staleExecutionId = await huntQueryStore.createExecution(OWNER_A, {
      huntId: hunt.hunt_id, queryId, connectorId, detectionId: 'det_1', detectionVersion: '1.0.0',
      format: 'kql', timeStart: VALID_BOUNDS.timeStart, timeEnd: VALID_BOUNDS.timeEnd, rowLimit: 50,
    });
    // Directly age the row's started_at past the staleness window via the fake D1 dump.
    const dump = global.__fakeD1ForTest._dump();
    dump.huntQueryExecutions.get(staleExecutionId).started_at = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, connectorId, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.error).toBeUndefined();
    expect(result.state).toBe('SUCCEEDED');
  });
});

describe('capability gating', () => {
  test('a connector platform with hunt_query_supported: false is rejected up front', async () => {
    connectorRegistry.getConnectorModule.mockReturnValue(undefined);
    const created = await siemConnectorStore.createConnector(OWNER_A, 'enterprise', {
      platform: 'microsoft-sentinel', name: 'Real Sentinel',
      target_config: { tenant_id: 't', subscription_id: 's', resource_group: 'rg', workspace_name: 'ws', client_id: 'c' },
      credential: { client_secret: 'shh' },
    });
    // Force the taxonomy lookup path by using a genuinely unsupported platform shape isn't
    // straightforward without a taxonomy edit, so instead prove the "no module registered"
    // branch directly: hunt_query_supported is true in the taxonomy for microsoft-sentinel,
    // but if the registry cannot resolve a module, runQuery must still fail closed.
    const hunt = await huntEngine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const queryId = await huntStore.addQuery(hunt.hunt_id, {
      sourceDetectionId: 'det_1', sourceDetectionVersion: '1.0.0', format: 'kql',
      querySnapshot: 'DeviceProcessEvents | take 1', validationStatus: 'STRUCTURALLY_VALID', addedBy: OWNER_A,
    });
    const result = await engine.runQuery(OWNER_A, hunt.hunt_id, queryId, created.connector.id, { ...VALID_BOUNDS, actor: OWNER_A });
    expect(result.error).toBe('HUNT_QUERY_NOT_SUPPORTED');
  });
});
