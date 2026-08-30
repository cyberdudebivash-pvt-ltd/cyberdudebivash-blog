'use strict';

process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = 'd'.repeat(64);

jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});
// Many requests per test share one synthetic IP -- matches the exact,
// already-established precedent in api/v1/__tests__/deployments.test.js
// (and billing.test.js before it) for exceeding security.js's unrelated
// global 10-req/min-per-IP budget across a whole suite.
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return { ...actual, globalIpRateLimit: jest.fn(async () => true) };
});
jest.mock('../../_lib/d1', () => {
  const { createFakeD1 } = require('../../_lib/__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});
jest.mock('../../_lib/detection-rules');
jest.mock('../../_lib/detection-intelligence');
jest.mock('../../_lib/defense-compatibility');
jest.mock('../../_lib/defense-profile-store');
jest.mock('../../_lib/deployment-store');
jest.mock('../../_lib/intel', () => ({
  getDossierAPI: jest.fn(() => ({ found: false, dossier: null, unsupported: false })),
  getActorDetailAPI: jest.fn(() => ({ found: false, actor: null })),
  getIocDetailAPI: jest.fn(() => ({ found: false, ioc: null })),
}));

const { authenticate } = require('../../_lib/middleware');
const detectionRules = require('../../_lib/detection-rules');
const detectionIntelligence = require('../../_lib/detection-intelligence');
const defenseCompatibility = require('../../_lib/defense-compatibility');
const defenseProfileStore = require('../../_lib/defense-profile-store');
const deploymentStore = require('../../_lib/deployment-store');
const intel = require('../../_lib/intel');
const handler = require('../hunts');
// Required LAST, deliberately, after every jest.mock('path')-without-factory
// (auto-mocked) module above: Jest's automocking inspects each real
// module's shape, which transitively re-requires '../../_lib/d1' several
// times before settling; requiring siem-connector-store.js (and therefore
// its own './d1' reference) before that settles captures a stale, never-
// reset instance -- confirmed empirically (moving this require earlier
// reintroduces phantom CONNECTOR_LIMIT_REACHED failures from "leftover"
// connectors that global.__fakeD1ForTest._reset() cannot see). Keep this
// require last.
const siemConnectorStore = require('../../_lib/siem-connector-store');

function mockReq({ method = 'GET', query = {}, body = null } = {}) {
  return { method, query, headers: { 'content-type': 'application/json' }, url: '/api/v1/hunts', body: body === null ? undefined : body };
}
function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn((s) => { res.statusCode = s; return res; });
  res.json = jest.fn((b) => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
function mockUser(tier, userId) {
  return { tier, userId, email: `${userId}@example.com`, keyHash: userId, requestsUsed: 1, requestsLimit: 999999 };
}
async function call(action, { method = 'GET', query = {}, body = null } = {}) {
  const req = mockReq({ method, query: { action, ...query }, body });
  const res = mockRes();
  await handler(req, res);
  return res;
}

beforeEach(() => {
  global.__fakeD1ForTest._reset();
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
  detectionRules.getRule.mockReset().mockImplementation((id) => ({
    id, technique_id: 'T1490', title: 'Test Rule', governance: { status: 'GENERATED', version: '1.0.0' },
  }));
  detectionIntelligence.classifyAttackEvidence.mockReset().mockImplementation((t) => (t && t.source ? 'SOURCE_ATTRIBUTED' : 'UNKNOWN'));
  detectionIntelligence.toCanonicalDetectionObject.mockReset().mockImplementation((_rawRule, { attackEvidenceState } = {}) => ({
    status: attackEvidenceState === 'SOURCE_ATTRIBUTED' ? 'RELEASED' : 'BLOCKED',
    version: '1.0.0', name: 'Test Rule',
    formats: { kql: { content: 'DeviceProcessEvents | where 1==1', maturity: 'Production Ready' } },
    attack: [{ id: 'T1490', evidence_state: attackEvidenceState || 'UNKNOWN' }],
  }));
  defenseCompatibility.evaluateDetectionCompatibility.mockReset().mockReturnValue({ status: 'READY', format_used: 'kql', sigma_portable: false, missing_telemetry: [], explanation: 'Ready.' });
  defenseProfileStore.getProfile.mockReset().mockResolvedValue({ profile: null });
  deploymentStore.listDeployments.mockReset().mockResolvedValue([]);
  deploymentStore.getDeployment.mockReset().mockResolvedValue({ error: 'NOT_FOUND' });
  intel.getDossierAPI.mockReset().mockReturnValue({ found: false, dossier: null, unsupported: false });
  intel.getActorDetailAPI.mockReset().mockReturnValue({ found: false, actor: null });
  intel.getIocDetailAPI.mockReset().mockReturnValue({ found: false, ioc: null });
});

describe('unauthenticated requests', () => {
  for (const [action, method] of [['list', 'GET'], ['create', 'POST'], ['feedback-submit', 'POST']]) {
    test(`action=${action} returns 401 with no API key`, async () => {
      const res = await call(action, { method });
      expect(res.statusCode).toBe(401);
    });
  }
});

describe('full lifecycle via the HTTP layer', () => {
  test('create -> get -> add-query -> add-observation -> add-evidence -> add-finding -> close -> reopen', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    // A real dossier-backed CVE context, so the technique is genuinely
    // SOURCE_ATTRIBUTED and the linked detection can actually reach
    // RELEASED -- add-query below deliberately gates on this, matching
    // deployment-engine.js's own contextual RELEASED-gate discipline.
    intel.getDossierAPI.mockReturnValue({
      found: true, unsupported: false,
      dossier: { title: 'CVE-2024-4577', attack_context: { techniques: [{ id: 'T1490', source: 'linked_report' }] } },
    });

    const create = await call('create', { method: 'POST', body: { title: 'Hunt for shadow copy deletion', entity_type: 'cve', entity_id: 'CVE-2024-4577', detection_id: 'det_1', priority: 'HIGH' } });
    expect(create.statusCode).toBe(200);
    const huntId = create.body.hunt.hunt_id;
    expect(create.body.hunt.status).toBe('DRAFT');

    const get = await call('get', { query: { id: huntId } });
    expect(get.statusCode).toBe(200);
    expect(get.body.hunt.hunt_id).toBe(huntId);
    expect(get.body.telemetry_readiness.readiness).toBe('READY');

    const addQuery = await call('add-query', { method: 'POST', query: { id: huntId }, body: { source_detection_id: 'det_1' } });
    expect(addQuery.statusCode).toBe(200);

    const addObs = await call('add-observation', { method: 'POST', query: { id: huntId }, body: { summary: 'Matched 2 events' } });
    expect(addObs.statusCode).toBe(200);
    const observationId = addObs.body.observation_id;

    const addEv = await call('add-evidence', { method: 'POST', query: { id: huntId }, body: { observation_id: observationId, description: 'Screenshot evidence' } });
    expect(addEv.statusCode).toBe(200);
    const evidenceId = addEv.body.evidence_id;

    const addFinding = await call('add-finding', { method: 'POST', query: { id: huntId }, body: { classification: 'CONFIRMED_MALICIOUS', confidence: 'HIGH', summary: 'Confirmed intrusion', evidence_refs: [evidenceId] } });
    expect(addFinding.statusCode).toBe(200);

    const close = await call('close', { method: 'POST', query: { id: huntId }, body: { disposition: 'CONFIRMED_THREAT', summary: 'Real intrusion confirmed' } });
    expect(close.statusCode).toBe(200);
    expect(close.body.hunt.status).toBe('CLOSED');

    const reopen = await call('reopen', { method: 'POST', query: { id: huntId }, body: { reason: 'New evidence' } });
    expect(reopen.statusCode).toBe(200);
    expect(reopen.body.hunt.status).toBe('ACTIVE');

    const timeline = await call('timeline', { query: { id: huntId } });
    expect(timeline.body.items.map((t) => t.event_type)).toEqual(
      expect.arrayContaining(['HUNT_CREATED', 'QUERY_ADDED', 'OBSERVATION_ADDED', 'EVIDENCE_ADDED', 'FINDING_ADDED', 'DISPOSITION_SET', 'HUNT_REOPENED'])
    );
  });

  test('add-query is rejected for a non-RELEASED detection (409 DETECTION_NOT_RELEASED)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue({ status: 'BLOCKED', version: '1.0.0', formats: {}, attack: [] });
    const create = await call('create', { method: 'POST', body: { detection_id: 'det_1' } });
    const huntId = create.body.hunt.hunt_id;
    const addQuery = await call('add-query', { method: 'POST', query: { id: huntId }, body: { source_detection_id: 'det_1' } });
    expect(addQuery.statusCode).toBe(409);
    expect(addQuery.body.error.code).toBe('DETECTION_NOT_RELEASED');
  });

  test('closing with CONFIRMED_THREAT and no evidence returns 409 EVIDENCE_REQUIRED', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const create = await call('create', { method: 'POST', body: { detection_id: 'det_1' } });
    const huntId = create.body.hunt.hunt_id;
    const close = await call('close', { method: 'POST', query: { id: huntId }, body: { disposition: 'CONFIRMED_THREAT', summary: 'x' } });
    expect(close.statusCode).toBe(409);
    expect(close.body.error.code).toBe('EVIDENCE_REQUIRED');
  });
});

describe('multi-tenant isolation over HTTP', () => {
  async function createHuntForOwner(userId) {
    authenticate.mockResolvedValue(mockUser('enterprise', userId));
    const res = await call('create', { method: 'POST', body: { detection_id: 'det_1' } });
    return res.body.hunt.hunt_id;
  }

  test('owner B cannot GET owner A\'s hunt (404, not 403 -- no existence signal leaked)', async () => {
    const huntId = await createHuntForOwner('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const res = await call('get', { query: { id: huntId } });
    expect(res.statusCode).toBe(404);
  });

  test('owner B cannot close owner A\'s hunt', async () => {
    const huntId = await createHuntForOwner('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const res = await call('close', { method: 'POST', query: { id: huntId }, body: { disposition: 'BENIGN_ACTIVITY', summary: 'x' } });
    expect(res.statusCode).toBe(404);
  });

  test('owner B cannot add a finding to owner A\'s hunt', async () => {
    const huntId = await createHuntForOwner('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const res = await call('add-finding', { method: 'POST', query: { id: huntId }, body: { classification: 'BENIGN', confidence: 'HIGH', summary: 'x' } });
    expect(res.statusCode).toBe(404);
  });

  test('owner B\'s hunt list never includes owner A\'s hunts', async () => {
    await createHuntForOwner('usr_a');
    const huntBId = await createHuntForOwner('usr_b');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const res = await call('list');
    expect(res.body.hunts.length).toBe(1);
    expect(res.body.hunts[0].hunt_id).toBe(huntBId);
  });

  test('owner B cannot attach feedback to owner A\'s hunt_id via feedback-submit', async () => {
    const huntId = await createHuntForOwner('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const res = await call('feedback-submit', { method: 'POST', body: { detection_id: 'det_1', hunt_id: huntId, classification: 'FALSE_POSITIVE' } });
    expect(res.statusCode).toBe(404);
  });
});

describe('input validation', () => {
  beforeEach(() => authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a')));

  test('create rejects an invalid priority', async () => {
    const res = await call('create', { method: 'POST', body: { title: 'x', priority: 'ULTRA' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PRIORITY');
  });

  test('create rejects an invalid entity_type', async () => {
    const res = await call('create', { method: 'POST', body: { entity_type: 'not_a_real_kind', entity_id: 'x' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_ENTITY_TYPE');
  });

  test('close rejects an invalid disposition', async () => {
    const create = await call('create', { method: 'POST', body: { detection_id: 'det_1' } });
    const res = await call('close', { method: 'POST', query: { id: create.body.hunt.hunt_id }, body: { disposition: 'MAYBE', summary: 'x' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_DISPOSITION');
  });

  test('add-finding rejects an invalid classification', async () => {
    const create = await call('create', { method: 'POST', body: { detection_id: 'det_1' } });
    const res = await call('add-finding', { method: 'POST', query: { id: create.body.hunt.hunt_id }, body: { classification: 'PROBABLY_BAD', confidence: 'HIGH', summary: 'x' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_CLASSIFICATION');
  });

  test('feedback-submit rejects an invalid classification', async () => {
    const res = await call('feedback-submit', { method: 'POST', body: { detection_id: 'det_1', classification: 'MEH' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_CLASSIFICATION');
  });

  test('an unwhitelisted body field is rejected', async () => {
    const res = await call('create', { method: 'POST', body: { title: 'x', not_a_real_field: 'hack' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_FIELDS');
  });

  test('an unknown action returns 400 INVALID_ACTION', async () => {
    const res = await call('delete-everything');
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_ACTION');
  });
});

describe('detection feedback endpoints', () => {
  test('feedback-signal requires no hunt_id/owner context and never leaks submitter identity', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    await call('feedback-submit', { method: 'POST', body: { detection_id: 'det_1', classification: 'QUERY_ERROR', summary: 'internal-hostname-soc01' } });
    const res = await call('feedback-signal', { query: { detection_id: 'det_1', detection_version: '1.0.0' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.signal.signal).toBe('REVIEW_REQUIRED');
    expect(JSON.stringify(res.body)).not.toContain('internal-hostname-soc01');
    expect(JSON.stringify(res.body)).not.toContain('usr_a');
  });

  test('feedback-list only returns the caller\'s own feedback', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    await call('feedback-submit', { method: 'POST', body: { detection_id: 'det_1', classification: 'TRUE_POSITIVE' } });
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    await call('feedback-submit', { method: 'POST', body: { detection_id: 'det_1', classification: 'FALSE_POSITIVE' } });
    const res = await call('feedback-list');
    expect(res.body.feedback.length).toBe(1);
    expect(res.body.feedback[0].classification).toBe('FALSE_POSITIVE');
  });
});

describe('detection-maturity', () => {
  test('returns NOT_AVAILABLE without entity context, and a real ladder value with it', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const noContext = await call('detection-maturity', { query: { detection_id: 'det_1' } });
    expect(noContext.body.maturity).toBe('NOT_AVAILABLE');

    intel.getDossierAPI.mockReturnValue({
      found: true, unsupported: false,
      dossier: { title: 'CVE-TEST', attack_context: { techniques: [{ id: 'T1490', source: 'linked_report' }] } },
    });

    const withContext = await call('detection-maturity', { query: { detection_id: 'det_1', entity_type: 'cve', entity_id: 'CVE-TEST' } });
    expect(['AVAILABLE', 'ENVIRONMENT_COMPATIBLE', 'DEPLOYED', 'OBSERVED_SIGNAL', 'ANALYST_VALIDATED']).toContain(withContext.body.maturity);
  });
});

describe('Controlled Read-Only SIEM Hunting Connectors v1 — query-preview / query-run / query-executions', () => {
  async function setupReadyHuntWithQuery(userId, { querySnapshot } = {}) {
    intel.getDossierAPI.mockReturnValue({
      found: true, unsupported: false,
      dossier: { title: 'CVE-2024-4577', attack_context: { techniques: [{ id: 'T1490', source: 'linked_report' }] } },
    });
    const create = await call('create', { method: 'POST', body: { entity_type: 'cve', entity_id: 'CVE-2024-4577', detection_id: 'det_1' } });
    const huntId = create.body.hunt.hunt_id;
    const addQuery = await call('add-query', { method: 'POST', query: { id: huntId }, body: { source_detection_id: 'det_1' } });
    const queryId = addQuery.body.query_id;
    if (querySnapshot) {
      // add-query snapshots the mocked detection's fixed content -- override
      // it directly via the real store when a test needs a specific marker.
      const huntStore = require('../../_lib/hunt-store');
      const rows = await huntStore.listQueries(huntId);
      global.__fakeD1ForTest._dump().huntQueries.get(rows[0].query_id).query_snapshot = querySnapshot;
    }
    const created = await siemConnectorStore.createConnector(userId, 'free', { platform: 'mock-siem', name: 'Test Sandbox', target_config: {} });
    return { huntId, queryId, connectorId: created.connector.id };
  }

  test('query-preview never touches the network and reports read_only:true', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const { huntId, queryId, connectorId } = await setupReadyHuntWithQuery('usr_a');
    const res = await call('query-preview', { query: { id: huntId, query_id: queryId, connector_id: connectorId } });
    expect(res.statusCode).toBe(200);
    expect(res.body.preview.read_only).toBe(true);
    expect(res.body.preview.readiness.ready).toBe(true);
  });

  test('query-preview 404s on a connector_id belonging to another tenant', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const a = await setupReadyHuntWithQuery('usr_a');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const b = await setupReadyHuntWithQuery('usr_b');
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const res = await call('query-preview', { query: { id: a.huntId, query_id: a.queryId, connector_id: b.connectorId } });
    expect(res.statusCode).toBe(404);
  });

  test('query-run executes against the sandbox connector and returns bounded, normalized results', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const { huntId, queryId, connectorId } = await setupReadyHuntWithQuery('usr_a');
    const res = await call('query-run', {
      method: 'POST', query: { id: huntId },
      body: { query_id: queryId, connector_id: connectorId, time_start: '2026-08-01T00:00:00Z', time_end: '2026-08-02T00:00:00Z', row_limit: 50 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.state).toBe('SUCCEEDED');
    expect(res.body.results).toEqual([]);
  });

  test('query-run without an attributed actor concept still requires the authenticated caller (structural: actor is always the authenticated user)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const { huntId, queryId, connectorId } = await setupReadyHuntWithQuery('usr_a');
    const res = await call('query-run', {
      method: 'POST', query: { id: huntId },
      body: { query_id: queryId, connector_id: connectorId, time_start: '2026-08-01T00:00:00Z', time_end: '2026-08-02T00:00:00Z' },
    });
    expect(res.statusCode).toBe(200); // actor is always derived from authenticate(), never a separate body field
  });

  test('query-run rejects an invalid time range with 400', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const { huntId, queryId, connectorId } = await setupReadyHuntWithQuery('usr_a');
    const res = await call('query-run', {
      method: 'POST', query: { id: huntId },
      body: { query_id: queryId, connector_id: connectorId, time_start: '2026-08-02T00:00:00Z', time_end: '2026-08-01T00:00:00Z', row_limit: 50 },
    });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_TIME_RANGE');
  });

  test('query-run rejects when telemetry is not READY (409 NOT_READY)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const { huntId, queryId, connectorId } = await setupReadyHuntWithQuery('usr_a');
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'TELEMETRY_GAP', missing_telemetry: [{ source_label: 'X' }] });
    const res = await call('query-run', {
      method: 'POST', query: { id: huntId },
      body: { query_id: queryId, connector_id: connectorId, time_start: '2026-08-01T00:00:00Z', time_end: '2026-08-02T00:00:00Z', row_limit: 50 },
    });
    expect(res.statusCode).toBe(409);
    expect(res.body.error.code).toBe('NOT_READY');
  });

  test('a query-run outcome that fails remotely (simulated) still returns HTTP 200 with the failure encoded in the body', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    intel.getDossierAPI.mockReturnValue({
      found: true, unsupported: false,
      dossier: { title: 'CVE-2024-4577', attack_context: { techniques: [{ id: 'T1490', source: 'linked_report' }] } },
    });
    const create = await call('create', { method: 'POST', body: { entity_type: 'cve', entity_id: 'CVE-2024-4577', detection_id: 'det_1' } });
    const huntId = create.body.hunt.hunt_id;
    const addQuery = await call('add-query', { method: 'POST', query: { id: huntId }, body: { source_detection_id: 'det_1' } });
    const created = await siemConnectorStore.createConnector('usr_a', 'free', { platform: 'mock-siem', name: 'Failing Sandbox', target_config: { simulate: 'AUTH_FAILED' } });
    const res = await call('query-run', {
      method: 'POST', query: { id: huntId },
      body: { query_id: addQuery.body.query_id, connector_id: created.connector.id, time_start: '2026-08-01T00:00:00Z', time_end: '2026-08-02T00:00:00Z', row_limit: 50 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.state).toBe('FAILED');
    expect(res.body.error_classification).toBe('AUTH_ISSUE');
  });

  test('query-executions returns bounded metadata, never raw telemetry, and is tenant-isolated', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const { huntId, queryId, connectorId } = await setupReadyHuntWithQuery('usr_a');
    await call('query-run', {
      method: 'POST', query: { id: huntId },
      body: { query_id: queryId, connector_id: connectorId, time_start: '2026-08-01T00:00:00Z', time_end: '2026-08-02T00:00:00Z', row_limit: 50 },
    });
    const res = await call('query-executions', { query: { id: huntId } });
    expect(res.statusCode).toBe(200);
    expect(res.body.executions.length).toBe(1);
    expect(res.body.executions[0].state).toBe('SUCCEEDED');
    expect(res.body.executions[0]).not.toHaveProperty('results');

    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_b'));
    const otherOwnerRes = await call('query-executions', { query: { id: huntId } });
    expect(otherOwnerRes.statusCode).toBe(404);
  });

  test('a selected result can be persisted as a hunt observation carrying execution provenance, never automatically', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise', 'usr_a'));
    const { huntId, queryId, connectorId } = await setupReadyHuntWithQuery('usr_a', {
      querySnapshot: `DeviceProcessEvents ${require('../../_lib/connectors/mock-siem-connector').HUNT_SIMULATE_MARKER}ONE_RESULT`,
    });
    const run = await call('query-run', {
      method: 'POST', query: { id: huntId },
      body: { query_id: queryId, connector_id: connectorId, time_start: '2026-08-01T00:00:00Z', time_end: '2026-08-02T00:00:00Z', row_limit: 50 },
    });
    expect(run.body.results.length).toBe(1);
    const addObs = await call('add-observation', {
      method: 'POST', query: { id: huntId },
      body: { query_id: queryId, summary: 'Analyst-selected sandbox host', execution_id: run.body.execution_id, selected_fields: run.body.results[0].fields },
    });
    expect(addObs.statusCode).toBe(200);
    const huntStore = require('../../_lib/hunt-store');
    const observations = await huntStore.listObservations(huntId);
    expect(observations[0].execution_id).toBe(run.body.execution_id);
    expect(observations[0].selected_fields_json).toEqual(run.body.results[0].fields);
  });
});
