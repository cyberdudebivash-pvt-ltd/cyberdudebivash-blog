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
