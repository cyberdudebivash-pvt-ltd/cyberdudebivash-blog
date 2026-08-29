'use strict';
/**
 * SENTINEL APEX — Threat Hunting Workspace v1: hunt-engine.js
 *
 * Detection lifecycle, compatibility, and deployment state are already
 * independently certified elsewhere -- mocked here (matching deployment-
 * engine.test.js's exact precedent) so these tests prove THIS tranche's
 * own composition/validation logic (hypothesis generation, readiness
 * rollup, coverage-maturity ladder, evidence-required gates, tenant-scoped
 * feedback linkage) rather than re-testing already-covered engines.
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

const detectionRules = require('../detection-rules');
const detectionIntelligence = require('../detection-intelligence');
const defenseCompatibility = require('../defense-compatibility');
const defenseProfileStore = require('../defense-profile-store');
const deploymentStore = require('../deployment-store');
const intel = require('../intel');
const huntStore = require('../hunt-store');
const feedbackStore = require('../detection-feedback-store');
const engine = require('../hunt-engine');

const OWNER_A = 'usr_a';
const OWNER_B = 'usr_b';

function fixtureRawRule(overrides = {}) {
  return {
    id: 'det_1', technique_id: 'T1490', title: 'Inhibit System Recovery',
    governance: { status: 'GENERATED', version: '1.0.0' },
    ...overrides,
  };
}
function fixtureCanonical(overrides = {}) {
  return {
    status: 'RELEASED', version: '1.0.0', name: 'Inhibit System Recovery',
    formats: { kql: { content: 'DeviceProcessEvents | where ProcessCommandLine has "vssadmin"', maturity: 'Production Ready' } },
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
  defenseProfileStore.getProfile.mockReset().mockResolvedValue({ profile: { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } } });
  deploymentStore.listDeployments.mockReset().mockResolvedValue([]);
  deploymentStore.getDeployment.mockReset().mockResolvedValue({ error: 'NOT_FOUND' });
  intel.getDossierAPI.mockReset().mockReturnValue({ found: false, dossier: null, unsupported: false });
  intel.getActorDetailAPI.mockReset().mockReturnValue({ found: false, actor: null });
  intel.getIocDetailAPI.mockReset().mockReturnValue({ found: false, ioc: null });
});

describe('createHuntFromContext — hypothesis_source derivation', () => {
  test('a detection_id with no dossier context yields DETECTION_DERIVED', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    expect(hunt.hypothesis_source).toBe('DETECTION_DERIVED');
    expect(hunt.hypothesis).toMatch(/testable hypothesis/i);
  });

  test('a resolvable CVE/campaign entity with no detection_id yields INTELLIGENCE_DERIVED', async () => {
    intel.getDossierAPI.mockReturnValue({
      found: true, unsupported: false,
      dossier: { title: 'CVE-2024-4577', attack_context: { techniques: [{ id: 'T1059.001', source: 'linked_report' }] } },
    });
    const hunt = await engine.createHuntFromContext(OWNER_A, { entityType: 'cve', entityId: 'CVE-2024-4577', createdBy: OWNER_A });
    expect(hunt.hypothesis_source).toBe('INTELLIGENCE_DERIVED');
  });

  test('an unresolvable entity and no detection falls back to ANALYST_CREATED', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { title: 'Manual hunt', createdBy: OWNER_A });
    expect(hunt.hypothesis_source).toBe('ANALYST_CREATED');
  });

  test('a detection_id ref, entity ref, and technique ref are all recorded', async () => {
    intel.getDossierAPI.mockReturnValue({
      found: true, unsupported: false,
      dossier: { title: 'CVE-2024-4577', attack_context: { techniques: [{ id: 'T1490', source: 'linked_report' }] } },
    });
    const hunt = await engine.createHuntFromContext(OWNER_A, { entityType: 'cve', entityId: 'CVE-2024-4577', detectionId: 'det_1', createdBy: OWNER_A });
    const refs = await huntStore.listRefs(hunt.hunt_id);
    expect(refs).toEqual(expect.arrayContaining([
      expect.objectContaining({ ref_kind: 'cve', ref_id: 'CVE-2024-4577' }),
      expect.objectContaining({ ref_kind: 'detection', ref_id: 'det_1' }),
      expect.objectContaining({ ref_kind: 'attack_technique', ref_id: 'T1490' }),
    ]));
  });

  test('hypothesis text is always hedged, never framed as an established fact', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    expect(hunt.hypothesis).toMatch(/may be present/i);
    expect(hunt.hypothesis).not.toMatch(/is confirmed|has occurred/i);
  });
});

describe('computeHuntReadiness', () => {
  test('a hunt with no linked detection is UNKNOWN readiness', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { title: 'No detections', createdBy: OWNER_A });
    const readiness = await engine.computeHuntReadiness(OWNER_A, hunt.hunt_id);
    expect(readiness.readiness).toBe('UNKNOWN');
    expect(readiness.per_detection).toEqual([]);
  });

  test('a RELEASED, READY detection rolls up to READY hunt readiness', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const readiness = await engine.computeHuntReadiness(OWNER_A, hunt.hunt_id);
    expect(readiness.readiness).toBe('READY');
  });

  test('a non-RELEASED canonical detection surfaces as NO_VALIDATED_DETECTION per-detection', async () => {
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ status: 'BLOCKED' }));
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const readiness = await engine.computeHuntReadiness(OWNER_A, hunt.hunt_id);
    expect(readiness.per_detection[0].status).toBe('NO_VALIDATED_DETECTION');
  });
});

describe('resolveDeploymentLinkage', () => {
  test('surfaces a DRIFTED deployment state exactly as stored -- never silently reconciled', async () => {
    deploymentStore.listDeployments.mockResolvedValue([{ deployment_id: 'dep_1', detection_id: 'det_1', state: 'DRIFTED', connector_id: 'conn_1' }]);
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const linkage = await engine.resolveDeploymentLinkage(OWNER_A, hunt.hunt_id);
    expect(linkage[0].deployments[0]).toEqual({ deployment_id: 'dep_1', state: 'DRIFTED', connector_id: 'conn_1' });
  });

  test('surfaces a REVOKED detection status strongly, independent of deployment state', async () => {
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ status: 'REVOKED' }));
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const linkage = await engine.resolveDeploymentLinkage(OWNER_A, hunt.hunt_id);
    expect(linkage[0].detection_status).toBe('REVOKED');
  });
});

describe('computeDetectionMaturity — the coverage ladder', () => {
  test('no RELEASED canonical detection => NOT_AVAILABLE', async () => {
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ status: 'BLOCKED' }));
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1')).toBe('NOT_AVAILABLE');
  });

  test('RELEASED but no entity context supplied is an honest NOT_AVAILABLE floor, not a guess', async () => {
    detectionIntelligence.classifyAttackEvidence.mockReturnValue('UNKNOWN');
    detectionIntelligence.toCanonicalDetectionObject.mockImplementation((_rule, { attackEvidenceState }) =>
      attackEvidenceState === 'SOURCE_ATTRIBUTED' ? fixtureCanonical({ status: 'RELEASED' }) : fixtureCanonical({ status: 'BLOCKED' }));
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1')).toBe('NOT_AVAILABLE');
  });

  test('RELEASED + no profile match => AVAILABLE only', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'UNKNOWN' });
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1', { entityType: 'cve', entityId: 'CVE-X' })).toBe('AVAILABLE');
  });

  test('RELEASED + READY compatibility => ENVIRONMENT_COMPATIBLE', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'READY' });
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1', { entityType: 'cve', entityId: 'CVE-X' })).toBe('ENVIRONMENT_COMPATIBLE');
  });

  test('+ a live deployment => DEPLOYED', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'READY' });
    deploymentStore.listDeployments.mockResolvedValue([{ deployment_id: 'dep_1', detection_id: 'det_1', state: 'VERIFIED' }]);
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1', { entityType: 'cve', entityId: 'CVE-X' })).toBe('DEPLOYED');
  });

  test('+ a hunt observation (this owner\'s own hunt) => OBSERVED_SIGNAL', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'READY' });
    deploymentStore.listDeployments.mockResolvedValue([{ deployment_id: 'dep_1', detection_id: 'det_1', state: 'VERIFIED' }]);
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    await huntStore.addObservation(hunt.hunt_id, { summary: 'Matched activity', createdBy: OWNER_A });
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1', { entityType: 'cve', entityId: 'CVE-X' })).toBe('OBSERVED_SIGNAL');
  });

  test('+ a CONFIRMED_MALICIOUS finding => ANALYST_VALIDATED', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'READY' });
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const evId = await huntStore.addEvidence(hunt.hunt_id, { description: 'proof', createdBy: OWNER_A });
    await huntStore.addFinding(hunt.hunt_id, { classification: 'CONFIRMED_MALICIOUS', confidence: 'HIGH', summary: 'confirmed', evidenceRefs: [evId], createdBy: OWNER_A });
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1', { entityType: 'cve', entityId: 'CVE-X' })).toBe('ANALYST_VALIDATED');
  });

  test('a TRUE_POSITIVE detection_feedback row alone (no hunt finding) also reaches ANALYST_VALIDATED', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'READY' });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_A });
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1', { entityType: 'cve', entityId: 'CVE-X' })).toBe('ANALYST_VALIDATED');
  });

  test('another owner\'s hunt/finding/feedback never inflates THIS owner\'s maturity (tenant isolation)', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue({ status: 'READY' });
    const huntB = await engine.createHuntFromContext(OWNER_B, { detectionId: 'det_1', createdBy: OWNER_B });
    const evId = await huntStore.addEvidence(huntB.hunt_id, { description: 'proof', createdBy: OWNER_B });
    await huntStore.addFinding(huntB.hunt_id, { classification: 'CONFIRMED_MALICIOUS', confidence: 'HIGH', summary: 'confirmed', evidenceRefs: [evId], createdBy: OWNER_B });
    await feedbackStore.submitFeedback(OWNER_B, { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_B });
    expect(await engine.computeDetectionMaturity(OWNER_A, 'det_1', { entityType: 'cve', entityId: 'CVE-X' })).toBe('ENVIRONMENT_COMPATIBLE');
  });
});

describe('addFindingWithValidation — CONFIRMED_MALICIOUS requires linked evidence', () => {
  test('rejects a CONFIRMED_MALICIOUS finding with no evidence_refs', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.addFindingWithValidation(OWNER_A, hunt.hunt_id, { classification: 'CONFIRMED_MALICIOUS', confidence: 'HIGH', summary: 'x', evidenceRefs: [], createdBy: OWNER_A });
    expect(result.error).toBe('EVIDENCE_REQUIRED');
  });

  test('accepts a CONFIRMED_MALICIOUS finding WITH evidence_refs', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const evId = await huntStore.addEvidence(hunt.hunt_id, { description: 'x', createdBy: OWNER_A });
    const result = await engine.addFindingWithValidation(OWNER_A, hunt.hunt_id, { classification: 'CONFIRMED_MALICIOUS', confidence: 'HIGH', summary: 'x', evidenceRefs: [evId], createdBy: OWNER_A });
    expect(result.error).toBeUndefined();
    expect(result.finding_id).toBeTruthy();
  });

  test('a weaker classification (e.g. NO_EVIDENCE_FOUND) never requires evidence', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.addFindingWithValidation(OWNER_A, hunt.hunt_id, { classification: 'NO_EVIDENCE_FOUND', confidence: 'LOW', summary: 'x', evidenceRefs: [], createdBy: OWNER_A });
    expect(result.error).toBeUndefined();
  });

  test('a non-owner cannot add a finding to another owner\'s hunt', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.addFindingWithValidation(OWNER_B, hunt.hunt_id, { classification: 'BENIGN', confidence: 'HIGH', summary: 'x', evidenceRefs: [], createdBy: OWNER_B });
    expect(result.error).toBe('NOT_FOUND');
  });
});

describe('setDisposition — the terminal act', () => {
  test('requires both a summary and an attributed actor', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.setDisposition(OWNER_A, hunt.hunt_id, { disposition: 'BENIGN_ACTIVITY', summary: '', actor: OWNER_A });
    expect(result.error).toBe('DISPOSITION_INCOMPLETE');
  });

  test('CONFIRMED_THREAT requires at least one finding or evidence record', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.setDisposition(OWNER_A, hunt.hunt_id, { disposition: 'CONFIRMED_THREAT', summary: 'Confirmed', actor: OWNER_A });
    expect(result.error).toBe('EVIDENCE_REQUIRED');
  });

  test('CONFIRMED_THREAT succeeds once evidence exists, and closes the hunt', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    await huntStore.addEvidence(hunt.hunt_id, { description: 'proof', createdBy: OWNER_A });
    const result = await engine.setDisposition(OWNER_A, hunt.hunt_id, { disposition: 'CONFIRMED_THREAT', summary: 'Confirmed via evidence', actor: OWNER_A });
    expect(result.error).toBeUndefined();
    expect(result.hunt.status).toBe('CLOSED');
    expect(result.hunt.disposition).toBe('CONFIRMED_THREAT');
    expect(result.hunt.closed_at).toBeTruthy();
  });

  test('a weaker disposition (e.g. NO_EVIDENCE) does not require evidence', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.setDisposition(OWNER_A, hunt.hunt_id, { disposition: 'NO_EVIDENCE', summary: 'Nothing found', actor: OWNER_A });
    expect(result.error).toBeUndefined();
    expect(result.hunt.status).toBe('CLOSED');
  });
});

describe('reopenHunt', () => {
  test('cannot reopen a hunt that is not CLOSED', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.reopenHunt(OWNER_A, hunt.hunt_id, { actor: OWNER_A });
    expect(result.error).toBe('NOT_CLOSED');
  });

  test('requires an attributed actor', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    await huntStore.addEvidence(hunt.hunt_id, { description: 'proof', createdBy: OWNER_A });
    await engine.setDisposition(OWNER_A, hunt.hunt_id, { disposition: 'CONFIRMED_THREAT', summary: 'x', actor: OWNER_A });
    const result = await engine.reopenHunt(OWNER_A, hunt.hunt_id, {});
    expect(result.error).toBe('ACTOR_REQUIRED');
  });

  test('reopening clears closed_at, sets ACTIVE, and preserves the prior disposition as history until a new one is set', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    await huntStore.addEvidence(hunt.hunt_id, { description: 'proof', createdBy: OWNER_A });
    await engine.setDisposition(OWNER_A, hunt.hunt_id, { disposition: 'CONFIRMED_THREAT', summary: 'Confirmed', actor: OWNER_A });
    const result = await engine.reopenHunt(OWNER_A, hunt.hunt_id, { reason: 'New evidence', actor: OWNER_A });
    expect(result.hunt.status).toBe('ACTIVE');
    expect(result.hunt.closed_at).toBeNull();
    expect(result.hunt.disposition).toBe('CONFIRMED_THREAT'); // preserved until overwritten by a new close
    const timeline = await huntStore.listTimeline(hunt.hunt_id);
    expect(timeline.some((t) => t.event_type === 'HUNT_REOPENED')).toBe(true);
  });
});

describe('submitDetectionFeedback — independent ownership verification of hunt_id/deployment_id', () => {
  test('rejects a hunt_id belonging to a different owner rather than silently attaching it', async () => {
    const huntB = await engine.createHuntFromContext(OWNER_B, { detectionId: 'det_1', createdBy: OWNER_B });
    const result = await engine.submitDetectionFeedback(OWNER_A, { detectionId: 'det_1', huntId: huntB.hunt_id, classification: 'FALSE_POSITIVE', createdBy: OWNER_A });
    expect(result.error).toBe('NOT_FOUND');
  });

  test('rejects a deployment_id belonging to a different owner', async () => {
    deploymentStore.getDeployment.mockImplementation(async (ownerId) => (ownerId === OWNER_A ? { deployment: { deployment_id: 'dep_1' } } : { error: 'NOT_FOUND' }));
    const result = await engine.submitDetectionFeedback(OWNER_B, { detectionId: 'det_1', deploymentId: 'dep_1', classification: 'FALSE_POSITIVE', createdBy: OWNER_B });
    expect(result.error).toBe('NOT_FOUND');
  });

  test('succeeds with a valid, owned hunt_id and appends a hunt timeline entry', async () => {
    const hunt = await engine.createHuntFromContext(OWNER_A, { detectionId: 'det_1', createdBy: OWNER_A });
    const result = await engine.submitDetectionFeedback(OWNER_A, { detectionId: 'det_1', huntId: hunt.hunt_id, classification: 'TRUE_POSITIVE', createdBy: OWNER_A });
    expect(result.error).toBeUndefined();
    expect(result.feedback_id).toBeTruthy();
    const timeline = await huntStore.listTimeline(hunt.hunt_id);
    expect(timeline.some((t) => t.event_type === 'FEEDBACK_SUBMITTED')).toBe(true);
  });

  test('an unknown detection_id is rejected', async () => {
    detectionRules.getRule.mockReturnValue(null);
    const result = await engine.submitDetectionFeedback(OWNER_A, { detectionId: 'no_such_detection', classification: 'FALSE_POSITIVE', createdBy: OWNER_A });
    expect(result.error).toBe('NOT_FOUND');
  });
});
