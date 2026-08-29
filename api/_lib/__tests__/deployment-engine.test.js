'use strict';
/**
 * SENTINEL APEX — Controlled SIEM Deployment Gateway v1: deployment-engine.js
 *
 * Detection lifecycle (detection-rules.js/detection-intelligence.js) and
 * customer compatibility (defense-compatibility.js/defense-profile-store.js)
 * are already independently certified elsewhere (Threat-to-Defense Fabric
 * v1 / Customer Telemetry & Defense Context v1) — mocked here so these
 * tests prove THIS tranche's orchestration logic (approval hash,
 * idempotency, reconciliation, drift, rollback, state machine) rather
 * than re-testing already-covered engines. The real mock-siem-connector.js
 * and a fake in-memory D1 (matching every other __tests__ file's
 * established pattern) are used unmocked, so the actual connector
 * dispatch/read-back/idempotency logic runs for real.
 */

process.env.CONNECTOR_CREDENTIAL_MASTER_KEY = '0'.repeat(64);

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
jest.mock('../intel', () => ({
  getDossierAPI: jest.fn(() => ({
    found: true, unsupported: false,
    dossier: { attack_context: { techniques: [{ id: 'T1490', source: 'linked_report' }] } },
  })),
}));

const detectionRules = require('../detection-rules');
const detectionIntelligence = require('../detection-intelligence');
const defenseCompatibility = require('../defense-compatibility');
const defenseProfileStore = require('../defense-profile-store');
const connectorStore = require('../siem-connector-store');
const mockConnector = require('../connectors/mock-siem-connector');
const engine = require('../deployment-engine');

const OWNER_A = 'usr_a';
const OWNER_B = 'usr_b';

function fixtureRawRule(overrides = {}) {
  return {
    id: 'det_test_1', technique_id: 'T1490', title: 'Inhibit System Recovery',
    description: 'vssadmin shadow-copy deletion.', level: 'high', data_source: 'process_creation',
    platforms: { sigma: null, kql: 'DeviceProcessEvents | where ProcessCommandLine has "vssadmin"', splunk: null, osquery: null },
    suricata: [],
    governance: { status: 'GENERATED', confidence: 'HIGH', created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z', version: '1.0.0' },
    source: { iocs: [], articles: ['CVE-2023-27351'], campaigns: [], evidence: 'test' },
    history: [],
    ...overrides,
  };
}

function fixtureCanonical(overrides = {}) {
  return {
    status: 'RELEASED', version: '1.0.0',
    formats: { kql: { content: 'DeviceProcessEvents | where ProcessCommandLine has "vssadmin"', maturity: 'Production Ready With Limitations' } },
    attack: [{ id: 'T1490', evidence_state: 'SOURCE_ATTRIBUTED' }],
    telemetry_requirements: {},
    ...overrides,
  };
}

function fixtureCompat(overrides = {}) {
  return { status: 'READY', format_used: 'kql', sigma_portable: false, missing_telemetry: [], explanation: 'Ready.', ...overrides };
}

async function makeSandboxConnector(ownerId, name = 'Sandbox') {
  const result = await connectorStore.createConnector(ownerId, 'enterprise', { platform: 'mock-siem', name, target_config: {} });
  return result.connector;
}

beforeEach(() => {
  global.__fakeD1ForTest._reset();
  detectionRules.getRule.mockReset().mockImplementation(() => fixtureRawRule());
  detectionIntelligence.classifyAttackEvidence.mockReset().mockReturnValue('SOURCE_ATTRIBUTED');
  detectionIntelligence.toCanonicalDetectionObject.mockReset().mockImplementation(() => fixtureCanonical());
  defenseCompatibility.evaluateDetectionCompatibility.mockReset().mockImplementation(() => fixtureCompat());
  defenseProfileStore.getProfile.mockReset().mockResolvedValue({ profile: { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } } });
});

describe('happy path: preview -> approve -> execute -> VERIFIED', () => {
  test('deploys, reads back, and verifies against the real mock connector', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({
      ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1',
      entityType: 'cve', entityId: 'CVE-2023-27351', enabledRequested: false,
    });
    expect(preview.blocked).toBe(false);
    expect(preview.action).toBe('CREATE');
    expect(preview.format).toBe('kql');

    const approved = await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(approved.blocked).toBe(false);
    expect(approved.deployment.state).toBe('APPROVED');

    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.blocked).toBe(false);
    expect(executed.deployment.state).toBe('VERIFIED');
    expect(executed.deployment.remote_resource_id).toBeTruthy();
  });
});

describe('compatibility and validation gates', () => {
  test('blocks preview when detection is not RELEASED', async () => {
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ status: 'REVIEW_REQUIRED' }));
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    expect(preview.blocked).toBe(true);
    expect(preview.reason).toBe('DETECTION_NOT_RELEASED');
  });

  test('blocks preview when compatibility is not READY (e.g. TELEMETRY_GAP)', async () => {
    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue(fixtureCompat({ status: 'TELEMETRY_GAP', format_used: 'kql' }));
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    expect(preview.blocked).toBe(true);
    expect(preview.reason).toBe('COMPATIBILITY_NOT_READY');
  });
});

describe('approval bypass and hash-mismatch protection', () => {
  test('direct execute without any prior approval is blocked', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.blocked).toBe(true);
    expect(executed.reason).toBe('INVALID_STATE_FOR_EXECUTE');
  });

  test('a version/content change between approve and execute is caught as APPROVAL_HASH_MISMATCH, not silently deployed', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });

    // Simulate a new detection version being released after approval but before execution.
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ version: '1.0.1', formats: { kql: { content: 'DeviceProcessEvents | where ProcessCommandLine has "a different query"', maturity: 'Production Ready With Limitations' } } }));

    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.blocked).toBe(true);
    expect(executed.reason).toBe('APPROVAL_HASH_MISMATCH');
  });

  test('a REVOKED detection blocks execution even after approval', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });

    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ status: 'REVOKED' }));
    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.blocked).toBe(true);
    expect(executed.reason).toBe('DETECTION_NOT_RELEASED');
  });

  test('telemetry becoming unavailable between approve and execute blocks execution', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });

    defenseCompatibility.evaluateDetectionCompatibility.mockReturnValue(fixtureCompat({ status: 'TELEMETRY_GAP' }));
    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.blocked).toBe(true);
    expect(executed.reason).toBe('COMPATIBILITY_NOT_READY');
  });
});

describe('idempotency and concurrency', () => {
  test('two concurrent execute calls on the same approved deployment produce exactly one remote deployment', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });

    const deploySpy = jest.spyOn(mockConnector, 'deploy');
    const [r1, r2] = await Promise.all([
      engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id }),
      engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id }),
    ]);
    const results = [r1, r2];
    const succeeded = results.filter(r => !r.blocked);
    const rejected = results.filter(r => r.blocked && r.reason === 'INVALID_STATE_FOR_EXECUTE');
    expect(succeeded.length).toBe(1);
    expect(rejected.length).toBe(1);
    expect(deploySpy).toHaveBeenCalledTimes(1);
    deploySpy.mockRestore();
  });

  test('a timeout immediately after the remote resource is actually created is reconciled, not duplicated', async () => {
    const connector = await connectorStore.createConnector(OWNER_A, 'enterprise', {
      platform: 'mock-siem', name: 'Flaky', target_config: { simulate: 'TIMEOUT_AFTER_CREATE' },
    });
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.blocked).toBe(false);
    expect(executed.deployment.state).toBe('VERIFIED');

    const dump = global.__fakeD1ForTest._dump();
    const resourceRows = [...dump.mockSiemResources.values()].filter(r => r.connector_id === connector.connector.id);
    expect(resourceRows.length).toBe(1); // no duplicate remote resource
  });
});

describe('drift detection', () => {
  test('an out-of-band remote change is detected as DRIFTED and never silently overwritten', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.deployment.state).toBe('VERIFIED');

    await mockConnector._simulateOutOfBandChange(connector.id, executed.deployment.remote_resource_name, { enabled: true, query: 'SOMETHING AN ADMIN TYPED DIRECTLY' });

    const verified = await engine.verifyDeployment({ ownerId: OWNER_A, deploymentId: preview.deployment_id });
    expect(verified.blocked).toBe(false);
    expect(verified.deployment.state).toBe('DRIFTED');

    // The remote resource itself must still hold the out-of-band value -- never auto-overwritten.
    const dump = global.__fakeD1ForTest._dump();
    const row = dump.mockSiemResources.get(`${connector.id}|${executed.deployment.remote_resource_name}`);
    expect(JSON.parse(row.payload).query).toBe('SOMETHING AN ADMIN TYPED DIRECTLY');
  });
});

describe('update and rollback', () => {
  test('deploy v1, update to v2, then roll back to v1 — read-back verifies the restored v1 content', async () => {
    const connector = await makeSandboxConnector(OWNER_A);

    // v1
    const previewV1 = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: previewV1.deployment_id });
    const v1Result = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: previewV1.deployment_id });
    expect(v1Result.deployment.state).toBe('VERIFIED');

    // v2 (same triple -> same row, reused via findActiveDeployment)
    detectionIntelligence.toCanonicalDetectionObject.mockReturnValue(fixtureCanonical({ version: '2.0.0', formats: { kql: { content: 'DeviceProcessEvents | where ProcessCommandLine has "v2 query"', maturity: 'Production Ready With Limitations' } } }));
    const previewV2 = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    expect(previewV2.deployment_id).toBe(previewV1.deployment_id);
    expect(previewV2.action).toBe('UPDATE');
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: previewV2.deployment_id });
    const v2Result = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: previewV2.deployment_id });
    expect(v2Result.deployment.state).toBe('VERIFIED');
    expect(v2Result.deployment.rollback_available).toBe(true);

    // Roll back to v1
    const rollbackPreview = await engine.previewRollback({ ownerId: OWNER_A, deploymentId: previewV1.deployment_id });
    expect(rollbackPreview.blocked).toBe(false);
    expect(rollbackPreview.to_version).toBe('1.0.0');
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: previewV1.deployment_id });
    const rollbackResult = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: previewV1.deployment_id });
    expect(rollbackResult.deployment.state).toBe('VERIFIED');
    expect(rollbackResult.deployment.rollback_available).toBe(false); // one level of undo, now consumed

    const dump = global.__fakeD1ForTest._dump();
    const row = dump.mockSiemResources.get(`${connector.id}|${v1Result.deployment.remote_resource_name}`);
    expect(JSON.parse(row.payload).query).toContain('vssadmin');
  });
});

describe('tenant isolation', () => {
  test("owner B cannot preview a deployment against owner A's connector", async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_B, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    expect(preview.blocked).toBe(true);
    expect(preview.reason).toBe('NOT_FOUND');
  });

  test("owner B cannot execute or view owner A's deployment by guessing its id", async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351' });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });

    const crossTenantExecute = await engine.executeDeployment({ ownerId: OWNER_B, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(crossTenantExecute.blocked).toBe(true);
    expect(crossTenantExecute.reason).toBe('NOT_FOUND');
  });
});

describe('disable', () => {
  test('disabling a verified deployment sets the remote rule enabled:false and marks the row DISABLED', async () => {
    const connector = await makeSandboxConnector(OWNER_A);
    const preview = await engine.previewDeployment({ ownerId: OWNER_A, tier: 'enterprise', connectorId: connector.id, detectionId: 'det_test_1', entityType: 'cve', entityId: 'CVE-2023-27351', enabledRequested: true });
    await engine.approveDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id, enabledRequested: true });
    const executed = await engine.executeDeployment({ ownerId: OWNER_A, tier: 'enterprise', deploymentId: preview.deployment_id });
    expect(executed.deployment.state).toBe('VERIFIED');

    const disabled = await engine.disableDeployment({ ownerId: OWNER_A, deploymentId: preview.deployment_id });
    expect(disabled.blocked).toBe(false);
    expect(disabled.deployment.state).toBe('DISABLED');

    const dump = global.__fakeD1ForTest._dump();
    const row = dump.mockSiemResources.get(`${connector.id}|${executed.deployment.remote_resource_name}`);
    expect(JSON.parse(row.payload).enabled).toBe(false);
  });
});
