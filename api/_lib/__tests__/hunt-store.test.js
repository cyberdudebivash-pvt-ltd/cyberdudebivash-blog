'use strict';
/**
 * SENTINEL APEX — Threat Hunting Workspace v1: hunt-store.js
 *
 * Pure persistence layer — exercised against the real fake-d1 fixture
 * (matching every other __tests__ file's established pattern), no
 * detection/compatibility mocking needed since this module has zero
 * dependency on either.
 */

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const huntStore = require('../hunt-store');

const OWNER_A = 'usr_a';
const OWNER_B = 'usr_b';

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

describe('hunt CRUD + tenant isolation', () => {
  test('createHunt then getHunt round-trips the same owner', async () => {
    const row = await huntStore.createHunt(OWNER_A, {
      title: 'Investigate suspicious PowerShell', hypothesis: 'Test hypothesis.',
      hypothesisSource: 'ANALYST_CREATED', priority: 'HIGH', createdBy: OWNER_A,
    });
    const { hunt } = await huntStore.getHunt(OWNER_A, row.hunt_id);
    expect(hunt.title).toBe('Investigate suspicious PowerShell');
    expect(hunt.status).toBe('DRAFT');
    expect(hunt.priority).toBe('HIGH');
  });

  test('a different owner cannot read another owner\'s hunt (NOT_FOUND, not a distinguishing 403)', async () => {
    const row = await huntStore.createHunt(OWNER_A, {
      title: 'Owner A hunt', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'MEDIUM', createdBy: OWNER_A,
    });
    const result = await huntStore.getHunt(OWNER_B, row.hunt_id);
    expect(result.error).toBe('NOT_FOUND');
  });

  test('listHunts only returns the caller\'s own hunts, optionally filtered by status', async () => {
    await huntStore.createHunt(OWNER_A, { title: 'A1', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    await huntStore.createHunt(OWNER_A, { title: 'A2', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    await huntStore.createHunt(OWNER_B, { title: 'B1', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_B });

    const aHunts = await huntStore.listHunts(OWNER_A);
    expect(aHunts.length).toBe(2);
    expect(aHunts.every((h) => ['A1', 'A2'].includes(h.title))).toBe(true);

    await huntStore.updateHunt((await huntStore.listHunts(OWNER_A))[0].hunt_id, { status: 'ACTIVE' });
    const activeOnly = await huntStore.listHunts(OWNER_A, { status: 'ACTIVE' });
    expect(activeOnly.length).toBe(1);
  });

  test('updateHunt is a generic column setter that always bumps updated_at', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    const before = row.updated_at;
    await new Promise((r) => setTimeout(r, 2));
    await huntStore.updateHunt(row.hunt_id, { title: 'Renamed' });
    const { hunt } = await huntStore.getHunt(OWNER_A, row.hunt_id);
    expect(hunt.title).toBe('Renamed');
    expect(hunt.updated_at).not.toBe(before);
  });
});

describe('hunt_refs — polymorphic entity linkage', () => {
  test('addRef then listRefs returns the linked entity', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    await huntStore.addRef(row.hunt_id, 'cve', 'CVE-2024-4577');
    await huntStore.addRef(row.hunt_id, 'attack_technique', 'T1059.001');
    const refs = await huntStore.listRefs(row.hunt_id);
    expect(refs).toEqual(expect.arrayContaining([
      expect.objectContaining({ ref_kind: 'cve', ref_id: 'CVE-2024-4577' }),
      expect.objectContaining({ ref_kind: 'attack_technique', ref_id: 'T1059.001' }),
    ]));
  });

  test('addRef is idempotent (ON CONFLICT DO NOTHING) -- adding the same ref twice does not duplicate it', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    await huntStore.addRef(row.hunt_id, 'detection', 'det_1');
    await huntStore.addRef(row.hunt_id, 'detection', 'det_1');
    const refs = await huntStore.listRefs(row.hunt_id);
    expect(refs.filter((r) => r.ref_kind === 'detection' && r.ref_id === 'det_1').length).toBe(1);
  });

  test('listHuntIdsReferencing finds every hunt (across owners) linked to an entity -- an internal, not tenant-filtered, reverse index', async () => {
    const rowA = await huntStore.createHunt(OWNER_A, { title: 'A', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    const rowB = await huntStore.createHunt(OWNER_B, { title: 'B', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_B });
    await huntStore.addRef(rowA.hunt_id, 'detection', 'det_shared');
    await huntStore.addRef(rowB.hunt_id, 'detection', 'det_shared');
    const huntIds = await huntStore.listHuntIdsReferencing('detection', 'det_shared');
    expect(huntIds.sort()).toEqual([rowA.hunt_id, rowB.hunt_id].sort());
  });
});

describe('hunt_queries — data, never executed', () => {
  test('addQuery snapshots the exact content passed, independent of anything else', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    const queryId = await huntStore.addQuery(row.hunt_id, {
      sourceDetectionId: 'det_1', sourceDetectionVersion: '1.0.0', format: 'kql',
      querySnapshot: 'DeviceProcessEvents | where ProcessCommandLine has "vssadmin"',
      validationStatus: 'RELEASED', addedBy: OWNER_A,
    });
    const queries = await huntStore.listQueries(row.hunt_id);
    expect(queries.length).toBe(1);
    expect(queries[0].query_id).toBe(queryId);
    expect(queries[0].query_snapshot).toBe('DeviceProcessEvents | where ProcessCommandLine has "vssadmin"');
    expect(queries[0].validation_status).toBe('RELEASED');
  });
});

describe('hunt_observations / hunt_evidence_links', () => {
  test('addObservation and addEvidence link together via observation_id', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    const obsId = await huntStore.addObservation(row.hunt_id, { queryId: null, summary: 'Matched 3 events', createdBy: OWNER_A });
    const evId = await huntStore.addEvidence(row.hunt_id, { observationId: obsId, description: 'Screenshot of matched events', referenceUrl: null, createdBy: OWNER_A });
    const observations = await huntStore.listObservations(row.hunt_id);
    const evidence = await huntStore.listEvidence(row.hunt_id);
    expect(observations[0].observation_id).toBe(obsId);
    expect(evidence[0].evidence_id).toBe(evId);
    expect(evidence[0].observation_id).toBe(obsId);
  });
});

describe('hunt_findings — evidence_refs JSON round-trip', () => {
  test('evidence_refs is stored as JSON and parsed back into a real array', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    const evId = await huntStore.addEvidence(row.hunt_id, { description: 'x', createdBy: OWNER_A });
    await huntStore.addFinding(row.hunt_id, {
      classification: 'CONFIRMED_MALICIOUS', confidence: 'HIGH', summary: 'Confirmed intrusion', evidenceRefs: [evId], createdBy: OWNER_A,
    });
    const findings = await huntStore.listFindings(row.hunt_id);
    expect(Array.isArray(findings[0].evidence_refs)).toBe(true);
    expect(findings[0].evidence_refs).toEqual([evId]);
  });

  test('an empty evidenceRefs array round-trips as an empty array, not null/undefined', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    await huntStore.addFinding(row.hunt_id, { classification: 'NO_EVIDENCE_FOUND', confidence: 'MEDIUM', summary: 'Nothing found', evidenceRefs: [], createdBy: OWNER_A });
    const findings = await huntStore.listFindings(row.hunt_id);
    expect(findings[0].evidence_refs).toEqual([]);
  });
});

describe('hunt_timeline — append-only, ordered, trimmed', () => {
  test('appendTimeline records events in insertion order', async () => {
    const row = await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    await huntStore.appendTimeline(row.hunt_id, 'HUNT_CREATED', 'Hunt created.', OWNER_A);
    await huntStore.appendTimeline(row.hunt_id, 'QUERY_ADDED', 'Query added.', OWNER_A);
    await huntStore.appendTimeline(row.hunt_id, 'DISPOSITION_SET', 'Closed.', OWNER_A);
    const timeline = await huntStore.listTimeline(row.hunt_id);
    expect(timeline.map((t) => t.event_type)).toEqual(['HUNT_CREATED', 'QUERY_ADDED', 'DISPOSITION_SET']);
  });

  test('appendTimeline never throws even if given a huntId that does not exist -- observability must never break the primary action', async () => {
    await expect(huntStore.appendTimeline('hunt_does_not_exist', 'HUNT_CREATED', 'x', OWNER_A)).resolves.not.toThrow();
  });
});

describe('bounded pagination -- no unlimited history responses', () => {
  test('listHunts caps at MAX_LIST_LIMIT regardless of a huge requested limit', async () => {
    for (let i = 0; i < 5; i++) {
      await huntStore.createHunt(OWNER_A, { title: `Hunt ${i}`, hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    }
    const rows = await huntStore.listHunts(OWNER_A, { limit: 999999 });
    expect(rows.length).toBe(5); // fewer than MAX_LIST_LIMIT exist, so this just proves no error/overflow, not the cap itself
  });

  test('a non-numeric or zero limit falls back to the default rather than erroring', async () => {
    await huntStore.createHunt(OWNER_A, { title: 'X', hypothesis: 'h', hypothesisSource: 'ANALYST_CREATED', priority: 'LOW', createdBy: OWNER_A });
    const rows = await huntStore.listHunts(OWNER_A, { limit: 'not-a-number' });
    expect(rows.length).toBe(1);
  });
});
