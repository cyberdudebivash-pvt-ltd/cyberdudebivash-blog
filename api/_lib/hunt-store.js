'use strict';
/**
 * SENTINEL APEX — Threat Hunting Workspace Persistence
 *
 * D1-backed lifecycle state for hunts / hunt_refs / hunt_queries /
 * hunt_observations / hunt_evidence_links / hunt_findings / hunt_timeline
 * (migrations/0005_threat_hunting_workspace.sql). Ownership is always
 * re-derived from the caller's authenticate()-issued userId, matching
 * deployment-store.js's exact precedent.
 *
 * Pure persistence + identity derivation only — hypothesis generation,
 * telemetry-readiness computation, deployment linkage, and coverage
 * maturity live in hunt-engine.js, which composes this module with the
 * already-certified detection/compatibility/deployment engines rather than
 * re-implementing any of them.
 */

const crypto = require('crypto');
const d1 = require('./d1');

const HUNT_STATUSES = ['DRAFT', 'READY', 'ACTIVE', 'PAUSED', 'AWAITING_EVIDENCE', 'ANALYSIS_COMPLETE', 'CLOSED'];
const HUNT_PRIORITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const HYPOTHESIS_SOURCES = ['ANALYST_CREATED', 'INTELLIGENCE_DERIVED', 'DETECTION_DERIVED', 'ALERT_DERIVED'];
const DISPOSITIONS = ['CONFIRMED_THREAT', 'BENIGN_ACTIVITY', 'FALSE_POSITIVE', 'INCONCLUSIVE', 'NO_EVIDENCE', 'MONITORING_REQUIRED'];
const FINDING_CLASSIFICATIONS = ['CONFIRMED_MALICIOUS', 'LIKELY_MALICIOUS', 'BENIGN', 'EXPECTED_ACTIVITY', 'INCONCLUSIVE', 'FALSE_POSITIVE', 'NO_EVIDENCE_FOUND'];
const REF_KINDS = ['threat_actor', 'cve', 'campaign', 'ioc', 'attack_technique', 'detection', 'deployment'];
const CONFIDENCE_LEVELS = ['HIGH', 'MEDIUM', 'LOW'];

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;
const CHILD_LIST_LIMIT = 200;
const TIMELINE_MAX_ENTRIES = 5000;

function generateId(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

function boundedLimit(requested) {
  const n = Number(requested);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_LIST_LIMIT;
  return Math.min(Math.floor(n), MAX_LIST_LIMIT);
}

function toPublicHunt(row) {
  return {
    hunt_id: row.hunt_id,
    title: row.title,
    status: row.status,
    priority: row.priority,
    hypothesis: row.hypothesis,
    hypothesis_source: row.hypothesis_source,
    linked_case_reference: row.linked_case_reference || null,
    disposition: row.disposition || null,
    disposition_summary: row.disposition_summary || null,
    disposition_by: row.disposition_by || null,
    disposition_at: row.disposition_at || null,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at,
    closed_at: row.closed_at || null,
  };
}

async function getHuntRaw(ownerId, huntId) {
  const rows = await d1.query('SELECT * FROM hunts WHERE hunt_id = ? AND owner_id = ?', [huntId, ownerId]);
  return rows[0] || null;
}

async function getHunt(ownerId, huntId) {
  const row = await getHuntRaw(ownerId, huntId);
  if (!row) return { error: 'NOT_FOUND', message: 'No hunt found.' };
  return { hunt: toPublicHunt(row) };
}

async function listHunts(ownerId, { status, limit } = {}) {
  const boundedN = boundedLimit(limit);
  if (status) {
    const rows = await d1.query(
      'SELECT * FROM hunts WHERE owner_id = ? AND status = ? ORDER BY updated_at DESC LIMIT ?',
      [ownerId, status, boundedN]
    );
    return rows.map(toPublicHunt);
  }
  const rows = await d1.query('SELECT * FROM hunts WHERE owner_id = ? ORDER BY updated_at DESC LIMIT ?', [ownerId, boundedN]);
  return rows.map(toPublicHunt);
}

async function createHunt(ownerId, { title, hypothesis, hypothesisSource, priority, createdBy }) {
  const huntId = generateId('hunt');
  const nowIso = new Date().toISOString();
  await d1.run(
    `INSERT INTO hunts
      (hunt_id, owner_id, title, status, priority, hypothesis, hypothesis_source, created_by, created_at, updated_at)
     VALUES (?, ?, ?, 'DRAFT', ?, ?, ?, ?, ?, ?)`,
    [huntId, ownerId, title, priority || 'MEDIUM', hypothesis, hypothesisSource, createdBy, nowIso, nowIso]
  );
  return getHuntRaw(ownerId, huntId);
}

/** Generic field updater, mirroring deployment-store.js#updateDeployment —
 *  the only mutation primitive hunt-engine.js goes through, so updated_at
 *  can never be forgotten at one call site but not another. */
async function updateHunt(huntId, fields) {
  const columns = Object.keys(fields);
  if (!columns.length) return;
  const setClause = columns.map((c) => `${c} = ?`).join(', ');
  const values = columns.map((c) => fields[c]);
  await d1.run(`UPDATE hunts SET ${setClause}, updated_at = ? WHERE hunt_id = ?`, [...values, new Date().toISOString(), huntId]);
}

async function addRef(huntId, refKind, refId) {
  await d1.run(
    'INSERT INTO hunt_refs (hunt_id, ref_kind, ref_id, created_at) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT (hunt_id, ref_kind, ref_id) DO NOTHING',
    [huntId, refKind, refId, new Date().toISOString()]
  );
}

async function listRefs(huntId) {
  return d1.query('SELECT ref_kind, ref_id, created_at FROM hunt_refs WHERE hunt_id = ? ORDER BY created_at ASC', [huntId]);
}

/** Reverse lookup — every hunt that references a given entity (used by
 *  detection-maturity.js to answer "has this detection produced an
 *  observed signal in any hunt for this owner" without a full table scan). */
async function listHuntIdsReferencing(refKind, refId) {
  const rows = await d1.query('SELECT hunt_id FROM hunt_refs WHERE ref_kind = ? AND ref_id = ?', [refKind, refId]);
  return rows.map((r) => r.hunt_id);
}

async function addQuery(huntId, { sourceDetectionId, sourceDetectionVersion, format, querySnapshot, validationStatus, addedBy }) {
  const queryId = generateId('hq');
  await d1.run(
    `INSERT INTO hunt_queries
      (query_id, hunt_id, source_detection_id, source_detection_version, format, query_snapshot, validation_status, added_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [queryId, huntId, sourceDetectionId, sourceDetectionVersion, format, querySnapshot, validationStatus, addedBy, new Date().toISOString()]
  );
  return queryId;
}

async function listQueries(huntId) {
  return d1.query('SELECT * FROM hunt_queries WHERE hunt_id = ? ORDER BY created_at ASC LIMIT ?', [huntId, CHILD_LIST_LIMIT]);
}

const MAX_SELECTED_FIELDS_JSON_LENGTH = 8000; // defense in depth on top of normalizeObservationRows' own per-field cap -- bounds one observation row's total size

/** executionId/selectedFields are optional (Controlled Read-Only SIEM
 *  Hunting Connectors v1) -- omitted entirely by every pre-existing,
 *  manually-authored observation, exactly as before this tranche.
 *  selectedFields, when supplied, is the ONE normalized result row
 *  (connector-contract.js#normalizeObservationRows' `fields` object) the
 *  analyst explicitly chose to keep -- never a bulk/automatic capture. */
async function addObservation(huntId, { queryId, summary, createdBy, executionId, selectedFields }) {
  const observationId = generateId('hob');
  let selectedFieldsJson = null;
  if (selectedFields && typeof selectedFields === 'object') {
    const serialized = JSON.stringify(selectedFields);
    selectedFieldsJson = serialized.length > MAX_SELECTED_FIELDS_JSON_LENGTH
      ? JSON.stringify({ truncated: true, reason: 'Selected fields exceeded the stored-size bound.' })
      : serialized;
  }
  await d1.run(
    'INSERT INTO hunt_observations (observation_id, hunt_id, query_id, summary, created_by, created_at, execution_id, selected_fields_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [observationId, huntId, queryId || null, summary, createdBy, new Date().toISOString(), executionId || null, selectedFieldsJson]
  );
  return observationId;
}

async function listObservations(huntId) {
  const rows = await d1.query('SELECT * FROM hunt_observations WHERE hunt_id = ? ORDER BY created_at ASC LIMIT ?', [huntId, CHILD_LIST_LIMIT]);
  return rows.map((r) => ({ ...r, selected_fields_json: r.selected_fields_json ? JSON.parse(r.selected_fields_json) : null }));
}

async function addEvidence(huntId, { observationId, description, referenceUrl, createdBy }) {
  const evidenceId = generateId('hev');
  await d1.run(
    'INSERT INTO hunt_evidence_links (evidence_id, hunt_id, observation_id, description, reference_url, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [evidenceId, huntId, observationId || null, description, referenceUrl || null, createdBy, new Date().toISOString()]
  );
  return evidenceId;
}

async function listEvidence(huntId) {
  return d1.query('SELECT * FROM hunt_evidence_links WHERE hunt_id = ? ORDER BY created_at ASC LIMIT ?', [huntId, CHILD_LIST_LIMIT]);
}

async function addFinding(huntId, { classification, confidence, summary, evidenceRefs, createdBy }) {
  const findingId = generateId('hfd');
  await d1.run(
    'INSERT INTO hunt_findings (finding_id, hunt_id, classification, confidence, summary, evidence_refs, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [findingId, huntId, classification, confidence, summary, JSON.stringify(evidenceRefs || []), createdBy, new Date().toISOString()]
  );
  return findingId;
}

async function listFindings(huntId) {
  const rows = await d1.query('SELECT * FROM hunt_findings WHERE hunt_id = ? ORDER BY created_at ASC LIMIT ?', [huntId, CHILD_LIST_LIMIT]);
  return rows.map((r) => ({ ...r, evidence_refs: r.evidence_refs ? JSON.parse(r.evidence_refs) : [] }));
}

async function appendTimeline(huntId, eventType, summary, actor) {
  try {
    await d1.run(
      'INSERT INTO hunt_timeline (hunt_id, event_type, summary, actor, created_at) VALUES (?, ?, ?, ?, ?)',
      [huntId, eventType, summary, actor, new Date().toISOString()]
    );
    await d1
      .run('DELETE FROM hunt_timeline WHERE id NOT IN (SELECT id FROM hunt_timeline ORDER BY id DESC LIMIT ?)', [TIMELINE_MAX_ENTRIES])
      .catch(() => {});
  } catch (_) {
    // Timeline is observability, never allowed to break the primary hunt action it's recording.
  }
}

async function listTimeline(huntId) {
  return d1.query('SELECT event_type, summary, actor, created_at FROM hunt_timeline WHERE hunt_id = ? ORDER BY id ASC LIMIT ?', [huntId, CHILD_LIST_LIMIT]);
}

module.exports = {
  HUNT_STATUSES,
  HUNT_PRIORITIES,
  HYPOTHESIS_SOURCES,
  DISPOSITIONS,
  FINDING_CLASSIFICATIONS,
  REF_KINDS,
  CONFIDENCE_LEVELS,
  generateId,
  toPublicHunt,
  getHuntRaw,
  getHunt,
  listHunts,
  createHunt,
  updateHunt,
  addRef,
  listRefs,
  listHuntIdsReferencing,
  addQuery,
  listQueries,
  addObservation,
  listObservations,
  addEvidence,
  listEvidence,
  addFinding,
  listFindings,
  appendTimeline,
  listTimeline,
};
