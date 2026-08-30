'use strict';
/**
 * SENTINEL APEX — SIEM Connector Contract (Controlled SIEM Deployment
 * Gateway v1)
 *
 * The common internal interface every connector module implements.
 * Capability flags (siem-connector-taxonomy.js#KNOWN_PLATFORMS) govern
 * which of these a given connector actually supports — a connector is
 * never required to implement every method; deployment-engine.js checks
 * the capability flag before calling.
 *
 * @typedef {Object} DeploymentIntent
 * @property {string} remote_resource_name  Deterministic, from deployment-store.js#deriveRemoteResourceName() — the idempotency key.
 * @property {string} detection_id
 * @property {string} detection_version
 * @property {string} title
 * @property {string} description
 * @property {string} technique_id          ATT&CK technique id, e.g. "T1490"
 * @property {string} severity_raw          detection-rules.js's raw `level` field (e.g. "critical"/"high"/"medium"/"low") — the connector maps this to its own severity enum
 * @property {string} format                e.g. "kql" — matches defense-compatibility.js's format_used
 * @property {string} query                 the format-specific rule content (raw text)
 * @property {boolean} enabled              customer-approved enabled/disabled state (safe default: false)
 *
 * @typedef {Object} ObservedState  Canonical, connector-agnostic read-back shape.
 * @property {string} query
 * @property {string} severity              connector-native severity string, as actually stored remotely
 * @property {boolean} enabled
 * @property {string[]} techniques           sorted, for stable hashing (Section 47: remote normalization)
 *
 * Every connector module exports:
 *   platformId: string
 *   testConnection(connector): Promise<{ result: 'CONNECTED'|'AUTH_FAILED'|'INSUFFICIENT_PERMISSION'|'TARGET_NOT_FOUND'|'UNAVAILABLE', detail?: string }>
 *     Read-only. Must never create/modify a remote resource (Section 25).
 *   mapIntent(connector, intent): { nativePayload: object }
 *     Pure function, no I/O — the vendor-shaped payload a deploy() call would send. Used by previewDeployment() to show the customer exactly what would be created/changed.
 *   deploy(connector, intent): Promise<{ remote_resource_id: string, remote_etag: string|null, raw: object }>
 *     Idempotent upsert keyed by intent.remote_resource_name — calling twice with the same intent must not create a duplicate remote resource.
 *   readBack(connector, remoteResourceName): Promise<{ found: boolean, observed: ObservedState|null, etag: string|null, raw: object|null }>
 *   disable(connector, remoteResourceName): Promise<{ ok: boolean }>
 *     Sets the remote resource's enabled state to false (never deletes).
 *   deleteRemote(connector, remoteResourceName): Promise<{ ok: boolean }>
 *     Only present when capabilities.delete_supported — hard delete, used only on explicit customer request (Section 56/80).
 *
 * Controlled Read-Only SIEM Hunting Connectors v1 adds three further
 * optional methods, gated by capabilities.hunt_query_supported — a
 * SEPARATE flag from deploy_supported, never assumed equal to it
 * (siem-connector-taxonomy.js's file header explains why: a genuinely
 * different OAuth scope/RBAC role is required for microsoft-sentinel):
 *
 *   testHuntQueryConnection(connector): Promise<{ result: 'CONNECTED'|'AUTH_FAILED'|'INSUFFICIENT_PERMISSION'|'TARGET_NOT_FOUND'|'UNAVAILABLE', detail?: string }>
 *     Same result contract as testConnection(), but exercises the
 *     hunting-specific credential/scope/permission path — its result is
 *     never inferred from testConnection()'s result, only ever a real,
 *     independent read-only test call.
 *   executeHuntQuery(connector, { query, format, timeStart, timeEnd, rowLimit }): Promise<{ rows: object[], truncated: boolean, raw: object }>
 *     Read-only remote search — must never create, modify, or delete a
 *     remote resource. timeStart/timeEnd are explicit ISO 8601 bounds
 *     (never an unbounded historical query); the connector must enforce
 *     rowLimit itself and set `truncated: true` rather than silently
 *     returning more rows than requested. Throws ConnectorError on
 *     failure, including a new QUERY_REJECTED code (query/format rejected
 *     before any remote call was attempted — e.g. unsupported format).
 *   normalizeResults(connector, rawRows): Array<{ fields: object, source_row_index: number }>
 *     Pure function, no I/O. Maps vendor-native row shape into a stable
 *     envelope analysts can review — deliberately NOT forcing every SIEM's
 *     fields into one identical schema (Section 86), only the envelope is
 *     shared. `fields` values are always primitives (string/number/
 *     boolean/null) after normalization — never nested objects/arrays —
 *     so downstream XSS-safe rendering and hunt_observations storage never
 *     has to guard against unbounded remote-JSON shape.
 *
 * `connector` passed to every method is the full siem_connectors row with
 * `credential` already decrypted onto it as `connector.credential` (an
 * object, shape per platform) by the caller (deployment-engine.js /
 * siem-connector-store.js#testConnector()) — connector modules never read
 * connector_crypto.js or D1 directly themselves, keeping "decrypt only
 * for the duration of one authorized operation" (Section 21) enforced in
 * exactly one place.
 */

const CONNECTION_TEST_RESULTS = Object.freeze([
  'CONNECTED', 'AUTH_FAILED', 'INSUFFICIENT_PERMISSION', 'TARGET_NOT_FOUND', 'UNAVAILABLE',
]);

/**
 * Uniform error shape every connector throws on a failed deploy/readBack/
 * disable/deleteRemote call, so deployment-engine.js can classify
 * RETRYABLE vs TERMINAL failures identically regardless of which
 * connector raised them (Section 70/71 failure-state taxonomy).
 */
class ConnectorError extends Error {
  constructor(code, message, { retryable = false, httpStatus = null } = {}) {
    super(message);
    this.name = 'ConnectorError';
    this.code = code;           // AUTH_FAILED | PERMISSION_DENIED | TARGET_NOT_FOUND | RATE_LIMITED | REMOTE_ERROR | TIMEOUT | RESPONSE_TOO_LARGE | QUERY_REJECTED
    this.retryable = retryable;
    this.httpStatus = httpStatus;
  }
}

const DANGEROUS_OBSERVATION_FIELD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_OBSERVATION_FIELD_STRING_LENGTH = 2000;

function sanitizeObservationFieldValue(value) {
  if (value === null) return null;
  const t = typeof value;
  if (t === 'string') return value.length > MAX_OBSERVATION_FIELD_STRING_LENGTH ? value.slice(0, MAX_OBSERVATION_FIELD_STRING_LENGTH) : value;
  if (t === 'number' || t === 'boolean') return value;
  return undefined; // objects/arrays/functions/symbols/undefined -- never carried through; caller drops the key entirely
}

/**
 * Shared by every connector's normalizeResults(connector, rawRows)
 * (Section 47/86) — the one, single-source-of-truth implementation of the
 * stable { fields, source_row_index } envelope every hunt-query connector
 * returns. `fields` values are always primitives (string/number/boolean/
 * null); `__proto__`/`constructor`/`prototype` keys are always dropped,
 * never merely overwritten, so a hostile remote row can never pollute
 * anything downstream that later spreads/assigns these fields onto
 * another object. Deliberately does NOT force every SIEM's field NAMES
 * into one identical schema (Section 86) — only this envelope and the
 * primitive-only/dangerous-key discipline are shared; a structurally
 * malformed row (not an object, or null) is dropped entirely rather than
 * guessed at.
 */
function normalizeObservationRows(rawRows) {
  if (!Array.isArray(rawRows)) return [];
  const normalized = [];
  for (let i = 0; i < rawRows.length; i++) {
    const row = rawRows[i];
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    const fields = {};
    for (const key of Object.keys(row)) {
      if (DANGEROUS_OBSERVATION_FIELD_KEYS.has(key) || key.length > 200) continue;
      const safe = sanitizeObservationFieldValue(row[key]);
      if (safe === undefined) continue;
      fields[key] = safe;
    }
    normalized.push({ fields, source_row_index: i });
  }
  return normalized;
}

module.exports = { CONNECTION_TEST_RESULTS, ConnectorError, normalizeObservationRows };
