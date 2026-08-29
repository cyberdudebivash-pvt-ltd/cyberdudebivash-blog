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
    this.code = code;           // AUTH_FAILED | PERMISSION_DENIED | TARGET_NOT_FOUND | RATE_LIMITED | REMOTE_ERROR | TIMEOUT | RESPONSE_TOO_LARGE
    this.retryable = retryable;
    this.httpStatus = httpStatus;
  }
}

module.exports = { CONNECTION_TEST_RESULTS, ConnectorError };
