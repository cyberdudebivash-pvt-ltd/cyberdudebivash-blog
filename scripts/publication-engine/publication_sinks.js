'use strict';

/**
 * Mock sink adapters — local stubs that prove the enforcement PATTERN, not
 * real integrations with any live RSS feed, Blogger account, API gateway,
 * bundle store, or enterprise delivery channel. See SKILL.md — "REAL
 * PUBLISHING DAG" / "PRODUCTION CONTAINMENT: NOT VERIFIED" — for what
 * wiring this into an actual egress path would require.
 *
 * Every sink independently re-verifies the authorization (never trusts a
 * precomputed boolean) and independently re-checks its own distribution
 * eligibility from the verified manifest's disposition (never trusts a
 * caller-supplied classification string).
 */

const { verifyAuthorization } = require('./authorization');
const { recordAuditEvent } = require('./audit');

const PUBLIC_SINK_TYPES = new Set(['rss', 'blogger', 'api', 'downloadable-bundle']);
const RESTRICTED_SINK_TYPES = new Set(['restricted-enterprise']);
const ALL_SINK_TYPES = new Set([...PUBLIC_SINK_TYPES, ...RESTRICTED_SINK_TYPES]);

function auditFrom(type, authRecord, context, decision, reasonCode) {
  const payload = authRecord && authRecord.payload;
  return recordAuditEvent({
    sink: type,
    manifest: context.manifest,
    artifactHash: payload && payload.artifactHash,
    keyId: payload && payload.keyId,
    signerIdentity: payload && payload.signerIdentity,
    decision,
    reasonCode,
    policyVersion: context.policyVersion || (context.manifest && context.manifest.policyVersion),
    now: context.now,
  });
}

/**
 * @param {'rss'|'blogger'|'api'|'downloadable-bundle'|'restricted-enterprise'} type
 */
function createSink(type) {
  if (!ALL_SINK_TYPES.has(type)) {
    throw new TypeError(`createSink: unknown sink type "${type}" — must be one of ${[...ALL_SINK_TYPES].join(', ')}`);
  }
  const isPublic = PUBLIC_SINK_TYPES.has(type);

  return {
    type,
    isPublic,
    /**
     * @param {ReturnType<import('./authorization').authorize>} authRecord
     * @param {object} context - { manifest, artifactBytes, verifier, revokedKeyIds, nonceStore, policyVersion, now }
     * @returns {ReturnType<import('./audit').recordAuditEvent>}
     */
    publish(authRecord, context = {}) {
      const verification = verifyAuthorization(authRecord, context);

      if (!verification.ok) {
        return auditFrom(type, authRecord, context, 'DENY', verification.reasonCode);
      }

      // verification.disposition was recomputed and verified inside
      // verifyAuthorization() from context.manifest's own fields — not
      // supplied by the caller. A public sink never carries
      // RESTRICTED-CONDITIONAL, no matter how validly it was authorized
      // for the *restricted* channel.
      if (verification.disposition === 'RESTRICTED-CONDITIONAL' && isPublic) {
        return auditFrom(type, authRecord, context, 'DENY', 'DENY_RESTRICTED_PUBLICATION');
      }

      return auditFrom(type, authRecord, context, 'ALLOW', verification.reasonCode);
    },
  };
}

module.exports = { createSink, PUBLIC_SINK_TYPES, RESTRICTED_SINK_TYPES, ALL_SINK_TYPES };
