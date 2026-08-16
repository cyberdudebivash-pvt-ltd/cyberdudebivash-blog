'use strict';

/**
 * Structured, deterministic audit events for every publication decision —
 * one per sink.publish() call, ALLOW or DENY, always. Fields are limited
 * to hashes, identifiers, and reason codes; never a private key or other
 * secret material.
 */

function recordAuditEvent({ sink, manifest, artifactHash, keyId, signerIdentity, decision, reasonCode, policyVersion, now } = {}) {
  if (decision !== 'ALLOW' && decision !== 'DENY') {
    throw new TypeError(`recordAuditEvent: decision must be "ALLOW" or "DENY", got ${JSON.stringify(decision)}`);
  }
  if (typeof reasonCode !== 'string' || reasonCode.length === 0) {
    throw new TypeError('recordAuditEvent: reasonCode is required');
  }
  const timestamp = (now instanceof Date ? now : new Date()).toISOString();
  return Object.freeze({
    timestamp,
    sink: sink || null,
    manifestHash: (manifest && manifest.manifestHash) || null,
    artifactHash: artifactHash || null,
    keyId: keyId || null,
    signerIdentity: signerIdentity || null,
    disposition: (manifest && manifest.disposition) || null,
    authorizationStatus: decision === 'ALLOW' ? 'AUTHORIZED' : 'NOT_AUTHORIZED',
    decision,
    reasonCode,
    policyVersion: policyVersion || (manifest && manifest.policyVersion) || null,
  });
}

module.exports = { recordAuditEvent };
