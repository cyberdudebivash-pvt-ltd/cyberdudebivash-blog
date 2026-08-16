'use strict';

/**
 * Freezes decide()'s output into a content-addressed manifest. The
 * manifest's hash is what authorization.js signs and what every sink
 * re-verifies — nothing downstream trusts the manifest object's fields
 * directly, only the hash recomputed from them.
 */

const { randomUUID } = require('node:crypto');
const { canonicalize, sha256Hex } = require('./canonical_json');
const { POLICY_VERSION } = require('./publication_engine');

// Only these fields of decide()'s output are covered by manifestHash.
// Extend deliberately if decide()'s output shape grows — anything not
// listed here is not tamper-evident.
const MANIFEST_HASHED_FIELDS = ['caseId', 'disposition', 'reasonCode', 'reasons', 'evaluatedAt', 'policyVersion'];

function hashedPayloadOf(source) {
  const payload = {};
  for (const field of MANIFEST_HASHED_FIELDS) payload[field] = source[field];
  return payload;
}

/**
 * @param {ReturnType<import('./publication_engine').decide>} decision
 * @param {{ now?: Date, manifestId?: string }} [options]
 */
function buildManifest(decision, options = {}) {
  if (!decision || typeof decision !== 'object') {
    throw new TypeError('buildManifest: decision must be the object returned by decide()');
  }
  for (const field of [...MANIFEST_HASHED_FIELDS, 'caseId']) {
    if (!(field in decision)) {
      throw new TypeError(`buildManifest: decision is missing required field "${field}" — did you pass the raw output of decide()?`);
    }
  }
  if (decision.policyVersion !== POLICY_VERSION) {
    throw new TypeError(
      `buildManifest: decision.policyVersion "${decision.policyVersion}" does not match engine POLICY_VERSION "${POLICY_VERSION}"`
    );
  }

  const now = options.now instanceof Date ? options.now : new Date();
  const manifestHash = sha256Hex(canonicalize(hashedPayloadOf(decision)));

  return Object.freeze({
    manifestId: options.manifestId || randomUUID(),
    caseId: decision.caseId,
    disposition: decision.disposition,
    reasonCode: decision.reasonCode,
    reasons: Object.freeze([...decision.reasons]),
    evaluatedAt: decision.evaluatedAt,
    policyVersion: decision.policyVersion,
    createdAt: now.toISOString(),
    manifestHash,
  });
}

/**
 * Recomputes a manifest's hash from its own current field values.
 * Verifiers must always call this rather than trusting the manifestHash
 * property as printed on a manifest object handed to them.
 */
function recomputeManifestHash(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new TypeError('recomputeManifestHash: manifest must be an object');
  }
  return sha256Hex(canonicalize(hashedPayloadOf(manifest)));
}

function verifyManifestIntegrity(manifest) {
  try {
    return recomputeManifestHash(manifest) === manifest.manifestHash;
  } catch {
    return false;
  }
}

module.exports = { buildManifest, recomputeManifestHash, verifyManifestIntegrity, MANIFEST_HASHED_FIELDS };
