'use strict';

/**
 * Signed authorization: binds a manifest + the exact artifact bytes + a
 * signer identity into one Ed25519-signed record. SHA-256 alone (as used
 * by release_manifest.js) proves the manifest hasn't changed; it does not
 * prove anyone with authority approved release. This module adds the
 * authenticity half.
 *
 * authorize() refuses unconditionally to sign a HOLD or DENY disposition.
 * verifyAuthorization() re-derives every fact it checks from the raw
 * manifest/artifact/authorization it is given — it never trusts a
 * caller-supplied hash, disposition, or boolean flag — and fails closed on
 * any exception, unknown state, or missing dependency.
 */

const crypto = require('node:crypto');
const { canonicalize, sha256Hex } = require('./canonical_json');
const { verifyManifestIntegrity, recomputeManifestHash } = require('./release_manifest');

const AUTHORIZABLE_DISPOSITIONS = new Set(['PUBLISH-READY', 'RESTRICTED-CONDITIONAL']);

const AUTHORIZATION_PAYLOAD_FIELDS = [
  'manifestHash',
  'artifactHash',
  'signerIdentity',
  'authorizationDecision',
  'issuedAt',
  'expiresAt',
  'policyVersion',
  'keyId',
  'nonce',
];

class AuthorizationRefusedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthorizationRefusedError';
  }
}

function sha256OfArtifact(artifactBytes) {
  const buf = Buffer.isBuffer(artifactBytes) ? artifactBytes : Buffer.from(String(artifactBytes), 'utf8');
  return sha256Hex(buf);
}

/**
 * @param {object} params
 * @param {object} params.manifest - output of buildManifest()
 * @param {Buffer|string} params.artifactBytes - exact bytes of the artifact being released
 * @param {string} params.signerIdentity - identity of the human/system granting authorization
 * @param {number} params.expiresInSeconds - required; no implicit default
 * @param {string} [params.nonce] - defaults to a random UUID
 * @param {Date} [params.now] - defaults to current time; inject for deterministic tests
 * @param {{ keyId: string, sign(payload: string): string }} signer - see signing.js createSigner()
 */
function authorize(params, signer) {
  const { manifest, artifactBytes, signerIdentity, expiresInSeconds, nonce, now } = params || {};

  if (!manifest || typeof manifest !== 'object') {
    throw new TypeError('authorize: manifest is required');
  }
  if (!verifyManifestIntegrity(manifest)) {
    throw new AuthorizationRefusedError(
      'authorize: manifest failed its own integrity check (manifestHash does not match its fields) — refusing to sign'
    );
  }
  if (!AUTHORIZABLE_DISPOSITIONS.has(manifest.disposition)) {
    throw new AuthorizationRefusedError(
      `authorize: refusing to authorize a manifest with disposition "${manifest.disposition}" — only ${[...AUTHORIZABLE_DISPOSITIONS].join(
        ', '
      )} may ever be signed`
    );
  }
  if (artifactBytes === undefined || artifactBytes === null) {
    throw new TypeError('authorize: artifactBytes is required');
  }
  if (typeof signerIdentity !== 'string' || signerIdentity.trim().length === 0) {
    throw new TypeError('authorize: signerIdentity is required');
  }
  if (!Number.isFinite(expiresInSeconds) || expiresInSeconds <= 0) {
    throw new TypeError('authorize: expiresInSeconds must be a positive, finite number (explicit — no default)');
  }
  if (!signer || typeof signer.sign !== 'function' || typeof signer.keyId !== 'string' || signer.keyId.length === 0) {
    throw new TypeError('authorize: signer must be { keyId, sign(payload) } — see signing.js createSigner()');
  }

  const issuedAtDate = now instanceof Date ? now : new Date();
  const issuedAt = issuedAtDate.toISOString();
  const expiresAt = new Date(issuedAtDate.getTime() + expiresInSeconds * 1000).toISOString();

  const payload = {
    manifestHash: manifest.manifestHash,
    artifactHash: sha256OfArtifact(artifactBytes),
    signerIdentity,
    authorizationDecision: manifest.disposition,
    issuedAt,
    expiresAt,
    policyVersion: manifest.policyVersion,
    keyId: signer.keyId,
    nonce: nonce || crypto.randomUUID(),
  };

  const payloadCanonical = canonicalize(payload);
  const signature = signer.sign(payloadCanonical);

  return Object.freeze({
    payload: Object.freeze({ ...payload }),
    payloadCanonical,
    signature,
  });
}

function isStructurallyValidRecord(authRecord) {
  if (!authRecord || typeof authRecord !== 'object') return false;
  if (typeof authRecord.payloadCanonical !== 'string' || authRecord.payloadCanonical.length === 0) return false;
  if (authRecord.signature !== undefined && typeof authRecord.signature !== 'string') return false;
  const payload = authRecord.payload;
  if (!payload || typeof payload !== 'object') return false;
  for (const field of AUTHORIZATION_PAYLOAD_FIELDS) {
    if (typeof payload[field] !== 'string' || payload[field].length === 0) return false;
  }
  return true;
}

function deny(reasonCode, reason) {
  return { ok: false, reasonCode, reason };
}

/**
 * Independently re-verifies every fact a publication decision depends on.
 * Never trusts anything already computed by the caller — recomputes the
 * manifest hash from `context.manifest`'s own fields and the artifact hash
 * from `context.artifactBytes`'s own bytes, and only then compares against
 * what the signed payload claims.
 *
 * @param {ReturnType<typeof authorize>} authRecord
 * @param {object} context
 * @param {object} context.manifest - the manifest to check the authorization against
 * @param {Buffer|string} context.artifactBytes - the exact artifact bytes to check against
 * @param {{ isKnownKey(keyId:string):boolean, verify(payload:string, signature:string, keyId:string):boolean }} context.verifier
 * @param {string[]} [context.revokedKeyIds]
 * @param {{ has(nonce:string):boolean, record(nonce:string):void }} [context.nonceStore]
 * @param {string} [context.policyVersion] - defaults to context.manifest.policyVersion
 * @param {Date} [context.now]
 */
function verifyAuthorization(authRecord, context = {}) {
  try {
    if (!isStructurallyValidRecord(authRecord)) {
      return deny('DENY_MALFORMED_AUTHORIZATION', 'authorization record is missing required fields or has the wrong shape');
    }

    const { payload, payloadCanonical, signature } = authRecord;

    let recomputedCanonical;
    try {
      recomputedCanonical = canonicalize(payload);
    } catch {
      return deny('DENY_MALFORMED_AUTHORIZATION', 'authorization payload is not canonicalizable');
    }
    if (recomputedCanonical !== payloadCanonical) {
      return deny('DENY_MALFORMED_AUTHORIZATION', 'payloadCanonical does not match canonicalize(payload) — record is inconsistent');
    }

    if (!context.verifier || typeof context.verifier.verify !== 'function' || typeof context.verifier.isKnownKey !== 'function') {
      return deny('DENY_MISSING_VERIFIER', 'no verifier supplied — cannot fail open on a missing dependency');
    }

    if (!signature || signature.length === 0) {
      return deny('DENY_MISSING_SIGNATURE', 'authorization has no signature');
    }

    if (!context.verifier.isKnownKey(payload.keyId)) {
      return deny('DENY_UNKNOWN_KEY', `keyId "${payload.keyId}" is not in the trusted key store`);
    }

    const revokedKeyIds = Array.isArray(context.revokedKeyIds) ? context.revokedKeyIds : [];
    if (revokedKeyIds.includes(payload.keyId)) {
      return deny('DENY_REVOKED_AUTHORIZATION', `keyId "${payload.keyId}" is revoked`);
    }

    // Intentionally NOT wrapped in a local try/catch: a verifier that
    // throws is a distinct failure mode from one that cryptographically
    // checked the signature and found it invalid, and must be reported
    // differently (DENY_INTERNAL_VERIFICATION_ERROR via the outer catch,
    // not DENY_INVALID_SIGNATURE) so operators don't mistake a broken
    // verifier for a forged signature.
    const sigValid = context.verifier.verify(recomputedCanonical, signature, payload.keyId);
    if (!sigValid) {
      return deny('DENY_INVALID_SIGNATURE', 'signature does not verify against the payload and keyId');
    }

    if (!context.manifest || typeof context.manifest !== 'object') {
      return deny('DENY_MALFORMED_MANIFEST', 'no manifest supplied for verification');
    }
    if (!verifyManifestIntegrity(context.manifest)) {
      return deny('DENY_MALFORMED_MANIFEST', 'manifest supplied for verification fails its own integrity check');
    }
    if (recomputeManifestHash(context.manifest) !== payload.manifestHash) {
      return deny('DENY_MANIFEST_HASH_MISMATCH', 'this authorization is bound to a different manifest than the one supplied');
    }

    if (context.manifest.disposition === 'HOLD' || context.manifest.disposition === 'DENY') {
      return deny('DENY_HOLD', `manifest disposition is "${context.manifest.disposition}" — HOLD/DENY can never be published`);
    }
    if (payload.authorizationDecision !== context.manifest.disposition) {
      return deny(
        'DENY_AUTHORIZATION_DECISION_MISMATCH',
        `authorization was granted for disposition "${payload.authorizationDecision}" but manifest now reports "${context.manifest.disposition}"`
      );
    }

    if (context.artifactBytes === undefined || context.artifactBytes === null) {
      return deny('DENY_ARTIFACT_HASH_MISMATCH', 'no artifact bytes supplied for verification');
    }
    if (sha256OfArtifact(context.artifactBytes) !== payload.artifactHash) {
      return deny('DENY_ARTIFACT_HASH_MISMATCH', 'artifact bytes do not match the hash bound in the authorization');
    }

    const now = context.now instanceof Date ? context.now : new Date();
    const issuedAtMs = Date.parse(payload.issuedAt);
    const expiresAtMs = Date.parse(payload.expiresAt);
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
      return deny('DENY_MALFORMED_AUTHORIZATION', 'issuedAt/expiresAt are not valid timestamps');
    }
    if (now.getTime() < issuedAtMs) {
      return deny('DENY_NOT_YET_VALID', 'authorization issuedAt is in the future relative to verification time');
    }
    if (now.getTime() > expiresAtMs) {
      return deny('DENY_EXPIRED_AUTHORIZATION', 'authorization has expired');
    }

    const expectedPolicyVersion = context.policyVersion || context.manifest.policyVersion;
    if (payload.policyVersion !== expectedPolicyVersion) {
      return deny('DENY_POLICY_VERSION', `authorization policyVersion "${payload.policyVersion}" does not match expected "${expectedPolicyVersion}"`);
    }

    if (context.nonceStore) {
      if (typeof context.nonceStore.has !== 'function' || typeof context.nonceStore.record !== 'function') {
        return deny('DENY_INTERNAL_VERIFICATION_ERROR', 'nonceStore does not implement the required interface');
      }
      if (context.nonceStore.has(payload.nonce)) {
        return deny('DENY_REPLAY', `nonce "${payload.nonce}" has already been used — replay rejected`);
      }
      context.nonceStore.record(payload.nonce);
    }

    return {
      ok: true,
      reasonCode: context.manifest.disposition === 'RESTRICTED-CONDITIONAL' ? 'ALLOW_AUTHORIZED_RESTRICTED_RELEASE' : 'ALLOW_AUTHORIZED_PUBLIC_RELEASE',
      reason: 'all authorization checks passed',
      keyId: payload.keyId,
      disposition: context.manifest.disposition,
    };
  } catch (err) {
    return deny('DENY_INTERNAL_VERIFICATION_ERROR', `unexpected exception during verification: ${err && err.message ? err.message : String(err)}`);
  }
}

module.exports = {
  authorize,
  verifyAuthorization,
  AuthorizationRefusedError,
  AUTHORIZATION_PAYLOAD_FIELDS,
  AUTHORIZABLE_DISPOSITIONS,
};
