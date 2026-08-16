'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { decide } = require('./publication_engine');
const { buildManifest } = require('./release_manifest');
const { generateEphemeralKeypair, createSigner, createVerifier } = require('./signing');
const { authorize, verifyAuthorization, AuthorizationRefusedError } = require('./authorization');
const { createInMemoryNonceStore } = require('./nonce_store');
const { validCase, restrictedCase } = require('./test/fixtures');

const FIXED_NOW = new Date('2026-08-16T12:00:00.000Z');
const ARTIFACT = Buffer.from('SYNTHETIC ARTIFACT FIXTURE — NOT REAL INTELLIGENCE — CVE-2099-00001 test report body');
const OTHER_ARTIFACT = Buffer.from('SYNTHETIC ARTIFACT FIXTURE — a completely different report body');

function setup(caseInput = validCase(), keyId = 'key-A') {
  const { publicKey, privateKey } = generateEphemeralKeypair();
  const signer = createSigner({ keyId, privateKey });
  const verifier = createVerifier({ trustedKeys: { [keyId]: publicKey } });
  const manifest = buildManifest(decide(caseInput, { now: FIXED_NOW }), { now: FIXED_NOW });
  return { keyId, publicKey, privateKey, signer, verifier, manifest };
}

function authorizeFx(fx, overrides = {}) {
  return authorize(
    {
      manifest: fx.manifest,
      artifactBytes: overrides.artifactBytes || ARTIFACT,
      signerIdentity: overrides.signerIdentity || 'analyst@cyberdudebivash.com',
      expiresInSeconds: overrides.expiresInSeconds || 3600,
      now: overrides.now || FIXED_NOW,
      nonce: overrides.nonce,
    },
    overrides.signer || fx.signer
  );
}

function ctx(fx, overrides = {}) {
  return {
    manifest: 'manifest' in overrides ? overrides.manifest : fx.manifest,
    artifactBytes: 'artifactBytes' in overrides ? overrides.artifactBytes : ARTIFACT,
    verifier: 'verifier' in overrides ? overrides.verifier : fx.verifier,
    revokedKeyIds: overrides.revokedKeyIds || [],
    nonceStore: overrides.nonceStore,
    policyVersion: overrides.policyVersion,
    now: overrides.now || FIXED_NOW,
  };
}

describe('authorize(): refuses to ever sign a non-releasable disposition', () => {
  test('refuses a HOLD manifest', () => {
    const fx = setup(validCase({ contradictions: [{ field: 'x', resolved: false }] }));
    assert.equal(fx.manifest.disposition, 'HOLD');
    assert.throws(() => authorizeFx(fx), AuthorizationRefusedError);
  });

  test('refuses a DENY manifest (cannot even be constructed via buildManifest, but authorize() checks independently)', () => {
    const fx = setup();
    const denyManifest = { ...fx.manifest, disposition: 'DENY' };
    // Force a self-consistent DENY manifest by rebuilding its hash the same way release_manifest does.
    const { canonicalize, sha256Hex } = require('./canonical_json');
    const { MANIFEST_HASHED_FIELDS } = require('./release_manifest');
    const payload = {};
    for (const f of MANIFEST_HASHED_FIELDS) payload[f] = denyManifest[f];
    denyManifest.manifestHash = sha256Hex(canonicalize(payload));
    assert.throws(
      () => authorize({ manifest: denyManifest, artifactBytes: ARTIFACT, signerIdentity: 'a', expiresInSeconds: 60 }, fx.signer),
      AuthorizationRefusedError
    );
  });

  test('refuses a manifest that fails its own integrity check', () => {
    const fx = setup();
    const corrupted = { ...fx.manifest, disposition: 'PUBLISH-READY-BUT-TAMPERED' };
    assert.throws(
      () => authorize({ manifest: corrupted, artifactBytes: ARTIFACT, signerIdentity: 'a', expiresInSeconds: 60 }, fx.signer),
      AuthorizationRefusedError
    );
  });

  test('requires artifactBytes, signerIdentity, expiresInSeconds, and a signer', () => {
    const fx = setup();
    assert.throws(() => authorize({ manifest: fx.manifest, signerIdentity: 'a', expiresInSeconds: 60 }, fx.signer));
    assert.throws(() => authorize({ manifest: fx.manifest, artifactBytes: ARTIFACT, expiresInSeconds: 60 }, fx.signer));
    assert.throws(() => authorize({ manifest: fx.manifest, artifactBytes: ARTIFACT, signerIdentity: 'a' }, fx.signer));
    assert.throws(() => authorize({ manifest: fx.manifest, artifactBytes: ARTIFACT, signerIdentity: 'a', expiresInSeconds: 60 }, null));
    assert.throws(() => authorize({ manifest: fx.manifest, artifactBytes: ARTIFACT, signerIdentity: 'a', expiresInSeconds: -1 }, fx.signer));
  });
});

describe('authorize(): success shape', () => {
  test('binds manifestHash, artifactHash, signerIdentity, decision, issuedAt, expiresAt, policyVersion, keyId, nonce', () => {
    const fx = setup();
    const record = authorizeFx(fx, { signerIdentity: 'analyst@cyberdudebivash.com', expiresInSeconds: 7200 });
    const p = record.payload;
    assert.equal(p.manifestHash, fx.manifest.manifestHash);
    assert.equal(p.signerIdentity, 'analyst@cyberdudebivash.com');
    assert.equal(p.authorizationDecision, 'PUBLISH-READY');
    assert.equal(p.policyVersion, fx.manifest.policyVersion);
    assert.equal(p.keyId, fx.keyId);
    assert.equal(p.issuedAt, FIXED_NOW.toISOString());
    assert.equal(p.expiresAt, new Date(FIXED_NOW.getTime() + 7200 * 1000).toISOString());
    assert.ok(typeof p.nonce === 'string' && p.nonce.length > 0);
    assert.ok(typeof record.signature === 'string' && record.signature.length > 0);
  });
});

describe('verifyAuthorization(): happy path', () => {
  test('a correctly authorized PUBLISH-READY artifact verifies as ALLOW_AUTHORIZED_PUBLIC_RELEASE', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx));
    assert.equal(result.ok, true);
    assert.equal(result.reasonCode, 'ALLOW_AUTHORIZED_PUBLIC_RELEASE');
    assert.equal(result.disposition, 'PUBLISH-READY');
  });

  test('a correctly authorized RESTRICTED-CONDITIONAL artifact verifies as ALLOW_AUTHORIZED_RESTRICTED_RELEASE', () => {
    const fx = setup(restrictedCase());
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx));
    assert.equal(result.ok, true);
    assert.equal(result.reasonCode, 'ALLOW_AUTHORIZED_RESTRICTED_RELEASE');
    assert.equal(result.disposition, 'RESTRICTED-CONDITIONAL');
  });
});

describe('verifyAuthorization(): manifest integrity', () => {
  test('manifest tampering (disposition mutated in place) -> DENY', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const tamperedManifest = { ...fx.manifest, disposition: 'PUBLISH-READY-FORGED' };
    const result = verifyAuthorization(record, ctx(fx, { manifest: tamperedManifest }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MALFORMED_MANIFEST');
  });

  test('disposition tampering specifically: a HOLD manifest hand-flipped to PUBLISH-READY fails its own integrity check, so no real authorization can ever bind to it', () => {
    const fx = setup(validCase({ contradictions: [{ field: 'x', resolved: false }] }));
    assert.equal(fx.manifest.disposition, 'HOLD');
    const tamperedManifest = { ...fx.manifest, disposition: 'PUBLISH-READY' };
    assert.equal(require('./release_manifest').verifyManifestIntegrity(tamperedManifest), false);
    // A legitimately-authorized record from an unrelated case cannot be laundered
    // through the tampered manifest either, because its hash cannot match.
    const other = setup();
    const otherRecord = authorizeFx(other);
    const result = verifyAuthorization(otherRecord, ctx(other, { manifest: tamperedManifest }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MALFORMED_MANIFEST');
  });

  test('authorization for manifest A rejected when checked against unrelated manifest B', () => {
    const fxA = setup(validCase({ caseId: 'CASE-A' }));
    const fxB = setup(validCase({ caseId: 'CASE-B' }));
    const recordA = authorizeFx(fxA);
    const result = verifyAuthorization(recordA, ctx(fxA, { manifest: fxB.manifest, verifier: fxA.verifier }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MANIFEST_HASH_MISMATCH');
  });

  test('claim mutation after manifest generation: old authorization rejected against the manifest rebuilt from mutated evidence', () => {
    const original = validCase({ claims: [{ claimId: 'c1', claimText: 'x', claimType: 'FACT', critical: true, evidenceIds: ['e1'], verificationState: 'VERIFIED' }] });
    const fx = setup(original);
    const record = authorizeFx(fx);

    const mutated = validCase({ claims: [{ claimId: 'c1', claimText: 'x', claimType: 'FACT', critical: true, evidenceIds: [], verificationState: 'UNVERIFIED' }] });
    const mutatedManifest = buildManifest(decide(mutated, { now: FIXED_NOW }), { now: FIXED_NOW });

    const result = verifyAuthorization(record, ctx(fx, { manifest: mutatedManifest }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MANIFEST_HASH_MISMATCH');
  });

  test('no manifest supplied at verification time -> DENY', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx, { manifest: null }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MALFORMED_MANIFEST');
  });
});

describe('verifyAuthorization(): artifact integrity', () => {
  test('one-byte artifact mutation -> DENY_ARTIFACT_HASH_MISMATCH', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const mutated = Buffer.from(ARTIFACT);
    mutated[0] = mutated[0] ^ 0xff;
    const result = verifyAuthorization(record, ctx(fx, { artifactBytes: mutated }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_ARTIFACT_HASH_MISMATCH');
  });

  test('a different report entirely, same authorization -> DENY_ARTIFACT_HASH_MISMATCH', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx, { artifactBytes: OTHER_ARTIFACT }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_ARTIFACT_HASH_MISMATCH');
  });

  test('no artifact bytes supplied at verification time -> DENY', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx, { artifactBytes: null }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_ARTIFACT_HASH_MISMATCH');
  });
});

describe('verifyAuthorization(): signature security', () => {
  test('missing signature -> DENY_MISSING_SIGNATURE', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const stripped = { ...record, signature: undefined };
    const result = verifyAuthorization(stripped, ctx(fx));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MISSING_SIGNATURE');
  });

  test('empty-string signature -> DENY_MISSING_SIGNATURE', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const stripped = { ...record, signature: '' };
    const result = verifyAuthorization(stripped, ctx(fx));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MISSING_SIGNATURE');
  });

  test('corrupted signature -> DENY_INVALID_SIGNATURE', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const corrupted = { ...record, signature: record.signature.slice(0, -4) + (record.signature.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA') };
    const result = verifyAuthorization(corrupted, ctx(fx));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_INVALID_SIGNATURE');
  });

  test('wrong public key registered under the same trusted keyId -> DENY_INVALID_SIGNATURE', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const wrongKp = generateEphemeralKeypair();
    const wrongVerifier = createVerifier({ trustedKeys: { [fx.keyId]: wrongKp.publicKey } });
    const result = verifyAuthorization(record, ctx(fx, { verifier: wrongVerifier }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_INVALID_SIGNATURE');
  });

  test('unknown keyId -> DENY_UNKNOWN_KEY', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const emptyVerifier = createVerifier({ trustedKeys: {} });
    const result = verifyAuthorization(record, ctx(fx, { verifier: emptyVerifier }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_UNKNOWN_KEY');
  });

  test('payload modified (and re-canonicalized) without re-signing -> DENY_INVALID_SIGNATURE', () => {
    const fx = setup();
    const record = authorizeFx(fx, { expiresInSeconds: 60 });
    const { canonicalize } = require('./canonical_json');
    const forgedPayload = { ...record.payload, expiresAt: new Date(FIXED_NOW.getTime() + 999999 * 1000).toISOString() };
    const forgedRecord = { payload: forgedPayload, payloadCanonical: canonicalize(forgedPayload), signature: record.signature };
    const result = verifyAuthorization(forgedRecord, ctx(fx));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_INVALID_SIGNATURE');
  });

  test('self-inconsistent record (payloadCanonical stale relative to mutated payload) -> DENY_MALFORMED_AUTHORIZATION', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const forged = { ...record, payload: { ...record.payload, signerIdentity: 'someone-else@example.com' } };
    const result = verifyAuthorization(forged, ctx(fx));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MALFORMED_AUTHORIZATION');
  });
});

describe('verifyAuthorization(): authorization lifecycle', () => {
  test('expired authorization -> DENY_EXPIRED_AUTHORIZATION', () => {
    const fx = setup();
    const record = authorizeFx(fx, { expiresInSeconds: 60 });
    const later = new Date(FIXED_NOW.getTime() + 3600 * 1000);
    const result = verifyAuthorization(record, ctx(fx, { now: later }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_EXPIRED_AUTHORIZATION');
  });

  test('not-yet-valid authorization -> DENY_NOT_YET_VALID', () => {
    const fx = setup();
    const record = authorizeFx(fx, { expiresInSeconds: 3600 });
    const earlier = new Date(FIXED_NOW.getTime() - 60 * 1000);
    const result = verifyAuthorization(record, ctx(fx, { now: earlier }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_NOT_YET_VALID');
  });

  test('revoked key -> DENY_REVOKED_AUTHORIZATION', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx, { revokedKeyIds: [fx.keyId] }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_REVOKED_AUTHORIZATION');
  });

  test('wrong expected policyVersion -> DENY_POLICY_VERSION', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx, { policyVersion: '9.9.9' }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_POLICY_VERSION');
  });

  test('nonce reuse is rejected as a replay on the second verification', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const nonceStore = createInMemoryNonceStore();
    const first = verifyAuthorization(record, ctx(fx, { nonceStore }));
    assert.equal(first.ok, true);
    const second = verifyAuthorization(record, ctx(fx, { nonceStore }));
    assert.equal(second.ok, false);
    assert.equal(second.reasonCode, 'DENY_REPLAY');
  });
});

describe('verifyAuthorization(): disposition controls', () => {
  test('HOLD can never verify as authorized, even via a hand-forged record bypassing authorize()', () => {
    const fx = setup(validCase({ contradictions: [{ field: 'x', resolved: false }] }));
    assert.equal(fx.manifest.disposition, 'HOLD');
    const { canonicalize } = require('./canonical_json');
    const payload = {
      manifestHash: fx.manifest.manifestHash,
      artifactHash: require('node:crypto').createHash('sha256').update(ARTIFACT).digest('hex'),
      signerIdentity: 'rogue@example.com',
      authorizationDecision: 'HOLD',
      issuedAt: FIXED_NOW.toISOString(),
      expiresAt: new Date(FIXED_NOW.getTime() + 3600000).toISOString(),
      policyVersion: fx.manifest.policyVersion,
      keyId: fx.keyId,
      nonce: 'forged-nonce-1',
    };
    const payloadCanonical = canonicalize(payload);
    const forged = { payload, payloadCanonical, signature: fx.signer.sign(payloadCanonical) };
    const result = verifyAuthorization(forged, ctx(fx));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_HOLD');
  });
});

describe('verifyAuthorization(): failure behavior fails closed', () => {
  test('a verifier that throws -> DENY_INTERNAL_VERIFICATION_ERROR, never a crash or an implicit allow', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const throwingVerifier = {
      isKnownKey: () => true,
      verify: () => {
        throw new Error('verifier exploded');
      },
    };
    const result = verifyAuthorization(record, ctx(fx, { verifier: throwingVerifier }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_INTERNAL_VERIFICATION_ERROR');
  });

  test('missing verifier -> DENY_MISSING_VERIFIER, never fail-open', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx, { verifier: null }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MISSING_VERIFIER');
  });

  test('undefined verifier -> DENY_MISSING_VERIFIER', () => {
    const fx = setup();
    const record = authorizeFx(fx);
    const result = verifyAuthorization(record, ctx(fx, { verifier: undefined }));
    assert.equal(result.ok, false);
    assert.equal(result.reasonCode, 'DENY_MISSING_VERIFIER');
  });

  for (const malformed of [null, undefined, {}, { payload: {} }, { payload: null, payloadCanonical: 'x', signature: 'y' }, 'not-a-record', 42]) {
    test(`malformed authorization record ${JSON.stringify(malformed)} -> DENY_MALFORMED_AUTHORIZATION`, () => {
      const fx = setup();
      const result = verifyAuthorization(malformed, ctx(fx));
      assert.equal(result.ok, false);
      assert.equal(result.reasonCode, 'DENY_MALFORMED_AUTHORIZATION');
    });
  }

  test('verifyAuthorization() never throws, regardless of input garbage', () => {
    const fx = setup();
    assert.doesNotThrow(() => verifyAuthorization(undefined, ctx(fx)));
    assert.doesNotThrow(() => verifyAuthorization({ a: 1 }, {}));
    assert.doesNotThrow(() => verifyAuthorization(null, null));
  });
});
