'use strict';

/**
 * P0 acceptance gate: the full DAG, exercised end to end through every
 * sink. This is the suite that answers "can a bypass reach a customer" —
 * see SKILL.md §"Final Quality Bar" for the adversarial questions each
 * describe block below answers.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { decide } = require('./publication_engine');
const { buildManifest } = require('./release_manifest');
const { generateEphemeralKeypair, createSigner, createVerifier } = require('./signing');
const { authorize } = require('./authorization');
const { createInMemoryNonceStore } = require('./nonce_store');
const { createSink, PUBLIC_SINK_TYPES } = require('./publication_sinks');
const { validCase, restrictedCase } = require('./test/fixtures');

const FIXED_NOW = new Date('2026-08-16T12:00:00.000Z');
const ARTIFACT = Buffer.from('SYNTHETIC ARTIFACT FIXTURE — NOT REAL INTELLIGENCE — CVE-2099-00001 test report body');
const OTHER_ARTIFACT = Buffer.from('SYNTHETIC ARTIFACT FIXTURE — a completely different report body');

function buildAuthorizedRelease(caseInput, opts = {}) {
  const keyId = opts.keyId || 'key-A';
  const kp = generateEphemeralKeypair();
  const signer = createSigner({ keyId, privateKey: kp.privateKey });
  const verifier = createVerifier({ trustedKeys: { [keyId]: kp.publicKey } });
  const now = opts.now || FIXED_NOW;
  const artifactBytes = opts.artifactBytes || ARTIFACT;

  const decision = decide(caseInput, { now });
  const manifest = buildManifest(decision, { now });

  let record = null;
  if (manifest.disposition === 'PUBLISH-READY' || manifest.disposition === 'RESTRICTED-CONDITIONAL') {
    record = authorize(
      {
        manifest,
        artifactBytes,
        signerIdentity: opts.signerIdentity || 'analyst@cyberdudebivash.com',
        expiresInSeconds: opts.expiresInSeconds || 3600,
        now,
      },
      signer
    );
  }
  return { decision, manifest, record, verifier, artifactBytes, now, keyId };
}

describe('P0 acceptance gate: every public sink', () => {
  for (const sinkType of PUBLIC_SINK_TYPES) {
    describe(`sink: ${sinkType}`, () => {
      test('HOLD is denied', () => {
        const rel = buildAuthorizedRelease(validCase({ contradictions: [{ field: 'x', resolved: false }] }));
        assert.equal(rel.manifest.disposition, 'HOLD');
        assert.equal(rel.record, null, 'no authorization can exist for a HOLD manifest');
        const event = createSink(sinkType).publish(null, {
          manifest: rel.manifest,
          artifactBytes: rel.artifactBytes,
          verifier: rel.verifier,
          now: rel.now,
        });
        assert.equal(event.decision, 'DENY');
      });

      test('unauthorized (missing signature) is denied', () => {
        const rel = buildAuthorizedRelease(validCase());
        const unsigned = { payload: rel.record.payload, payloadCanonical: rel.record.payloadCanonical, signature: undefined };
        const event = createSink(sinkType).publish(unsigned, {
          manifest: rel.manifest,
          artifactBytes: rel.artifactBytes,
          verifier: rel.verifier,
          now: rel.now,
        });
        assert.equal(event.decision, 'DENY');
        assert.equal(event.reasonCode, 'DENY_MISSING_SIGNATURE');
      });

      test('a validly-authorized RESTRICTED-CONDITIONAL artifact is denied on this public sink', () => {
        const rel = buildAuthorizedRelease(restrictedCase());
        assert.equal(rel.manifest.disposition, 'RESTRICTED-CONDITIONAL');
        const event = createSink(sinkType).publish(rel.record, {
          manifest: rel.manifest,
          artifactBytes: rel.artifactBytes,
          verifier: rel.verifier,
          now: rel.now,
        });
        assert.equal(event.decision, 'DENY');
        assert.equal(event.reasonCode, 'DENY_RESTRICTED_PUBLICATION');
      });

      test('a fully-authorized, zero-restriction PUBLISH-READY artifact is allowed', () => {
        const rel = buildAuthorizedRelease(validCase());
        const event = createSink(sinkType).publish(rel.record, {
          manifest: rel.manifest,
          artifactBytes: rel.artifactBytes,
          verifier: rel.verifier,
          now: rel.now,
        });
        assert.equal(event.decision, 'ALLOW');
        assert.equal(event.reasonCode, 'ALLOW_AUTHORIZED_PUBLIC_RELEASE');
      });
    });
  }
});

describe('P0 acceptance gate: restricted-enterprise sink', () => {
  test('a properly authorized RESTRICTED-CONDITIONAL artifact is allowed', () => {
    const rel = buildAuthorizedRelease(restrictedCase());
    const event = createSink('restricted-enterprise').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
    });
    assert.equal(event.decision, 'ALLOW');
    assert.equal(event.reasonCode, 'ALLOW_AUTHORIZED_RESTRICTED_RELEASE');
  });

  test('a fully-authorized PUBLISH-READY artifact is also allowed (zero restriction reaches every sink)', () => {
    const rel = buildAuthorizedRelease(validCase());
    const event = createSink('restricted-enterprise').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
    });
    assert.equal(event.decision, 'ALLOW');
  });

  test('HOLD is still denied on the restricted sink', () => {
    const rel = buildAuthorizedRelease(validCase({ contradictions: [{ field: 'x', resolved: false }] }));
    const event = createSink('restricted-enterprise').publish(null, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
    });
    assert.equal(event.decision, 'DENY');
  });
});

describe('end-to-end adversarial scenarios (Final Quality Bar)', () => {
  test('cannot fabricate PUBLISH-READY: a hand-forged manifest self-signed with an untrusted key is rejected at the sink', () => {
    const caseInput = validCase({ contradictions: [{ field: 'x', resolved: false }] });
    const realDecision = decide(caseInput, { now: FIXED_NOW });
    assert.equal(realDecision.disposition, 'HOLD');

    // Attacker hand-crafts a decision object claiming PUBLISH-READY. Manifest
    // hashing is not secret (it's an integrity check, not an authorization),
    // so this manifest is legitimately self-consistent.
    const forgedDecision = { ...realDecision, disposition: 'PUBLISH-READY', reasonCode: 'PUBLISH_READY_CLEARED', reasons: ['forged'] };
    const forgedManifest = buildManifest(forgedDecision, { now: FIXED_NOW });

    const attackerKp = generateEphemeralKeypair();
    const attackerSigner = createSigner({ keyId: 'attacker-key', privateKey: attackerKp.privateKey });
    const forgedRecord = authorize(
      { manifest: forgedManifest, artifactBytes: ARTIFACT, signerIdentity: 'attacker@evil.example', expiresInSeconds: 3600, now: FIXED_NOW },
      attackerSigner
    );

    const realTrustStore = createVerifier({ trustedKeys: { 'key-A': generateEphemeralKeypair().publicKey } }); // attacker-key never trusted
    const event = createSink('rss').publish(forgedRecord, {
      manifest: forgedManifest,
      artifactBytes: ARTIFACT,
      verifier: realTrustStore,
      now: FIXED_NOW,
    });
    assert.equal(event.decision, 'DENY');
    assert.equal(event.reasonCode, 'DENY_UNKNOWN_KEY');
  });

  test('cannot modify the artifact after approval and still publish', () => {
    const rel = buildAuthorizedRelease(validCase());
    const event = createSink('api').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: OTHER_ARTIFACT,
      verifier: rel.verifier,
      now: rel.now,
    });
    assert.equal(event.decision, 'DENY');
    assert.equal(event.reasonCode, 'DENY_ARTIFACT_HASH_MISMATCH');
  });

  test('an authorization cannot be replayed across two different sinks sharing one nonce store', () => {
    const rel = buildAuthorizedRelease(validCase());
    const nonceStore = createInMemoryNonceStore();
    const first = createSink('rss').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
      nonceStore,
    });
    assert.equal(first.decision, 'ALLOW');
    const second = createSink('blogger').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
      nonceStore,
    });
    assert.equal(second.decision, 'DENY');
    assert.equal(second.reasonCode, 'DENY_REPLAY');
  });

  test('an expired authorization cannot publish', () => {
    const rel = buildAuthorizedRelease(validCase(), { expiresInSeconds: 60 });
    const later = new Date(FIXED_NOW.getTime() + 3600 * 1000);
    const event = createSink('rss').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: later,
    });
    assert.equal(event.decision, 'DENY');
    assert.equal(event.reasonCode, 'DENY_EXPIRED_AUTHORIZATION');
  });

  test('a revoked key cannot publish', () => {
    const rel = buildAuthorizedRelease(validCase());
    const event = createSink('rss').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      revokedKeyIds: [rel.keyId],
      now: rel.now,
    });
    assert.equal(event.decision, 'DENY');
    assert.equal(event.reasonCode, 'DENY_REVOKED_AUTHORIZATION');
  });

  test('a missing verifier fails closed at the sink — it never fails open', () => {
    const rel = buildAuthorizedRelease(validCase());
    const event = createSink('rss').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: null,
      now: rel.now,
    });
    assert.equal(event.decision, 'DENY');
    assert.equal(event.reasonCode, 'DENY_MISSING_VERIFIER');
  });

  test('a case requiring analyst sign-off without one HOLDs at decide() and therefore never reaches an authorizable state', () => {
    const rel = buildAuthorizedRelease(validCase({ analystSignOff: { required: true, signedBy: null, signedAt: null } }));
    assert.equal(rel.decision.disposition, 'HOLD');
    assert.equal(rel.record, null);
  });

  test('createSink rejects an unknown sink type rather than silently defaulting to public or restricted', () => {
    assert.throws(() => createSink('legacy-ftp-uploader'));
  });
});

describe('audit events are structured and complete', () => {
  const REQUIRED_FIELDS = [
    'timestamp',
    'sink',
    'manifestHash',
    'artifactHash',
    'keyId',
    'signerIdentity',
    'disposition',
    'authorizationStatus',
    'decision',
    'reasonCode',
    'policyVersion',
  ];

  test('every ALLOW produces a fully-populated, SIEM-ready audit event', () => {
    const rel = buildAuthorizedRelease(validCase());
    const event = createSink('rss').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
    });
    for (const field of REQUIRED_FIELDS) assert.ok(field in event, `audit event missing field "${field}"`);
    assert.equal(event.sink, 'rss');
    assert.equal(event.manifestHash, rel.manifest.manifestHash);
    assert.equal(event.authorizationStatus, 'AUTHORIZED');
  });

  test('every DENY also produces a fully-populated audit event', () => {
    const rel = buildAuthorizedRelease(restrictedCase());
    const event = createSink('rss').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
    });
    for (const field of REQUIRED_FIELDS) assert.ok(field in event, `audit event missing field "${field}"`);
    assert.equal(event.decision, 'DENY');
    assert.equal(event.authorizationStatus, 'NOT_AUTHORIZED');
  });

  test('audit events never contain key material', () => {
    const rel = buildAuthorizedRelease(validCase());
    const event = createSink('rss').publish(rel.record, {
      manifest: rel.manifest,
      artifactBytes: rel.artifactBytes,
      verifier: rel.verifier,
      now: rel.now,
    });
    const serialized = JSON.stringify(event);
    assert.ok(!serialized.includes('PRIVATE KEY'));
    assert.ok(!serialized.includes('BEGIN'));
  });
});

describe('full DAG walkthrough', () => {
  test('case -> decide -> buildManifest -> authorize -> sink.publish traces end to end for a PUBLISH-READY release', () => {
    const kp = generateEphemeralKeypair();
    const signer = createSigner({ keyId: 'prod-key-1', privateKey: kp.privateKey });
    const verifier = createVerifier({ trustedKeys: { 'prod-key-1': kp.publicKey } });

    const decision = decide(validCase(), { now: FIXED_NOW });
    assert.equal(decision.disposition, 'PUBLISH-READY');

    const manifest = buildManifest(decision, { now: FIXED_NOW });
    assert.equal(manifest.manifestHash.length, 64);

    const record = authorize(
      { manifest, artifactBytes: ARTIFACT, signerIdentity: 'analyst@cyberdudebivash.com', expiresInSeconds: 3600, now: FIXED_NOW },
      signer
    );

    const event = createSink('downloadable-bundle').publish(record, { manifest, artifactBytes: ARTIFACT, verifier, now: FIXED_NOW });

    assert.equal(event.decision, 'ALLOW');
    assert.equal(event.reasonCode, 'ALLOW_AUTHORIZED_PUBLIC_RELEASE');
    assert.equal(event.manifestHash, manifest.manifestHash);
  });
});
