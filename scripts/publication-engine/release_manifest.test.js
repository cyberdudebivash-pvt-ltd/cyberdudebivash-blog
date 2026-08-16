'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { decide } = require('./publication_engine');
const { buildManifest, recomputeManifestHash, verifyManifestIntegrity, MANIFEST_HASHED_FIELDS } = require('./release_manifest');
const { validCase } = require('./test/fixtures');

const FIXED_NOW = new Date('2026-08-16T12:00:00.000Z');

describe('release_manifest.buildManifest(): content-addressed snapshot of a decision', () => {
  test('produces a manifest whose hash matches recomputeManifestHash()', () => {
    const decision = decide(validCase(), { now: FIXED_NOW });
    const manifest = buildManifest(decision, { now: FIXED_NOW });
    assert.equal(manifest.manifestHash, recomputeManifestHash(manifest));
    assert.equal(verifyManifestIntegrity(manifest), true);
  });

  test('throws if handed something other than decide()\'s output', () => {
    assert.throws(() => buildManifest({ disposition: 'PUBLISH-READY' }));
    assert.throws(() => buildManifest(null));
    assert.throws(() => buildManifest('PUBLISH-READY'));
  });

  test('throws on a policyVersion mismatch between decision and engine', () => {
    const decision = decide(validCase(), { now: FIXED_NOW });
    assert.throws(() => buildManifest({ ...decision, policyVersion: '9.9.9' }));
  });

  test('two manifests built from identical decision content share the same manifestHash despite different manifestId/createdAt', () => {
    const decision = decide(validCase(), { now: FIXED_NOW });
    const m1 = buildManifest(decision, { now: new Date('2026-08-16T12:00:00.000Z') });
    const m2 = buildManifest(decision, { now: new Date('2026-08-16T13:30:00.000Z') });
    assert.notEqual(m1.manifestId, m2.manifestId);
    assert.notEqual(m1.createdAt, m2.createdAt);
    assert.equal(m1.manifestHash, m2.manifestHash);
  });

  test(`manifestHash covers exactly ${MANIFEST_HASHED_FIELDS.join(', ')} — a decision differing only in an uncovered field produces the same hash, so callers must not add fields to decide() output without extending MANIFEST_HASHED_FIELDS`, () => {
    const decision = decide(validCase(), { now: FIXED_NOW });
    const manifestA = buildManifest(decision, { now: FIXED_NOW });
    const manifestB = buildManifest({ ...decision, someUnrelatedField: 'ignored' }, { now: FIXED_NOW });
    assert.equal(manifestA.manifestHash, manifestB.manifestHash);
  });
});

describe('release_manifest tamper detection', () => {
  test('mutating disposition after manifest generation is caught by verifyManifestIntegrity', () => {
    const decision = decide(validCase({ contradictions: [{ field: 'x', resolved: false }] }), { now: FIXED_NOW });
    assert.equal(decision.disposition, 'HOLD');
    const manifest = buildManifest(decision, { now: FIXED_NOW });
    const tampered = { ...manifest, disposition: 'PUBLISH-READY' };
    assert.equal(verifyManifestIntegrity(tampered), false);
  });

  test('mutating reasons after manifest generation is caught by verifyManifestIntegrity', () => {
    const decision = decide(validCase(), { now: FIXED_NOW });
    const manifest = buildManifest(decision, { now: FIXED_NOW });
    const tampered = { ...manifest, reasons: ['fabricated reason'] };
    assert.equal(verifyManifestIntegrity(tampered), false);
  });

  test('mutating caseId after manifest generation is caught by verifyManifestIntegrity', () => {
    const decision = decide(validCase(), { now: FIXED_NOW });
    const manifest = buildManifest(decision, { now: FIXED_NOW });
    const tampered = { ...manifest, caseId: 'SOME-OTHER-CASE' };
    assert.equal(verifyManifestIntegrity(tampered), false);
  });

  test('a claim edit that changes the underlying decision produces a different manifestHash', () => {
    const holdingCase = validCase({ contradictions: [{ field: 'x', resolved: false }] });
    const fixedCase = validCase({ contradictions: [{ field: 'x', resolved: true }] });
    const manifestA = buildManifest(decide(holdingCase, { now: FIXED_NOW }), { now: FIXED_NOW });
    const manifestB = buildManifest(decide(fixedCase, { now: FIXED_NOW }), { now: FIXED_NOW });
    assert.notEqual(manifestA.manifestHash, manifestB.manifestHash);
    assert.equal(manifestA.disposition, 'HOLD');
    assert.equal(manifestB.disposition, 'PUBLISH-READY');
  });

  test('verifyManifestIntegrity fails closed (returns false, does not throw) on a garbage object', () => {
    assert.equal(verifyManifestIntegrity({}), false);
    assert.equal(verifyManifestIntegrity(null), false);
    assert.equal(verifyManifestIntegrity('not a manifest'), false);
  });
});
