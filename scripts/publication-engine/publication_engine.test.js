'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { decide, POLICY_VERSION } = require('./publication_engine');
const { validCase, validClaim, restrictedCase } = require('./test/fixtures');

const FIXED_NOW = new Date('2026-08-16T12:00:00.000Z');

describe('publication_engine.decide(): clears to a release disposition only when every gate passes', () => {
  test('a clean PUBLIC case clears to PUBLISH-READY', () => {
    const result = decide(validCase(), { now: FIXED_NOW });
    assert.equal(result.disposition, 'PUBLISH-READY');
    assert.equal(result.reasonCode, 'PUBLISH_READY_CLEARED');
    assert.equal(result.evaluatedAt, FIXED_NOW.toISOString());
    assert.equal(result.policyVersion, POLICY_VERSION);
  });

  test('a clean RESTRICTED-CONDITIONAL case clears to RESTRICTED-CONDITIONAL, never PUBLISH-READY', () => {
    const result = decide(restrictedCase(), { now: FIXED_NOW });
    assert.equal(result.disposition, 'RESTRICTED-CONDITIONAL');
    assert.equal(result.reasonCode, 'RESTRICTED_CONDITIONAL_CLEARED');
  });

  test('decide() is deterministic for identical input', () => {
    const a = decide(validCase(), { now: FIXED_NOW });
    const b = decide(validCase(), { now: FIXED_NOW });
    assert.deepEqual(a, b);
  });
});

describe('publication_engine.decide(): malformed / policy-mismatched input -> DENY', () => {
  test('malformed case -> DENY with DENY_MALFORMED_CASE', () => {
    const result = decide({ not: 'a case' }, { now: FIXED_NOW });
    assert.equal(result.disposition, 'DENY');
    assert.equal(result.reasonCode, 'DENY_MALFORMED_CASE');
    assert.ok(result.reasons.length > 0);
  });

  test('wrong policyVersion -> DENY with DENY_CASE_POLICY_VERSION_MISMATCH', () => {
    const result = decide(validCase({ policyVersion: '0.9.0' }), { now: FIXED_NOW });
    assert.equal(result.disposition, 'DENY');
    assert.equal(result.reasonCode, 'DENY_CASE_POLICY_VERSION_MISMATCH');
  });
});

describe('publication_engine.decide(): critical-claim evidentiary gate', () => {
  for (const state of ['UNVERIFIED', 'NOT VERIFIED', 'CONFLICTING EVIDENCE', 'NOT AVAILABLE', 'INFERRED', 'ASSESSMENT', 'NOT APPLICABLE']) {
    test(`a critical claim in verificationState "${state}" holds the case`, () => {
      const result = decide(validCase({ claims: [validClaim({ verificationState: state })] }), { now: FIXED_NOW });
      assert.equal(result.disposition, 'HOLD');
      assert.ok(result.reasons.some((r) => r.includes(state)));
    });
  }

  for (const state of ['VERIFIED', 'CORROBORATED', 'SINGLE-SOURCE']) {
    test(`a critical claim in verificationState "${state}" with evidence does not hold the case`, () => {
      const result = decide(validCase({ claims: [validClaim({ verificationState: state, evidenceIds: ['e1'] })] }), {
        now: FIXED_NOW,
      });
      assert.equal(result.disposition, 'PUBLISH-READY');
    });
  }

  test('a critical claim marked VERIFIED but with zero bound evidenceIds still holds', () => {
    const result = decide(validCase({ claims: [validClaim({ verificationState: 'VERIFIED', evidenceIds: [] })] }), {
      now: FIXED_NOW,
    });
    assert.equal(result.disposition, 'HOLD');
    assert.ok(result.reasons.some((r) => r.includes('no bound evidenceIds')));
  });

  test('a NON-critical claim in verificationState UNVERIFIED does NOT hold the case', () => {
    const result = decide(validCase({ claims: [validClaim({ critical: false, verificationState: 'UNVERIFIED', evidenceIds: [] })] }), {
      now: FIXED_NOW,
    });
    assert.equal(result.disposition, 'PUBLISH-READY');
  });
});

describe('publication_engine.decide(): contradictions, QA findings, and sign-off gates', () => {
  test('an unresolved contradiction holds the case', () => {
    const result = decide(validCase({ contradictions: [{ field: 'exploitation-status', resolved: false }] }), { now: FIXED_NOW });
    assert.equal(result.disposition, 'HOLD');
    assert.ok(result.reasons.some((r) => r.includes('exploitation-status')));
  });

  test('a resolved contradiction does not hold the case', () => {
    const result = decide(validCase({ contradictions: [{ field: 'exploitation-status', resolved: true }] }), { now: FIXED_NOW });
    assert.equal(result.disposition, 'PUBLISH-READY');
  });

  for (const field of ['unsupportedClaims', 'missingEvidence', 'invalidCitations', 'unverifiedIocs', 'confidenceInflation']) {
    test(`a non-empty QA.${field} holds the case`, () => {
      const qa = { unsupportedClaims: [], missingEvidence: [], invalidCitations: [], unverifiedIocs: [], confidenceInflation: [] };
      qa[field] = ['flagged-item-1'];
      const result = decide(validCase({ qa }), { now: FIXED_NOW });
      assert.equal(result.disposition, 'HOLD');
      assert.ok(result.reasons.some((r) => r.includes(field)));
    });
  }

  test('analyst sign-off required but missing holds the case', () => {
    const result = decide(validCase({ analystSignOff: { required: true, signedBy: null, signedAt: null } }), { now: FIXED_NOW });
    assert.equal(result.disposition, 'HOLD');
    assert.ok(result.reasons.some((r) => r.includes('sign-off')));
  });

  test('analyst sign-off required and present does not hold the case', () => {
    const result = decide(
      validCase({ analystSignOff: { required: true, signedBy: 'analyst@cyberdudebivash.com', signedAt: '2026-08-16T00:00:00.000Z' } }),
      { now: FIXED_NOW }
    );
    assert.equal(result.disposition, 'PUBLISH-READY');
  });
});

describe('publication_engine.decide(): cannot be talked into a disposition', () => {
  test('a caller-supplied "disposition"/"requestedDisposition" field is never read — a case that should HOLD still HOLDs even if it claims PUBLISH-READY', () => {
    const forged = validCase({
      contradictions: [{ field: 'x', resolved: false }],
      disposition: 'PUBLISH-READY',
      requestedDisposition: 'PUBLISH-READY',
    });
    const result = decide(forged, { now: FIXED_NOW });
    assert.equal(result.disposition, 'HOLD');
  });
});
