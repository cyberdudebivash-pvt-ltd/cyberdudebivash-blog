'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { validateCase, assertValidCase, CaseValidationError } = require('./case_schema');
const { validCase, validClaim } = require('./test/fixtures');

describe('case_schema: structural validation fails closed', () => {
  test('accepts a well-formed case', () => {
    const result = validateCase(validCase());
    assert.equal(result.valid, true);
    assert.deepEqual(result.errors, []);
  });

  for (const bad of [null, undefined, 'a string', 42, true, [], ['array']]) {
    test(`rejects non-object input: ${JSON.stringify(bad)}`, () => {
      const result = validateCase(bad);
      assert.equal(result.valid, false);
      assert.ok(result.errors.length > 0);
    });
  }

  test('rejects missing caseId', () => {
    const c = validCase();
    delete c.caseId;
    const result = validateCase(c);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('caseId')));
  });

  test('rejects empty-string title', () => {
    const result = validateCase(validCase({ title: '   ' }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('title')));
  });

  test('rejects malformed createdAt', () => {
    const result = validateCase(validCase({ createdAt: 'not-a-date' }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('createdAt')));
  });

  test('rejects claims that is not an array', () => {
    const result = validateCase(validCase({ claims: 'not-an-array' }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('claims')));
  });

  test('rejects a claim with an unknown claimType', () => {
    const c = validCase({ claims: [validClaim({ claimType: 'MADE_UP_TYPE' })] });
    const result = validateCase(c);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('claimType')));
  });

  test('rejects a claim with an unknown verificationState', () => {
    const c = validCase({ claims: [validClaim({ verificationState: 'PROBABLY_TRUE' })] });
    const result = validateCase(c);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('verificationState')));
  });

  test('rejects a claim whose evidenceIds is not an array of strings', () => {
    const c = validCase({ claims: [validClaim({ evidenceIds: [123, null] })] });
    const result = validateCase(c);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('evidenceIds')));
  });

  test('rejects a claim missing the critical boolean', () => {
    const claim = validClaim();
    delete claim.critical;
    const result = validateCase(validCase({ claims: [claim] }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('critical')));
  });

  test('accepts a claim with a valid optional confidence and rejects an invalid one', () => {
    assert.equal(validateCase(validCase({ claims: [validClaim({ confidence: 'VERY HIGH' })] })).valid, true);
    const result = validateCase(validCase({ claims: [validClaim({ confidence: 'SUPER HIGH' })] }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('confidence')));
  });

  test('rejects malformed evidence entries', () => {
    const result = validateCase(validCase({ evidence: [{ evidenceId: 'e1' }] }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('evidence[0]')));
  });

  test('rejects contradictions missing the resolved boolean', () => {
    const result = validateCase(validCase({ contradictions: [{ field: 'x' }] }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('contradictions[0].resolved')));
  });

  test('requires contradictions to be present (even if empty) rather than omitted', () => {
    const c = validCase();
    delete c.contradictions;
    const result = validateCase(c);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('contradictions')));
  });

  test('rejects an unknown distribution.classification', () => {
    const result = validateCase(validCase({ distribution: { classification: 'SECRET-ISH' } }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('distribution.classification')));
  });

  test('rejects analystSignOff.signedBy that is neither a string nor null', () => {
    const result = validateCase(validCase({ analystSignOff: { required: true, signedBy: 42, signedAt: null } }));
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('analystSignOff.signedBy')));
  });

  test('requires qa to be present (even if all-empty) rather than omitted', () => {
    const c = validCase();
    delete c.qa;
    const result = validateCase(c);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('qa')));
  });

  test('rejects a qa section with a missing sub-array', () => {
    const c = validCase();
    delete c.qa.unverifiedIocs;
    const result = validateCase(c);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('qa.unverifiedIocs')));
  });

  test('an extraneous "disposition" field on the input is ignored by validation (decide() must not read it either — see publication_engine.test.js)', () => {
    const result = validateCase(validCase({ disposition: 'PUBLISH-READY' }));
    assert.equal(result.valid, true);
  });
});

describe('assertValidCase', () => {
  test('returns the input unchanged when valid', () => {
    const c = validCase();
    assert.equal(assertValidCase(c), c);
  });

  test('throws CaseValidationError with .errors when invalid', () => {
    assert.throws(() => assertValidCase({}), (err) => {
      assert.ok(err instanceof CaseValidationError);
      assert.ok(Array.isArray(err.errors) && err.errors.length > 0);
      return true;
    });
  });
});
