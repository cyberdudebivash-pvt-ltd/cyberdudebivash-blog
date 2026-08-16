'use strict';

// SYNTHETIC TEST FIXTURE — NOT REAL INTELLIGENCE.
// Every value here is fabricated for testing this engine's control logic
// and must never be treated as, or copied into, a real intelligence
// product. See CLAUDE.md Zero-Hallucination addendum §30.

const { POLICY_VERSION } = require('../publication_engine');

function validClaim(overrides = {}) {
  return {
    claimId: 'claim-1',
    claimText: 'SYNTHETIC: example claim text long enough to be meaningful for a unit test.',
    claimType: 'FACT',
    critical: true,
    evidenceIds: ['evidence-1'],
    verificationState: 'VERIFIED',
    confidence: 'HIGH',
    ...overrides,
  };
}

function validCase(overrides = {}) {
  return {
    caseId: 'CASE-TEST-0001',
    title: 'SYNTHETIC TEST FIXTURE — NOT REAL INTELLIGENCE',
    createdAt: '2026-08-16T00:00:00.000Z',
    policyVersion: POLICY_VERSION,
    claims: [validClaim()],
    evidence: [{ evidenceId: 'evidence-1', sourceId: 'source-1', retrievedAt: '2026-08-16T00:00:00.000Z' }],
    contradictions: [],
    distribution: { classification: 'PUBLIC' },
    analystSignOff: { required: false, signedBy: null, signedAt: null },
    qa: { unsupportedClaims: [], missingEvidence: [], invalidCitations: [], unverifiedIocs: [], confidenceInflation: [] },
    ...overrides,
  };
}

function restrictedCase(overrides = {}) {
  return validCase({ distribution: { classification: 'RESTRICTED-CONDITIONAL' }, ...overrides });
}

module.exports = { validClaim, validCase, restrictedCase };
