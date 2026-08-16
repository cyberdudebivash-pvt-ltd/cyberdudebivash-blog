'use strict';

/**
 * Decision engine: the single authoritative place that turns an evidence
 * case into a publication disposition. Nothing downstream (manifest,
 * authorization, sinks) re-derives a disposition independently — they only
 * ever re-verify what this function already decided, against the hash it
 * was decided under. See SKILL.md for the full DAG.
 *
 * decide() never reads a caller-supplied disposition/requestedDisposition
 * field. A case cannot talk its way to PUBLISH-READY by claiming it —
 * only by actually satisfying every gate below.
 */

const { validateCase, QA_ARRAY_FIELDS } = require('./case_schema');

// Single source of truth for the policy version this engine enforces.
// release_manifest.js and authorization.js both import this rather than
// hardcoding their own copy.
const POLICY_VERSION = '1.0.0';

// Critical claims (Zero-Hallucination addendum §28) must rest on more than
// an analyst's inference to clear the gate. VERIFIED/CORROBORATED/
// SINGLE-SOURCE all mean "backed by at least one identified source record";
// everything else (UNVERIFIED, NOT VERIFIED, CONFLICTING EVIDENCE,
// NOT AVAILABLE, INFERRED, ASSESSMENT, NOT APPLICABLE) means the claim
// cannot yet stand on its own and must hold the release.
const SUFFICIENT_CRITICAL_VERIFICATION_STATES = new Set(['VERIFIED', 'CORROBORATED', 'SINGLE-SOURCE']);

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * @param {unknown} caseInput
 * @param {{ now?: Date }} [options] - inject `now` for deterministic tests
 * @returns {{disposition: 'PUBLISH-READY'|'RESTRICTED-CONDITIONAL'|'HOLD'|'DENY', reasonCode: string, reasons: string[], evaluatedAt: string, policyVersion: string, caseId: string|null}}
 */
function decide(caseInput, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const evaluatedAt = now.toISOString();
  const caseIdIfKnown = isPlainObject(caseInput) && typeof caseInput.caseId === 'string' ? caseInput.caseId : null;

  const validation = validateCase(caseInput);
  if (!validation.valid) {
    return {
      disposition: 'DENY',
      reasonCode: 'DENY_MALFORMED_CASE',
      reasons: validation.errors,
      evaluatedAt,
      policyVersion: POLICY_VERSION,
      caseId: caseIdIfKnown,
    };
  }

  if (caseInput.policyVersion !== POLICY_VERSION) {
    return {
      disposition: 'DENY',
      reasonCode: 'DENY_CASE_POLICY_VERSION_MISMATCH',
      reasons: [`case declares policyVersion "${caseInput.policyVersion}" but engine enforces "${POLICY_VERSION}"`],
      evaluatedAt,
      policyVersion: POLICY_VERSION,
      caseId: caseIdIfKnown,
    };
  }

  const reasons = [];

  for (const claim of caseInput.claims) {
    if (!claim.critical) continue;
    if (!SUFFICIENT_CRITICAL_VERIFICATION_STATES.has(claim.verificationState)) {
      reasons.push(
        `critical claim "${claim.claimId}" has verificationState "${claim.verificationState}" ` +
          `(requires one of ${[...SUFFICIENT_CRITICAL_VERIFICATION_STATES].join(', ')})`
      );
    } else if (claim.evidenceIds.length === 0) {
      reasons.push(`critical claim "${claim.claimId}" is marked "${claim.verificationState}" but has no bound evidenceIds`);
    }
  }

  const unresolved = caseInput.contradictions.filter((c) => c.resolved !== true);
  if (unresolved.length > 0) {
    reasons.push(`${unresolved.length} unresolved contradiction(s): ${unresolved.map((c) => c.field).join(', ')}`);
  }

  for (const field of QA_ARRAY_FIELDS) {
    const flagged = caseInput.qa[field];
    if (flagged.length > 0) {
      reasons.push(`QA flagged ${flagged.length} item(s) in "${field}": ${flagged.slice(0, 5).join(', ')}`);
    }
  }

  if (caseInput.analystSignOff.required && !caseInput.analystSignOff.signedBy) {
    reasons.push('analyst sign-off is required but analystSignOff.signedBy is not set');
  }

  if (reasons.length > 0) {
    return {
      disposition: 'HOLD',
      reasonCode: 'HOLD_EVIDENCE_POLICY_GATE',
      reasons,
      evaluatedAt,
      policyVersion: POLICY_VERSION,
      caseId: caseInput.caseId,
    };
  }

  if (caseInput.distribution.classification === 'RESTRICTED-CONDITIONAL') {
    return {
      disposition: 'RESTRICTED-CONDITIONAL',
      reasonCode: 'RESTRICTED_CONDITIONAL_CLEARED',
      reasons: ['all evidentiary and policy gates passed; distribution is restricted by classification'],
      evaluatedAt,
      policyVersion: POLICY_VERSION,
      caseId: caseInput.caseId,
    };
  }

  return {
    disposition: 'PUBLISH-READY',
    reasonCode: 'PUBLISH_READY_CLEARED',
    reasons: ['all evidentiary and policy gates passed; no distribution restriction'],
    evaluatedAt,
    policyVersion: POLICY_VERSION,
    caseId: caseInput.caseId,
  };
}

module.exports = { decide, POLICY_VERSION };
