'use strict';

/**
 * Pre-decision case validation. Fails closed: anything structurally
 * ambiguous or outside the declared vocabulary is an error, never a
 * best-effort guess. decide() in publication_engine.js must never run
 * against a case that has not passed validateCase().
 */

const CLAIM_TYPES = new Set([
  'FACT',
  'SOURCE_CLAIM',
  'CORROBORATED_FACT',
  'ASSESSMENT',
  'INFERENCE',
  'UNKNOWN',
]);

const VERIFICATION_STATES = new Set([
  'VERIFIED',
  'CORROBORATED',
  'SINGLE-SOURCE',
  'UNVERIFIED',
  'INFERRED',
  'ASSESSMENT',
  'CONFLICTING EVIDENCE',
  'NOT AVAILABLE',
  'NOT APPLICABLE',
  'NOT VERIFIED',
]);

const CONFIDENCE_LEVELS = new Set(['VERY LOW', 'LOW', 'MEDIUM', 'HIGH', 'VERY HIGH']);

const DISTRIBUTION_CLASSIFICATIONS = new Set(['PUBLIC', 'RESTRICTED-CONDITIONAL']);

const QA_ARRAY_FIELDS = [
  'unsupportedClaims',
  'missingEvidence',
  'invalidCitations',
  'unverifiedIocs',
  'confidenceInflation',
];

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v) &&
    (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function isIsoDateString(v) {
  if (typeof v !== 'string' || v.trim().length === 0) return false;
  const t = Date.parse(v);
  return Number.isFinite(t);
}

function isBoolean(v) {
  return typeof v === 'boolean';
}

function isStringArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

/**
 * Validates a case object against the structural schema. Never throws for
 * malformed input — returns { valid: false, errors } so callers (and
 * decide()) can fail closed deterministically instead of catching an
 * exception that might accidentally be swallowed into a default allow.
 */
function validateCase(input) {
  const errors = [];
  const push = (msg) => errors.push(msg);

  if (!isPlainObject(input)) {
    return { valid: false, errors: ['case: must be a plain object'] };
  }

  if (!isNonEmptyString(input.caseId)) push('caseId: required non-empty string');
  if (!isNonEmptyString(input.title)) push('title: required non-empty string');
  if (!isIsoDateString(input.createdAt)) push('createdAt: required ISO-8601 date string');
  if (!isNonEmptyString(input.policyVersion)) push('policyVersion: required non-empty string');

  if (!Array.isArray(input.claims)) {
    push('claims: required array');
  } else {
    input.claims.forEach((claim, i) => {
      if (!isPlainObject(claim)) {
        push(`claims[${i}]: must be a plain object`);
        return;
      }
      if (!isNonEmptyString(claim.claimId)) push(`claims[${i}].claimId: required non-empty string`);
      if (!isNonEmptyString(claim.claimText)) push(`claims[${i}].claimText: required non-empty string`);
      if (!CLAIM_TYPES.has(claim.claimType)) {
        push(`claims[${i}].claimType: must be one of ${[...CLAIM_TYPES].join(', ')}`);
      }
      if (!isBoolean(claim.critical)) push(`claims[${i}].critical: required boolean`);
      if (!isStringArray(claim.evidenceIds)) push(`claims[${i}].evidenceIds: required array of strings`);
      if (!VERIFICATION_STATES.has(claim.verificationState)) {
        push(`claims[${i}].verificationState: must be one of ${[...VERIFICATION_STATES].join(', ')}`);
      }
      if (claim.confidence !== undefined && !CONFIDENCE_LEVELS.has(claim.confidence)) {
        push(`claims[${i}].confidence: if present, must be one of ${[...CONFIDENCE_LEVELS].join(', ')}`);
      }
    });
  }

  if (!Array.isArray(input.evidence)) {
    push('evidence: required array');
  } else {
    input.evidence.forEach((ev, i) => {
      if (!isPlainObject(ev)) {
        push(`evidence[${i}]: must be a plain object`);
        return;
      }
      if (!isNonEmptyString(ev.evidenceId)) push(`evidence[${i}].evidenceId: required non-empty string`);
      if (!isNonEmptyString(ev.sourceId)) push(`evidence[${i}].sourceId: required non-empty string`);
      if (!isIsoDateString(ev.retrievedAt)) push(`evidence[${i}].retrievedAt: required ISO-8601 date string`);
    });
  }

  if (!Array.isArray(input.contradictions)) {
    push('contradictions: required array (empty array if none)');
  } else {
    input.contradictions.forEach((c, i) => {
      if (!isPlainObject(c)) {
        push(`contradictions[${i}]: must be a plain object`);
        return;
      }
      if (!isNonEmptyString(c.field)) push(`contradictions[${i}].field: required non-empty string`);
      if (!isBoolean(c.resolved)) push(`contradictions[${i}].resolved: required boolean`);
    });
  }

  if (!isPlainObject(input.distribution)) {
    push('distribution: required object');
  } else if (!DISTRIBUTION_CLASSIFICATIONS.has(input.distribution.classification)) {
    push(`distribution.classification: must be one of ${[...DISTRIBUTION_CLASSIFICATIONS].join(', ')}`);
  }

  if (!isPlainObject(input.analystSignOff)) {
    push('analystSignOff: required object');
  } else {
    if (!isBoolean(input.analystSignOff.required)) push('analystSignOff.required: required boolean');
    if (input.analystSignOff.signedBy !== null && !isNonEmptyString(input.analystSignOff.signedBy)) {
      push('analystSignOff.signedBy: required (string or null)');
    }
    if (input.analystSignOff.signedAt !== null && !isIsoDateString(input.analystSignOff.signedAt)) {
      push('analystSignOff.signedAt: required (ISO-8601 string or null)');
    }
  }

  if (!isPlainObject(input.qa)) {
    push('qa: required object (pre-publication QA must have run — see Zero-Hallucination addendum §26)');
  } else {
    QA_ARRAY_FIELDS.forEach((field) => {
      if (!Array.isArray(input.qa[field])) push(`qa.${field}: required array (empty if none found)`);
    });
  }

  return { valid: errors.length === 0, errors };
}

class CaseValidationError extends Error {
  constructor(errors) {
    super(`Case validation failed: ${errors.join('; ')}`);
    this.name = 'CaseValidationError';
    this.errors = errors;
  }
}

function assertValidCase(input) {
  const result = validateCase(input);
  if (!result.valid) throw new CaseValidationError(result.errors);
  return input;
}

module.exports = {
  validateCase,
  assertValidCase,
  CaseValidationError,
  CLAIM_TYPES,
  VERIFICATION_STATES,
  CONFIDENCE_LEVELS,
  DISTRIBUTION_CLASSIFICATIONS,
  QA_ARRAY_FIELDS,
};
