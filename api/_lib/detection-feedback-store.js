'use strict';
/**
 * SENTINEL APEX — Detection Feedback Intelligence Persistence
 *
 * D1-backed store for detection_feedback (migrations/0005_threat_hunting_
 * workspace.sql). Feedback is always pinned to (detection_id,
 * detection_version) and always tenant-scoped by owner_id — one
 * customer's FALSE_POSITIVE never globalizes into a claim about the
 * detection for every other customer.
 *
 * computeFeedbackSignal() is the ONE deliberate exception to this
 * platform's "every query is owner-scoped" rule: it reads feedback across
 * ALL owners for a given detection/version, because a review signal is a
 * property of the shared, canonically-authored detection, not of any one
 * customer's tenancy. To keep this safe it returns ONLY a coarse signal
 * enum, trigger reason codes, and a sample size — never a raw feedback
 * row, owner_id, created_by, or free-text summary. No other function in
 * this module performs a cross-owner read.
 */

const crypto = require('crypto');
const d1 = require('./d1');

const FEEDBACK_CLASSIFICATIONS = [
  'TRUE_POSITIVE', 'FALSE_POSITIVE', 'USEFUL_SIGNAL', 'TOO_BROAD', 'TOO_NARROW',
  'TELEMETRY_MISMATCH', 'QUERY_ERROR', 'TUNING_REQUIRED', 'NO_SIGNAL',
];

// Classifications that alone (single distinct owner) are strong enough to flag a review signal --
// both indicate the detection may be structurally broken for the environment it was written against,
// not a matter of taste or tuning.
const SINGLE_REPORT_TRIGGERS = new Set(['QUERY_ERROR', 'TELEMETRY_MISMATCH']);
// Classifications that only matter in aggregate -- one customer's opinion that a detection is too
// broad/narrow is normal tuning feedback, not a defect signal; several independent customers saying
// the same thing is a real quality signal worth surfacing.
const REPEATED_REPORT_TRIGGERS = new Set(['TOO_BROAD', 'TOO_NARROW']);
const REPEATED_REPORT_THRESHOLD = 3; // distinct owners

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;

function generateId(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

function boundedLimit(requested) {
  const n = Number(requested);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_LIST_LIMIT;
  return Math.min(Math.floor(n), MAX_LIST_LIMIT);
}

function toPublicFeedback(row) {
  return {
    feedback_id: row.feedback_id,
    detection_id: row.detection_id,
    detection_version: row.detection_version,
    hunt_id: row.hunt_id || null,
    deployment_id: row.deployment_id || null,
    classification: row.classification,
    summary: row.summary || null,
    created_by: row.created_by,
    created_at: row.created_at,
  };
}

async function submitFeedback(ownerId, { detectionId, detectionVersion, huntId, deploymentId, classification, summary, createdBy }) {
  const feedbackId = generateId('dfb');
  await d1.run(
    `INSERT INTO detection_feedback
      (feedback_id, owner_id, detection_id, detection_version, hunt_id, deployment_id, classification, summary, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [feedbackId, ownerId, detectionId, detectionVersion, huntId || null, deploymentId || null, classification, summary || null, createdBy, new Date().toISOString()]
  );
  return feedbackId;
}

async function listFeedbackForOwner(ownerId, { detectionId, limit } = {}) {
  const boundedN = boundedLimit(limit);
  if (detectionId) {
    const rows = await d1.query(
      'SELECT * FROM detection_feedback WHERE owner_id = ? AND detection_id = ? ORDER BY created_at DESC LIMIT ?',
      [ownerId, detectionId, boundedN]
    );
    return rows.map(toPublicFeedback);
  }
  const rows = await d1.query('SELECT * FROM detection_feedback WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?', [ownerId, boundedN]);
  return rows.map(toPublicFeedback);
}

async function listFeedbackForHunt(huntId) {
  const rows = await d1.query('SELECT * FROM detection_feedback WHERE hunt_id = ? ORDER BY created_at DESC LIMIT ?', [huntId, MAX_LIST_LIMIT]);
  return rows.map(toPublicFeedback);
}

/**
 * Aggregate-only, cross-tenant review signal for a detection/version. See
 * this file's header for the safety contract: no identifying field is
 * ever returned. "validated defect" (an analyst-confirmed root cause) is
 * not implemented in v1 -- there is no analyst-review workflow for
 * feedback yet, so only the two automatic triggers below are real.
 */
async function computeFeedbackSignal(detectionId, detectionVersion) {
  const rows = await d1.query(
    'SELECT classification, COUNT(DISTINCT owner_id) AS distinct_owners, COUNT(*) AS total FROM detection_feedback ' +
      'WHERE detection_id = ? AND detection_version = ? GROUP BY classification',
    [detectionId, detectionVersion]
  );

  const reasonCodes = [];
  let sampleSize = 0;
  for (const row of rows) {
    sampleSize += Number(row.total) || 0;
    const distinctOwners = Number(row.distinct_owners) || 0;
    if (SINGLE_REPORT_TRIGGERS.has(row.classification) && distinctOwners >= 1) {
      reasonCodes.push(row.classification);
    } else if (REPEATED_REPORT_TRIGGERS.has(row.classification) && distinctOwners >= REPEATED_REPORT_THRESHOLD) {
      reasonCodes.push(`REPEATED_${row.classification}`);
    }
  }

  return {
    signal: reasonCodes.length ? 'REVIEW_REQUIRED' : null,
    reason_codes: reasonCodes,
    sample_size: sampleSize,
  };
}

/**
 * Tenant-scoped performance record (Detection Performance Intelligence v1)
 * -- "your operational feedback" for one (detection_id, detection_version)
 * pair, computed fresh on demand from this owner's OWN detection_feedback
 * rows only (owner_id = ? in the WHERE clause, matching every other
 * function in this file except computeFeedbackSignal). Deliberately not
 * materialized into a separate counts table -- see migrations/0006's
 * header for why: no evidence justifies it at this platform's scale, and
 * an on-demand GROUP BY over one owner's own rows for one detection is
 * cheap. classification_counts only includes classifications this owner
 * has actually reported (zero-filling every possible classification would
 * add noise, not information, for a customer detail page).
 */
async function computeTenantPerformance(ownerId, detectionId, detectionVersion) {
  const rows = await d1.query(
    'SELECT classification, COUNT(*) AS total, MAX(created_at) AS last_at FROM detection_feedback ' +
      'WHERE owner_id = ? AND detection_id = ? AND detection_version = ? GROUP BY classification',
    [ownerId, detectionId, detectionVersion]
  );
  const classificationCounts = {};
  let total = 0;
  let lastFeedbackAt = null;
  for (const row of rows) {
    const count = Number(row.total) || 0;
    classificationCounts[row.classification] = count;
    total += count;
    if (!lastFeedbackAt || row.last_at > lastFeedbackAt) lastFeedbackAt = row.last_at;
  }
  return { total_feedback: total, classification_counts: classificationCounts, last_feedback_at: lastFeedbackAt };
}

/**
 * Review-priority support metrics -- GLOBAL (cross-tenant) like
 * computeFeedbackSignal, and subject to the exact same safety contract:
 * aggregate counts and a timestamp only, never a raw row, owner_id, or
 * free-text summary. Composes computeFeedbackSignal() unchanged rather
 * than re-deriving the trigger/threshold math (Single Source of Truth) --
 * adds only the two extra aggregate fields (distinct_owners_total,
 * last_feedback_at) Review Priority needs that computeFeedbackSignal
 * itself has no reason to expose to its own existing caller
 * (api/v1/hunts.js's feedback-signal action).
 */
async function computeGlobalReviewMetrics(detectionId, detectionVersion) {
  const signal = await computeFeedbackSignal(detectionId, detectionVersion);
  // Column alias deliberately does NOT contain the substring "AS distinct_owners"
  // (unqualified) -- that exact text is also what computeFeedbackSignal's own
  // query above emits per-classification, and fake-d1.js's test double
  // dispatches on substring matches, not real SQL parsing (see that file's
  // header); a shared prefix would misroute this statement to the wrong
  // branch. "global_owner_count" avoids the collision outright.
  const rows = await d1.query(
    'SELECT COUNT(DISTINCT owner_id) AS global_owner_count, MAX(created_at) AS last_feedback_at ' +
      'FROM detection_feedback WHERE detection_id = ? AND detection_version = ?',
    [detectionId, detectionVersion]
  );
  const row = rows[0] || {};
  return {
    ...signal,
    distinct_owners_total: Number(row.global_owner_count) || 0,
    last_feedback_at: row.last_feedback_at || null,
  };
}

module.exports = {
  FEEDBACK_CLASSIFICATIONS,
  generateId,
  toPublicFeedback,
  submitFeedback,
  listFeedbackForOwner,
  listFeedbackForHunt,
  computeFeedbackSignal,
  computeTenantPerformance,
  computeGlobalReviewMetrics,
};
