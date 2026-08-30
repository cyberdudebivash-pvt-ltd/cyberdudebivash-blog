'use strict';
/**
 * SENTINEL APEX — Detection Performance Intelligence, Defensive Efficacy
 * Fabric, Privacy-Safe Analyst Feedback Aggregation, Detection Review
 * Prioritization & Closed-Loop Defense Quality Engine v1
 *
 * Answers "what are we learning about this detection from real defensive
 * use?" by composing four already-existing, unmodified systems -- never
 * re-implementing any of them:
 *
 *   - detection-rules.js / detection-intelligence.js (via hunt-engine.js's
 *     resolveCanonicalDetection())  -- the canonical RELEASED/BLOCKED/
 *     REVIEW_REQUIRED/REVOKED/DEPRECATED validation gate
 *   - detection-version-store.js                     -- immutable version
 *     content snapshots (migrations/0006)
 *   - detection-feedback-store.js's computeGlobalReviewMetrics()          --
 *     the ONE existing privacy-safe cross-tenant aggregate read
 *   - deployment-store.js's countDeploymentsByDetection()                 --
 *     GLOBAL, count-only live-deployment reach
 *
 * Nothing here is an ML score, a customer-surveillance system, an
 * automatic rule rewriter, or a single 0-100 "efficacy" number. Every
 * output is a deterministic function of the inputs above, with an
 * explicit, human-readable reason attached. No output is ever probabilistic
 * ("87% confidence") or a fabricated precision/recall/false-positive-rate
 * statistic -- see the "Statistical Truth Policy" section below for why
 * feedback counts are NOT the same thing as a validated efficacy rate.
 *
 * ─────────────────────── Statistical Truth Policy ───────────────────────
 * detection_feedback rows are OBSERVATIONS, not a random sample. A
 * FALSE_POSITIVE_COUNT / HUNT_COUNT ratio is not a real false-positive
 * rate: hunts are analyst-selected, biased toward interesting activity,
 * and a customer who never hunts against a detection contributes zero
 * signal either way. This module never computes or exposes such a ratio,
 * and never presents feedback counts as a probability or confidence
 * percentage. Evidence Sufficiency below is deliberately binary (does any
 * real-world signal exist at all?), not a finer-grained confidence score,
 * for exactly this reason.
 *
 * ─────────────────────────── Privacy Boundary ────────────────────────────
 * Every function in this module that reads across tenants (computeQuality,
 * computeReviewQueueEntry) returns ONLY aggregate counts, timestamps, and
 * the shared canonical detection's own public fields -- never an owner_id,
 * connector_id, deployment_id, hunt_id, or free-text summary. Tenant-
 * private detail (a customer's OWN feedback counts, via
 * computeTenantPerformance()) is a clearly separate function, only ever
 * called with the caller's own authenticated ownerId -- see
 * docs/architecture/DETECTION-FEEDBACK-PRIVACY-MODEL.md.
 */

const huntEngine = require('./hunt-engine');
const feedbackStore = require('./detection-feedback-store');
const versionStore = require('./detection-version-store');
const deploymentStore = require('./deployment-store');
const detectionRules = require('./detection-rules');

const QUALITY_STATES = Object.freeze([
  'REVOKED', 'DEPRECATED', 'TECHNICAL_FAILURE', 'REVIEW_REQUIRED',
  'TUNING_RECOMMENDED', 'INSUFFICIENT_EVIDENCE', 'HEALTHY',
]);

const EVIDENCE_SUFFICIENCY_LEVELS = Object.freeze(['NO_OPERATIONAL_EVIDENCE', 'OPERATIONAL_EVIDENCE_PRESENT']);

const PRIORITY_TIERS = Object.freeze(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']);

// Deterministic, per-reason-code guidance -- never an auto-generated
// replacement query. Mirrors falsePositiveGuidanceFor()'s own honesty
// discipline in detection-intelligence.js: general, defensible guidance
// keyed by a known signal, not a fabricated per-technique claim.
const TUNING_RECOMMENDATIONS = Object.freeze({
  QUERY_ERROR: 'Re-run structural and query validation for this detection. At least one customer reports the query fails to execute as written in their environment.',
  TELEMETRY_MISMATCH: 'Review the normalized field mapping against this detection\'s declared data_source. At least one customer reports the fields this detection expects are not present in their telemetry.',
  REPEATED_TOO_BROAD: 'Review this detection\'s conditions against benign negative fixtures. Three or more distinct customers report it is matching more activity than expected.',
  REPEATED_TOO_NARROW: 'Review this detection\'s conditions against the technique\'s full behavioral range. Three or more distinct customers report it is missing expected activity.',
});

function deriveEvidenceSufficiency(sampleSize) {
  return sampleSize > 0 ? 'OPERATIONAL_EVIDENCE_PRESENT' : 'NO_OPERATIONAL_EVIDENCE';
}

/**
 * The single deterministic Quality State. Priority order (first match
 * wins) -- see this file's header and migrations/0006/the certification
 * doc for the full evidence trail behind this ordering:
 *
 *   1. manualOverrideStatus REVOKED/DEPRECATED -- a governance decision,
 *      always wins, independent of any feedback.
 *   2. TECHNICAL_FAILURE -- gateStatus BLOCKED (context-independent: none
 *      of evaluateReleaseGate()'s hardBlockers reasons depend on ATT&CK
 *      evidence state), or >=1 distinct customer reported QUERY_ERROR.
 *   3. REVIEW_REQUIRED -- >=1 distinct customer reported TELEMETRY_MISMATCH.
 *      Deliberately NOT triggered by gateStatus REVIEW_REQUIRED: that
 *      status is near-universally true whenever evidence context is
 *      UNKNOWN (the case at this global level), so it would be an
 *      uninformative artifact here rather than a real signal -- see the
 *      in-line comment below for the full reasoning.
 *   4. TUNING_RECOMMENDED -- 3+ distinct customers reported the same
 *      TOO_BROAD or TOO_NARROW classification.
 *   5. floor: INSUFFICIENT_EVIDENCE (zero operational feedback) or
 *      HEALTHY (feedback exists, no trigger fired).
 *
 * `gateStatus` is deliberately nullable: the canonical validation gate
 * (BLOCKED/REVIEW_REQUIRED) is only ever computed against the CURRENT
 * version's live content (detection-intelligence.js has no way to
 * re-validate a past version -- its evidence-linkage fields, e.g.
 * source.articles/campaigns, are not part of the immutable version
 * snapshot, and fabricating a historical gate result from an incomplete
 * snapshot would be exactly the kind of invented history the mandate
 * forbids). Callers pass gateStatus=null for a non-current version, so
 * only the feedback-derived tiers (which ARE correctly pinned to that
 * exact version, per detection_feedback.detection_version) apply.
 */
function deriveQualityState({ manualOverrideStatus, gateStatus, feedbackSignal }) {
  if (manualOverrideStatus === 'REVOKED') {
    return { quality_state: 'REVOKED', reason: 'This detection has been manually revoked by governance action. This applies to every version and is independent of any operational feedback.' };
  }
  if (manualOverrideStatus === 'DEPRECATED') {
    return { quality_state: 'DEPRECATED', reason: 'This detection has been manually deprecated by governance action. This applies to every version and is independent of any operational feedback.' };
  }

  const reasonCodes = feedbackSignal.reason_codes || [];
  const technicalReasons = [];
  if (gateStatus === 'BLOCKED') technicalReasons.push('The canonical validation gate reports this version as BLOCKED (a structural, telemetry, or fixture check failed).');
  if (reasonCodes.includes('QUERY_ERROR')) technicalReasons.push('At least one customer reported QUERY_ERROR feedback for this version (the query failed to execute as written).');
  if (technicalReasons.length) return { quality_state: 'TECHNICAL_FAILURE', reason: technicalReasons.join(' ') };

  // Deliberately NOT triggered by gateStatus === 'REVIEW_REQUIRED': that
  // canonical status is computed here with attackEvidenceState always
  // UNKNOWN (resolveCanonicalDetection(id, []) -- no specific customer
  // entity context exists at this global level), and evaluateReleaseGate()
  // always adds ATTACK_MAPPING_UNCERTAIN whenever evidence is UNKNOWN --
  // meaning gateStatus would read REVIEW_REQUIRED for nearly every real
  // detection regardless of its actual quality, purely as an artifact of
  // missing entity context, not a genuine signal. Confirmed live against
  // the real canonical store while building this tranche (see the
  // certification doc) before this was corrected. A real, hard structural
  // defect already surfaces via gateStatus === 'BLOCKED' above instead,
  // which IS context-independent (none of evaluateReleaseGate()'s
  // hardBlockers reasons depend on ATT&CK evidence state).
  const reviewReasons = [];
  if (reasonCodes.includes('TELEMETRY_MISMATCH')) reviewReasons.push('At least one customer reported TELEMETRY_MISMATCH feedback for this version (expected fields were not present in their environment).');
  if (reviewReasons.length) return { quality_state: 'REVIEW_REQUIRED', reason: reviewReasons.join(' ') };

  const tuningReasons = [];
  if (reasonCodes.includes('REPEATED_TOO_BROAD')) tuningReasons.push('3 or more distinct customers reported this version as TOO_BROAD.');
  if (reasonCodes.includes('REPEATED_TOO_NARROW')) tuningReasons.push('3 or more distinct customers reported this version as TOO_NARROW.');
  if (tuningReasons.length) return { quality_state: 'TUNING_RECOMMENDED', reason: tuningReasons.join(' ') };

  if ((feedbackSignal.sample_size || 0) === 0) {
    return { quality_state: 'INSUFFICIENT_EVIDENCE', reason: 'No operational feedback has been recorded for this detection version yet. Quality cannot yet be assessed from real defensive use.' };
  }
  return { quality_state: 'HEALTHY', reason: 'No technical-failure, review, or tuning signal is present, and at least one operational feedback record exists for this detection version.' };
}

/**
 * Full Quality State + Evidence Sufficiency for one (detection_id,
 * detection_version). Pass detectionVersion to evaluate a SPECIFIC past
 * version (immutable, always answers the same way regardless of what the
 * canonical detection has since become -- requirement: "v3 performance
 * remains immutable"); omit it to evaluate the CURRENT version.
 */
async function computeDetectionQuality(detectionId, detectionVersion) {
  const canonical = huntEngine.resolveCanonicalDetection(detectionId, []);
  if (!canonical) return null;

  const version = detectionVersion || canonical.version;
  const isCurrentVersion = version === canonical.version;
  const manualOverrideStatus = (canonical.status === 'REVOKED' || canonical.status === 'DEPRECATED') ? canonical.status : null;
  const gateStatus = isCurrentVersion ? canonical.status : null;

  const feedbackSignal = await feedbackStore.computeGlobalReviewMetrics(detectionId, version);
  const { quality_state, reason } = deriveQualityState({ manualOverrideStatus, gateStatus, feedbackSignal });

  return {
    detection_id: detectionId,
    detection_version: version,
    is_current_version: isCurrentVersion,
    canonical_status: canonical.status,
    // Only meaningful when validation_evaluated_for_this_version is true --
    // these are the SAME lifecycle_reasons detection-intelligence.js
    // already computes (structural/telemetry/fixture/evidence-linkage
    // reasons), surfaced here so the Validation axis is never a bare
    // status word with no explanation.
    validation_reasons: isCurrentVersion ? (canonical.lifecycle_reasons || []) : [],
    validation_evaluated_for_this_version: isCurrentVersion,
    evidence_sufficiency: deriveEvidenceSufficiency(feedbackSignal.sample_size),
    quality_state,
    reason,
    operational_evidence: {
      sample_size: feedbackSignal.sample_size,
      distinct_owners_total: feedbackSignal.distinct_owners_total,
      last_feedback_at: feedbackSignal.last_feedback_at,
      reason_codes: feedbackSignal.reason_codes,
    },
    tuning_recommendations: (feedbackSignal.reason_codes || []).map(code => TUNING_RECOMMENDATIONS[code]).filter(Boolean),
  };
}

/**
 * Version history: the live history[] metadata (always available, never
 * lost) joined with whatever immutable content snapshot exists for each
 * version. A version with no snapshot row (predates this tranche's
 * backfill and was never re-stored since) is marked content_available:
 * false -- never fabricated. See migrations/0006's header.
 */
async function getVersionHistory(detectionId) {
  const rule = detectionRules.getRule(detectionId);
  if (!rule) return null;
  const snapshots = await versionStore.listVersionSnapshots(detectionId);
  const byVersion = new Map(snapshots.map(s => [s.version, s]));
  const entries = (rule.history || []).map(h => {
    const snapshot = byVersion.get(h.version);
    return {
      version: h.version,
      timestamp: h.timestamp,
      change: h.change,
      author: h.author,
      content_available: !!snapshot,
      snapshot_source: snapshot ? snapshot.snapshot_source : null,
      content_hash: snapshot ? snapshot.content_hash : null,
      formats: snapshot ? Object.keys(snapshot.platforms || {}).filter(f => snapshot.platforms[f]) : null,
    };
  });
  return { detection_id: detectionId, current_version: rule.governance.version, versions: entries };
}

/**
 * Deterministic Review Priority. A TIER (CRITICAL/HIGH/MEDIUM/LOW/NONE),
 * never an opaque numeric score -- computed from exactly two auditable
 * inputs (how severe the quality state is, and whether it's actually
 * affecting live customer deployments today). threat_relevance,
 * recency, and multiple_environments are reported as separate,
 * transparent factors alongside the tier for the Review Queue to display
 * or sort by -- deliberately not folded into the tier math itself, so the
 * tier's meaning stays auditable rather than a blend of unrelated axes.
 */
function computeReviewPriority({ qualityState, level, deploymentReach, lastFeedbackAt }) {
  const distinctOwners = deploymentReach ? deploymentReach.distinct_owners : 0;
  let tier = 'NONE';
  if (qualityState === 'TECHNICAL_FAILURE') tier = distinctOwners > 0 ? 'CRITICAL' : 'HIGH';
  else if (qualityState === 'REVIEW_REQUIRED') tier = distinctOwners > 0 ? 'HIGH' : 'MEDIUM';
  else if (qualityState === 'TUNING_RECOMMENDED') tier = 'MEDIUM';
  else if (qualityState === 'REVOKED' || qualityState === 'DEPRECATED') tier = 'NONE';

  return {
    priority_tier: tier,
    factors: {
      technical_failure: qualityState === 'TECHNICAL_FAILURE',
      affected_deployments: distinctOwners,
      multiple_environments: distinctOwners > 1,
      threat_relevance: level || null,
      last_feedback_at: lastFeedbackAt || null,
    },
  };
}

/**
 * One Review Queue entry for one canonical detection (its CURRENT
 * version only -- the queue is about acting on what's live today). No
 * customer-private content anywhere in the return value: only the
 * detection's own public fields and cross-tenant aggregate counts.
 */
async function computeReviewQueueEntry(rule) {
  const canonical = huntEngine.resolveCanonicalDetection(rule.id, []);
  if (!canonical) return null;
  const quality = await computeDetectionQuality(rule.id, canonical.version);
  const deploymentReach = await deploymentStore.countDeploymentsByDetection(rule.id);
  const priority = computeReviewPriority({
    qualityState: quality.quality_state,
    level: rule.level,
    deploymentReach,
    lastFeedbackAt: quality.operational_evidence.last_feedback_at,
  });
  return {
    detection_id: rule.id,
    title: rule.title,
    technique_id: rule.technique_id,
    level: rule.level || null,
    detection_version: canonical.version,
    canonical_status: canonical.status,
    validation_reasons: quality.validation_reasons,
    quality_state: quality.quality_state,
    reason: quality.reason,
    evidence_sufficiency: quality.evidence_sufficiency,
    tuning_recommendations: quality.tuning_recommendations,
    priority_tier: priority.priority_tier,
    factors: priority.factors,
  };
}

/**
 * Internal-only Review Queue: every canonical detection's current-version
 * quality state, priority tier, and deterministic factors. Sorted worst-
 * first (CRITICAL > HIGH > MEDIUM > LOW > NONE). The corpus is small
 * (a handful of canonical detections today) so a full scan on every call
 * is deliberately not cached or paginated -- matching this platform's
 * existing "coverage is never stored" discipline; revisit only with
 * evidence of real scale.
 */
async function computeReviewQueue() {
  const store = detectionRules.loadCanonical();
  const entries = [];
  for (const rule of store.rules || []) {
    const entry = await computeReviewQueueEntry(rule);
    if (entry) entries.push(entry);
  }
  const tierRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
  entries.sort((a, b) => (tierRank[a.priority_tier] - tierRank[b.priority_tier]) || (b.factors.affected_deployments - a.factors.affected_deployments));
  return entries;
}

module.exports = {
  QUALITY_STATES,
  EVIDENCE_SUFFICIENCY_LEVELS,
  PRIORITY_TIERS,
  TUNING_RECOMMENDATIONS,
  deriveQualityState,
  computeDetectionQuality,
  getVersionHistory,
  computeReviewPriority,
  computeReviewQueueEntry,
  computeReviewQueue,
};
