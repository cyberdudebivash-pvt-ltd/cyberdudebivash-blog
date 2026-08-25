/**
 * SENTINEL APEX — Deterministic Intelligence Change Detector
 *
 * Pure, deterministic diffing of two watchable-state snapshots (see
 * api/_lib/watchable-state.js) into typed, evidence-aware change events.
 * No LLM is used or permitted here -- every change_type below is derived
 * from a structured field comparison, never an inferred judgment call.
 *
 * Evaluated and NOT built on api/_lib/intelligence-change-detection.js
 * (a real, pre-existing diff class in this repo): that engine diffs whole
 * intelligence-holdings snapshots ({threatActors[], campaigns[], ...}),
 * not a single watched CVE/Campaign; several of its comparisons use
 * `JSON.stringify(a) !== JSON.stringify(b)` on arrays (e.g.
 * actor.knownMalware), which is exactly the array-reorder false-positive
 * this module exists to avoid (Phase 17/22/71 of the governing mandate);
 * its severities are flat per-type hardcodes with no evidence awareness;
 * and it carries no source/evidence references and no idempotent event
 * identity. It is a reasonable multi-entity notification summarizer for
 * a different, coarser use case, not a component this module's
 * single-entity, evidence-graded, idempotent contract can safely extend.
 * See the certification doc's reuse-before-build section for the full
 * comparison.
 *
 * Relationship semantics (Phase 77): v1 detects ADDITIONS only (a new
 * campaign/actor/report association appearing). Removals are NOT
 * detected -- this platform's canonical pipelines do not yet guarantee a
 * disappearance reflects a real correction rather than a temporary
 * projection error (see the campaign-delivery-integrity certification's
 * own findings), so surfacing "X was removed" would risk exactly the
 * false alert storm Phase 72 warns against. This is a deliberate scope
 * boundary, not an oversight: it also means a catastrophic upstream data
 * drop (a graph temporarily losing most of its edges) cannot, by
 * construction, generate a mass "removed" event storm -- there is no
 * removal code path to trigger one.
 *
 * KEV / exploitation status (Phase 74): treated as ADDITION-ONLY for the
 * same reason -- flipping true-to-false is not a state this data model's
 * upstream pipelines are known to represent reliably, so no reversal
 * event type exists for it in v1.
 */
'use strict';

const crypto = require('crypto');
const { canonicalize } = require('./watchable-state');

const CHANGE_EVENT_SCHEMA_VERSION = '1.0';

// Phase 78: documented, deterministic importance mapping. Not re-derived
// per event -- one table, reviewed here, not invented ad hoc per call.
const IMPORTANCE = {
  CVE_ACTIVE_EXPLOITATION_CONFIRMED: 'CRITICAL',
  CVE_KEV_ADDED:                     'HIGH',
  CVE_NEW_CAMPAIGN_ASSOCIATION:      'HIGH',
  CVE_NEW_ACTOR_ASSOCIATION:         'HIGH',
  CVE_CVSS_CHANGED:                  'MEDIUM',
  CVE_SEVERITY_CHANGED:              'MEDIUM',
  CVE_NEW_REPORT:                    'MEDIUM',
  CAMPAIGN_KEV_FLAG_ADDED:           'HIGH',
  CAMPAIGN_EXPLOITED_FLAG_ADDED:     'HIGH',
  CAMPAIGN_RANSOMWARE_FLAG_ADDED:    'HIGH',
  CAMPAIGN_NEW_ACTOR:                'HIGH',
  CAMPAIGN_NEW_CVE:                  'HIGH',
  CAMPAIGN_SEVERITY_CHANGED:         'MEDIUM',
  CAMPAIGN_CONFIDENCE_CHANGED:       'MEDIUM',
  CAMPAIGN_NEW_REPORT:               'MEDIUM',
  CAMPAIGN_LAST_SEEN_ADVANCED:       'LOW',
};

// Phase 45: deterministic, evidence-gated recommended actions -- never a
// generic "block everything", never issued for a fact with no supporting
// change.
const RECOMMENDED_ACTION = {
  CVE_ACTIVE_EXPLOITATION_CONFIRMED: 'Validate exposure to this CVE in your environment now.',
  CVE_KEV_ADDED:                     'Reassess exposure and remediation priority; CISA KEV listing indicates confirmed exploitation.',
  CVE_NEW_CAMPAIGN_ASSOCIATION:      'Review the newly linked campaign for related infrastructure and activity.',
  CVE_NEW_ACTOR_ASSOCIATION:         'Review the newly attributed actor\'s known TTPs and infrastructure.',
  CVE_CVSS_CHANGED:                  'Re-evaluate remediation priority against the updated score.',
  CVE_SEVERITY_CHANGED:              'Re-evaluate remediation priority against the updated severity.',
  CVE_NEW_REPORT:                    'Review the new report for additional analysis and context.',
  CAMPAIGN_KEV_FLAG_ADDED:           'Review linked CVEs for KEV-driven remediation urgency.',
  CAMPAIGN_EXPLOITED_FLAG_ADDED:     'Review linked CVEs and hunt for related indicators.',
  CAMPAIGN_RANSOMWARE_FLAG_ADDED:    'Escalate incident-response readiness for assets tied to this campaign.',
  CAMPAIGN_NEW_ACTOR:                'Review the newly attributed actor\'s known TTPs and infrastructure.',
  CAMPAIGN_NEW_CVE:                  'Confirm remediation status for the newly linked CVE.',
  CAMPAIGN_SEVERITY_CHANGED:         'Re-evaluate response priority against the updated severity.',
  CAMPAIGN_CONFIDENCE_CHANGED:       'Review the updated clustering confidence before acting on attribution.',
  CAMPAIGN_NEW_REPORT:               'Review the new report for additional analysis and context.',
  CAMPAIGN_LAST_SEEN_ADVANCED:       'Monitor for continued activity; no immediate action required.',
};

function numEq(a, b) {
  // Phase 71 adversarial case: 9.8 vs "9.8" must compare equal. Both sides
  // coerced through Number(); NaN (missing/malformed) is treated as null.
  const na = a === null || a === undefined || a === '' ? null : Number(a);
  const nb = b === null || b === undefined || b === '' ? null : Number(b);
  const va = Number.isFinite(na) ? na : null;
  const vb = Number.isFinite(nb) ? nb : null;
  return va === vb;
}

function strEq(a, b) {
  return (a || null) === (b || null);
}

function setAdditions(beforeSet, afterSet) {
  const before = new Set(beforeSet || []);
  return (afterSet || []).filter(id => !before.has(id));
}

// Phase 31: deterministic event identity -- the same semantic change
// (same entity, same type, same resulting value) always produces the
// same event_id, so re-running the same before/after comparison (a
// replayed batch, a duplicate queue message) can be deduplicated with a
// single atomic SET...NX at persistence time (api/_lib/change-engine.js)
// instead of a race-prone read-then-write check.
function makeEventId({ entityType, entityId, changeType, after }) {
  const basis = `${CHANGE_EVENT_SCHEMA_VERSION}|${entityType}|${entityId}|${changeType}|${JSON.stringify(canonicalize(after))}`;
  return 'IEV-' + crypto.createHash('sha256').update(basis).digest('hex').slice(0, 24);
}

function buildEvent({ entityType, entityId, changeType, before, after, related, reason, observedAt }) {
  return {
    schema_version: CHANGE_EVENT_SCHEMA_VERSION,
    event_id: makeEventId({ entityType, entityId, changeType, after }),
    entity_id: entityId,
    entity_type: entityType,
    change_type: changeType,
    importance: IMPORTANCE[changeType] || 'LOW',
    before: before === undefined ? null : before,
    after: after === undefined ? null : after,
    related: related || null,
    reason,
    recommended_action: RECOMMENDED_ACTION[changeType] || 'Review the updated record for details.',
    observed_at: observedAt,
  };
}

/* ───────────────────────── CVE change rules ───────────────────────── */

function detectCveChanges(before, after, observedAt) {
  const id = after.entity_id;
  const events = [];

  if (!before.kev && after.kev) {
    events.push(buildEvent({
      entityType: 'cve', entityId: id, changeType: 'CVE_KEV_ADDED',
      before: false, after: true, observedAt,
      reason: `${id} was added to the CISA Known Exploited Vulnerabilities (KEV) catalog.`,
    }));
  }

  if (before.active_exploitation !== 'CONFIRMED' && after.active_exploitation === 'CONFIRMED') {
    events.push(buildEvent({
      entityType: 'cve', entityId: id, changeType: 'CVE_ACTIVE_EXPLOITATION_CONFIRMED',
      before: before.active_exploitation, after: after.active_exploitation, observedAt,
      reason: `${id}'s exploitation status changed from ${before.active_exploitation} to CONFIRMED.`,
    }));
  }

  if (!numEq(before.cvss, after.cvss) && after.cvss !== null) {
    events.push(buildEvent({
      entityType: 'cve', entityId: id, changeType: 'CVE_CVSS_CHANGED',
      before: before.cvss, after: after.cvss, observedAt,
      reason: `${id}'s CVSS score changed from ${before.cvss ?? 'unknown'} to ${after.cvss}.`,
    }));
  }

  if (!strEq(before.severity, after.severity) && after.severity) {
    events.push(buildEvent({
      entityType: 'cve', entityId: id, changeType: 'CVE_SEVERITY_CHANGED',
      before: before.severity, after: after.severity, observedAt,
      reason: `${id}'s severity changed from ${before.severity || 'unknown'} to ${after.severity}.`,
    }));
  }

  for (const campaignId of setAdditions(before.campaign_ids, after.campaign_ids)) {
    events.push(buildEvent({
      entityType: 'cve', entityId: id, changeType: 'CVE_NEW_CAMPAIGN_ASSOCIATION',
      before: null, after: campaignId, related: { id: campaignId, type: 'campaign' }, observedAt,
      reason: `${id} was newly associated with campaign ${campaignId}.`,
    }));
  }

  for (const actorId of setAdditions(before.actor_ids, after.actor_ids)) {
    events.push(buildEvent({
      entityType: 'cve', entityId: id, changeType: 'CVE_NEW_ACTOR_ASSOCIATION',
      before: null, after: actorId, related: { id: actorId, type: 'actor' }, observedAt,
      reason: `${id} was newly associated with actor ${actorId}.`,
    }));
  }

  for (const reportId of setAdditions(before.report_ids, after.report_ids)) {
    events.push(buildEvent({
      entityType: 'cve', entityId: id, changeType: 'CVE_NEW_REPORT',
      before: null, after: reportId, related: { id: reportId, type: 'report' }, observedAt,
      reason: `A new report (${reportId}) was published referencing ${id}.`,
    }));
  }

  return events;
}

/* ───────────────────────── Campaign change rules ───────────────────────── */

function detectCampaignChanges(before, after, observedAt) {
  const id = after.entity_id;
  const events = [];

  if (!before.has_kev && after.has_kev) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_KEV_FLAG_ADDED',
      before: false, after: true, observedAt,
      reason: `${id} now includes a CISA KEV-listed vulnerability.`,
    }));
  }
  if (!before.has_exploited && after.has_exploited) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_EXPLOITED_FLAG_ADDED',
      before: false, after: true, observedAt,
      reason: `${id} now includes an actively exploited vulnerability.`,
    }));
  }
  if (!before.has_ransomware && after.has_ransomware) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_RANSOMWARE_FLAG_ADDED',
      before: false, after: true, observedAt,
      reason: `${id} is now linked to ransomware activity.`,
    }));
  }

  if (!strEq(before.severity, after.severity) && after.severity) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_SEVERITY_CHANGED',
      before: before.severity, after: after.severity, observedAt,
      reason: `${id}'s severity changed from ${before.severity || 'unknown'} to ${after.severity}.`,
    }));
  }

  if (!strEq(before.confidence_bucket, after.confidence_bucket)) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_CONFIDENCE_CHANGED',
      before: before.confidence_bucket, after: after.confidence_bucket, observedAt,
      reason: `${id}'s clustering confidence changed from ${before.confidence_bucket} to ${after.confidence_bucket}.`,
    }));
  }

  if (before.last_seen && after.last_seen && after.last_seen > before.last_seen) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_LAST_SEEN_ADVANCED',
      before: before.last_seen, after: after.last_seen, observedAt,
      reason: `${id} was observed again; last-seen advanced from ${before.last_seen} to ${after.last_seen}.`,
    }));
  }

  for (const actorId of setAdditions(before.actor_ids, after.actor_ids)) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_NEW_ACTOR',
      before: null, after: actorId, related: { id: actorId, type: 'actor' }, observedAt,
      reason: `${id} was newly attributed to actor ${actorId}.`,
    }));
  }

  for (const cveId of setAdditions(before.cve_ids, after.cve_ids)) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_NEW_CVE',
      before: null, after: cveId, related: { id: cveId, type: 'cve' }, observedAt,
      reason: `${id} was newly linked to ${cveId}.`,
    }));
  }

  for (const reportId of setAdditions(before.report_ids, after.report_ids)) {
    events.push(buildEvent({
      entityType: 'campaign', entityId: id, changeType: 'CAMPAIGN_NEW_REPORT',
      before: null, after: reportId, related: { id: reportId, type: 'report' }, observedAt,
      reason: `A new report (${reportId}) was published referencing ${id}.`,
    }));
  }

  return events;
}

/**
 * detectChanges({entityType, before, after, observedAt})
 *
 * `before` may be null/undefined (no prior snapshot exists yet -- Phase
 * 52: this must establish a baseline, never a flood of synthetic "every
 * field just changed from nothing" events).
 */
function detectChanges({ entityType, before, after, observedAt }) {
  const now = observedAt || new Date().toISOString();
  if (!after) return { status: 'no_current_state', events: [] };
  if (!before) return { status: 'baseline_established', events: [] };
  if (before.entity_type !== after.entity_type || before.entity_id !== after.entity_id) {
    return { status: 'entity_mismatch', events: [] };
  }

  const events = entityType === 'cve'
    ? detectCveChanges(before, after, now)
    : entityType === 'campaign'
      ? detectCampaignChanges(before, after, now)
      : [];

  return { status: events.length ? 'changed' : 'unchanged', events };
}

module.exports = {
  CHANGE_EVENT_SCHEMA_VERSION,
  IMPORTANCE,
  detectChanges,
  makeEventId,
};
