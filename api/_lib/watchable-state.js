/**
 * SENTINEL APEX — Watchable State Projection
 *
 * A "watchable state" is a small, deterministic, normalized snapshot of a
 * CVE or Campaign, containing only the fields whose changes are meaningful
 * to a customer. It is NOT the dossier, and it is NOT persisted as a
 * second intelligence store: it is derived fresh from the same canonical
 * sources api/_lib/intelligence-dossier.js already reads (the threat
 * graph, campaigns.json, the CVE enrichment index, reports-index.json),
 * then fingerprinted and compared by api/_lib/change-detector.js. Only
 * the fingerprint + this small object are ever written to Redis (by
 * api/_lib/change-engine.js) as the "last observed state" needed to
 * detect the NEXT change -- deleting that snapshot and re-evaluating the
 * watched entity always reproduces the same state from canonical data.
 *
 * Deliberately excludes: generated_at, request-scoped timestamps, cache
 * metadata, array insertion order, and anything else that can change
 * without the underlying intelligence changing (Phase 13/22 of the
 * governing mandate). Relationship fields are always normalized sets
 * (sorted, deduplicated) so reordering a source array can never look like
 * a change (Phase 17).
 *
 * Truth reuse: CVE exploitation status is classified via
 * intelligence-dossier.js's own classifyExploitation() and campaign
 * confidence via its campaignConfidenceBucket() -- the exact same
 * functions the dossier itself uses, so a dossier and a change event can
 * never disagree about what "confirmed" or "HIGH confidence" means.
 */
'use strict';

const crypto = require('crypto');
const { getNeighbors } = require('./threat-graph');
const { classifyExploitation, campaignConfidenceBucket } = require('./intelligence-dossier');

const WATCHABLE_STATE_SCHEMA_VERSION = '1.0';

/* ───────────────────────── shared helpers ───────────────────────── */

// Phase 17: relationship arrays are sets, not ordered lists -- sort+dedupe
// so ["b","a"] and ["a","b"] (or a value repeated by two edges) always
// normalize identically.
function normalizeIdSet(ids) {
  return [...new Set((ids || []).filter(Boolean))].sort();
}

// Recursively sort object keys so JSON.stringify is stable regardless of
// construction order -- required for the fingerprint (Phase 29) to be a
// true semantic hash, not an incidental key-order hash.
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((acc, k) => {
      acc[k] = canonicalize(value[k]);
      return acc;
    }, {});
  }
  return value;
}

// Phase 29: semantic SHA-256 fingerprint over the canonicalized state.
// Two states with the same meaning always fingerprint identically, so the
// change engine can skip deep diffing entirely when nothing changed.
function fingerprintState(state) {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(state))).digest('hex');
}

function reportIdsFor(reportsIndexData, matches) {
  return normalizeIdSet(matches.map(r => r.report_id));
}

/* ───────────────────────── CVE watchable state ───────────────────────── */

// Phase 13: only fields whose change is meaningful. `cvss` and `kev` are
// intentionally the raw values (not string-coerced) here -- the change
// detector, not this module, is responsible for the numeric-vs-string
// noise-suppression Phase 71 requires ("9.8" vs 9.8 must compare equal).
function buildCveWatchableState({ graph, cveId, cveItem, reportsIndexData }) {
  const attrs = {
    cvss:      typeof cveItem.cvss === 'number' ? cveItem.cvss : null,
    threat_level: cveItem.threat_level || null,
    cisa_kev:  !!(cveItem.cisa_kev || cveItem.cisaKev),
    exploited: !!cveItem.exploited,
  };
  const exploitation = classifyExploitation(attrs);

  const campaignIds = graph ? normalizeIdSet(getNeighbors(graph, cveId, 'includes').map(e => e.node.id)) : [];
  const actorIds     = graph ? normalizeIdSet(getNeighbors(graph, cveId, 'exploits').map(e => e.node.id)) : [];
  const reports = ((reportsIndexData && reportsIndexData.reports) || [])
    .filter(r => Array.isArray(r.cves) && r.cves.includes(cveId));

  return {
    schema_version: WATCHABLE_STATE_SCHEMA_VERSION,
    entity_type: 'cve',
    entity_id: cveId,
    cvss: attrs.cvss,
    severity: attrs.threat_level,
    kev: attrs.cisa_kev,
    active_exploitation: exploitation.status, // CONFIRMED | ASSESSED | UNKNOWN
    campaign_ids: campaignIds,
    actor_ids: actorIds,
    report_ids: reportIdsFor(reportsIndexData, reports),
  };
}

/* ───────────────────────── Campaign watchable state ───────────────────────── */

function buildCampaignWatchableState({ campaign, reportsIndexData }) {
  const actorIds = normalizeIdSet((campaign.threat_actors || []).map(a => a.id));
  const cveIds   = normalizeIdSet(campaign.shared_cves || []);
  const reports = ((reportsIndexData && reportsIndexData.reports) || [])
    .filter(r => Array.isArray(r.cves) && cveIds.some(c => r.cves.includes(c)));

  return {
    schema_version: WATCHABLE_STATE_SCHEMA_VERSION,
    entity_type: 'campaign',
    entity_id: campaign.campaign_id,
    severity: campaign.severity || null,
    confidence_bucket: campaignConfidenceBucket(campaign.confidence),
    last_seen: campaign.last_seen || null,
    actor_ids: actorIds,
    cve_ids: cveIds,
    report_ids: reportIdsFor(reportsIndexData, reports),
    has_kev: !!campaign.has_kev,
    has_exploited: !!campaign.has_exploited,
    has_ransomware: !!campaign.has_ransomware,
  };
}

module.exports = {
  WATCHABLE_STATE_SCHEMA_VERSION,
  buildCveWatchableState,
  buildCampaignWatchableState,
  normalizeIdSet,
  canonicalize,
  fingerprintState,
};
