/**
 * SENTINEL APEX — Campaign Clustering Engine v2.0
 * Phase 2 Hardening: Weighted similarity model with time decay.
 *
 * Similarity formula:
 *   cluster_score = (ioc_overlap*0.35) + (cve_match*0.25)
 *                 + (time_proximity*0.20) + (text_similarity*0.20)
 *
 * Time decay:
 *   time_proximity = exp(-daysBetween(a, b) / 7)
 *   → items 7 days apart: ~0.37  (decay factor)
 *   → items 14 days apart: ~0.14
 *   → items same day: 1.0
 *
 * Actor-overlap bonus:
 *   Both items attributed to same actor (confidence ≥ 0.50)
 *   → implied infrastructure overlap → ioc_overlap += 0.30 (capped at 1.0)
 *
 * Threshold: CLUSTER_THRESHOLD = 0.60 (strict — no weak clusters)
 *
 * Every campaign includes reasoning[] explaining WHY items were clustered.
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { getNeighbors } = require('./threat-graph');

const CAMPAIGNS_PATH      = path.resolve(__dirname, '../../api/intel/campaigns.json');
const CAMPAIGNS_CACHE_TTL = 120000;
let _campaignsCache     = null;
let _campaignsCacheTime = 0;

/* ─── TUNING CONSTANTS ───────────────────────────────────────────────── */
const CLUSTER_THRESHOLD = 0.60;  // min weighted score to join/create cluster
const MIN_CLUSTER_SCORE = 60;    // min priority_score for single-item campaign
const TIME_DECAY_TAU    = 7;     // half-life in days for time proximity decay

/* ═══════════════════════════════════════════════════════════════════════
   STORAGE
═══════════════════════════════════════════════════════════════════════ */
function loadCampaigns() {
  const now = Date.now();
  if (_campaignsCache && (now - _campaignsCacheTime) < CAMPAIGNS_CACHE_TTL) return _campaignsCache;
  try {
    if (fs.existsSync(CAMPAIGNS_PATH)) {
      const raw = fs.readFileSync(CAMPAIGNS_PATH, 'utf8');
      _campaignsCache = JSON.parse(raw);
      _campaignsCacheTime = now;
      return _campaignsCache;
    }
  } catch (e) { console.error(`[CAMPAIGNS] Load failed: ${e.message}`); }
  return { generated: new Date().toISOString(), version: '1.0', campaigns: [] };
}

// Catastrophic-drop guard (campaign delivery integrity v1): the real
// production defect this guards against was campaigns.json going from
// 1,187 campaigns to 0 in a single write, because the caller passed only
// the current ingestion cycle's freshly-clustered batch instead of a
// merge against existing state (see mergeCampaigns() below, which is the
// actual fix -- this is defense-in-depth at the single write chokepoint,
// so a future caller that bypasses the merge, or a bug in the merge
// itself, can't silently reintroduce the same class of data loss).
// DROP_FLOOR avoids false positives while campaign state is still small
// (e.g. a fresh environment, or early in this fix's rollout) --
// production has already been observed at 1,187, so 5 is conservative,
// not tuned to any specific current count.
const CAMPAIGN_DROP_FLOOR = 5;

function saveCampaigns(data, { allowDrop = false } = {}) {
  data.generated = new Date().toISOString();
  data.version   = '1.0';
  data.platform  = 'CYBERDUDEBIVASH SENTINEL APEX v4.0';
  const newCount = (data.campaigns || []).length;

  if (!allowDrop) {
    let existingCount = 0;
    try {
      if (fs.existsSync(CAMPAIGNS_PATH)) {
        existingCount = (JSON.parse(fs.readFileSync(CAMPAIGNS_PATH, 'utf8')).campaigns || []).length;
      }
    } catch (e) { console.error(`[CAMPAIGNS] Drop-guard read failed: ${e.message}`); }

    if (existingCount >= CAMPAIGN_DROP_FLOOR && newCount < existingCount) {
      console.error(
        `[CAMPAIGNS] BLOCKED destructive write: ${existingCount} -> ${newCount} campaigns. ` +
        `saveCampaigns() only ever expects a monotonically-accumulating list (see mergeCampaigns()); ` +
        `a caller passed fewer campaigns than are already persisted. Refusing to overwrite -- ` +
        `existing file left untouched. Pass { allowDrop: true } if this is a deliberate reset.`
      );
      return { saved: false, blocked: true, existingCount, attemptedCount: newCount };
    }
  }

  try {
    fs.writeFileSync(CAMPAIGNS_PATH, JSON.stringify(data, null, 2), 'utf8');
    _campaignsCache     = data;
    _campaignsCacheTime = Date.now();
    console.log(`[CAMPAIGNS] Saved: ${newCount} campaigns`);
    return { saved: true, blocked: false, existingCount: null, attemptedCount: newCount };
  } catch (e) {
    console.error(`[CAMPAIGNS] Save failed: ${e.message}`);
    return { saved: false, blocked: false, error: e.message, attemptedCount: newCount };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   CAMPAIGN PERSISTENCE MERGE (campaign delivery integrity v1)
   buildCampaigns() only ever sees the current ingestion cycle's freshly-
   fetched batch -- it has no visibility into campaigns clustered in any
   earlier run. mergeCampaigns() is what makes accumulation safe: it
   upserts a batch of newly-built campaigns into the previously-persisted
   set by campaign_id (buildCampaignId() is deterministic -- the same
   underlying CVE/cluster always produces the same id, so this is a
   correct identity key, not a name-similarity guess), rather than
   replacing the set outright. An existing campaign whose id doesn't
   appear in this run's batch is left completely untouched -- that's the
   fix: campaigns discovered in earlier cycles are no longer silently
   dropped just because none of their underlying intel re-appeared in
   today's fetch.
═══════════════════════════════════════════════════════════════════════ */
const MAX_MERGED_SHARED_IOCS = 25; // matches buildCampaigns()'s own per-campaign cap
const MAX_MERGED_REASONING   = 12; // bounds unbounded growth across many merge cycles

/** Mirrors campaignSeverity()'s thresholds, but operates on already-merged
 * scalar flags instead of a raw items array -- related_intel[] (the
 * persisted per-item projection) doesn't carry every field campaignSeverity()
 * reads from a raw intel item (e.g. no per-item `ransomware` flag), so
 * recomputing from campaign-level has_kev/has_ransomware/has_exploited/
 * max_priority_score (each already merged correctly via OR/max below) is
 * the correct way to keep severity in sync after a merge, not calling
 * campaignSeverity() against a differently-shaped array. */
function severityFromFlags(maxScore, hasKev, hasRansomware, hasExploited) {
  if (maxScore >= 85 || (hasKev && hasRansomware))                 return 'CRITICAL';
  if (maxScore >= 65 || hasKev || (hasRansomware && hasExploited)) return 'HIGH';
  if (maxScore >= 45 || hasExploited)                              return 'MEDIUM';
  return 'LOW';
}

/**
 * Merge one incoming (freshly-clustered) campaign into its previously-
 * persisted counterpart (same campaign_id). Field-specific semantics --
 * never a blind object spread, which would let an incoming batch with a
 * smaller related_intel[] silently shrink history.
 */
function mergeCampaign(existing, incoming) {
  // Union related_intel by id -- incoming wins on a rare id collision
  // (the freshest re-observation of the same item), existing entries for
  // ids not present in this batch are preserved untouched.
  const relatedIntelById = new Map();
  for (const item of (existing.related_intel || [])) if (item && item.id) relatedIntelById.set(item.id, item);
  for (const item of (incoming.related_intel || [])) if (item && item.id) relatedIntelById.set(item.id, item);
  const relatedIntel   = [...relatedIntelById.values()];
  const relatedIntelIds = relatedIntel.map(i => i.id);

  const sharedIOCs = [...new Set([...(existing.shared_iocs || []), ...(incoming.shared_iocs || [])])]
    .slice(0, MAX_MERGED_SHARED_IOCS);
  const sharedCVEs = [...new Set([...(existing.shared_cves || []), ...(incoming.shared_cves || [])])];

  // Union threat_actors by id, keeping whichever observation has higher
  // confidence rather than always preferring one side.
  const actorsById = new Map();
  for (const a of (existing.threat_actors || [])) if (a && a.id) actorsById.set(a.id, a);
  for (const a of (incoming.threat_actors || [])) {
    if (!a || !a.id) continue;
    const prev = actorsById.get(a.id);
    if (!prev || (a.confidence || 0) > (prev.confidence || 0)) actorsById.set(a.id, a);
  }
  const threatActors = [...actorsById.values()].sort((a, b) => (b.confidence || 0) - (a.confidence || 0));

  // first_seen/last_seen recomputed from the full merged related_intel
  // set (not just whichever side's timestamp is "newer") -- correct
  // regardless of the order cycles happen to run in, including a replay
  // of an older batch after a newer one (Phase 42/43: out-of-order safe
  // by construction, not by assuming chronological arrival).
  const dates = relatedIntel.map(i => i.published).filter(Boolean).sort();
  const firstSeen = dates[0] || existing.first_seen || incoming.first_seen || null;
  const lastSeen   = dates[dates.length - 1] || incoming.last_seen || existing.last_seen || null;

  const maxPriorityScore = Math.max(existing.max_priority_score || 0, incoming.max_priority_score || 0);
  const hasKev        = !!(existing.has_kev || incoming.has_kev);
  const hasRansomware = !!(existing.has_ransomware || incoming.has_ransomware);
  const hasExploited  = !!(existing.has_exploited || incoming.has_exploited);

  const reasoningSet = new Set([...(existing.reasoning || []), ...(incoming.reasoning || [])]);
  const gainedNewItems = relatedIntelIds.some(id => !(existing.related_intel_ids || []).includes(id));
  if (gainedNewItems) {
    reasoningSet.add(
      `Merged ${incoming.related_intel_ids?.length || 0} item(s) observed in a later ingestion cycle ` +
      `(${new Date().toISOString().slice(0, 10)}) -- ${relatedIntel.length} total item(s) accumulated`
    );
  }
  const reasoning = [...reasoningSet].slice(0, MAX_MERGED_REASONING);

  return {
    // Identity and presentation are stable once first established --
    // never overwritten by a later merge (Phase 4/40: a campaign's name
    // must not silently change out from under a customer who bookmarked
    // or referenced it).
    campaign_id:      existing.campaign_id,
    name:             existing.name,
    clustering_model: existing.clustering_model || incoming.clustering_model || 'weighted_v2',

    severity:    severityFromFlags(maxPriorityScore, hasKev, hasRansomware, hasExploited),
    confidence:  Math.max(existing.confidence || 0, incoming.confidence || 0),
    item_count:  relatedIntel.length,
    ioc_count:   sharedIOCs.length,
    first_seen:  firstSeen,
    last_seen:   lastSeen,

    related_intel_ids: relatedIntelIds,
    related_intel:      relatedIntel,
    shared_iocs:        sharedIOCs,
    shared_cves:        sharedCVEs,
    threat_actor:       threatActors.length > 0 ? threatActors[0].name : (existing.threat_actor || incoming.threat_actor || null),
    threat_actors:      threatActors,

    max_priority_score: maxPriorityScore,
    has_kev:             hasKev,
    has_ransomware:      hasRansomware,
    has_exploited:       hasExploited,

    reasoning,
  };
}

/**
 * Upsert a batch of freshly-clustered campaigns into the previously-
 * persisted set. Provably monotonic in campaign count by construction --
 * every existing entry is retained in the output Map (updated in place
 * if re-observed, left untouched otherwise); nothing is ever deleted.
 * Idempotent: merging the same batch twice produces the same result,
 * since every merge operation above is a set union or a min/max, not an
 * append that would grow unboundedly on replay.
 */
function mergeCampaigns(existingCampaigns, newCampaigns) {
  const byId = new Map();
  for (const c of (existingCampaigns || [])) if (c && c.campaign_id) byId.set(c.campaign_id, c);
  for (const c of (newCampaigns || [])) {
    if (!c || !c.campaign_id) continue;
    const existing = byId.get(c.campaign_id);
    byId.set(c.campaign_id, existing ? mergeCampaign(existing, c) : c);
  }

  return [...byId.values()].sort((a, b) => {
    const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const sevDiff = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
    return sevDiff !== 0 ? sevDiff : (b.item_count || 0) - (a.item_count || 0);
  });
}

/* ═══════════════════════════════════════════════════════════════════════
   ONE-TIME HISTORICAL RECOVERY (campaign delivery integrity v1)
   mergeCampaigns() above only prevents FUTURE data loss -- it has nothing
   to merge against for campaigns that were already dropped from
   campaigns.json before this fix existed. Unlike campaigns.json, the
   graph's own Campaign nodes were never lost (addNode()'s upsert-into-
   loaded-graph pattern already accumulated them correctly), so a
   reconstruction is possible without replaying any external source.
   Dry-run only by design -- reconstructCampaignsFromGraph() never writes
   anything; a caller decides separately whether/how to persist its output.
═══════════════════════════════════════════════════════════════════════ */
const MAX_RECONSTRUCTED_SHARED_IOCS = 25; // matches the live pipeline's own per-campaign cap

/**
 * Derive campaign objects directly from the graph's own Campaign nodes
 * and their edges. Everything used here is either a node attribute set
 * at ingestion time or reachable via a bounded traversal over
 * already-proven edge types (includes / executes / linked_to) --
 * no external source is replayed, nothing is invented.
 *
 * STRICT TRUTH RULE / provenance: this is a strictly LOWER-FIDELITY
 * reconstruction than the original live clustering run that first built
 * each campaign. In particular, shared_iocs depends on a 2-hop traversal
 * (Campaign->includes->Intel/CVE->linked_to->IOC) through data that was
 * already capped at ingestion time (buildGraphFromIntel() keeps at most
 * 5 IOC nodes per intel item), so a reconstructed campaign's shared_iocs
 * can legitimately undercount relative to what the original clustering
 * run captured from the item's full, uncapped IOC list. clustering_model
 * is therefore always 'graph_reconstruction_v1', never 'weighted_v2' --
 * a reconstruction must never claim the same evidentiary basis as a live
 * clustering run produced from the original source data.
 */
function reconstructCampaignsFromGraph(graph) {
  const campaignNodes = Object.values((graph && graph.nodes) || {}).filter(n => n && n.type === 'Campaign');
  const results = [];

  for (const node of campaignNodes) {
    const attrs = node.attributes || {};

    const includesEdges = getNeighbors(graph, node.id, 'includes').filter(n => n.direction === 'outbound');
    const relatedIntel = includesEdges
      .map(n => n.node)
      .filter(Boolean)
      .map(intelNode => ({
        id:             intelNode.id,
        title:          intelNode.name || intelNode.id,
        type:           intelNode.attributes?.type || (intelNode.type === 'CVE' ? 'CVE_REPORT' : 'INTEL'),
        priority_score: intelNode.attributes?.priority_score || 0,
        published:      intelNode.attributes?.published || '',
        exploited:      !!intelNode.attributes?.exploited,
        cisa_kev:       !!intelNode.attributes?.cisa_kev,
      }));
    const relatedIntelIds = relatedIntel.map(i => i.id);
    const sharedCVEs = relatedIntelIds.filter(id => String(id).startsWith('CVE-'));

    const sharedIOCsSet = new Set();
    for (const intelId of relatedIntelIds) {
      for (const iocNeighbor of getNeighbors(graph, intelId, 'linked_to')) {
        if (iocNeighbor.direction === 'outbound' && iocNeighbor.node?.type === 'IOC') {
          sharedIOCsSet.add(iocNeighbor.node.id);
        }
      }
    }
    const sharedIOCs = [...sharedIOCsSet].slice(0, MAX_RECONSTRUCTED_SHARED_IOCS);

    const threatActors = getNeighbors(graph, node.id, 'executes')
      .filter(n => n.direction === 'inbound')
      .map(n => (n.node ? { id: n.node.id, name: n.node.name, confidence: n.confidence, category: n.node.attributes?.category } : null))
      .filter(Boolean)
      .sort((a, b) => (b.confidence || 0) - (a.confidence || 0));

    const maxPriorityScore = relatedIntel.reduce((max, i) => Math.max(max, i.priority_score || 0), 0);
    const hasKev        = relatedIntel.some(i => i.cisa_kev);
    const hasRansomware = includesEdges.some(n => !!n.node?.attributes?.ransomware);
    const hasExploited  = relatedIntel.some(i => i.exploited);

    results.push({
      campaign_id:      node.id,
      name:             node.name || node.id,
      severity:         severityFromFlags(maxPriorityScore, hasKev, hasRansomware, hasExploited),
      confidence:       typeof attrs.confidence === 'number' ? attrs.confidence : 0.5,
      item_count:       relatedIntel.length,
      ioc_count:        sharedIOCs.length,
      first_seen:       attrs.first_seen || null,
      last_seen:        attrs.last_seen || null,
      related_intel_ids: relatedIntelIds,
      related_intel:     relatedIntel,
      shared_iocs:       sharedIOCs,
      shared_cves:       sharedCVEs,
      threat_actor:      threatActors.length > 0 ? threatActors[0].name : null,
      threat_actors:     threatActors,
      max_priority_score: maxPriorityScore,
      has_kev:            hasKev,
      has_ransomware:     hasRansomware,
      has_exploited:      hasExploited,
      reasoning: [
        `Reconstructed from graph state (not re-clustered) — ${relatedIntel.length} related item(s), ` +
        `${threatActors.length} attributed actor(s).`,
        ...(attrs.reasoning ? [attrs.reasoning] : []),
      ],
      clustering_model: 'graph_reconstruction_v1',
    });
  }

  return results;
}

/* ═══════════════════════════════════════════════════════════════════════
   UTILITY
═══════════════════════════════════════════════════════════════════════ */
function jaccardSimilarity(setA, setB) {
  if (!setA.size || !setB.size) return 0;
  let intersectionCount = 0;
  for (const item of setA) { if (setB.has(item)) intersectionCount++; }
  return intersectionCount / (setA.size + setB.size - intersectionCount);
}

const STOP_WORDS = new Set([
  'the','a','an','in','on','at','of','to','for','and','or','is','are','was','be',
  'has','have','had','this','that','it','its','with','as','by','from','cve','can',
  'may','via','use','using','used','allows','attacker','could','lead','remote',
  'local','code','execution','vulnerability','security','update','patch','advisory',
]);

function keywordSet(text) {
  const words = String(text || '').toLowerCase().match(/\b[a-z][a-z0-9-]{2,}\b/g) || [];
  return new Set(words.filter(w => !STOP_WORDS.has(w)));
}

function extractIOCSet(item) {
  return new Set(
    (item.iocs || [])
      .filter(ioc => ioc && ioc.value && ioc.type !== 'url')
      .map(ioc => `${ioc.type}:${ioc.value}`)
  );
}

function extractCVESet(item) {
  const cves = new Set();
  if (String(item.id || '').startsWith('CVE-')) cves.add(item.id);
  (item.cves || []).forEach(c => cves.add(String(c).toUpperCase()));
  return cves;
}

function daysBetween(dateA, dateB) {
  const a = new Date(dateA || Date.now()).getTime();
  const b = new Date(dateB || Date.now()).getTime();
  return Math.abs(a - b) / 86400000;
}

/**
 * Time proximity score using exponential decay.
 * tau = 7 days: items same-day → 1.0; 7 days apart → ~0.37; 14 days → ~0.14
 */
function timeProximity(dateA, dateB) {
  if (!dateA || !dateB) return 0.5; // unknown dates → neutral
  const days = daysBetween(dateA, dateB);
  return Math.exp(-days / TIME_DECAY_TAU);
}

/**
 * Get the primary actor attribution from an item.
 * Returns { actorId, confidence } or null.
 */
function getPrimaryAttribution(item) {
  // Support both actor_attribution (enriched) and legacy threat_actor string
  if (item.actor_attribution && item.actor_attribution.primary_actor_id) {
    return {
      actorId:    item.actor_attribution.primary_actor_id,
      confidence: item.actor_attribution.primary_confidence || 0,
    };
  }
  if (item.threat_actor_id) return { actorId: item.threat_actor_id, confidence: 0.75 };
  return null;
}

/* ═══════════════════════════════════════════════════════════════════════
   PHASE 2 HARDENING: WEIGHTED ITEM-TO-ITEM SIMILARITY
   Returns { score, signals, reasons }
═══════════════════════════════════════════════════════════════════════ */
/**
 * Compute weighted similarity between two intel items.
 *
 * Formula:
 *   cluster_score = (ioc_overlap*0.35) + (cve_match*0.25)
 *                 + (time_proximity*0.20) + (text_similarity*0.20)
 *
 * Actor-overlap bonus:
 *   Same actor (both conf ≥ 0.50) → ioc_overlap += 0.30 (implied infra)
 *
 * @returns {{ score: number, signals: Object, reasons: string[] }}
 */
function computeItemSimilarity(itemA, itemB) {
  const reasons = [];

  // ── Signal 1: IOC overlap (weight 0.35) ──────────────────────────────
  const iocA = extractIOCSet(itemA);
  const iocB = extractIOCSet(itemB);
  let iocOverlap = 0;
  if (iocA.size > 0 && iocB.size > 0) {
    iocOverlap = jaccardSimilarity(iocA, iocB);
  }

  // Actor-based IOC overlap bonus: same actor (both conf ≥ 0.50) = implied infra
  const attrA = getPrimaryAttribution(itemA);
  const attrB = getPrimaryAttribution(itemB);
  let actorBonusApplied = false;
  if (
    attrA && attrB &&
    attrA.actorId === attrB.actorId &&
    attrA.actorId !== null &&
    attrA.confidence >= 0.50 &&
    attrB.confidence >= 0.50
  ) {
    const prev = iocOverlap;
    iocOverlap = Math.min(1.0, iocOverlap + 0.30);
    actorBonusApplied = true;
    const actorName = (itemA.actor_attribution?.primary_actor) || attrA.actorId;
    reasons.push(`Shared actor ${actorName} (conf: ${attrA.confidence.toFixed(2)}) implies infrastructure overlap (+0.30 ioc_overlap, from ${prev.toFixed(2)} → ${iocOverlap.toFixed(2)})`);
  }

  if (iocOverlap > 0 && !actorBonusApplied) {
    const sharedCount = [...iocA].filter(v => iocB.has(v)).length;
    reasons.push(`${sharedCount} shared IOC(s) (Jaccard: ${iocOverlap.toFixed(3)})`);
  }

  // ── Signal 2: CVE match (weight 0.25) ────────────────────────────────
  const cveA = extractCVESet(itemA);
  const cveB = extractCVESet(itemB);
  let cveMatch = 0;
  if (cveA.size > 0 && cveB.size > 0) {
    cveMatch = jaccardSimilarity(cveA, cveB);
    if (cveMatch > 0) {
      const sharedCVEs = [...cveA].filter(c => cveB.has(c));
      reasons.push(`Shared CVE(s): ${sharedCVEs.join(', ')} (Jaccard: ${cveMatch.toFixed(3)})`);
    }
  }
  // Direct match: itemA.id === one of itemB's CVEs or vice versa
  const directCVEMatch = cveA.has(String(itemB.id || '')) || cveB.has(String(itemA.id || ''));
  if (directCVEMatch && cveMatch === 0) {
    cveMatch = 1.0;
    reasons.push(`Direct CVE ID match: ${itemA.id} ↔ ${itemB.id}`);
  }

  // ── Signal 3: Time proximity (weight 0.20) ───────────────────────────
  const dateA = itemA.pubDate || itemA.published || '';
  const dateB = itemB.pubDate || itemB.published || '';
  const timeSim = timeProximity(dateA, dateB);
  const daysApart = (dateA && dateB) ? daysBetween(dateA, dateB).toFixed(1) : 'unknown';
  reasons.push(`Temporal proximity: ${daysApart} days apart → time_weight = ${timeSim.toFixed(3)} (τ=7d decay)`);

  // ── Signal 4: Text similarity (weight 0.20) ──────────────────────────
  const textA = `${itemA.title || ''} ${itemA.desc || itemA.description || ''}`;
  const textB = `${itemB.title || ''} ${itemB.desc || itemB.description || ''}`;
  const kwSimRaw = jaccardSimilarity(keywordSet(textA), keywordSet(textB));
  const textSim  = kwSimRaw; // direct Jaccard — no threshold gate anymore
  if (textSim > 0) {
    reasons.push(`Keyword text similarity: ${textSim.toFixed(3)} (Jaccard on filtered tokens)`);
  }

  // ── Weighted composite ───────────────────────────────────────────────
  const score = Math.min(1.0,
    (iocOverlap * 0.35) +
    (cveMatch   * 0.25) +
    (timeSim    * 0.20) +
    (textSim    * 0.20)
  );

  const signals = {
    ioc_overlap:      Math.round(iocOverlap * 1000) / 1000,
    cve_match:        Math.round(cveMatch   * 1000) / 1000,
    time_proximity:   Math.round(timeSim    * 1000) / 1000,
    text_similarity:  Math.round(textSim    * 1000) / 1000,
    actor_bonus:      actorBonusApplied,
  };

  return { score: Math.round(score * 1000) / 1000, signals, reasons };
}

/* ═══════════════════════════════════════════════════════════════════════
   GREEDY SINGLE-PASS CLUSTERING (strict threshold = 0.60)
═══════════════════════════════════════════════════════════════════════ */
function clusterItems(items) {
  const clusters = [];

  for (const item of items) {
    let bestCluster  = null;
    let bestScore    = 0;
    let bestSignals  = null;
    let bestReasons  = null;

    for (const cluster of clusters) {
      // Compare against highest-priority item in the cluster (representative)
      const representative = cluster.items.reduce((best, i) =>
        (i.priority || i.priority_score || 0) > (best.priority || best.priority_score || 0) ? i : best,
        cluster.items[0]
      );

      const simResult = computeItemSimilarity(item, representative);

      if (simResult.score > bestScore && simResult.score >= CLUSTER_THRESHOLD) {
        bestScore   = simResult.score;
        bestCluster = cluster;
        bestSignals = simResult.signals;
        bestReasons = simResult.reasons;
      }
    }

    if (bestCluster) {
      bestCluster.items.push(item);
      bestCluster.total_similarity += bestScore;
      bestCluster.edge_signals.push({ item_id: item.id, score: bestScore, signals: bestSignals, reasons: bestReasons });
    } else {
      clusters.push({
        items:            [item],
        total_similarity: 1.0,
        edge_signals:     [],
      });
    }
  }

  return clusters;
}

/* ═══════════════════════════════════════════════════════════════════════
   CAMPAIGN METADATA BUILDERS
═══════════════════════════════════════════════════════════════════════ */
function campaignSeverity(items) {
  const maxScore      = Math.max(...items.map(i => i.priority || i.priority_score || 0));
  const hasKev        = items.some(i => i.cisaKev || i.cisa_kev);
  const hasRansomware = items.some(i => i.ransomware);
  const hasExploited  = items.some(i => i.exploited);

  if (maxScore >= 85 || (hasKev && hasRansomware))                    return 'CRITICAL';
  if (maxScore >= 65 || hasKev || (hasRansomware && hasExploited))    return 'HIGH';
  if (maxScore >= 45 || hasExploited)                                 return 'MEDIUM';
  return 'LOW';
}

const CAMPAIGN_NAME_PATTERNS = [
  [/papercut/i,     'PaperCut Exploitation Wave'],
  [/teamcity/i,     'JetBrains TeamCity Supply Chain Campaign'],
  [/simplehelp/i,   'SimpleHelp Privilege Escalation Campaign'],
  [/trueconf/i,     'TrueConf Server Exploitation Campaign'],
  [/adt/i,          'ADT Data Breach Campaign'],
  [/cisco.*ios/i,   'Cisco IOS XE Zero-Day Campaign'],
  [/moveit/i,       'MOVEit File Transfer Exploitation'],
  [/goanywhere/i,   'GoAnywhere MFT Exploitation'],
  [/ransomware/i,   'Multi-Vector Ransomware Campaign'],
  [/china.nexus/i,  'China-Nexus Covert Intrusion Campaign'],
  [/microsoft/i,    'Microsoft Ecosystem Targeting Campaign'],
  [/apache/i,       'Apache Vulnerability Exploitation Campaign'],
  [/cisco/i,        'Cisco Infrastructure Attack Campaign'],
  [/fortinet/i,     'Fortinet VPN Exploitation Campaign'],
  [/ivanti/i,       'Ivanti Gateway Exploitation Campaign'],
];

function buildCampaignName(items) {
  const allText = items.map(i =>
    `${i.vendor || ''} ${i.product || ''} ${i.title || ''} ${i.desc || ''}`
  ).join(' ');

  for (const [pattern, name] of CAMPAIGN_NAME_PATTERNS) {
    if (pattern.test(allText)) return name;
  }

  const top     = items.slice().sort((a, b) => (b.priority || b.priority_score || 0) - (a.priority || a.priority_score || 0))[0];
  const vendor  = (top.vendor  || '').split(/\s/)[0] || 'Multi-Vendor';
  const product = (top.product || '').split(/\s/)[0] || 'Platform';
  return `${vendor} ${product} Exploitation Campaign`;
}

function buildCampaignId(items) {
  const cves = [...new Set(
    items.flatMap(i => {
      const cv = [];
      if (String(i.id || '').startsWith('CVE-')) cv.push(i.id);
      return cv;
    })
  )].slice(0, 2);

  if (cves.length) {
    return `campaign:${cves[0].toLowerCase()}${cves.length > 1 ? '-and-' + cves[1].toLowerCase() : ''}`;
  }

  const key  = items.slice(0, 3).map(i => i.id).sort().join('|');
  const hash = crypto.createHash('md5').update(key).digest('hex').slice(0, 8);
  return `campaign:cluster-${hash}`;
}

/**
 * Build human-readable reasoning[] array for a campaign.
 * Explains WHY items were clustered together.
 */
function buildCampaignReasoning(items, edgeSignals, confidence) {
  const reasons = [];

  const cveIds    = [...new Set(items.flatMap(i => {
    const cv = [];
    if (String(i.id || '').startsWith('CVE-')) cv.push(i.id);
    (i.cves || []).forEach(c => cv.push(c));
    return cv;
  }))];
  const iocCount  = new Set(items.flatMap(i => (i.iocs || []).map(ioc => `${ioc.type}:${ioc.value}`))).size;
  const kevCount  = items.filter(i => i.cisaKev || i.cisa_kev).length;
  const exploited = items.filter(i => i.exploited).length;

  // Cluster composition
  reasons.push(`${items.length} intel item(s) clustered with composite confidence ${confidence.toFixed(3)}`);

  // CVE basis
  if (cveIds.length >= 2) {
    reasons.push(`${cveIds.length} related CVEs: ${cveIds.slice(0, 4).join(', ')}${cveIds.length > 4 ? '...' : ''}`);
  } else if (cveIds.length === 1) {
    reasons.push(`Single CVE basis: ${cveIds[0]}`);
  }

  // IOC basis
  if (iocCount > 0) {
    reasons.push(`${iocCount} shared IOC(s) across items`);
  }

  // KEV + exploitation
  if (kevCount > 0 && exploited > 0) {
    reasons.push(`${kevCount} CISA KEV item(s), ${exploited} confirmed exploited — elevated campaign priority`);
  } else if (kevCount > 0) {
    reasons.push(`${kevCount} item(s) on CISA Known Exploited Vulnerabilities list`);
  } else if (exploited > 0) {
    reasons.push(`${exploited} item(s) confirmed exploited in the wild`);
  }

  // Edge signal summaries (top 3)
  const topEdges = edgeSignals.slice(0, 3);
  for (const edge of topEdges) {
    if (edge.reasons && edge.reasons.length > 0) {
      const dominant = edge.reasons[0];
      reasons.push(`Item ${edge.item_id} joined cluster (score: ${edge.score.toFixed(3)}): ${dominant}`);
    }
  }

  // Actor-overlap bonus mention
  if (edgeSignals.some(e => e.signals && e.signals.actor_bonus)) {
    reasons.push('Actor-based infrastructure overlap bonus applied (same attributed actor ≥0.50 confidence)');
  }

  return reasons;
}

/* ═══════════════════════════════════════════════════════════════════════
   MAIN BUILDER — called from enrichment pipeline
═══════════════════════════════════════════════════════════════════════ */
function buildCampaigns(intelItems) {
  if (!intelItems || intelItems.length === 0) return [];

  // Sort by priority descending — higher-value items cluster first
  const sorted = intelItems.slice().sort((a, b) =>
    (b.priority || b.priority_score || 0) - (a.priority || a.priority_score || 0)
  );

  const clusters = clusterItems(sorted);

  return clusters
    .filter(c =>
      c.items.length >= 2 ||
      (c.items.length === 1 && (c.items[0].priority || c.items[0].priority_score || 0) >= MIN_CLUSTER_SCORE)
    )
    .map(cluster => {
      const { items, total_similarity, edge_signals } = cluster;

      const allIOCValues = [...new Set(
        items.flatMap(i => (i.iocs || [])
          .filter(ioc => ioc && ioc.value && ioc.type !== 'url')
          .map(ioc => `${ioc.type}:${ioc.value}`)
        )
      )].slice(0, 25);

      const allCVEs = [...new Set(
        items.flatMap(i => {
          const cv = [];
          if (String(i.id || '').startsWith('CVE-')) cv.push(i.id);
          (i.cves || []).forEach(c => cv.push(c));
          return cv;
        })
      )];

      const dates = items
        .map(i => i.pubDate || i.published)
        .filter(Boolean)
        .sort();

      const campaignId = buildCampaignId(items);

      // Confidence formula: scaled by cluster size and average inter-item similarity
      const avgSim = items.length >= 2 ? total_similarity / items.length : 1.0;
      const confidence = Math.min(0.97, Math.max(0.50,
        items.length >= 3
          ? 0.65 + avgSim * 0.32
          : 0.55 + avgSim * 0.35
      ));
      const confRounded = Math.round(confidence * 100) / 100;

      // Build reasoning array
      const reasoning = buildCampaignReasoning(items, edge_signals, confRounded);

      // Collect actor attributions from enriched items
      const actorMap = new Map();
      for (const item of items) {
        const attr = item.actor_attribution;
        if (attr && attr.primary_actor_id && !attr.unattributed) {
          if (!actorMap.has(attr.primary_actor_id)) {
            actorMap.set(attr.primary_actor_id, {
              id:         attr.primary_actor_id,
              name:       attr.primary_actor,
              confidence: attr.primary_confidence,
              category:   item._actorCategory || 'unknown',
            });
          }
        }
      }
      const threatActors = [...actorMap.values()];

      return {
        campaign_id:        campaignId,
        name:               buildCampaignName(items),
        severity:           campaignSeverity(items),
        confidence:         confRounded,
        item_count:         items.length,
        ioc_count:          allIOCValues.length,
        first_seen:         dates[0]              || new Date().toISOString().slice(0, 10),
        last_seen:          dates[dates.length - 1] || new Date().toISOString().slice(0, 10),
        related_intel_ids:  items.map(i => i.id),
        related_intel: items.map(i => ({
          id:             i.id,
          title:          i.title,
          type:           i.type,
          priority_score: i.priority || i.priority_score || 0,
          published:      i.pubDate || i.published,
          exploited:      !!(i.exploited),
          cisa_kev:       !!(i.cisaKev || i.cisa_kev),
        })),
        shared_iocs:        allIOCValues,
        shared_cves:        allCVEs,
        threat_actor:       threatActors.length > 0 ? threatActors[0].name : null,
        threat_actors:      threatActors,
        max_priority_score: Math.max(...items.map(i => i.priority || i.priority_score || 0)),
        has_kev:            items.some(i => i.cisaKev || i.cisa_kev),
        has_ransomware:     items.some(i => i.ransomware),
        has_exploited:      items.some(i => i.exploited),
        reasoning,
        clustering_model:   'weighted_v2',
      };
    })
    .sort((a, b) => {
      const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const sevDiff  = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      return sevDiff !== 0 ? sevDiff : b.item_count - a.item_count;
    });
}

/**
 * Link actors from graph to campaigns.
 * Enriches campaigns' threat_actors[] from graph edges.
 */
function linkActorsToCampaigns(graph, campaigns) {
  if (!graph || !campaigns) return campaigns;

  for (const campaign of campaigns) {
    const campaignNode = (graph.nodes || {})[campaign.campaign_id];
    if (!campaignNode) continue;

    const actorEdges = (graph.edges || []).filter(e =>
      (e.target === campaign.campaign_id || e.source === campaign.campaign_id) &&
      (e.relationship === 'executes' || e.relationship === 'associated_with' || e.relationship === 'attributed_to')
    );

    for (const edge of actorEdges) {
      const actorId   = edge.source === campaign.campaign_id ? edge.target : edge.source;
      const actorNode = (graph.nodes || {})[actorId];
      if (!actorNode || actorNode.type !== 'ThreatActor') continue;

      const alreadyPresent = campaign.threat_actors.some(a => a.id === actorId);
      if (!alreadyPresent) {
        campaign.threat_actors.push({
          id:         actorId,
          name:       actorNode.name,
          confidence: edge.confidence || 0.75,
          category:   actorNode.attributes?.category || 'unknown',
        });
      }
    }

    if (campaign.threat_actors.length > 0) {
      // Primary actor = highest-confidence
      campaign.threat_actors.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
      campaign.threat_actor = campaign.threat_actors[0].name;
    }
  }

  return campaigns;
}

module.exports = {
  buildCampaigns,
  linkActorsToCampaigns,
  loadCampaigns,
  saveCampaigns,
  mergeCampaign,
  mergeCampaigns,
  reconstructCampaignsFromGraph,
  severityFromFlags,
  computeItemSimilarity,
  jaccardSimilarity,
  campaignSeverity,
  timeProximity,
  daysBetween,
};
