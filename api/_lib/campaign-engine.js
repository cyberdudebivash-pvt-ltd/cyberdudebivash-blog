/**
 * SENTINEL APEX — Campaign Clustering Engine v1.0
 * Phase 2: Groups related intel items into threat campaigns.
 *
 * Clustering signals (all data-driven — no random grouping):
 *   1. Shared IOCs (Jaccard similarity ≥ 0.15)
 *   2. Shared CVE IDs
 *   3. Keyword overlap in title/description (Jaccard ≥ 0.20)
 *   4. Temporal proximity (within 30-day window)
 *   5. Same ransomware flag + vendor pattern
 *
 * Output: { campaign_id, name, related_intel_ids[], shared_iocs[],
 *           shared_cves[], threat_actors[], first_seen, last_seen,
 *           severity, confidence }
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const CAMPAIGNS_PATH = path.resolve(__dirname, '../../api/intel/campaigns.json');
const CAMPAIGNS_CACHE_TTL = 120000;
let _campaignsCache = null;
let _campaignsCacheTime = 0;

/* ─── TUNING CONSTANTS ───────────────────────────────────────────────── */
const TIME_WINDOW_DAYS      = 30;   // max days apart to be in same campaign
const IOC_SIM_THRESHOLD     = 0.15; // Jaccard threshold for IOC set similarity
const KEYWORD_SIM_THRESHOLD = 0.20; // Jaccard threshold for keyword similarity
const CLUSTER_THRESHOLD     = 0.22; // min composite score to join existing cluster
const MIN_CLUSTER_SCORE     = 60;   // min priority_score to create single-item campaign

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

function saveCampaigns(data) {
  data.generated = new Date().toISOString();
  data.version   = '1.0';
  data.platform  = 'CYBERDUDEBIVASH SENTINEL APEX v4.0';
  try {
    fs.writeFileSync(CAMPAIGNS_PATH, JSON.stringify(data, null, 2), 'utf8');
    _campaignsCache     = data;
    _campaignsCacheTime = Date.now();
    console.log(`[CAMPAIGNS] Saved: ${data.campaigns.length} campaigns`);
  } catch (e) { console.error(`[CAMPAIGNS] Save failed: ${e.message}`); }
}

/* ═══════════════════════════════════════════════════════════════════════
   SIMILARITY FUNCTIONS
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
      .filter(ioc => ioc && ioc.value && ioc.type !== 'url') // skip URLs (too noisy)
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

/* ═══════════════════════════════════════════════════════════════════════
   ITEM-TO-ITEM SIMILARITY (composite score 0.0–1.0)
═══════════════════════════════════════════════════════════════════════ */
function computeItemSimilarity(itemA, itemB) {
  const dateA = itemA.pubDate || itemA.published || '';
  const dateB = itemB.pubDate || itemB.published || '';

  // Hard cutoff: items too far apart cannot be the same campaign
  if (dateA && dateB) {
    const diff = daysBetween(dateA, dateB);
    if (diff > TIME_WINDOW_DAYS) return 0;
  }

  let score = 0;

  // 1. IOC overlap (weight 0.40) — strongest signal
  const iocA = extractIOCSet(itemA);
  const iocB = extractIOCSet(itemB);
  if (iocA.size > 0 && iocB.size > 0) {
    const iocSim = jaccardSimilarity(iocA, iocB);
    if (iocSim >= IOC_SIM_THRESHOLD) score += iocSim * 0.40;
  }

  // 2. CVE overlap (weight 0.30) — strong structural signal
  const cveA = extractCVESet(itemA);
  const cveB = extractCVESet(itemB);
  if (cveA.size > 0 && cveB.size > 0) {
    const cveSim = jaccardSimilarity(cveA, cveB);
    if (cveSim > 0) score += cveSim * 0.30;
  }

  // 3. Same vendor + ransomware flag (weight 0.15)
  const sameVendor    = itemA.vendor && itemB.vendor && itemA.vendor.toLowerCase() === itemB.vendor.toLowerCase();
  const bothRansomware = (itemA.ransomware || itemA.type === 'RANSOMWARE') && (itemB.ransomware || itemB.type === 'RANSOMWARE');
  if (sameVendor)      score += 0.10;
  if (bothRansomware)  score += 0.05;

  // 4. Keyword similarity in title + description (weight 0.15)
  const textA = `${itemA.title || ''} ${itemA.desc || itemA.description || ''}`;
  const textB = `${itemB.title || ''} ${itemB.desc || itemB.description || ''}`;
  const kwSim = jaccardSimilarity(keywordSet(textA), keywordSet(textB));
  if (kwSim >= KEYWORD_SIM_THRESHOLD) score += kwSim * 0.15;

  // 5. Temporal proximity bonus (weight 0.10)
  if (dateA && dateB) {
    const diff = daysBetween(dateA, dateB);
    score += Math.max(0, (1 - diff / TIME_WINDOW_DAYS)) * 0.10;
  }

  return Math.min(1.0, score);
}

/* ═══════════════════════════════════════════════════════════════════════
   GREEDY SINGLE-PASS CLUSTERING
═══════════════════════════════════════════════════════════════════════ */
function clusterItems(items) {
  const clusters = [];

  for (const item of items) {
    let bestCluster = null;
    let bestScore   = 0;

    for (const cluster of clusters) {
      // Compare against the highest-priority item in the cluster
      const representative = cluster.items.reduce((best, i) =>
        (i.priority || 0) > (best.priority || 0) ? i : best, cluster.items[0]);
      const sim = computeItemSimilarity(item, representative);

      if (sim > bestScore && sim >= CLUSTER_THRESHOLD) {
        bestScore   = sim;
        bestCluster = cluster;
      }
    }

    if (bestCluster) {
      bestCluster.items.push(item);
      bestCluster.total_similarity += bestScore;
    } else {
      clusters.push({ items: [item], total_similarity: 1.0 });
    }
  }

  return clusters;
}

/* ═══════════════════════════════════════════════════════════════════════
   CAMPAIGN METADATA BUILDERS
═══════════════════════════════════════════════════════════════════════ */
function campaignSeverity(items) {
  const maxScore    = Math.max(...items.map(i => i.priority || i.priority_score || 0));
  const hasKev      = items.some(i => i.cisaKev || i.cisa_kev);
  const hasRansomware = items.some(i => i.ransomware);
  const hasExploited  = items.some(i => i.exploited);

  if (maxScore >= 85 || (hasKev && hasRansomware))        return 'CRITICAL';
  if (maxScore >= 65 || hasKev || (hasRansomware && hasExploited)) return 'HIGH';
  if (maxScore >= 45 || hasExploited)                     return 'MEDIUM';
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

  // Fallback: top-priority item's vendor + product
  const top     = items.slice().sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];
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

  // Hash-based deterministic ID
  const key  = items.slice(0, 3).map(i => i.id).sort().join('|');
  const hash = crypto.createHash('md5').update(key).digest('hex').slice(0, 8);
  return `campaign:cluster-${hash}`;
}

/* ═══════════════════════════════════════════════════════════════════════
   MAIN BUILDER — called from enrichment pipeline
═══════════════════════════════════════════════════════════════════════ */
function buildCampaigns(intelItems) {
  if (!intelItems || intelItems.length === 0) return [];

  // Sort by priority descending — higher-value items cluster first
  const sorted = intelItems.slice().sort((a, b) => (b.priority || 0) - (a.priority || 0));

  const clusters = clusterItems(sorted);

  return clusters
    .filter(c =>
      c.items.length >= 2 ||
      (c.items.length === 1 && (c.items[0].priority || c.items[0].priority_score || 0) >= MIN_CLUSTER_SCORE)
    )
    .map(cluster => {
      const { items, total_similarity } = cluster;

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
      const confidence = items.length >= 3
        ? Math.min(0.97, 0.6 + (total_similarity / items.length) * 0.35)
        : Math.min(0.90, total_similarity / items.length);

      return {
        campaign_id:       campaignId,
        name:              buildCampaignName(items),
        severity:          campaignSeverity(items),
        confidence:        Math.round(confidence * 100) / 100,
        item_count:        items.length,
        ioc_count:         allIOCValues.length,
        first_seen:        dates[0]             || new Date().toISOString().slice(0, 10),
        last_seen:         dates[dates.length - 1] || new Date().toISOString().slice(0, 10),
        related_intel_ids: items.map(i => i.id),
        related_intel: items.map(i => ({
          id:            i.id,
          title:         i.title,
          type:          i.type,
          priority_score: i.priority || i.priority_score || 0,
          published:     i.pubDate || i.published,
          exploited:     !!(i.exploited),
          cisa_kev:      !!(i.cisaKev || i.cisa_kev),
        })),
        shared_iocs:       allIOCValues,
        shared_cves:       allCVEs,
        threat_actor:      null,  // filled by enrichment-pipeline using graph
        threat_actors:     [],    // filled by enrichment-pipeline using graph
        max_priority_score: Math.max(...items.map(i => i.priority || i.priority_score || 0)),
        has_kev:           items.some(i => i.cisaKev || i.cisa_kev),
        has_ransomware:    items.some(i => i.ransomware),
        has_exploited:     items.some(i => i.exploited),
      };
    })
    .sort((a, b) => {
      // Sort campaigns: CRITICAL first, then by item count
      const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const sevDiff = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      return sevDiff !== 0 ? sevDiff : b.item_count - a.item_count;
    });
}

module.exports = {
  buildCampaigns,
  loadCampaigns,
  saveCampaigns,
  computeItemSimilarity,
  jaccardSimilarity,
  campaignSeverity,
};
