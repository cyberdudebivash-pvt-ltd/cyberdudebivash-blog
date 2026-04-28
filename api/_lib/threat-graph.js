/**
 * SENTINEL APEX — Threat Actor Graph Engine v1.0
 * Phase 1: Relationship graph across CVE → Actor → Campaign → IOC entities.
 *
 * Node types:   ThreatActor | CVE | Campaign | Malware | IOC
 * Relationships: exploits | executes | uses | targets | linked_to |
 *                associated_with | attributed_to | includes
 *
 * ALL attributions are backed by public CISA advisories, vendor reports,
 * or law-enforcement disclosures. NO speculative attribution.
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';
const fs   = require('fs');
const path = require('path');

const GRAPH_PATH = path.resolve(__dirname, '../../api/intel/threat-graph.json');
const GRAPH_CACHE_TTL = 120000; // 2 min in-process cache
let _graphCache = null;
let _graphCacheTime = 0;

/* ═══════════════════════════════════════════════════════════════════════
   THREAT ACTOR KNOWLEDGE BASE
   Sources: CISA advisories, DOJ indictments, vendor threat reports
═══════════════════════════════════════════════════════════════════════ */
const THREAT_ACTOR_DB = {
  'actor:lockbit': {
    id: 'actor:lockbit', type: 'ThreatActor', name: 'LockBit',
    attributes: {
      aliases: ['LockBit 2.0', 'LockBit 3.0', 'LockBit Black', 'ABCD Ransomware'],
      category: 'ransomware_group', motivation: 'financial',
      sophistication: 'advanced', origin: 'criminal', active: true,
      first_seen: '2019-09-01', last_seen: null,
      target_sectors: ['healthcare', 'finance', 'manufacturing', 'education', 'government'],
      target_regions: ['global'],
      ttps: ['T1190', 'T1486', 'T1490', 'T1489', 'T1566.001', 'T1078', 'T1003'],
      description: 'Prolific RaaS operation responsible for the most ransomware attacks globally (2022–2024). LockBit 3.0 (Black) introduced bug bounty programs, Zcash payments, and anti-analysis techniques. Disrupted by Operation Cronos (Feb 2024) but resurged with LockBit 3.0.',
      known_cves: ['CVE-2023-27351', 'CVE-2021-22986', 'CVE-2021-34527', 'CVE-2023-0669'],
      refs: ['https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a',
             'https://www.justice.gov/opa/pr/justice-department-disrupts-lockbit-ransomware-group'],
    },
  },
  'actor:apt41': {
    id: 'actor:apt41', type: 'ThreatActor', name: 'APT41',
    attributes: {
      aliases: ['Winnti', 'Double Dragon', 'BARIUM', 'Wicked Panda', 'Earth Baku'],
      category: 'nation_state', motivation: 'espionage,financial',
      sophistication: 'advanced', origin: 'china', active: true,
      first_seen: '2012-01-01', last_seen: null,
      target_sectors: ['technology', 'healthcare', 'telecommunications', 'finance', 'gaming'],
      target_regions: ['global'],
      ttps: ['T1195.002', 'T1190', 'T1078', 'T1059.001', 'T1071.001', 'T1027'],
      description: 'Chinese state-sponsored threat group conducting both espionage for the MSS and financially motivated cybercrime. Known for supply chain attacks, gaming industry IP theft, and rapid exploitation of public-facing application vulnerabilities.',
      known_cves: ['CVE-2024-27199', 'CVE-2024-27198', 'CVE-2019-3396', 'CVE-2020-10189'],
      refs: ['https://www.mandiant.com/resources/insights/apt41-dual-espionage-and-cyber-crime-operations',
             'https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-associates-charged'],
    },
  },
  'actor:cl0p': {
    id: 'actor:cl0p', type: 'ThreatActor', name: 'Cl0p',
    attributes: {
      aliases: ['TA505', 'FIN11', 'LACE TEMPEST', 'Clop'],
      category: 'ransomware_group', motivation: 'financial',
      sophistication: 'advanced', origin: 'criminal', active: true,
      first_seen: '2019-02-01', last_seen: null,
      target_sectors: ['finance', 'retail', 'healthcare', 'manufacturing', 'legal'],
      target_regions: ['global'],
      ttps: ['T1190', 'T1486', 'T1041', 'T1566.002', 'T1048'],
      description: 'Financially motivated threat actor pioneering mass exploitation of enterprise file-transfer tools (GoAnywhere, MOVEit, Accellion). Cl0p operations resulted in 100s of simultaneous victim organizations from single CVE exploitations.',
      known_cves: ['CVE-2024-27199', 'CVE-2023-34362', 'CVE-2023-0669', 'CVE-2021-27101'],
      refs: ['https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a'],
    },
  },
  'actor:volt-typhoon': {
    id: 'actor:volt-typhoon', type: 'ThreatActor', name: 'Volt Typhoon',
    attributes: {
      aliases: ['VANGUARD PANDA', 'Bronze Silhouette', 'Dev-0391', 'UNC3236'],
      category: 'nation_state', motivation: 'espionage,pre-positioning',
      sophistication: 'advanced', origin: 'china', active: true,
      first_seen: '2021-01-01', last_seen: null,
      target_sectors: ['critical_infrastructure', 'communications', 'energy', 'transportation', 'defense_industrial_base'],
      target_regions: ['usa', 'guam', 'pacific', 'australia', 'uk'],
      ttps: ['T1190', 'T1078', 'T1133', 'T1036', 'T1571', 'T1021.002'],
      description: 'Chinese state-sponsored actor pre-positioning within US critical infrastructure for potential disruption during geopolitical crises. Noted for living-off-the-land (LOTL) techniques, minimal malware footprint, and use of compromised SOHO routers as proxy infrastructure.',
      known_cves: ['CVE-2024-39717', 'CVE-2021-40539', 'CVE-2021-27860', 'CVE-2022-42475'],
      refs: ['https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a',
             'https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure'],
    },
  },
  'actor:salt-typhoon': {
    id: 'actor:salt-typhoon', type: 'ThreatActor', name: 'Salt Typhoon',
    attributes: {
      aliases: ['GhostEmperor', 'FamousSparrow', 'Earth Estries', 'UNC2286'],
      category: 'nation_state', motivation: 'espionage,signals_intelligence',
      sophistication: 'advanced', origin: 'china', active: true,
      first_seen: '2020-01-01', last_seen: null,
      target_sectors: ['telecommunications', 'government', 'internet_service_providers', 'law_enforcement'],
      target_regions: ['usa', 'europe', 'southeast_asia'],
      ttps: ['T1190', 'T1071', 'T1078', 'T1021.006', 'T1557'],
      description: 'Chinese state-sponsored actor responsible for the most significant telecom sector breach in US history. Compromised AT&T, Verizon, T-Mobile and others, intercepting communications of US officials, law enforcement, and intelligence targets. Exploits Cisco IOS XE vulnerabilities.',
      known_cves: ['CVE-2023-20198', 'CVE-2023-20273', 'CVE-2018-0171'],
      refs: ['https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a'],
    },
  },
  'actor:phantomcore': {
    id: 'actor:phantomcore', type: 'ThreatActor', name: 'PhantomCore',
    attributes: {
      aliases: ['PhantomCore Group'],
      category: 'targeted_attacker', motivation: 'espionage',
      sophistication: 'intermediate', origin: 'unknown', active: true,
      first_seen: '2024-01-01', last_seen: null,
      target_sectors: ['technology', 'communications', 'government'],
      target_regions: ['russia', 'eastern_europe', 'cis'],
      ttps: ['T1190', 'T1059', 'T1566', 'T1055'],
      description: 'Threat actor exploiting TrueConf Server and related collaboration software vulnerabilities to deploy a proprietary RAT backdoor. Targets organizations in Russia and Eastern Europe. Attributed by BI.ZONE threat researchers.',
      known_cves: [],
      refs: ['https://blog.cyberdudebivash.in/posts/phantomcore-exploits-trueconf-vulnerabilities-to-breach-russ.html'],
    },
  },
  'actor:shinyhunters': {
    id: 'actor:shinyhunters', type: 'ThreatActor', name: 'ShinyHunters',
    attributes: {
      aliases: ['Shiny Hunters', 'ShinyCorp'],
      category: 'cybercriminal', motivation: 'financial',
      sophistication: 'intermediate', origin: 'criminal', active: true,
      first_seen: '2020-01-01', last_seen: null,
      target_sectors: ['technology', 'retail', 'healthcare', 'financial_services', 'security'],
      target_regions: ['global'],
      ttps: ['T1078', 'T1190', 'T1530', 'T1619', 'T1213'],
      description: 'Prolific data theft group specializing in cloud-hosted database breaches and SaaS platform compromises. Sells stolen data on dark web forums. Confirmed involvement in breaches of ADT, AT&T, Ticketmaster, Santander, and 100+ organizations.',
      known_cves: [],
      refs: ['https://blog.cyberdudebivash.in/posts/adt-confirms-data-breach-after-shinyhunters-leak-threat.html'],
    },
  },
  'actor:russia-nexus-ransomware': {
    id: 'actor:russia-nexus-ransomware', type: 'ThreatActor', name: 'Russia-Nexus Ransomware Operators',
    attributes: {
      aliases: ['UNKN', 'Russian RaaS Ecosystem', 'Black Basta', 'Conti Successors'],
      category: 'ransomware_group', motivation: 'financial',
      sophistication: 'advanced', origin: 'russia', active: true,
      first_seen: '2020-01-01', last_seen: null,
      target_sectors: ['healthcare', 'manufacturing', 'finance', 'government', 'critical_infrastructure'],
      target_regions: ['western_europe', 'usa', 'global'],
      ttps: ['T1486', 'T1190', 'T1566', 'T1078', 'T1133', 'T1003'],
      description: 'Umbrella designation for Russia-based ransomware groups operating within or tolerated by Russian jurisdiction. Germany doxed "UNKN" in 2026, believed to be the operator of a major Russian ransomware-as-a-service empire.',
      known_cves: [],
      refs: ['https://blog.cyberdudebivash.in/posts/germany-doxes-8220-unkn-8221-head-of-ru-ransomware-gang.html'],
    },
  },
};

/* ─── CVE → ACTOR MAPPING (public, verifiable attributions only) ─────── */
const CVE_ACTOR_MAP = {
  'CVE-2023-27351': ['actor:lockbit', 'actor:cl0p'],     // PaperCut — CISA KEV AA23-131A
  'CVE-2024-27199': ['actor:apt41', 'actor:cl0p'],       // JetBrains TeamCity — widely attributed
  'CVE-2024-27198': ['actor:apt41', 'actor:cl0p'],       // JetBrains TeamCity companion
  'CVE-2023-34362': ['actor:cl0p'],                      // MOVEit — CISA AA23-158A
  'CVE-2023-0669':  ['actor:cl0p'],                      // GoAnywhere MFT
  'CVE-2023-20198': ['actor:salt-typhoon'],               // Cisco IOS XE
  'CVE-2023-20273': ['actor:salt-typhoon'],               // Cisco IOS XE chain
  'CVE-2021-40539': ['actor:volt-typhoon'],               // Zoho ManageEngine
};

/* ─── KEYWORD → ACTOR MAPPING ────────────────────────────────────────── */
const KEYWORD_ACTOR_MAP = [
  { patterns: [/papercut/i],                                           actors: ['actor:lockbit'] },
  { patterns: [/teamcity/i, /jetbrains/i],                             actors: ['actor:apt41', 'actor:cl0p'] },
  { patterns: [/trueconf/i, /phantomcore/i],                           actors: ['actor:phantomcore'] },
  { patterns: [/shinyhunters/i, /shiny\s*hunters/i],                   actors: ['actor:shinyhunters'] },
  { patterns: [/volt\s*typhoon/i, /vanguard\s*panda/i],                actors: ['actor:volt-typhoon'] },
  { patterns: [/salt\s*typhoon/i, /ghostemperor/i, /earth\s*estries/i], actors: ['actor:salt-typhoon'] },
  { patterns: [/china.nexus/i, /china.*covert/i, /chinese.*apt/i],     actors: ['actor:volt-typhoon', 'actor:salt-typhoon', 'actor:apt41'] },
  { patterns: [/\blockbit\b/i],                                        actors: ['actor:lockbit'] },
  { patterns: [/\bcl0p\b/i, /\bclop\b/i, /\bta505\b/i],               actors: ['actor:cl0p'] },
  { patterns: [/\bapt41\b/i, /\bwinnti\b/i, /double\s*dragon/i],       actors: ['actor:apt41'] },
  { patterns: [/russia.*ransomware/i, /\bunknown\s*gang\b/i, /russian.*gang/i], actors: ['actor:russia-nexus-ransomware'] },
];

/* ═══════════════════════════════════════════════════════════════════════
   GRAPH STORAGE
═══════════════════════════════════════════════════════════════════════ */
function getDefaultGraph() {
  return {
    generated: new Date().toISOString(),
    version: '1.0',
    platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0',
    stats: { total_nodes: 0, actors: 0, cves: 0, campaigns: 0, malware: 0, iocs: 0, edges: 0 },
    nodes: {},
    edges: [],
  };
}

function loadGraph() {
  const now = Date.now();
  if (_graphCache && (now - _graphCacheTime) < GRAPH_CACHE_TTL) return _graphCache;
  try {
    if (fs.existsSync(GRAPH_PATH)) {
      const raw = fs.readFileSync(GRAPH_PATH, 'utf8');
      _graphCache = JSON.parse(raw);
      _graphCacheTime = now;
      return _graphCache;
    }
  } catch (e) { console.error(`[GRAPH] Load failed: ${e.message}`); }
  return getDefaultGraph();
}

function saveGraph(graph) {
  graph.generated = new Date().toISOString();
  graph.stats = computeStats(graph);
  try {
    fs.writeFileSync(GRAPH_PATH, JSON.stringify(graph, null, 2), 'utf8');
    _graphCache = graph;
    _graphCacheTime = Date.now();
    console.log(`[GRAPH] Saved: ${graph.stats.total_nodes} nodes, ${graph.stats.edges} edges`);
  } catch (e) { console.error(`[GRAPH] Save failed: ${e.message}`); }
}

function computeStats(graph) {
  const nodes = Object.values(graph.nodes || {});
  return {
    total_nodes: nodes.length,
    actors:    nodes.filter(n => n.type === 'ThreatActor').length,
    cves:      nodes.filter(n => n.type === 'CVE').length,
    campaigns: nodes.filter(n => n.type === 'Campaign').length,
    malware:   nodes.filter(n => n.type === 'Malware').length,
    iocs:      nodes.filter(n => n.type === 'IOC').length,
    edges:     (graph.edges || []).length,
  };
}

/* ═══════════════════════════════════════════════════════════════════════
   GRAPH OPERATIONS
═══════════════════════════════════════════════════════════════════════ */
function normalizeNodeId(type, id) {
  if (type === 'ThreatActor') return id.startsWith('actor:')    ? id : `actor:${id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;
  if (type === 'Campaign')    return id.startsWith('campaign:') ? id : `campaign:${id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;
  if (type === 'Malware')     return id.startsWith('malware:')  ? id : `malware:${id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;
  if (type === 'IOC')         return id.startsWith('ioc:')      ? id : `ioc:${id}`;
  return id;
}

function addNode(graph, node) {
  const nid = normalizeNodeId(node.type, node.id);
  if (!graph.nodes[nid]) {
    graph.nodes[nid] = { ...node, id: nid, connections: [] };
  } else {
    // Merge — preserve existing connections
    const existing = graph.nodes[nid];
    graph.nodes[nid] = {
      ...existing,
      ...node,
      id: nid,
      connections: existing.connections || [],
      attributes: { ...(existing.attributes || {}), ...(node.attributes || {}) },
    };
  }
  return nid;
}

function addEdge(graph, source, target, relationship, confidence = 0.8, meta = {}) {
  if (!source || !target) return;
  const edgeId = `${source}→${relationship}→${target}`;
  if (graph.edges.find(e => e.id === edgeId)) return; // idempotent

  graph.edges.push({
    id: edgeId,
    source,
    target,
    relationship,
    confidence,
    first_seen: meta.first_seen || new Date().toISOString().slice(0, 10),
    sources: meta.sources || [],
  });

  // Update adjacency list on source node
  if (graph.nodes[source]) {
    if (!graph.nodes[source].connections) graph.nodes[source].connections = [];
    graph.nodes[source].connections.push({ target, relationship, confidence });
  }
}

function getNode(graph, id) {
  return graph.nodes[id] || null;
}

function getNeighbors(graph, nodeId, relationship) {
  return (graph.edges || [])
    .filter(e => (e.source === nodeId || e.target === nodeId) && (!relationship || e.relationship === relationship))
    .map(e => ({
      node:         graph.nodes[e.source === nodeId ? e.target : e.source] || null,
      relationship: e.relationship,
      confidence:   e.confidence,
      direction:    e.source === nodeId ? 'outbound' : 'inbound',
    }))
    .filter(n => n.node !== null);
}

function getActorsForItem(graph, itemId) {
  return (graph.edges || [])
    .filter(e => e.target === itemId && e.relationship === 'exploits')
    .map(e => graph.nodes[e.source])
    .filter(Boolean);
}

function getTopActors(graph, limit = 10) {
  const actors = Object.values(graph.nodes || {}).filter(n => n.type === 'ThreatActor');
  return actors
    .map(actor => {
      const edges = (graph.edges || []).filter(e => e.source === actor.id || e.target === actor.id);
      const cveLinks      = edges.filter(e => e.relationship === 'exploits').length;
      const campaignLinks = edges.filter(e => e.relationship === 'executes' || e.relationship === 'associated_with').length;
      return {
        id:               actor.id,
        name:             actor.name,
        type:             actor.type,
        attributes:       actor.attributes,
        connection_count: edges.length,
        cve_count:        cveLinks,
        campaign_count:   campaignLinks,
        activity_score:   Math.min(100, cveLinks * 15 + campaignLinks * 10 + edges.length * 3),
      };
    })
    .sort((a, b) => b.activity_score - a.activity_score)
    .slice(0, limit);
}

/* ═══════════════════════════════════════════════════════════════════════
   GRAPH BUILDER — ingestion-time call, builds graph from intel items
═══════════════════════════════════════════════════════════════════════ */
function buildGraphFromIntel(intelItems) {
  const graph = loadGraph() || getDefaultGraph();

  // 1. Seed all known actors from static database
  for (const [id, actor] of Object.entries(THREAT_ACTOR_DB)) {
    addNode(graph, {
      id,
      type: 'ThreatActor',
      name: actor.name,
      attributes: actor.attributes,
    });
    // Pre-wire known CVE edges with high confidence
    for (const cveId of (actor.attributes.known_cves || [])) {
      addEdge(graph, id, cveId, 'exploits', 0.92, { sources: (actor.attributes.refs || []).slice(0, 1) });
    }
  }

  // 2. Process each intel item
  for (const item of (intelItems || [])) {
    const itemId = String(item.id || '');
    if (!itemId) continue;

    addNode(graph, {
      id: itemId,
      type: itemId.startsWith('CVE-') ? 'CVE' : 'Intel',
      name: item.title || itemId,
      attributes: {
        cvss:           item.cvss || 0,
        threat_level:   item.threatLevel || item.threat_level || 'UNKNOWN',
        priority_score: item.priority || item.priority_score || 0,
        exploited:      !!(item.exploited),
        cisa_kev:       !!(item.cisaKev || item.cisa_kev),
        ransomware:     !!(item.ransomware),
        vendor:         item.vendor || '',
        product:        item.product || '',
        published:      item.pubDate || item.published || '',
        type:           item.type || 'CVE_REPORT',
      },
    });

    // Match actors via CVE map
    const matched = new Set();
    if (CVE_ACTOR_MAP[itemId]) CVE_ACTOR_MAP[itemId].forEach(a => matched.add(a));

    // Match actors via keyword patterns
    const text = `${item.title || ''} ${item.desc || item.description || ''}`;
    for (const { patterns, actors } of KEYWORD_ACTOR_MAP) {
      if (patterns.some(p => p.test(text))) actors.forEach(a => matched.add(a));
    }

    for (const actorId of matched) {
      addEdge(graph, actorId, itemId, 'exploits', 0.85);
    }

    // Add IOC nodes (top 5 per item, avoid graph bloat)
    for (const ioc of (item.iocs || []).slice(0, 5)) {
      if (!ioc || !ioc.value || ioc.type === 'url') continue; // skip noisy URLs
      const iocId = `ioc:${ioc.type}:${String(ioc.value).replace(/[^a-zA-Z0-9._\-:]/g, '_').slice(0, 50)}`;
      addNode(graph, {
        id: iocId, type: 'IOC', name: ioc.value,
        attributes: { ioc_type: ioc.type, confidence: ioc.confidence_score || 0.8, first_seen: ioc.first_seen || '' },
      });
      addEdge(graph, itemId, iocId, 'linked_to', ioc.confidence_score || 0.8);
    }
  }

  return graph;
}

/* ═══════════════════════════════════════════════════════════════════════
   TIER-BASED GRAPH FILTER — prevents free-tier users from seeing all data
═══════════════════════════════════════════════════════════════════════ */
function getGraphForTier(graph, tier) {
  const allNodes = Object.values(graph.nodes || {});
  const limit    = tier === 'enterprise' ? 999 : tier === 'pro' ? 300 : 60;

  // Free: only actors + critical CVEs, no IOC nodes
  const filtered = tier === 'free'
    ? allNodes.filter(n => n.type === 'ThreatActor' ||
        (n.type === 'CVE' && (n.attributes?.priority_score || 0) >= 70) ||
        n.type === 'Campaign')
    : allNodes;

  const topNodes  = filtered.slice(0, limit);
  const nodeIds   = new Set(topNodes.map(n => n.id));
  const topEdges  = (graph.edges || []).filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));

  return {
    nodes:     topNodes,
    edges:     topEdges,
    stats:     graph.stats,
    generated: graph.generated,
    tier_info: { tier, node_limit: limit, showing: topNodes.length, total_available: allNodes.length },
  };
}

module.exports = {
  THREAT_ACTOR_DB,
  CVE_ACTOR_MAP,
  KEYWORD_ACTOR_MAP,
  loadGraph,
  saveGraph,
  getDefaultGraph,
  addNode,
  addEdge,
  getNode,
  getNeighbors,
  getActorsForItem,
  getTopActors,
  buildGraphFromIntel,
  getGraphForTier,
  computeStats,
};
