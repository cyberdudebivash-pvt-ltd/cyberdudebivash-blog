/**
 * SENTINEL APEX — Intelligence Enrichment Pipeline v1.0
 * Phase 4: For each intel item:
 *   1. Extract entities (CVEs, actors, vendor/product)
 *   2. Link item to threat actor graph
 *   3. Assign campaign via clustering engine
 *   4. Compute enhanced AI threat score
 *   5. Return enriched object
 *
 * Called from fetch-live-intel.js after correlation + merge.
 * Writes updated threat-graph.json + campaigns.json to disk.
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';

const {
  buildGraphFromIntel, saveGraph, addNode, addEdge,
  getActorsForItem, getTopActors, KEYWORD_ACTOR_MAP, CVE_ACTOR_MAP,
} = require('./threat-graph');

const {
  buildCampaigns, saveCampaigns,
} = require('./campaign-engine');

const { computeEnhancedScore } = require('./threat-scorer');

/* ─── Actor name extraction from free text ───────────────────────────── */
const ACTOR_TEXT_MAP = {
  'LockBit':         'actor:lockbit',
  'Cl0p':            'actor:cl0p',
  'Clop':            'actor:cl0p',
  'TA505':           'actor:cl0p',
  'APT41':           'actor:apt41',
  'Winnti':          'actor:apt41',
  'Double Dragon':   'actor:apt41',
  'Volt Typhoon':    'actor:volt-typhoon',
  'Salt Typhoon':    'actor:salt-typhoon',
  'GhostEmperor':    'actor:salt-typhoon',
  'PhantomCore':     'actor:phantomcore',
  'ShinyHunters':    'actor:shinyhunters',
  'Shiny Hunters':   'actor:shinyhunters',
};

function extractEntities(item) {
  const text = `${item.title || ''} ${item.desc || item.description || ''}`;

  // CVE references
  const cveRefs = [...new Set(
    (text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(c => c.toUpperCase())
  )];

  // Actor mentions via static name table
  const actorMentions = [];
  for (const [name, actorId] of Object.entries(ACTOR_TEXT_MAP)) {
    if (new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(text)) {
      if (!actorMentions.includes(actorId)) actorMentions.push(actorId);
    }
  }

  // Actor matches via keyword patterns
  for (const { patterns, actors } of KEYWORD_ACTOR_MAP) {
    if (patterns.some(p => p.test(text))) {
      actors.forEach(a => { if (!actorMentions.includes(a)) actorMentions.push(a); });
    }
  }

  // CVE→actor map
  const itemId = String(item.id || '');
  if (CVE_ACTOR_MAP[itemId]) {
    CVE_ACTOR_MAP[itemId].forEach(a => {
      if (!actorMentions.includes(a)) actorMentions.push(a);
    });
  }

  // Vendor + product as entity refs
  const vendors = [item.vendor, item.product]
    .filter(v => v && v !== 'Unknown Vendor' && v !== 'Unknown Product' && v.length > 2);

  return { cveRefs, actorMentions, vendors };
}

/* ─── Enrich a single item given pre-built graph + campaign list ─────── */
function enrichItem(item, graph, campaigns) {
  const entities = extractEntities(item);

  // Actors from graph edges (already wired by buildGraphFromIntel)
  const graphActors    = getActorsForItem(graph, String(item.id || ''));
  const allActorIds    = [...new Set([...entities.actorMentions, ...graphActors.map(a => a.id)])];

  // Find associated campaign
  const campaign = (campaigns || []).find(c => c.related_intel_ids?.includes(String(item.id || '')));

  // Graph context for scorer
  const graphContext = {
    actorCount:       allActorIds.length,
    inCampaign:       !!campaign,
    campaignSize:     campaign?.item_count || 0,
    campaignSeverity: campaign?.severity || null,
  };

  // Enhanced scoring
  const scoring = computeEnhancedScore(item, graphContext);

  return {
    ...item,
    // Overwrite scores with enhanced values
    priority_score:   scoring.priority_score,
    threat_level:     scoring.threat_level,
    confidence_score: scoring.confidence_score,
    score_breakdown:  scoring.score_breakdown,
    scoring_model:    scoring.scoring_model,

    // Intelligence enrichment block
    _intelligence: {
      entities,
      linked_actors: allActorIds.map(actorId => {
        const node = graph.nodes[actorId];
        return node ? {
          id:         actorId,
          name:       node.name,
          category:   node.attributes?.category,
          motivation: node.attributes?.motivation,
          origin:     node.attributes?.origin,
          ttps:       (node.attributes?.ttps || []).slice(0, 5),
        } : null;
      }).filter(Boolean),
      campaign_id:         campaign?.campaign_id     || null,
      campaign_name:       campaign?.name            || null,
      campaign_severity:   campaign?.severity        || null,
      campaign_item_count: campaign?.item_count      || 0,
      graph_node_id:       String(item.id || ''),
      enriched_at:         new Date().toISOString(),
    },
  };
}

/* ─── Link threat actors to campaigns via graph ─────────────────────── */
function linkActorsToCampaigns(graph, campaigns) {
  for (const campaign of campaigns) {
    const actorIds = new Set();

    for (const intelId of (campaign.related_intel_ids || [])) {
      getActorsForItem(graph, intelId).forEach(a => actorIds.add(a.id));
    }

    campaign.threat_actors = [...actorIds].map(id => {
      const node = graph.nodes[id];
      return node ? { id, name: node.name, category: node.attributes?.category } : null;
    }).filter(Boolean);

    campaign.threat_actor = campaign.threat_actors[0]?.name || null;

    // Add campaign node to graph
    addNode(graph, {
      id:   campaign.campaign_id,
      type: 'Campaign',
      name: campaign.name,
      attributes: {
        severity:   campaign.severity,
        item_count: campaign.item_count,
        first_seen: campaign.first_seen,
        last_seen:  campaign.last_seen,
        confidence: campaign.confidence,
      },
    });

    // Actor → executes → Campaign edges
    for (const actorId of actorIds) {
      addEdge(graph, actorId, campaign.campaign_id, 'executes', 0.85);
    }

    // Campaign → includes → CVE edges
    for (const intelId of (campaign.related_intel_ids || [])) {
      addEdge(graph, campaign.campaign_id, intelId, 'includes', 1.0);
    }
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   MAIN PIPELINE ENTRY POINT
   Called from fetch-live-intel.js after correlateAndMerge()
═══════════════════════════════════════════════════════════════════════ */
function runEnrichmentPipeline(intelItems) {
  const startTime = Date.now();
  console.log(`[ENRICH] Starting enrichment pipeline for ${intelItems.length} items...`);

  // Phase 1: Build / update threat graph from raw items
  const graph = buildGraphFromIntel(intelItems);
  console.log(`[ENRICH] Graph built: ${Object.keys(graph.nodes).length} nodes, ${graph.edges.length} edges`);

  // Phase 2: Build campaign clusters
  const campaigns = buildCampaigns(intelItems);
  console.log(`[ENRICH] Campaigns clustered: ${campaigns.length} campaigns`);

  // Phase 3: Link actors to campaigns and extend graph
  linkActorsToCampaigns(graph, campaigns);

  // Phase 4: Enrich every item with graph context, campaign, and enhanced score
  const enrichedItems = intelItems.map(item => enrichItem(item, graph, campaigns));
  console.log(`[ENRICH] Items enriched: ${enrichedItems.length}`);

  // Phase 5: Persist graph + campaigns to disk
  saveGraph(graph);
  saveCampaigns({ campaigns });

  const elapsed = Date.now() - startTime;
  console.log(`[ENRICH] Pipeline complete in ${elapsed}ms`);

  return {
    enrichedItems,
    graph,
    campaigns,
    stats: {
      items_processed: intelItems.length,
      graph_nodes:     Object.keys(graph.nodes).length,
      graph_edges:     graph.edges.length,
      campaigns:       campaigns.length,
      elapsed_ms:      elapsed,
    },
  };
}

/**
 * Lightweight enrichment for API-time use (no disk writes).
 * Used by the intel API router to add intelligence context to live queries.
 */
function enrichItemForAPI(item, graph, campaigns) {
  return enrichItem(item, graph, campaigns);
}

module.exports = { runEnrichmentPipeline, enrichItem, enrichItemForAPI, extractEntities };
