#!/usr/bin/env node
'use strict';
/**
 * One-time historical recovery for api/intel/campaigns.json (campaign
 * delivery integrity v1).
 *
 * Not part of the live ~30-min ingestion pipeline -- fetch-live-intel.js
 * now accumulates campaigns.json correctly going forward via
 * mergeCampaigns() (see api/_lib/enrichment-pipeline.js). This script
 * exists solely to recover campaigns that were already lost from
 * campaigns.json *before* that fix existed: campaigns.json was being
 * fully overwritten every cycle with only that cycle's freshly-clustered
 * batch, so any campaign whose underlying items weren't in the very last
 * batch before a fix landed was silently dropped. The graph itself never
 * lost this data (its Campaign nodes accumulate correctly), so it can be
 * reconstructed from there -- see reconstructCampaignsFromGraph()'s own
 * docstring in api/_lib/campaign-engine.js for exactly what is and isn't
 * recoverable this way, and why a reconstruction is honestly labeled
 * `graph_reconstruction_v1`, never `weighted_v2`.
 *
 * Defaults to a dry run -- prints what WOULD change, writes nothing.
 * Pass --write to actually persist (still goes through saveCampaigns()'s
 * catastrophic-drop guard as a second safety net).
 *
 * Usage:
 *   node scripts/backfill-campaigns-from-graph.js            # dry run
 *   node scripts/backfill-campaigns-from-graph.js --write     # persist
 */
const fs = require('fs');
const path = require('path');
const {
  loadCampaigns,
  saveCampaigns,
  mergeCampaigns,
  reconstructCampaignsFromGraph,
} = require('../api/_lib/campaign-engine');

const GRAPH_PATH = path.resolve(__dirname, '../api/intel/threat-graph.json');

function main() {
  const write = process.argv.includes('--write');

  const graph = JSON.parse(fs.readFileSync(GRAPH_PATH, 'utf8'));
  const existingState = loadCampaigns();
  const existingCampaigns = existingState.campaigns || [];

  const reconstructed = reconstructCampaignsFromGraph(graph);
  const existingIds = new Set(existingCampaigns.map(c => c.campaign_id));
  const newFromReconstruction = reconstructed.filter(c => !existingIds.has(c.campaign_id)).length;

  const merged = mergeCampaigns(existingCampaigns, reconstructed);

  console.log(`[BACKFILL] Graph Campaign nodes:        ${Object.values(graph.nodes || {}).filter(n => n.type === 'Campaign').length}`);
  console.log(`[BACKFILL] Reconstructed from graph:    ${reconstructed.length}`);
  console.log(`[BACKFILL] Currently in campaigns.json: ${existingCampaigns.length}`);
  console.log(`[BACKFILL] New (not already present):   ${newFromReconstruction}`);
  console.log(`[BACKFILL] Result after merge:           ${merged.length}`);
  console.log(`[BACKFILL] clustering_model breakdown:   ${JSON.stringify(
    merged.reduce((acc, c) => { acc[c.clustering_model] = (acc[c.clustering_model] || 0) + 1; return acc; }, {})
  )}`);

  if (!write) {
    console.log('[BACKFILL] Dry run only -- no file written. Re-run with --write to persist.');
    return;
  }

  const result = saveCampaigns({ campaigns: merged });
  if (!result.saved) {
    console.error(`[BACKFILL] saveCampaigns() did not persist: blocked=${result.blocked}, existingCount=${result.existingCount}, attemptedCount=${result.attemptedCount}`);
    process.exitCode = 1;
    return;
  }
  console.log(`[BACKFILL] Persisted ${merged.length} campaigns to api/intel/campaigns.json.`);
}

main();
