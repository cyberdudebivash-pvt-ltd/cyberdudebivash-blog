'use strict';
// Tests for reconstructCampaignsFromGraph() (api/_lib/campaign-engine.js) --
// the one-time historical-recovery path for campaigns.json entries lost
// before the mergeCampaigns() fix existed (campaign delivery integrity v1).
// Builds small synthetic graphs by hand (addNode/addEdge from
// threat-graph.js) rather than loading the real 8MB production graph, so
// these stay fast and fully deterministic.
const test = require('node:test');
const assert = require('node:assert/strict');
const { getDefaultGraph, addNode, addEdge } = require('../api/_lib/threat-graph');
const { reconstructCampaignsFromGraph } = require('../api/_lib/campaign-engine');

function buildSampleGraph() {
  const graph = getDefaultGraph();

  addNode(graph, { id: 'actor:lockbit', type: 'ThreatActor', name: 'LockBit', attributes: { category: 'ransomware_group' } });
  addNode(graph, {
    id: 'CVE-2026-0001', type: 'CVE', name: 'CVE-2026-0001: Example RCE',
    attributes: { priority_score: 95, published: '2026-08-01', exploited: true, cisa_kev: true, ransomware: true },
  });
  addNode(graph, {
    id: 'CVE-2026-0002', type: 'CVE', name: 'CVE-2026-0002: Example Second CVE',
    attributes: { priority_score: 60, published: '2026-08-05', exploited: false, cisa_kev: false, ransomware: false },
  });
  addNode(graph, { id: 'ioc:ip:1.2.3.4', type: 'IOC', name: '1.2.3.4', attributes: { ioc_type: 'ip' } });

  addNode(graph, {
    id: 'campaign:example', type: 'Campaign', name: 'Example Exploitation Campaign',
    attributes: { severity: 'CRITICAL', item_count: 2, first_seen: '2026-08-01', last_seen: '2026-08-05', confidence: 0.88, reasoning: '2 intel item(s) clustered with composite confidence 0.880' },
  });

  addEdge(graph, 'campaign:example', 'CVE-2026-0001', 'includes', 1.0);
  addEdge(graph, 'campaign:example', 'CVE-2026-0002', 'includes', 1.0);
  addEdge(graph, 'CVE-2026-0001', 'ioc:ip:1.2.3.4', 'linked_to', 0.9);
  addEdge(graph, 'actor:lockbit', 'campaign:example', 'executes', 0.85);

  return graph;
}

test('reconstructCampaignsFromGraph: derives a complete, correct campaign object from graph state', () => {
  const graph = buildSampleGraph();
  const [campaign] = reconstructCampaignsFromGraph(graph);

  assert.equal(campaign.campaign_id, 'campaign:example');
  assert.equal(campaign.name, 'Example Exploitation Campaign');
  assert.equal(campaign.item_count, 2);
  assert.deepEqual(campaign.related_intel_ids.sort(), ['CVE-2026-0001', 'CVE-2026-0002']);
  assert.deepEqual(campaign.shared_cves.sort(), ['CVE-2026-0001', 'CVE-2026-0002']);
  assert.deepEqual(campaign.shared_iocs, ['ioc:ip:1.2.3.4']);
  assert.equal(campaign.ioc_count, 1);
  assert.deepEqual(campaign.threat_actors, [{ id: 'actor:lockbit', name: 'LockBit', confidence: 0.85, category: 'ransomware_group' }]);
  assert.equal(campaign.threat_actor, 'LockBit');
  assert.equal(campaign.max_priority_score, 95);
  assert.equal(campaign.has_kev, true);
  assert.equal(campaign.has_ransomware, true);
  assert.equal(campaign.has_exploited, true);
  assert.equal(campaign.severity, 'CRITICAL');
  assert.equal(campaign.confidence, 0.88, 'reuses the original clustering confidence stored on the node, does not invent one');
  assert.equal(campaign.first_seen, '2026-08-01');
  assert.equal(campaign.last_seen, '2026-08-05');
});

test('reconstructCampaignsFromGraph: is honestly labeled as a reconstruction, never claims live-clustering provenance', () => {
  const [campaign] = reconstructCampaignsFromGraph(buildSampleGraph());
  assert.equal(campaign.clustering_model, 'graph_reconstruction_v1');
  assert.notEqual(campaign.clustering_model, 'weighted_v2');
  assert.ok(campaign.reasoning[0].includes('Reconstructed from graph state'));
});

test('reconstructCampaignsFromGraph: preserves the original clustering reasoning string as evidence', () => {
  const [campaign] = reconstructCampaignsFromGraph(buildSampleGraph());
  assert.ok(campaign.reasoning.some(r => r.includes('composite confidence 0.880')));
});

test('reconstructCampaignsFromGraph: a Campaign node with no includes edges reconstructs as zero-item, not a crash', () => {
  const graph = getDefaultGraph();
  addNode(graph, { id: 'campaign:orphan', type: 'Campaign', name: 'Orphan', attributes: { confidence: 0.6 } });
  const [campaign] = reconstructCampaignsFromGraph(graph);
  assert.equal(campaign.item_count, 0);
  assert.deepEqual(campaign.related_intel, []);
  assert.equal(campaign.severity, 'LOW');
});

test('reconstructCampaignsFromGraph: multiple campaigns reconstruct independently with no cross-contamination', () => {
  const graph = getDefaultGraph();
  addNode(graph, { id: 'CVE-2026-0010', type: 'CVE', name: 'A', attributes: { priority_score: 40 } });
  addNode(graph, { id: 'CVE-2026-0020', type: 'CVE', name: 'B', attributes: { priority_score: 40 } });
  addNode(graph, { id: 'campaign:one', type: 'Campaign', name: 'One', attributes: { confidence: 0.6 } });
  addNode(graph, { id: 'campaign:two', type: 'Campaign', name: 'Two', attributes: { confidence: 0.6 } });
  addEdge(graph, 'campaign:one', 'CVE-2026-0010', 'includes', 1.0);
  addEdge(graph, 'campaign:two', 'CVE-2026-0020', 'includes', 1.0);

  const reconstructed = reconstructCampaignsFromGraph(graph);
  assert.equal(reconstructed.length, 2);
  const one = reconstructed.find(c => c.campaign_id === 'campaign:one');
  const two = reconstructed.find(c => c.campaign_id === 'campaign:two');
  assert.deepEqual(one.related_intel_ids, ['CVE-2026-0010']);
  assert.deepEqual(two.related_intel_ids, ['CVE-2026-0020']);
});

test('reconstructCampaignsFromGraph: empty graph reconstructs to an empty array, no crash', () => {
  assert.deepEqual(reconstructCampaignsFromGraph(getDefaultGraph()), []);
  assert.deepEqual(reconstructCampaignsFromGraph({ nodes: {}, edges: [] }), []);
});

test('reconstructCampaignsFromGraph output is a valid mergeCampaigns() input (round-trips through the same merge path as live data)', () => {
  const { mergeCampaigns } = require('../api/_lib/campaign-engine');
  const reconstructed = reconstructCampaignsFromGraph(buildSampleGraph());
  assert.doesNotThrow(() => mergeCampaigns([], reconstructed));
  assert.doesNotThrow(() => mergeCampaigns(reconstructed, reconstructed)); // idempotent against itself
  const merged = mergeCampaigns(reconstructed, reconstructed);
  assert.equal(merged.length, reconstructed.length);
});
