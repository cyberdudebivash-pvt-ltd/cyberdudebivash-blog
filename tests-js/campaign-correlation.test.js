'use strict';
// Regression tests for linkCorrelatedCampaigns (api/_lib/enrichment-pipeline.js).
//
// Every edge in the live threat graph (verified directly against
// api/intel/threat-graph.json — 9,315 nodes, 3,378 edges, at the time of
// this audit) was strictly hierarchical: Campaign->includes->CVE/Intel,
// Actor->exploits->CVE/Intel, Actor->executes->Campaign, Intel/CVE->
// linked_to->IOC. None connected two entities of the same type, so two
// campaigns that clearly shared a CVE were never linked to each other
// (platform/open-issues.md Issue 8). This adds one new, purely additive
// 'co_occurs_with' edge between Campaign nodes sharing an included CVE,
// computed only from Campaign->CVE 'includes' edges already in the graph.
//
// Real data check at filing time: only 7 of 298 CVEs referenced by any
// campaign were shared by more than one campaign, and every one of those
// was shared by exactly 2 — so a defensive per-CVE cap (guarding against
// future growth, not today's data) was added rather than a lower one that
// might already need raising.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const { linkCorrelatedCampaigns, linkActorsToCampaignsGraph } = require(
  path.join(ROOT, 'api', '_lib', 'enrichment-pipeline.js')
);

function emptyGraph() {
  return { nodes: {}, edges: [] };
}

function addTestNode(graph, id, type) {
  graph.nodes[id] = { id, type, name: id, connections: [] };
}

function addTestEdge(graph, source, target, relationship) {
  graph.edges.push({
    id: `${source}→${relationship}→${target}`,
    source,
    target,
    relationship,
    confidence: 1.0,
    first_seen: '2026-01-01',
    sources: [],
  });
}

test('two campaigns sharing a CVE get a co_occurs_with edge', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'campaign:a', 'Campaign');
  addTestNode(graph, 'campaign:b', 'Campaign');
  addTestNode(graph, 'CVE-2026-1234', 'CVE');
  addTestEdge(graph, 'campaign:a', 'CVE-2026-1234', 'includes');
  addTestEdge(graph, 'campaign:b', 'CVE-2026-1234', 'includes');

  const added = linkCorrelatedCampaigns(graph);

  assert.strictEqual(added, 1);
  const correlationEdges = graph.edges.filter(e => e.relationship === 'co_occurs_with');
  assert.strictEqual(correlationEdges.length, 1);
  const edge = correlationEdges[0];
  assert.ok(
    (edge.source === 'campaign:a' && edge.target === 'campaign:b') ||
    (edge.source === 'campaign:b' && edge.target === 'campaign:a')
  );
});

test('a campaign that does not share a CVE with any other gets no edge', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'campaign:solo', 'Campaign');
  addTestNode(graph, 'CVE-2026-9999', 'CVE');
  addTestEdge(graph, 'campaign:solo', 'CVE-2026-9999', 'includes');

  const added = linkCorrelatedCampaigns(graph);

  assert.strictEqual(added, 0);
  assert.strictEqual(graph.edges.filter(e => e.relationship === 'co_occurs_with').length, 0);
});

test('running twice does not duplicate edges (idempotent, matches addEdge behavior)', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'campaign:a', 'Campaign');
  addTestNode(graph, 'campaign:b', 'Campaign');
  addTestNode(graph, 'CVE-2026-1234', 'CVE');
  addTestEdge(graph, 'campaign:a', 'CVE-2026-1234', 'includes');
  addTestEdge(graph, 'campaign:b', 'CVE-2026-1234', 'includes');

  linkCorrelatedCampaigns(graph);
  const afterFirstRun = graph.edges.length;
  linkCorrelatedCampaigns(graph);

  assert.strictEqual(graph.edges.length, afterFirstRun);
});

test('a CVE shared by more campaigns than the cap is skipped entirely', () => {
  const graph = emptyGraph();
  const campaignIds = [];
  for (let i = 0; i < 25; i++) {
    const id = `campaign:c${i}`;
    campaignIds.push(id);
    addTestNode(graph, id, 'Campaign');
  }
  addTestNode(graph, 'CVE-2026-5555', 'CVE');
  for (const id of campaignIds) {
    addTestEdge(graph, id, 'CVE-2026-5555', 'includes');
  }

  const added = linkCorrelatedCampaigns(graph);

  assert.strictEqual(added, 0);
});

test('edges to non-Campaign or non-CVE node types are ignored', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'campaign:a', 'Campaign');
  addTestNode(graph, 'actor:x', 'ThreatActor');
  addTestNode(graph, 'CVE-2026-1', 'CVE');
  // An 'includes' edge from a non-Campaign source must not be treated as
  // campaign membership.
  addTestEdge(graph, 'actor:x', 'CVE-2026-1', 'includes');
  addTestEdge(graph, 'campaign:a', 'CVE-2026-1', 'includes');

  const added = linkCorrelatedCampaigns(graph);

  assert.strictEqual(added, 0);
});

test('linkActorsToCampaignsGraph still exports and runs (no signature change)', () => {
  const graph = emptyGraph();
  const campaigns = [{
    campaign_id: 'campaign:new',
    name: 'Test Campaign',
    severity: 'HIGH',
    item_count: 1,
    first_seen: '2026-01-01',
    last_seen: '2026-01-01',
    confidence: 0.8,
    reasoning: ['test'],
    threat_actors: [],
    related_intel_ids: ['CVE-2026-1'],
  }];
  addTestNode(graph, 'CVE-2026-1', 'CVE');

  assert.doesNotThrow(() => linkActorsToCampaignsGraph(graph, campaigns));
  assert.ok(graph.nodes['campaign:new']);
});
