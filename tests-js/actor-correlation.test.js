'use strict';
// Regression tests for linkCorrelatedActors (api/_lib/enrichment-pipeline.js) --
// platform/open-issues.md Issue 8 continuation (GPEP v1). Third direction of
// the same gap: two ThreatActor nodes that both exploit the same CVE, or
// both executed the same Campaign, were never linked to each other either.
// Adds one new, purely additive 'co_occurs_with' edge between actors sharing
// either basis, computed only from existing Actor->CVE 'exploits' and
// Actor->Campaign 'executes' edges.
//
// Real data check at filing time (api/intel/threat-graph.json): only 6-8 of
// the graph's 8 curated ThreatActor nodes have any exploits/executes edge;
// of those, 20 of 35 actor-linked CVEs are shared by 2+ actors (20 pairs),
// and 3 of 20 actor-linked campaigns are shared by 2+ actors (5 pairs).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const { linkCorrelatedActors } = require(
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

test('two actors exploiting the same CVE get a co_occurs_with edge', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'actor:a', 'ThreatActor');
  addTestNode(graph, 'actor:b', 'ThreatActor');
  addTestNode(graph, 'CVE-2026-1', 'CVE');
  addTestEdge(graph, 'actor:a', 'CVE-2026-1', 'exploits');
  addTestEdge(graph, 'actor:b', 'CVE-2026-1', 'exploits');

  const added = linkCorrelatedActors(graph);

  assert.strictEqual(added, 1);
  const edges = graph.edges.filter(e => e.relationship === 'co_occurs_with');
  assert.strictEqual(edges.length, 1);
  assert.ok(
    (edges[0].source === 'actor:a' && edges[0].target === 'actor:b') ||
    (edges[0].source === 'actor:b' && edges[0].target === 'actor:a')
  );
  assert.ok(edges[0].sources[0].includes('CVE-2026-1'));
});

test('two actors executing the same campaign get a co_occurs_with edge', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'actor:a', 'ThreatActor');
  addTestNode(graph, 'actor:b', 'ThreatActor');
  addTestNode(graph, 'campaign:x', 'Campaign');
  addTestEdge(graph, 'actor:a', 'campaign:x', 'executes');
  addTestEdge(graph, 'actor:b', 'campaign:x', 'executes');

  const added = linkCorrelatedActors(graph);

  assert.strictEqual(added, 1);
  const edges = graph.edges.filter(e => e.relationship === 'co_occurs_with');
  assert.strictEqual(edges.length, 1);
  assert.ok(edges[0].sources[0].includes('campaign:x'));
});

test('an actor with no shared CVE or campaign gets no edge', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'actor:solo', 'ThreatActor');
  addTestNode(graph, 'CVE-2026-9', 'CVE');
  addTestEdge(graph, 'actor:solo', 'CVE-2026-9', 'exploits');

  const added = linkCorrelatedActors(graph);

  assert.strictEqual(added, 0);
});

test('sharing both a CVE and a campaign still produces exactly one edge (idempotent dedup)', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'actor:a', 'ThreatActor');
  addTestNode(graph, 'actor:b', 'ThreatActor');
  addTestNode(graph, 'CVE-2026-1', 'CVE');
  addTestNode(graph, 'campaign:x', 'Campaign');
  addTestEdge(graph, 'actor:a', 'CVE-2026-1', 'exploits');
  addTestEdge(graph, 'actor:b', 'CVE-2026-1', 'exploits');
  addTestEdge(graph, 'actor:a', 'campaign:x', 'executes');
  addTestEdge(graph, 'actor:b', 'campaign:x', 'executes');

  const added = linkCorrelatedActors(graph);

  assert.strictEqual(added, 1);
  assert.strictEqual(graph.edges.filter(e => e.relationship === 'co_occurs_with').length, 1);
});

test('running twice does not duplicate edges (idempotent, matches addEdge behavior)', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'actor:a', 'ThreatActor');
  addTestNode(graph, 'actor:b', 'ThreatActor');
  addTestNode(graph, 'CVE-2026-1', 'CVE');
  addTestEdge(graph, 'actor:a', 'CVE-2026-1', 'exploits');
  addTestEdge(graph, 'actor:b', 'CVE-2026-1', 'exploits');

  linkCorrelatedActors(graph);
  const afterFirstRun = graph.edges.length;
  linkCorrelatedActors(graph);

  assert.strictEqual(graph.edges.length, afterFirstRun);
});

test('a CVE shared by more actors than the cap is skipped entirely', () => {
  const graph = emptyGraph();
  const actorIds = [];
  for (let i = 0; i < 25; i++) {
    const id = `actor:a${i}`;
    actorIds.push(id);
    addTestNode(graph, id, 'ThreatActor');
  }
  addTestNode(graph, 'CVE-2026-5', 'CVE');
  for (const id of actorIds) {
    addTestEdge(graph, id, 'CVE-2026-5', 'exploits');
  }

  const added = linkCorrelatedActors(graph);

  assert.strictEqual(added, 0);
});

test('edges from non-ThreatActor sources or to non-CVE/Campaign targets are ignored', () => {
  const graph = emptyGraph();
  addTestNode(graph, 'actor:a', 'ThreatActor');
  addTestNode(graph, 'campaign:not-actor', 'Campaign');
  addTestNode(graph, 'CVE-2026-1', 'CVE');
  // A 'exploits' edge from a non-ThreatActor source must not be treated as
  // actor attribution.
  addTestEdge(graph, 'campaign:not-actor', 'CVE-2026-1', 'exploits');
  addTestEdge(graph, 'actor:a', 'CVE-2026-1', 'exploits');

  const added = linkCorrelatedActors(graph);

  assert.strictEqual(added, 0);
});
