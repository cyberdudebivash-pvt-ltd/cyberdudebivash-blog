'use strict';
// Regression tests for a real, sourced correction made during GPEP v2 Phase 3
// (2026-07-29): api/_lib/threat-graph.js's CVE_ACTOR_MAP and the persisted
// api/intel/threat-graph.json both attributed CVE-2024-27198/27199 (JetBrains
// TeamCity) to actor:apt41 and actor:cl0p, citing each actor's own general
// Mandiant/CISA profile URL rather than any source about this specific CVE
// pair or TeamCity. This platform's own certified SA-2026-0003 report
// independently found no source naming any actor for this CVE pair.
// Verified via WebSearch during this pass: real, independently-sourced
// public reporting (FortiGuard, citing Mandiant; a dedicated technical
// investigation) documents APT29 exploiting CVE-2024-27198 specifically, at
// medium confidence — not APT41, and no source supports Cl0p for this pair.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const tg = require(path.join(ROOT, 'api', '_lib', 'threat-graph.js'));

test('CVE-2024-27198 maps to actor:apt29, not the unsourced actor:apt41/actor:cl0p', () => {
  assert.deepStrictEqual(tg.CVE_ACTOR_MAP['CVE-2024-27198'], ['actor:apt29']);
});

test('CVE-2024-27199 has no actor attribution (no source found for any actor)', () => {
  assert.strictEqual(tg.CVE_ACTOR_MAP['CVE-2024-27199'], undefined);
});

test('actor:apt41 known_cves no longer claims the TeamCity CVE pair', () => {
  const knownCves = tg.THREAT_ACTOR_DB['actor:apt41'].attributes.known_cves;
  assert.ok(!knownCves.includes('CVE-2024-27198'));
  assert.ok(!knownCves.includes('CVE-2024-27199'));
});

test('actor:apt29 exists with a sourced, medium-confidence claim on CVE-2024-27198', () => {
  const apt29 = tg.THREAT_ACTOR_DB['actor:apt29'];
  assert.ok(apt29, 'actor:apt29 must exist in THREAT_ACTOR_DB');
  assert.ok(apt29.attributes.known_cves.includes('CVE-2024-27198'));
  assert.ok(apt29.attributes.refs.length > 0, 'must carry real source URLs');
});

test('KEYWORD_ACTOR_MAP no longer fires actor:apt41/actor:cl0p for teamcity/jetbrains text', () => {
  const entry = tg.KEYWORD_ACTOR_MAP.find(e => e.patterns.some(p => p.test('teamcity')));
  assert.ok(entry, 'a teamcity keyword rule must still exist');
  assert.deepStrictEqual(entry.actors, ['actor:apt29']);
});

test('persisted graph: no actor:apt41/actor:cl0p exploits or executes edge touches the TeamCity CVE pair or its campaigns', () => {
  const graphPath = path.join(ROOT, 'api', 'intel', 'threat-graph.json');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  const badTargets = new Set([
    'CVE-2024-27198', 'CVE-2024-27199',
    'campaign:cve-2024-27199-and-cve-2024-27198', 'campaign:cve-2024-27199',
  ]);
  const stale = graph.edges.filter(e =>
    (e.source === 'actor:apt41' || e.source === 'actor:cl0p') && badTargets.has(e.target)
  );
  assert.deepStrictEqual(stale, []);
});

test('persisted graph: actor:apt29 has a real exploits edge to CVE-2024-27198 with real source URLs', () => {
  const graphPath = path.join(ROOT, 'api', 'intel', 'threat-graph.json');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  const edge = graph.edges.find(e =>
    e.source === 'actor:apt29' && e.target === 'CVE-2024-27198' && e.relationship === 'exploits'
  );
  assert.ok(edge, 'expected actor:apt29 -> exploits -> CVE-2024-27198 edge');
  assert.ok(edge.sources.length > 0);
  assert.ok(edge.confidence < 0.92, 'must not carry the old, unsupported high-confidence score');
});

test('persisted graph: Malware node type is populated with BianLian and Jasmin from SA-2026-0003', () => {
  const graphPath = path.join(ROOT, 'api', 'intel', 'threat-graph.json');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  assert.ok(graph.nodes['malware:bianlian'], 'expected malware:bianlian node');
  assert.ok(graph.nodes['malware:jasmin'], 'expected malware:jasmin node');
  assert.strictEqual(graph.nodes['malware:bianlian'].type, 'Malware');
  assert.strictEqual(graph.nodes['malware:jasmin'].type, 'Malware');
  assert.ok(graph.stats.malware >= 2, 'stats.malware must reflect the new nodes');

  const bianlianEdge = graph.edges.find(e => e.target === 'malware:bianlian' && e.source === 'CVE-2024-27198');
  const jasminEdge = graph.edges.find(e => e.target === 'malware:jasmin' && e.source === 'CVE-2024-27198');
  assert.ok(bianlianEdge && bianlianEdge.sources.length > 0);
  assert.ok(jasminEdge && jasminEdge.sources.length > 0);
});
