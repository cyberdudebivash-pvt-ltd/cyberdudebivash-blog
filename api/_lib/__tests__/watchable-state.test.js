'use strict';

const { buildCveWatchableState, buildCampaignWatchableState, normalizeIdSet, fingerprintState } = require('../watchable-state');

// Minimal fake graph -- shaped exactly like threat-graph.js's real
// buildGraphFromIntel() output (nodes keyed by ID, edges carrying
// source/target -- confirmed against getNeighbors()'s real implementation,
// which filters on e.source/e.target, not e.from/e.to).
function makeGraph({ edges = [] } = {}) {
  const nodes = {};
  const allIds = new Set();
  for (const e of edges) { allIds.add(e.from); allIds.add(e.to); }
  for (const id of allIds) nodes[id] = { id, type: id.startsWith('campaign:') ? 'Campaign' : id.startsWith('actor:') ? 'ThreatActor' : 'CVE', name: id, connections: [] };
  return {
    nodes,
    edges: edges.map(e => ({ source: e.from, target: e.to, relationship: e.rel, confidence: e.confidence ?? 0.8, sources: e.sources || [], first_seen: e.first_seen || null })),
  };
}

describe('normalizeIdSet (Phase 17)', () => {
  test('sorts and deduplicates', () => {
    expect(normalizeIdSet(['b', 'a', 'b', 'a'])).toEqual(['a', 'b']);
  });
  test('drops falsy entries', () => {
    expect(normalizeIdSet(['a', null, undefined, '', 'b'])).toEqual(['a', 'b']);
  });
  test('empty/undefined input yields empty array', () => {
    expect(normalizeIdSet(undefined)).toEqual([]);
    expect(normalizeIdSet([])).toEqual([]);
  });
});

describe('fingerprintState (Phase 29)', () => {
  test('identical states fingerprint identically', () => {
    const a = { entity_id: 'CVE-1', cvss: 9.8, campaign_ids: ['a', 'b'] };
    const b = { entity_id: 'CVE-1', cvss: 9.8, campaign_ids: ['a', 'b'] };
    expect(fingerprintState(a)).toBe(fingerprintState(b));
  });

  test('key order does not affect the fingerprint', () => {
    const a = { entity_id: 'CVE-1', cvss: 9.8 };
    const b = { cvss: 9.8, entity_id: 'CVE-1' };
    expect(fingerprintState(a)).toBe(fingerprintState(b));
  });

  test('a genuine value difference changes the fingerprint', () => {
    const a = { entity_id: 'CVE-1', cvss: 9.8 };
    const b = { entity_id: 'CVE-1', cvss: 7.2 };
    expect(fingerprintState(a)).not.toBe(fingerprintState(b));
  });

  test('is a real 64-char hex SHA-256', () => {
    expect(fingerprintState({ a: 1 })).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('buildCveWatchableState', () => {
  test('extracts risk/exploitation facts and normalizes relationships', () => {
    const graph = makeGraph({
      edges: [
        { from: 'CVE-2026-1234', to: 'campaign:b', rel: 'includes' },
        { from: 'CVE-2026-1234', to: 'campaign:a', rel: 'includes' },
        { from: 'CVE-2026-1234', to: 'actor:lockbit', rel: 'exploits' },
      ],
    });
    const cveItem = { cvss: 9.8, threat_level: 'critical', cisa_kev: true, exploited: true };
    const state = buildCveWatchableState({ graph, cveId: 'CVE-2026-1234', cveItem, reportsIndexData: { reports: [] } });

    expect(state.entity_type).toBe('cve');
    expect(state.entity_id).toBe('CVE-2026-1234');
    expect(state.cvss).toBe(9.8);
    expect(state.severity).toBe('critical');
    expect(state.kev).toBe(true);
    expect(state.active_exploitation).toBe('CONFIRMED'); // reuses classifyExploitation -- cisa_kev implies CONFIRMED
    expect(state.campaign_ids).toEqual(['campaign:a', 'campaign:b']); // sorted regardless of edge order
    expect(state.actor_ids).toEqual(['actor:lockbit']);
  });

  test('a sparse CVE with no graph edges produces an honestly empty relationship state, not an error', () => {
    const graph = makeGraph({ edges: [] });
    const cveItem = { cvss: null, threat_level: null, cisa_kev: false, exploited: false };
    const state = buildCveWatchableState({ graph, cveId: 'CVE-2026-9999', cveItem, reportsIndexData: { reports: [] } });
    expect(state.active_exploitation).toBe('UNKNOWN');
    expect(state.campaign_ids).toEqual([]);
    expect(state.actor_ids).toEqual([]);
    expect(state.report_ids).toEqual([]);
  });

  test('reports are matched by cves[] membership, mirroring the dossier assembler', () => {
    const graph = makeGraph({ edges: [] });
    const reportsIndexData = { reports: [
      { report_id: 'SA-1', cves: ['CVE-2026-1234'] },
      { report_id: 'SA-2', cves: ['CVE-2026-9999'] },
    ] };
    const state = buildCveWatchableState({ graph, cveId: 'CVE-2026-1234', cveItem: {}, reportsIndexData });
    expect(state.report_ids).toEqual(['SA-1']);
  });
});

describe('buildCampaignWatchableState', () => {
  test('extracts flags and normalizes actor/cve relationships', () => {
    const campaign = {
      campaign_id: 'campaign:x', severity: 'critical', confidence: 0.92, last_seen: '2026-08-20',
      threat_actors: [{ id: 'actor:apt41', name: 'APT41', confidence: 0.9 }],
      shared_cves: ['CVE-2026-0002', 'CVE-2026-0001'],
      has_kev: true, has_exploited: true, has_ransomware: false,
    };
    const state = buildCampaignWatchableState({ campaign, reportsIndexData: { reports: [] } });
    expect(state.entity_type).toBe('campaign');
    expect(state.confidence_bucket).toBe('HIGH'); // reuses campaignConfidenceBucket -- 0.92 >= 0.8
    expect(state.actor_ids).toEqual(['actor:apt41']);
    expect(state.cve_ids).toEqual(['CVE-2026-0001', 'CVE-2026-0002']); // sorted
    expect(state.has_kev).toBe(true);
    expect(state.has_ransomware).toBe(false);
  });

  test('a campaign with no attributed actor produces an honest empty actor list, not a fabricated one', () => {
    const campaign = { campaign_id: 'campaign:y', threat_actors: [], shared_cves: [] };
    const state = buildCampaignWatchableState({ campaign, reportsIndexData: { reports: [] } });
    expect(state.actor_ids).toEqual([]);
    expect(state.confidence_bucket).toBe('UNKNOWN');
  });
});

describe('cross-module consistency', () => {
  test('CVE state fingerprint is unaffected by which order graph edges were discovered in', () => {
    const graphA = makeGraph({ edges: [
      { from: 'CVE-1', to: 'campaign:a', rel: 'includes' },
      { from: 'CVE-1', to: 'campaign:b', rel: 'includes' },
    ] });
    const graphB = makeGraph({ edges: [
      { from: 'CVE-1', to: 'campaign:b', rel: 'includes' },
      { from: 'CVE-1', to: 'campaign:a', rel: 'includes' },
    ] });
    const cveItem = { cvss: 8.1 };
    const stateA = buildCveWatchableState({ graph: graphA, cveId: 'CVE-1', cveItem, reportsIndexData: { reports: [] } });
    const stateB = buildCveWatchableState({ graph: graphB, cveId: 'CVE-1', cveItem, reportsIndexData: { reports: [] } });
    expect(fingerprintState(stateA)).toBe(fingerprintState(stateB));
  });
});
