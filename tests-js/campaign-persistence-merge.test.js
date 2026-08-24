'use strict';
// Regression tests for campaign delivery integrity v1 (api/_lib/campaign-engine.js's
// mergeCampaigns()/mergeCampaign()/saveCampaigns()'s catastrophic-drop guard).
//
// Real production defect this fixes: campaigns.json went from 1,187
// accumulated campaigns to 0 in a single write, because
// enrichment-pipeline.js called saveCampaigns({ campaigns }) with only the
// current ~30-min ingestion cycle's freshly-clustered batch -- it never
// loaded and merged against what was already persisted. The threat graph
// itself never had this problem (its Campaign nodes accumulate correctly
// via addNode()'s upsert-into-loaded-graph pattern); this brings
// campaigns.json's persistence in line with that already-proven-correct
// pattern.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {
  mergeCampaign,
  mergeCampaigns,
  saveCampaigns,
  severityFromFlags,
} = require('../api/_lib/campaign-engine');

function campaign(overrides = {}) {
  return {
    campaign_id: 'campaign:cve-2026-0001',
    name: 'Example Exploitation Campaign',
    severity: 'HIGH',
    confidence: 0.75,
    item_count: 1,
    ioc_count: 1,
    first_seen: '2026-08-01',
    last_seen: '2026-08-01',
    related_intel_ids: ['CVE-2026-0001'],
    related_intel: [{
      id: 'CVE-2026-0001', title: 'Example CVE', type: 'CVE_REPORT',
      priority_score: 70, published: '2026-08-01', exploited: false, cisa_kev: false,
    }],
    shared_iocs: ['ip:1.2.3.4'],
    shared_cves: ['CVE-2026-0001'],
    threat_actor: 'LockBit',
    threat_actors: [{ id: 'actor:lockbit', name: 'LockBit', confidence: 0.8, category: 'ransomware_group' }],
    max_priority_score: 70,
    has_kev: false,
    has_ransomware: false,
    has_exploited: false,
    reasoning: ['1 intel item(s) clustered with composite confidence 0.75'],
    clustering_model: 'weighted_v2',
    ...overrides,
  };
}

test('severityFromFlags mirrors campaignSeverity()\'s thresholds', () => {
  assert.equal(severityFromFlags(90, false, false, false), 'CRITICAL');
  assert.equal(severityFromFlags(50, true, true, false), 'CRITICAL');
  assert.equal(severityFromFlags(70, false, false, false), 'HIGH');
  assert.equal(severityFromFlags(50, true, false, false), 'HIGH');
  assert.equal(severityFromFlags(50, false, true, true), 'HIGH');
  assert.equal(severityFromFlags(50, false, false, false), 'MEDIUM');
  assert.equal(severityFromFlags(50, false, false, true), 'MEDIUM');
  assert.equal(severityFromFlags(10, false, false, false), 'LOW');
});

test('mergeCampaigns: no ID overlap -> both campaigns present, nothing lost', () => {
  const existing = [campaign({ campaign_id: 'campaign:a' })];
  const incoming = [campaign({ campaign_id: 'campaign:b' })];
  const merged = mergeCampaigns(existing, incoming);
  const ids = merged.map(c => c.campaign_id).sort();
  assert.deepEqual(ids, ['campaign:a', 'campaign:b']);
});

test('mergeCampaigns: an existing campaign absent from the new batch is preserved untouched', () => {
  const existing = [campaign({ campaign_id: 'campaign:historical', name: 'Historical Campaign' })];
  const merged = mergeCampaigns(existing, []); // this run's batch found nothing
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0], existing[0]);
});

test('THE production incident, reproduced and fixed: 1187 historical campaigns + an empty/small new batch does not collapse to the batch size', () => {
  const existing = Array.from({ length: 1187 }, (_, i) => campaign({ campaign_id: `campaign:hist-${i}` }));
  const newBatch = [campaign({ campaign_id: 'campaign:hist-0' })]; // re-observes exactly one
  const merged = mergeCampaigns(existing, newBatch);
  assert.equal(merged.length, 1187, 'merging must never drop below the existing accumulated count');
});

test('mergeCampaigns: same campaign_id upserts (merges), does not duplicate', () => {
  const existing = [campaign({ campaign_id: 'campaign:x' })];
  const incoming = [campaign({ campaign_id: 'campaign:x' })];
  const merged = mergeCampaigns(existing, incoming);
  assert.equal(merged.length, 1);
});

test('mergeCampaign: related_intel unions by id, no duplicates, ids accumulate', () => {
  const existing = campaign({
    related_intel_ids: ['CVE-2026-0001'],
    related_intel: [{ id: 'CVE-2026-0001', title: 'A', published: '2026-08-01', priority_score: 60, exploited: false, cisa_kev: false }],
  });
  const incoming = campaign({
    related_intel_ids: ['CVE-2026-0002'],
    related_intel: [{ id: 'CVE-2026-0002', title: 'B', published: '2026-08-10', priority_score: 60, exploited: false, cisa_kev: false }],
  });
  const merged = mergeCampaign(existing, incoming);
  assert.deepEqual(merged.related_intel_ids.sort(), ['CVE-2026-0001', 'CVE-2026-0002']);
  assert.equal(merged.item_count, 2);
});

test('mergeCampaign: shared_iocs/shared_cves union and deduplicate', () => {
  const existing = campaign({ shared_iocs: ['ip:1.1.1.1', 'ip:2.2.2.2'], shared_cves: ['CVE-2026-0001'] });
  const incoming = campaign({ shared_iocs: ['ip:2.2.2.2', 'ip:3.3.3.3'], shared_cves: ['CVE-2026-0001', 'CVE-2026-0002'] });
  const merged = mergeCampaign(existing, incoming);
  assert.deepEqual(merged.shared_iocs.sort(), ['ip:1.1.1.1', 'ip:2.2.2.2', 'ip:3.3.3.3']);
  assert.deepEqual(merged.shared_cves.sort(), ['CVE-2026-0001', 'CVE-2026-0002']);
  assert.equal(merged.ioc_count, 3);
});

test('mergeCampaign: shared_iocs stays capped at 25 even after merging two large lists', () => {
  const existing = campaign({ shared_iocs: Array.from({ length: 20 }, (_, i) => `ip:1.1.1.${i}`) });
  const incoming = campaign({ shared_iocs: Array.from({ length: 20 }, (_, i) => `ip:2.2.2.${i}`) });
  const merged = mergeCampaign(existing, incoming);
  assert.ok(merged.shared_iocs.length <= 25, `expected <=25, got ${merged.shared_iocs.length}`);
});

test('mergeCampaign: threat_actors union by id, keeping the higher-confidence observation', () => {
  const existing = campaign({ threat_actors: [{ id: 'actor:lockbit', name: 'LockBit', confidence: 0.6 }] });
  const incoming = campaign({ threat_actors: [{ id: 'actor:lockbit', name: 'LockBit', confidence: 0.9 }, { id: 'actor:cl0p', name: 'Cl0p', confidence: 0.7 }] });
  const merged = mergeCampaign(existing, incoming);
  const lockbit = merged.threat_actors.find(a => a.id === 'actor:lockbit');
  assert.equal(lockbit.confidence, 0.9, 'higher-confidence observation should win, not last-write-wins');
  assert.ok(merged.threat_actors.some(a => a.id === 'actor:cl0p'));
  assert.equal(merged.threat_actor, 'LockBit', 'primary actor is the highest-confidence one after merge');
});

test('mergeCampaign: has_kev/has_ransomware/has_exploited are OR\'d, never downgraded', () => {
  const existing = campaign({ has_kev: true, has_ransomware: false, has_exploited: false });
  const incoming = campaign({ has_kev: false, has_ransomware: true, has_exploited: false });
  const merged = mergeCampaign(existing, incoming);
  assert.equal(merged.has_kev, true);
  assert.equal(merged.has_ransomware, true);
  assert.equal(merged.has_exploited, false);
});

test('mergeCampaign: confidence and max_priority_score take the max, never decrease', () => {
  const existing = campaign({ confidence: 0.9, max_priority_score: 85 });
  const incoming = campaign({ confidence: 0.6, max_priority_score: 50 });
  const merged = mergeCampaign(existing, incoming);
  assert.equal(merged.confidence, 0.9);
  assert.equal(merged.max_priority_score, 85);
});

test('mergeCampaign: severity is recomputed from merged flags, not left stale', () => {
  const existing = campaign({ severity: 'MEDIUM', max_priority_score: 50, has_kev: false, has_ransomware: false, has_exploited: false });
  const incoming = campaign({ severity: 'LOW', max_priority_score: 40, has_kev: true, has_ransomware: false, has_exploited: false });
  const merged = mergeCampaign(existing, incoming);
  assert.equal(merged.severity, 'HIGH', 'has_kev now true after merge should push severity to HIGH, not stay at either input\'s stale value');
});

test('mergeCampaign: campaign_id, name, and clustering_model are stable across merges (never renamed)', () => {
  const existing = campaign({ campaign_id: 'campaign:x', name: 'Original Name', clustering_model: 'weighted_v2' });
  const incoming = campaign({ campaign_id: 'campaign:x', name: 'A Different Later Name', clustering_model: 'weighted_v2' });
  const merged = mergeCampaign(existing, incoming);
  assert.equal(merged.name, 'Original Name');
});

test('mergeCampaign: first_seen/last_seen are recomputed as min/max over the full merged item set (order-independent)', () => {
  const existing = campaign({
    related_intel_ids: ['CVE-2026-0005'],
    related_intel: [{ id: 'CVE-2026-0005', published: '2026-08-15', priority_score: 60, exploited: false, cisa_kev: false }],
  });
  // Replay of an OLDER observation arriving in a LATER cycle -- out-of-order safety (Phase 42/43).
  const incoming = campaign({
    related_intel_ids: ['CVE-2026-0001'],
    related_intel: [{ id: 'CVE-2026-0001', published: '2026-08-01', priority_score: 60, exploited: false, cisa_kev: false }],
  });
  const merged = mergeCampaign(existing, incoming);
  assert.equal(merged.first_seen, '2026-08-01', 'first_seen must reflect the earliest date even though it arrived in a later cycle');
  assert.equal(merged.last_seen, '2026-08-15');
});

test('idempotency: merging the identical batch twice produces the same result (no unbounded growth on replay)', () => {
  const existing = [campaign({ campaign_id: 'campaign:x' })];
  const batch = [campaign({ campaign_id: 'campaign:x', related_intel_ids: ['CVE-2026-0009'], related_intel: [{ id: 'CVE-2026-0009', published: '2026-08-05', priority_score: 60, exploited: false, cisa_kev: false }] })];
  const once  = mergeCampaigns(existing, batch);
  const twice = mergeCampaigns(once, batch);
  assert.deepEqual(once, twice);
});

test('adversarial: a malformed campaign missing campaign_id is skipped, not crashing', () => {
  const existing = [campaign({ campaign_id: 'campaign:ok' })];
  const incoming = [{ name: 'no id here' }, campaign({ campaign_id: 'campaign:ok2' })];
  assert.doesNotThrow(() => {
    const merged = mergeCampaigns(existing, incoming);
    assert.equal(merged.length, 2);
  });
});

test('adversarial: empty existing + empty incoming -> empty result, no crash', () => {
  assert.deepEqual(mergeCampaigns([], []), []);
  assert.deepEqual(mergeCampaigns(null, undefined), []);
});

test('adversarial: missing/null array fields on either side do not crash the merge', () => {
  const existing = campaign({ related_intel: null, shared_iocs: undefined, threat_actors: null });
  const incoming = campaign({ related_intel: undefined, shared_iocs: null, threat_actors: undefined });
  assert.doesNotThrow(() => mergeCampaign(existing, incoming));
});

test('adversarial: duplicate campaign_ids within the same incoming batch merge into one, not two', () => {
  const incoming = [
    campaign({ campaign_id: 'campaign:dup', related_intel_ids: ['CVE-2026-0001'] }),
    campaign({ campaign_id: 'campaign:dup', related_intel_ids: ['CVE-2026-0002'] }),
  ];
  const merged = mergeCampaigns([], incoming);
  assert.equal(merged.length, 1);
});

test('mergeCampaigns: sorts by severity desc, then item_count desc, deterministically', () => {
  const merged = mergeCampaigns([], [
    campaign({ campaign_id: 'campaign:low', severity: 'LOW', item_count: 5 }),
    campaign({ campaign_id: 'campaign:crit', severity: 'CRITICAL', item_count: 1 }),
    campaign({ campaign_id: 'campaign:high-big', severity: 'HIGH', item_count: 3 }),
    campaign({ campaign_id: 'campaign:high-small', severity: 'HIGH', item_count: 1 }),
  ]);
  assert.deepEqual(merged.map(c => c.campaign_id), ['campaign:crit', 'campaign:high-big', 'campaign:high-small', 'campaign:low']);
});

// ── saveCampaigns() catastrophic-drop guard ─────────────────────────────
// Mocks fs directly (node:test's built-in mock API) rather than touching
// the real api/intel/campaigns.json -- CAMPAIGNS_PATH is a module-level
// constant, not injectable, so this is the safe way to exercise the
// guard's actual read-before-write behavior without risking production data.
test('saveCampaigns: blocks a destructive write when existing count is well above the floor and new count is lower', (t) => {
  t.mock.method(fs, 'existsSync', () => true);
  t.mock.method(fs, 'readFileSync', () => JSON.stringify({ campaigns: Array.from({ length: 1187 }, (_, i) => ({ campaign_id: `c${i}` })) }));
  const writeSpy = t.mock.method(fs, 'writeFileSync', () => {});

  const result = saveCampaigns({ campaigns: [] }); // the exact production incident: 1187 -> 0

  assert.equal(result.saved, false);
  assert.equal(result.blocked, true);
  assert.equal(result.existingCount, 1187);
  assert.equal(writeSpy.mock.calls.length, 0, 'must not have written to disk');
});

test('saveCampaigns: allows growth (new count >= existing count)', (t) => {
  t.mock.method(fs, 'existsSync', () => true);
  t.mock.method(fs, 'readFileSync', () => JSON.stringify({ campaigns: Array.from({ length: 10 }, (_, i) => ({ campaign_id: `c${i}` })) }));
  const writeSpy = t.mock.method(fs, 'writeFileSync', () => {});

  const result = saveCampaigns({ campaigns: Array.from({ length: 12 }, (_, i) => ({ campaign_id: `c${i}` })) });

  assert.equal(result.saved, true);
  assert.equal(result.blocked, false);
  assert.equal(writeSpy.mock.calls.length, 1);
});

test('saveCampaigns: does not block below the floor (small/bootstrap state is allowed to fluctuate)', (t) => {
  t.mock.method(fs, 'existsSync', () => true);
  t.mock.method(fs, 'readFileSync', () => JSON.stringify({ campaigns: [{ campaign_id: 'c0' }, { campaign_id: 'c1' }] })); // below floor of 5
  const writeSpy = t.mock.method(fs, 'writeFileSync', () => {});

  const result = saveCampaigns({ campaigns: [] });

  assert.equal(result.saved, true);
  assert.equal(result.blocked, false);
  assert.equal(writeSpy.mock.calls.length, 1);
});

test('saveCampaigns: { allowDrop: true } explicitly bypasses the guard', (t) => {
  t.mock.method(fs, 'existsSync', () => true);
  t.mock.method(fs, 'readFileSync', () => JSON.stringify({ campaigns: Array.from({ length: 1187 }, (_, i) => ({ campaign_id: `c${i}` })) }));
  const writeSpy = t.mock.method(fs, 'writeFileSync', () => {});

  const result = saveCampaigns({ campaigns: [] }, { allowDrop: true });

  assert.equal(result.saved, true);
  assert.equal(result.blocked, false);
  assert.equal(writeSpy.mock.calls.length, 1);
});

test('saveCampaigns: no existing file at all (first-ever run) does not trip the guard', (t) => {
  t.mock.method(fs, 'existsSync', () => false);
  const writeSpy = t.mock.method(fs, 'writeFileSync', () => {});

  const result = saveCampaigns({ campaigns: [{ campaign_id: 'c0' }] });

  assert.equal(result.saved, true);
  assert.equal(writeSpy.mock.calls.length, 1);
});
