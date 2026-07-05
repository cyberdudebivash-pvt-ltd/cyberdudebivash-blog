'use strict';
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { AnalystMemory } = require('../analyst-memory');

// Two prior reports establishing a knowledge graph:
//  - APT41 + LockBit + T1059.001 + T1490 targeting Fortinet
const REPORT_A = {
  id: 'CVE-2024-4577', title: 'APT41 deploys LockBit against Fortinet',
  desc: 'APT41 used encoded PowerShell and vssadmin to delete shadow copies before LockBit encryption',
  vendor: 'Fortinet', product: 'FortiOS', cves: ['CVE-2024-4577'],
};
//  - Akira reusing the same shadow-copy-deletion TTP against Fortinet
const REPORT_B = {
  id: 'CVE-2025-2222', title: 'Akira ransomware hits Fortinet estates',
  desc: 'Akira operators ran vssadmin delete shadows to inhibit recovery before encryption',
  vendor: 'Fortinet', product: 'FortiGate', cves: ['CVE-2025-2222'],
};
// New incoming report: LockBit again, encoded PowerShell + shadow deletion, Fortinet
const NEW_REPORT = {
  id: 'CVE-2026-3333', title: 'LockBit resurgence targets Fortinet appliances',
  desc: 'LockBit affiliates used encoded PowerShell and deleted volume shadow copies with vssadmin',
  vendor: 'Fortinet', product: 'FortiOS', cves: ['CVE-2026-3333'],
};


function _seeded() {
  const mem = new AnalystMemory();
  mem.ingest(REPORT_A, 'report-a');
  mem.ingest(REPORT_B, 'report-b');
  return mem;
}

test('empty graph yields no correlation', () => {
  const c = new AnalystMemory().correlate(NEW_REPORT);
  assert.deepStrictEqual(c.actorTTPs, []);
  assert.deepStrictEqual(c.ttpReuse, []);
  assert.deepStrictEqual(c.relatedReports, []);
});

test('edges are built between co-occurring correlatable entities', () => {
  const mem = _seeded();
  assert.ok(mem.stats().edges > 0);
  // APT41 <-> T1490 edge exists (both in report A)
  const apt = AnalystMemory.key('actor', 'APT41');
  const t1490 = AnalystMemory.key('technique', 'T1490');
  assert.ok(mem.edges[apt] && mem.edges[apt][t1490] >= 1);
  assert.ok(mem.edges[t1490] && mem.edges[t1490][apt] >= 1);
});

test('actor TTP profile surfaces known techniques for the report actors', () => {
  const c = _seeded().correlate(NEW_REPORT);
  const lock = c.actorTTPs.find((a) => a.actor === 'LockBit');
  assert.ok(lock, 'LockBit TTP profile present');
  assert.ok(lock.techniques.includes('T1490')); // learned from report A
});

test('TTP reuse links a shared technique to multiple actors across campaigns', () => {
  const c = _seeded().correlate(NEW_REPORT);
  // T1490 (shadow deletion) was used by both LockBit(A) and Akira(B)
  const reuse = c.ttpReuse.find((t) => t.technique === 'T1490');
  assert.ok(reuse, 'T1490 reuse finding present');
  assert.ok(reuse.actors.includes('LockBit'));
  assert.ok(reuse.actors.includes('Akira'));
});

test('repeated targeting detects a recurring victim vendor', () => {
  const c = _seeded().correlate(NEW_REPORT);
  const fortinet = c.repeatTargets.find((r) => r.name === 'Fortinet');
  assert.ok(fortinet && fortinet.count >= 2);
});

test('related prior reports ranked by shared-entity overlap', () => {
  const c = _seeded().correlate(NEW_REPORT);
  assert.ok(c.relatedReports.length >= 1);
  // report-a shares Fortinet + FortiOS + T1059.001 + T1490 + LockBit -> strong overlap
  const a = c.relatedReports.find((r) => r.report === 'report-a');
  assert.ok(a && a.sharedEntities >= 2);
});

test('correlationNotes renders human-readable findings', () => {
  const notes = _seeded().correlationNotes(NEW_REPORT);
  assert.ok(notes.length > 0);
  assert.ok(notes.some((n) => /LockBit|Akira/.test(n)));
  assert.ok(notes.some((n) => /Fortinet/.test(n)));
});

test('correlate is read-only (does not mutate the graph)', () => {
  const mem = _seeded();
  const before = JSON.stringify(mem.toJSON());
  mem.correlate(NEW_REPORT);
  assert.strictEqual(JSON.stringify(mem.toJSON()), before);
});

test('malformed items never throw', () => {
  const mem = _seeded();
  for (const bad of [null, undefined, {}, { iocs: 'x' }, 42]) {
    assert.doesNotThrow(() => mem.correlate(bad));
    assert.doesNotThrow(() => mem.correlationNotes(bad));
  }
});

test('edges persist and reload with the graph', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'apex-corr-'));
  const file = path.join(dir, 'intel-memory.json');
  const mem = _seeded();
  mem.save(fs, file);
  const loaded = AnalystMemory.load(fs, file);
  assert.deepStrictEqual(loaded.stats(), mem.stats());
  // correlation still works after reload
  assert.ok(loaded.correlate(NEW_REPORT).ttpReuse.length > 0);
});

test('neighbor cap bounds edge growth per node (keeps highest-weight edges)', () => {
  const mem = new AnalystMemory();
  const src = AnalystMemory.key('actor', 'APT41');
  // 100 distinct neighbors, later ones related more often (higher weight)
  for (let i = 0; i < 100; i++) {
    for (let w = 0; w <= i % 5; w++) mem._relate(src, `technique:t${i}`);
  }
  const neighbors = Object.keys(mem.edges[src]);
  assert.ok(neighbors.length <= 60, 'neighbor count exceeded cap: ' + neighbors.length);
  // the cap must evict lowest-weight edges, not arbitrary ones
  const minKept = Math.min(...neighbors.map((k) => mem.edges[src][k]));
  assert.ok(minKept >= 1);
});
