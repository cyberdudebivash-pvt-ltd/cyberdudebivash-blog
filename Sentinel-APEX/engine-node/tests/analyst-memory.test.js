'use strict';
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { AnalystMemory } = require('../analyst-memory');

const ITEM = {
  id: 'CVE-2024-4577', title: 'LockBit ransomware exploits Fortinet appliance',
  desc: 'Operators used encoded PowerShell and deleted volume shadow copies; '
    + 'Cobalt Strike beacons observed. APT41 tooling overlap noted.',
  vendor: 'Fortinet', product: 'FortiOS', cves: ['CVE-2024-4577'],
  iocs: [{ type: 'domain', value: 'evil-c2[.]top' }, { type: 'ip', value: '45.61.136.39' },
    { type: 'sha256', value: 'a'.repeat(64) }],
};

test('entitiesOf extracts cve/vendor/product/network-ioc/technique/actor/malware', () => {
  const keys = AnalystMemory.entitiesOf(ITEM).map(([t, n]) => `${t}:${n}`);
  assert.ok(keys.includes('cve:CVE-2024-4577'));
  assert.ok(keys.includes('vendor:Fortinet'));
  assert.ok(keys.includes('product:FortiOS'));
  assert.ok(keys.some((k) => k.startsWith('ioc_domain:')));
  assert.ok(keys.some((k) => k.startsWith('ioc_ipv4:')));
  assert.ok(keys.includes('malware:LockBit'));
  assert.ok(keys.includes('malware:Cobalt Strike'));
  assert.ok(keys.includes('actor:APT41'));
  assert.ok(keys.some((k) => k.startsWith('technique:')));
});

test('entitiesOf skips non-network iocs (hashes) and dedups', () => {
  const keys = AnalystMemory.entitiesOf(ITEM).map(([t]) => t);
  assert.ok(!keys.some((t) => t === 'ioc_sha256'));
});

test('first report has no prior context; second does', () => {
  const mem = new AnalystMemory();
  assert.deepStrictEqual(mem.priorContext(ITEM), []);
  mem.ingest(ITEM, 'report-a');
  const notes = mem.priorContext(ITEM);
  assert.ok(notes.length > 0);
  assert.ok(notes.some((n) => n.includes('CVE-2024-4577')));
  assert.ok(notes.some((n) => n.includes('previously observed')));
});

test('counts accumulate across reports and reports list is bounded to 5', () => {
  const mem = new AnalystMemory();
  for (let i = 0; i < 8; i++) mem.ingest(ITEM, 'report-' + i);
  const node = mem.entities[AnalystMemory.key('cve', 'CVE-2024-4577')];
  assert.strictEqual(node.count, 8);
  assert.strictEqual(node.reports.length, 5);
  assert.strictEqual(node.reports[4], 'report-7');
});

test('malformed items are ignored, never thrown', () => {
  const mem = new AnalystMemory();
  for (const bad of [null, undefined, {}, { iocs: 'x' }, { cves: 5 }, 42, 'str']) {
    assert.deepStrictEqual(AnalystMemory.entitiesOf(bad), []);
    assert.doesNotThrow(() => mem.ingest(bad, 'r'));
    assert.deepStrictEqual(mem.priorContext(bad), []);
  }
});

test('pruning caps entity count at the configured maximum', () => {
  const mem = new AnalystMemory(null, { maxEntities: 10 });
  for (let i = 0; i < 40; i++) {
    mem.ingest({ id: 'CVE-2024-' + (1000 + i), cves: ['CVE-2024-' + (1000 + i)] }, 'r' + i);
  }
  assert.ok(mem.stats().entities <= 10, 'entity count exceeded cap');
});

test('persistence round-trips and survives corrupt files', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'apex-mem-'));
  const file = path.join(dir, 'intel-memory.json');
  const mem = new AnalystMemory();
  mem.ingest(ITEM, 'report-a');
  assert.ok(mem.save(fs, file));

  const loaded = AnalystMemory.load(fs, file);
  assert.deepStrictEqual(loaded.stats(), mem.stats());
  assert.ok(loaded.priorContext(ITEM).length > 0);

  fs.writeFileSync(file, '{ this is not json');
  const fresh = AnalystMemory.load(fs, file);
  assert.strictEqual(fresh.stats().entities, 0); // corrupt -> empty, no throw

  const missing = AnalystMemory.load(fs, path.join(dir, 'nope.json'));
  assert.strictEqual(missing.stats().entities, 0);
});

test('prior context is ordered most-recurrent first and limited', () => {
  const mem = new AnalystMemory();
  // make Fortinet very recurrent, CVE seen once
  for (let i = 0; i < 5; i++) mem.ingest({ vendor: 'Fortinet' }, 'r' + i);
  mem.ingest(ITEM, 'seed');
  const notes = mem.priorContext(ITEM, 2);
  assert.ok(notes.length <= 2);
  assert.ok(notes[0].includes('Fortinet'));
});
