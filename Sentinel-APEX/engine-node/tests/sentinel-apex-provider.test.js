'use strict';
// Tests the Sentinel APEX native-provider layer added to the live generator
// (fetch-live-intel.js): envelope extraction, canonical ID derivation, and
// per-record normalization. The live intel.cyberdudebivash.com schema could
// not be verified from the sandbox this was written in (outbound access to
// the host is blocked by that environment's network policy — see the
// comment above normalizeSentinelApexRecord in fetch-live-intel.js), so
// these tests exercise the mapper's *contract* — defensive field handling,
// multiple schema variants, graceful degradation on malformed input — with
// synthetic fixtures, not asserted-real production payloads. Requiring the
// generator is side-effect-free (only runs the pipeline when invoked
// directly), same as generator-wiring.test.js.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const GEN = path.join(__dirname, '..', '..', '..', 'fetch-live-intel.js');
const gen = require(GEN);

/* ─── extractSentinelApexRecords — envelope tolerance ────────────────── */

test('extractSentinelApexRecords unwraps a raw array', () => {
  const recs = [{ title: 'a' }, { title: 'b' }];
  assert.deepStrictEqual(gen.extractSentinelApexRecords(recs), recs);
});

for (const key of ['items', 'data', 'results', 'reports', 'records', 'articles', 'intel', 'threats', 'summaries']) {
  test(`extractSentinelApexRecords unwraps {${key}: [...]}`, () => {
    const recs = [{ title: 'x' }];
    assert.deepStrictEqual(gen.extractSentinelApexRecords({ [key]: recs }), recs);
  });
}

test('extractSentinelApexRecords unwraps a STIX 2.1 bundle', () => {
  const objects = [{ type: 'indicator', id: 'indicator--abc', name: 'x' }];
  assert.deepStrictEqual(gen.extractSentinelApexRecords({ type: 'bundle', objects }), objects);
});

test('extractSentinelApexRecords wraps a single-record object (ai_summary.json shape)', () => {
  const single = { title: 'Daily AI Threat Summary', summary: 'text' };
  assert.deepStrictEqual(gen.extractSentinelApexRecords(single), [single]);
});

test('extractSentinelApexRecords returns [] for null/undefined/non-object', () => {
  assert.deepStrictEqual(gen.extractSentinelApexRecords(null), []);
  assert.deepStrictEqual(gen.extractSentinelApexRecords(undefined), []);
  assert.deepStrictEqual(gen.extractSentinelApexRecords('not json'), []);
  assert.deepStrictEqual(gen.extractSentinelApexRecords(42), []);
});

test('extractSentinelApexRecords returns [] for an unrecognized envelope shape', () => {
  assert.deepStrictEqual(gen.extractSentinelApexRecords({ foo: 'bar', count: 3 }), []);
});

/* ─── sapexCanonicalId — dedup-key derivation ────────────────────────── */

test('sapexCanonicalId prefers a real CVE id', () => {
  assert.strictEqual(gen.normalizeSentinelApexRecord({
    title: 'Widget RCE', description: 'x', cve_id: 'cve-2026-12345',
  }, 'latest').id, 'CVE-2026-12345');
});

test('normalizeSentinelApexRecord derives a deterministic hash id when no CVE is present', () => {
  const raw = { id: 'intel--fixed-uuid-1', title: 'Sentinel APEX Threat Note' };
  const a = gen.normalizeSentinelApexRecord(raw, 'latest');
  const b = gen.normalizeSentinelApexRecord(raw, 'latest');
  assert.match(a.id, /^SENTINELAPEX-[0-9a-f]{12}$/);
  assert.strictEqual(a.id, b.id); // same input -> same id every run (dedup-stable)
});

test('normalizeSentinelApexRecord falls back to a title hash when no native id is present', () => {
  const item = gen.normalizeSentinelApexRecord({ title: 'Only A Title Here' }, 'feed');
  assert.match(item.id, /^SENTINELAPEX-[0-9a-f]{12}$/);
});

/* ─── normalizeSentinelApexRecord — defensive field mapping ──────────── */

test('normalizeSentinelApexRecord maps a rich, STIX-flavored record', () => {
  const item = gen.normalizeSentinelApexRecord({
    id: 'intel--e1f2', title: 'Acme Gateway Auth Bypass', cve_id: 'CVE-2026-40001',
    severity: 'critical', vendor: 'Acme', product: 'Gateway',
    description: 'Unauthenticated attacker bypasses login on Acme Gateway.',
    external_references: [{ url: 'https://intel.cyberdudebivash.com/r/1', source_name: 'Sentinel APEX' }],
    exploited: true, cisa_kev: false, published: '2026-06-01T00:00:00Z',
  }, 'apex');
  assert.strictEqual(item.source, 'sentinel_apex');
  assert.strictEqual(item.id, 'CVE-2026-40001');
  assert.strictEqual(item.title, 'Acme Gateway Auth Bypass');
  assert.strictEqual(item.cvss, 9.5); // 'critical' label -> approximated score
  assert.strictEqual(item.vendor, 'Acme');
  assert.strictEqual(item.product, 'Gateway');
  assert.strictEqual(item.exploited, true);
  assert.deepStrictEqual(item.cves, ['CVE-2026-40001']);
  assert.ok(item.refs.includes('https://intel.cyberdudebivash.com/r/1'));
  assert.strictEqual(item.pubDate, '2026-06-01');
});

test('normalizeSentinelApexRecord tolerates an alternate field-name variant of the same record', () => {
  // Same facts as the test above, different key names throughout.
  const item = gen.normalizeSentinelApexRecord({
    uuid: 'r-9001', name: 'Acme Gateway Auth Bypass', cves: ['CVE-2026-40001'],
    threat_level: 'critical', affected_vendor: 'Acme', affected_product: 'Gateway',
    summary: 'Unauthenticated attacker bypasses login on Acme Gateway.',
    links: ['https://intel.cyberdudebivash.com/r/1'],
    in_the_wild: true, created: '2026-06-01T00:00:00Z',
  }, 'latest');
  assert.strictEqual(item.id, 'CVE-2026-40001');
  assert.strictEqual(item.cvss, 9.5);
  assert.strictEqual(item.vendor, 'Acme');
  assert.strictEqual(item.exploited, true);
  assert.strictEqual(item.pubDate, '2026-06-01');
});

test('normalizeSentinelApexRecord extracts a CVE embedded only in free text', () => {
  const item = gen.normalizeSentinelApexRecord({
    title: 'Patch now', description: 'Exploitation of CVE-2026-55555 observed in the wild.',
  }, 'feed');
  assert.deepStrictEqual(item.cves, ['CVE-2026-55555']);
  assert.strictEqual(item.id, 'CVE-2026-55555');
});

test('normalizeSentinelApexRecord falls back to text-extracted IOCs when no explicit IOC array is present', () => {
  const item = gen.normalizeSentinelApexRecord({
    title: 'C2 activity observed', description: 'Beaconing traffic to 203.0.113.45 during the campaign.',
  }, 'feed');
  assert.ok(item.iocs.some(i => i.type === 'ipv4' && i.value === '203.0.113.45'));
});

test('normalizeSentinelApexRecord maps an explicit IOC array with a legitimate zero confidence score', () => {
  const item = gen.normalizeSentinelApexRecord({
    title: 'X', description: 'Y',
    iocs: [{ type: 'IPv4', value: '198.51.100.9', confidence_score: 0 }],
  }, 'latest');
  assert.strictEqual(item.iocs[0].type, 'ipv4');
  assert.strictEqual(item.iocs[0].value, '198.51.100.9');
  assert.strictEqual(item.iocs[0].confidence_score, 0); // explicit 0 must survive, not be coerced to the 0.75 default
});

test('normalizeSentinelApexRecord ignores unrecognized/extra fields without error', () => {
  const item = gen.normalizeSentinelApexRecord({
    title: 'Future Schema Field Test', description: 'x',
    some_field_added_later: { nested: true }, another_new_thing: [1, 2, 3],
  }, 'latest');
  assert.strictEqual(item.title, 'Future Schema Field Test');
});

test('normalizeSentinelApexRecord returns null (skips, does not fabricate) when no title/description exist', () => {
  assert.strictEqual(gen.normalizeSentinelApexRecord({ some_id: 123 }, 'latest'), null);
});

test('normalizeSentinelApexRecord never throws on malformed input', () => {
  for (const bad of [null, undefined, 'a string', 42, [], { iocs: 'not-an-array' }, { references: 12345 }]) {
    assert.doesNotThrow(() => gen.normalizeSentinelApexRecord(bad, 'latest'));
  }
});

/* ─── Native MITRE mapping — preferred over regex inference ──────────── */

test('sapexNativeMitre maps a native ATT&CK technique', () => {
  const mitre = gen.sapexNativeMitre({
    mitre_tactics: [{ tactic: 'Initial Access', technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application' }],
  });
  assert.strictEqual(mitre.tactic, 'Initial Access');
  assert.strictEqual(mitre.technique, 'T1190 — Exploit Public-Facing Application');
  assert.ok(!mitre.atlas);
});

test('sapexNativeMitre flags MITRE ATLAS technique ids', () => {
  const mitre = gen.sapexNativeMitre({
    mitre: [{ tactic: 'ML Model Access', technique_id: 'AML.T0051', technique_name: 'LLM Prompt Injection' }],
  });
  assert.strictEqual(mitre.framework, 'ATLAS');
  assert.strictEqual(mitre.atlas, true);
});

test('sapexNativeMitre returns null when no MITRE-shaped field is present', () => {
  assert.strictEqual(gen.sapexNativeMitre({ title: 'x', description: 'y' }), null);
});

test('normalizeSentinelApexRecord attaches mitreNative onto the produced item', () => {
  const item = gen.normalizeSentinelApexRecord({
    title: 'x', description: 'y',
    mitre_tactics: [{ tactic: 'Execution', technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter' }],
  }, 'apex');
  assert.ok(item.mitreNative);
  assert.match(item.mitreNative.technique, /T1059/);
});

test('generatePostHTML renders the native MITRE mapping instead of the regex-inferred one', () => {
  const item = {
    id: 'CVE-2024-4577', title: 'PHP-CGI argument injection exploited to deploy ransomware',
    desc: 'Attackers exploited a public-facing PHP flaw to deploy ransomware.',
    vendor: 'PHP', product: 'PHP-CGI', cvss: 9.8, threatLevel: 'CRITICAL', priority: 95,
    type: 'RANSOMWARE', cves: ['CVE-2024-4577'], iocs: [], refs: ['https://vendor.example/advisory'],
    pubDate: new Date().toISOString(),
    // Deliberately distinct from whatever getMitre() would infer for this
    // (ransomware-flavored) text, so a match proves override actually
    // happened rather than coincidentally matching the inferred mapping.
    mitreNative: { tactic: 'Custom Native Tactic', technique: 'T9999 — Sentinel APEX Native Mapping Test' },
  };
  const { html } = gen.generatePostHTML(item);
  assert.ok(html.includes('T9999'), 'expected the native mapping to appear in rendered output');
  assert.strictEqual(item._mitre.technique, 'T9999 — Sentinel APEX Native Mapping Test');
});

/* ─── correlateAndMerge — cross-source dedup integration ─────────────── */

test('correlateAndMerge collapses a shared CVE across nvd and sentinel_apex into one item', () => {
  const nvdItem = {
    source: 'nvd', id: 'CVE-2024-9999', title: 'NVD title wins the tie-break',
    desc: 'NVD description', cvss: 8.0, pubDate: '2026-01-01', vendor: 'Acme', product: 'Widget',
    exploited: false, cisaKev: false, ransomware: false, cves: ['CVE-2024-9999'],
    iocs: [], refs: ['https://nvd.nist.gov/x'], sourceCount: 1,
  };
  const sapexItem = gen.normalizeSentinelApexRecord({
    id: 'intel--abc123', title: 'Sentinel APEX title', description: 'Sentinel APEX description',
    cve_id: 'CVE-2024-9999', severity: 'high',
    references: ['https://intel.cyberdudebivash.com/y'],
    mitre_tactics: [{ tactic: 'Execution', technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter' }],
  }, 'latest');

  const merged = gen.correlateAndMerge([[nvdItem], [sapexItem]]);
  assert.strictEqual(merged.length, 1); // deduped, not two separate posts for the same CVE
  const item = merged[0];
  assert.strictEqual(item.sourceCount, 2);
  assert.strictEqual(item.title, 'NVD title wins the tie-break'); // nvd (rank 9) > sentinel_apex (rank 7)
  // ... but the richer native MITRE mapping must survive regardless of which side won the tie-break.
  assert.ok(item.mitreNative);
  assert.match(item.mitreNative.technique, /T1059/);
  assert.ok(item.refs.includes('https://nvd.nist.gov/x'));
  assert.ok(item.refs.includes('https://intel.cyberdudebivash.com/y'));
});

test('correlateAndMerge keeps a standalone sentinel_apex item (no collision) untouched', () => {
  const item = gen.normalizeSentinelApexRecord({ title: 'Solo APEX Item', description: 'No collision here', severity: 'medium' }, 'feed');
  const merged = gen.correlateAndMerge([[item]]);
  assert.strictEqual(merged.length, 1);
  assert.strictEqual(merged[0].source, 'sentinel_apex');
  assert.strictEqual(merged[0].sourceCount, 1);
});

test('correlateAndMerge does not merge items with different CVE ids', () => {
  const a = gen.normalizeSentinelApexRecord({ title: 'A', description: 'x', cve_id: 'CVE-2026-00001' }, 'latest');
  const b = gen.normalizeSentinelApexRecord({ title: 'B', description: 'y', cve_id: 'CVE-2026-00002' }, 'latest');
  const merged = gen.correlateAndMerge([[a], [b]]);
  assert.strictEqual(merged.length, 2);
});
