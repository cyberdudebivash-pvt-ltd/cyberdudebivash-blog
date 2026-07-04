'use strict';
const test = require('node:test');
const assert = require('node:assert');
const E = require('../detection-engine');

// ── ATT&CK mapping ────────────────────────────────────────────────────────
test('maps techniques with evidence', () => {
  const t = E.mapTechniques('attackers ran encoded PowerShell and used vssadmin to delete shadow copies');
  const ids = t.map((x) => x.technique_id);
  assert.ok(ids.includes('T1059.001'));
  assert.ok(ids.includes('T1490'));
  for (const m of t) assert.ok(m.evidence.length > 0);
});

test('no evidence -> no mapping', () => {
  assert.deepStrictEqual(E.mapTechniques('the quarterly finance review is next week'), []);
});

test('explicit technique ids extracted', () => {
  const t = E.mapTechniques('the advisory references T1574.002 behavior');
  assert.ok(t.some((m) => m.technique_id === 'T1574.002' && m.confidence === 'HIGH'));
});

test('technique id validation', () => {
  assert.ok(E.isValidTechniqueId('T1566.001'));
  assert.ok(!E.isValidTechniqueId('T9999'));
});

// ── cross-language UUID parity with the Python engine ─────────────────────
test('rule id matches the Python engine byte-for-byte', () => {
  // Python: uuid5(uuid5(NAMESPACE_DNS,"sentinel.cyberdudebivash.in"), title)
  assert.strictEqual(
    E.uuid5('Suspicious Encoded PowerShell Invocation'),
    '180ec008-0df2-59e2-a4d6-7b0797640f02',
  );
  assert.strictEqual(
    E.uuid5('LSASS Memory Access by Non-System Process'),
    'c46d4311-485b-54fb-ad82-cf02a98136d7',
  );
});

// ── format generation ─────────────────────────────────────────────────────
function art(tid) {
  return E.buildForTechnique(
    { technique_id: tid, tactic: E.KNOWN_TECHNIQUES[tid][1], evidence: 'sample evidence' },
    ['https://example.org/advisory'], '2026/07/04',
  );
}

test('powershell spec generates all four formats', () => {
  const a = art('T1059.001');
  assert.ok(a.sigma && a.kql && a.splunk && a.osquery);
});

test('lsass spec omits osquery honestly', () => {
  const a = art('T1003.001');
  assert.ok(a.kql && !a.osquery);
});

test('generated sigma parses as YAML-ish and carries evidence + id', () => {
  const a = art('T1490');
  assert.match(a.sigma, /^title: Shadow Copy Deletion/);
  assert.match(a.sigma, /id: [0-9a-f-]{36}/);
  assert.match(a.sigma, /Evidence basis: sample evidence/);
  assert.match(a.sigma, /attack\.t1490/);
});

test('kql valid, starts with table, has where', () => {
  const a = art('T1059.001');
  assert.strictEqual(a.kql.split('\n')[0], 'DeviceProcessEvents');
  assert.deepStrictEqual(E.validateKql(a.kql), []);
});

test('kql negation rendered for run-key filter', () => {
  const a = art('T1547.001');
  assert.match(a.kql, /where not \(/);
  assert.deepStrictEqual(E.validateKql(a.kql), []);
});

test('splunk and osquery validate', () => {
  const a = art('T1204.002');
  assert.deepStrictEqual(E.validateSplunk(a.splunk), []);
  const r = art('T1547.001');
  assert.deepStrictEqual(E.validateOsquery(r.osquery), []);
  assert.match(r.osquery, /^SELECT .* FROM registry WHERE .*;$/);
});

test('unknown technique returns null', () => {
  assert.strictEqual(E.buildForTechnique({ technique_id: 'T9999' }, [], '2026/07/04'), null);
});

// ── Suricata ──────────────────────────────────────────────────────────────
test('suricata for domain/ip/url with validation', () => {
  const iocs = [
    { type: 'domain', value: 'evil-c2.top' },
    { type: 'ip', value: '45.61.136.39' },
    { type: 'url', value: 'http://bad.example/malware.bin' },
  ];
  const rules = E.buildSuricata(iocs);
  assert.strictEqual(rules.length, 3);
  for (const r of rules) assert.deepStrictEqual(E.validateSuricata(r), []);
  assert.ok(rules.some((r) => r.includes('dns.query')));
  assert.ok(rules.some((r) => r.includes('http.host')));
});

test('suricata refangs defanged iocs', () => {
  const rules = E.buildSuricata([{ type: 'domain', value: 'evil[.]c2[.]top' }]);
  assert.match(rules[0], /content:"evil\.c2\.top"/);
});

test('suricata skips non-network iocs and unique sids', () => {
  assert.deepStrictEqual(E.buildSuricata([{ type: 'sha256', value: 'a'.repeat(64) }]), []);
  const rules = E.buildSuricata([{ type: 'domain', value: 'a.top' }, { type: 'domain', value: 'b.top' }], 5000);
  assert.match(rules[0], /sid:5000;/);
  assert.match(rules[1], /sid:5001;/);
});

// ── validators reject broken content ──────────────────────────────────────
test('validators reject malformed rules', () => {
  assert.ok(E.validateKql('| where x == 1').length > 0);
  assert.ok(E.validateOsquery('SELECT * FROM t WHERE a=1').some((p) => /semicolon/.test(p)));
  assert.ok(E.validateSplunk('| tstats count where (a=1').some((p) => /parentheses/.test(p)));
  assert.ok(E.validateSuricata('alert ip any any -> x any (msg:"x";)').some((p) => /sid/.test(p)));
});

// ── end-to-end ────────────────────────────────────────────────────────────
test('buildDetections end-to-end', () => {
  const text = 'operators ran encoded PowerShell, deleted volume shadow copies with vssadmin, and beaconed out';
  const iocs = [{ type: 'domain', value: 'evil-c2.top' }, { type: 'ip', value: '203.0.113.7' }];
  const { detections, suricata, techniques } = E.buildDetections(text, iocs, { references: ['https://ex.org/a'] });
  assert.ok(techniques.length >= 2);
  assert.ok(detections.some((d) => d.title.includes('Encoded PowerShell')));
  assert.strictEqual(suricata.length, 2);
});

test('no techniques and no iocs -> empty', () => {
  const { detections, suricata } = E.buildDetections('generic industry news about a conference', []);
  assert.deepStrictEqual(detections, []);
  assert.deepStrictEqual(suricata, []);
});
