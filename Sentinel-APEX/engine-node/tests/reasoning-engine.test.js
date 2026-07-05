'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { buildReasoning, hasSubstance } = require('../reasoning-engine');
const { AnalystMemory } = require('../analyst-memory');

const RANSOMWARE = {
  id: 'CVE-2024-4577', title: 'LockBit exploits public-facing PHP to deploy ransomware',
  desc: 'Attackers exploited a public-facing application, ran encoded PowerShell, and '
    + 'deleted volume shadow copies with vssadmin before encrypting files.',
  vendor: 'PHP', product: 'PHP-CGI', cves: ['CVE-2024-4577'],
  cvss: 9.8, cisaKev: true, exploited: true, sourceCount: 3,
  iocs: [{ type: 'domain', value: 'evil.top' }],
};

const THIN = { id: 'NEWS-1', title: 'Vendor announces a security conference',
  desc: 'Registration opens next month for general industry topics.' };

test('facts contain only directly-supported statements', () => {
  const r = buildReasoning(RANSOMWARE);
  assert.ok(r.facts.some((f) => f.includes('CVE-2024-4577')));
  assert.ok(r.facts.some((f) => f.includes('CVSS base score of 9.8')));
  assert.ok(r.facts.some((f) => /KEV/.test(f)));
  // a fact must never be phrased as an assessment
  assert.ok(!r.facts.some((f) => /assessed|likely|probable/i.test(f)));
});

test('every assessment carries a confidence label', () => {
  const r = buildReasoning(RANSOMWARE);
  assert.ok(r.assessments.length > 0);
  for (const a of r.assessments) {
    assert.ok(['LOW', 'MEDIUM', 'HIGH'].includes(a.confidence), a.confidence);
    assert.ok(a.text && a.text.length > 0);
  }
});

test('ransomware TTPs drive a high-confidence classification assessment', () => {
  const r = buildReasoning(RANSOMWARE);
  const cls = r.assessments.find((a) => /ransomware operation/.test(a.text));
  assert.ok(cls && cls.confidence === 'HIGH');
});

test('KEV/exploited yields active-risk assessment and high-confidence outlook', () => {
  const r = buildReasoning(RANSOMWARE);
  assert.ok(r.assessments.some((a) => /active — not theoretical/.test(a.text) && a.confidence === 'HIGH'));
  assert.ok(r.outlook.some((o) => o.confidence === 'HIGH'));
});

test('CVSS is a fact; severity is an assessment (facts/assessments never blur)', () => {
  const r = buildReasoning(RANSOMWARE);
  assert.ok(r.facts.some((f) => /CVSS base score of 9\.8/.test(f)));
  assert.ok(r.assessments.some((a) => /severity is assessed as critical/.test(a.text)));
});

test('thin report honestly reports gaps and stays sparse', () => {
  const r = buildReasoning(THIN);
  assert.ok(r.gaps.length >= 3);
  assert.ok(r.gaps.some((g) => /No confirmed public IOCs/.test(g)));
  assert.ok(r.gaps.some((g) => /exploitation is unconfirmed/.test(g)));
  assert.ok(r.gaps.some((g) => /Attribution/.test(g)));
  // no fabricated severity/classification without evidence
  assert.ok(!r.assessments.some((a) => /ransomware/.test(a.text)));
});

test('gaps disappear as evidence appears (no IOC gap when IOCs present)', () => {
  const withIoc = buildReasoning(RANSOMWARE);
  assert.ok(!withIoc.gaps.some((g) => /No confirmed public IOCs/.test(g)));
  const noIoc = buildReasoning({ ...RANSOMWARE, iocs: [] });
  assert.ok(noIoc.gaps.some((g) => /No confirmed public IOCs/.test(g)));
});

test('correlated observations are sourced from the knowledge graph', () => {
  const mem = new AnalystMemory();
  mem.ingest({ id: 'CVE-2023-1', title: 'APT41 LockBit against Fortinet',
    desc: 'APT41 vssadmin delete shadows and encoded PowerShell', vendor: 'Fortinet' }, 'prior');
  const r = buildReasoning({ ...RANSOMWARE, vendor: 'Fortinet' }, mem);
  assert.ok(r.observations.length > 0);
  // attribution caveat appears once actor correlation exists
  assert.ok(r.assessments.some((a) => /attribution derives from historical/i.test(a.text) && a.confidence === 'LOW'));
});

test('non-object inputs never throw and yield a fully empty structure', () => {
  for (const bad of [null, undefined, 42, 'x', []]) {
    const r = buildReasoning(bad);
    const total = r.facts.length + r.assessments.length + r.observations.length
      + r.gaps.length + r.outlook.length;
    assert.strictEqual(total, 0, `expected empty for ${String(bad)}`);
  }
});

test('empty object {} does not throw and produces only honest gaps', () => {
  const r = buildReasoning({});
  assert.strictEqual(r.facts.length, 0);
  assert.strictEqual(r.assessments.length, 0);
  assert.ok(r.gaps.length > 0); // an evidence-free item is all unknowns
});

test('hasSubstance gates rendering correctly', () => {
  assert.ok(hasSubstance(buildReasoning(RANSOMWARE)));
  assert.ok(!hasSubstance(buildReasoning(null)));
});
