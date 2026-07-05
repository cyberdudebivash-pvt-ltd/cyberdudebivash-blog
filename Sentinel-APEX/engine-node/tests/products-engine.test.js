'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { buildProducts, hasProducts } = require('../products-engine');
const { AnalystMemory } = require('../analyst-memory');

const ITEM = {
  id: 'CVE-2024-4577', type: 'RANSOMWARE',
  title: 'LockBit exploits public-facing PHP to deploy ransomware',
  desc: 'Attackers exploited a public-facing application, ran encoded PowerShell, and '
    + 'deleted volume shadow copies with vssadmin before encrypting files.',
  vendor: 'PHP', product: 'PHP-CGI', cves: ['CVE-2024-4577'], cvss: 9.8,
  cisaKev: true, exploited: true, sourceCount: 3, link: 'https://vendor.example/adv',
  iocs: [{ type: 'domain', value: 'evil-c2.top', confidence_score: 0.9 },
    { type: 'ip', value: '45.61.136.39' }],
};

test('produces all six deliverables for a rich item', () => {
  const p = buildProducts(ITEM);
  assert.ok(p.executiveAdvisory && p.boardBrief && p.socBulletin && p.huntingGuide);
  assert.ok(Array.isArray(p.iocFeed) && p.iocFeed.length === 2);
  assert.ok(p.apiPackage);
  assert.ok(hasProducts(p));
});

test('executive advisory carries situation, business risk, and decisions', () => {
  const p = buildProducts(ITEM);
  assert.ok(p.executiveAdvisory.situation.some((s) => /CVE-2024-4577/.test(s)));
  assert.ok(p.executiveAdvisory.businessRisk.length > 0);
  assert.ok(p.executiveAdvisory.decisions.every((d) => d.owner && d.decision && d.timeline));
});

test('board brief is concise strategic bullets mentioning regulatory exposure', () => {
  const b = buildProducts(ITEM).boardBrief;
  assert.ok(b.bullets.length >= 4 && b.bullets.length <= 6);
  assert.ok(b.bullets.some((x) => /GDPR|NIS2|DORA|regulatory/i.test(x)));
});

test('SOC bulletin lists detections, platforms, and IOCs to block', () => {
  const s = buildProducts(ITEM).socBulletin;
  assert.strictEqual(s.severity, 'CRITICAL');
  assert.ok(s.detectionCoverage.techniques.length > 0);
  assert.ok(s.detectionCoverage.platforms.includes('sigma'));
  assert.ok(s.iocsToBlock.length === 2);
  assert.ok(s.immediateActions.some((a) => /^P0/.test(a)));
});

test('IOC feed + human surfaces are defanged; functional rules use live values', () => {
  const p = buildProducts(ITEM);
  // IOC feed and SOC block-list are defanged
  assert.ok(p.iocFeed.every((i) => !/(^|[^[])\.[a-z]/.test(i.value) || i.value.includes('[.]')));
  assert.ok(p.iocFeed.some((i) => i.value === 'evil-c2[.]top'));
  assert.ok(p.socBulletin.iocsToBlock.some((i) => i.value === 'evil-c2[.]top'));
  // the API package's IOC list is defanged too
  assert.ok(p.apiPackage.iocs.some((i) => i.value === 'evil-c2[.]top'));
  assert.ok(!p.apiPackage.iocs.some((i) => i.value === 'evil-c2.top'));
  // but functional Suricata rules legitimately use live values to match traffic
  assert.ok(p.apiPackage.detections.suricata.some((r) => r.includes('45.61.136.39')));
});

test('hunting guide derives hypotheses from evidenced techniques + non-sigma queries', () => {
  const h = buildProducts(ITEM).huntingGuide;
  assert.ok(h.hypotheses.length > 0);
  assert.ok(h.hypotheses.every((x) => x.technique && x.hypothesis));
  assert.ok(h.queries.some((q) => q.platform === 'kql'));
  assert.ok(!h.queries.some((q) => q.platform === 'sigma')); // sigma is in detections, not hunts
});

test('API package is machine-readable and self-describing', () => {
  const a = buildProducts(ITEM).apiPackage;
  assert.strictEqual(a.schema, 'sentinel-apex.intelligence/1.0');
  assert.strictEqual(a.severity, 'CRITICAL');
  assert.strictEqual(a.cvss, 9.8);
  assert.strictEqual(a.cisa_kev, true);
  assert.ok(a.mitre_attack.length > 0);
  assert.ok(a.detections.sigma.length > 0);
  assert.ok(a.assessment.verified_facts.length > 0);
  assert.ok(a.assessment.analyst_assessments.every((x) => x.confidence));
  // round-trips as JSON (API-serializable)
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(a)));
});

test('correlation flows into the API package when memory is provided', () => {
  const mem = new AnalystMemory();
  mem.ingest({ id: 'CVE-2023-1', title: 'APT41 LockBit against PHP',
    desc: 'APT41 vssadmin delete shadows encoded PowerShell', vendor: 'PHP' }, 'prior');
  const a = buildProducts(ITEM, mem).apiPackage;
  assert.ok(a.correlations.length > 0);
});

test('malformed items never throw and yield empty products', () => {
  for (const bad of [null, undefined, 42, 'x', [], {}]) {
    const p = buildProducts(bad);
    assert.doesNotThrow(() => JSON.stringify(p));
    if (bad && typeof bad === 'object' && !Array.isArray(bad) && Object.keys(bad).length) continue;
    assert.strictEqual(hasProducts(p), false, `expected no products for ${String(bad)}`);
  }
});

test('thin item produces API package but minimal detection/IOC content', () => {
  const p = buildProducts({ id: 'NEWS-1', title: 'Security conference announced',
    desc: 'Registration opens next month.' });
  assert.ok(p.apiPackage);                       // still emits a package
  assert.strictEqual(p.iocFeed.length, 0);
  assert.strictEqual(p.apiPackage.detections.sigma.length, 0);
});
