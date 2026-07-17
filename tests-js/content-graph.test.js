'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { getEntity, ENTITY_TYPES } = require('../api/_lib/content-graph');

test('getEntity returns not-found for an empty id', () => {
  const result = getEntity('cve', '');
  assert.strictEqual(result.found, false);
  assert.deepStrictEqual(result.related, []);
});

test('getEntity returns not-found and an error for an unknown entity type', () => {
  const result = getEntity('spaceship', 'x');
  assert.strictEqual(result.found, false);
  assert.match(result.error, /Unknown entity type/);
});

test('getEntity resolves a real vendor (npm) from repo data with related CVE links', () => {
  const result = getEntity('vendor', 'npm');
  assert.strictEqual(result.type, 'vendor');
  assert.strictEqual(result.found, true);
  assert.strictEqual(result.data.slug, 'npm');
  assert.ok(result.data.count > 0);
  assert.ok(result.related.length > 0);
  assert.strictEqual(result.related[0].type, 'cve');
  assert.ok(result.related[0].url.startsWith('/cve/'));
});

test('getEntity returns not-found for a nonexistent vendor', () => {
  const result = getEntity('vendor', 'totally-not-a-real-vendor-xyz');
  assert.strictEqual(result.found, false);
});

test('getEntity resolves a real CVE and links back to its real vendor when known', () => {
  const vendorResult = getEntity('vendor', 'npm');
  const sampleCveId = vendorResult.data.items[0].id;
  const cveResult = getEntity('cve', sampleCveId);
  assert.strictEqual(cveResult.found, true);
  assert.strictEqual(cveResult.data.vendor, 'npm');
  assert.ok(cveResult.related.some((r) => r.type === 'vendor' && r.id === 'npm'));
});

test('getEntity returns not-found for a nonexistent CVE', () => {
  const result = getEntity('cve', 'CVE-0000-00000-DOES-NOT-EXIST');
  assert.strictEqual(result.found, false);
});

test('getEntity resolves a real populated collection with linked reports', () => {
  const result = getEntity('collection', 'ransomware-intelligence');
  assert.strictEqual(result.found, true);
  assert.ok(result.data.count > 0);
  assert.ok(result.related.length > 0);
  assert.strictEqual(result.related[0].type, 'report');
});

test('getEntity returns not-found for a nonexistent collection', () => {
  const result = getEntity('collection', 'not-a-real-collection');
  assert.strictEqual(result.found, false);
});

test('getEntity returns not-found (not a crash) for campaign/actor lookups against empty graph data', () => {
  // api/intel/campaigns.json and threat-graph.json may legitimately have
  // zero entries right now — this must degrade to not-found, never throw.
  assert.doesNotThrow(() => getEntity('campaign', 'campaign:does-not-exist'));
  assert.doesNotThrow(() => getEntity('actor', 'nonexistent-actor'));
  const campaignResult = getEntity('campaign', 'campaign:does-not-exist');
  assert.strictEqual(campaignResult.found, false);
});

test('ENTITY_TYPES lists exactly the five supported types', () => {
  assert.deepStrictEqual(ENTITY_TYPES, ['cve', 'vendor', 'actor', 'campaign', 'collection']);
});
