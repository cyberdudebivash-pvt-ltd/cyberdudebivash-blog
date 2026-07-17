'use strict';
const test = require('node:test');
const assert = require('node:assert');
const {
  isRealVendor, slugify, buildVendorIndex, buildTimeline,
  buildCollections, buildDetectionLibrary, articlesMatching,
} = require('../api/_lib/intelligence-hub');

/* ─── isRealVendor ───────────────────────────────────────────── */

test('isRealVendor rejects known news/citation sources', () => {
  assert.strictEqual(isRealVendor('SecurityWeek'), false);
  assert.strictEqual(isRealVendor('BleepingComputer'), false);
  assert.strictEqual(isRealVendor('The Hacker News'), false);
  assert.strictEqual(isRealVendor('reddit_cyber'), false);
  assert.strictEqual(isRealVendor('reddit_netsec'), false);
  assert.strictEqual(isRealVendor('SANS ISC'), false);
});

test('isRealVendor rejects empty/whitespace values', () => {
  assert.strictEqual(isRealVendor(''), false);
  assert.strictEqual(isRealVendor('   '), false);
  assert.strictEqual(isRealVendor(undefined), false);
});

test('isRealVendor accepts real technology vendors', () => {
  assert.strictEqual(isRealVendor('Microsoft'), true);
  assert.strictEqual(isRealVendor('Cisco'), true);
  assert.strictEqual(isRealVendor('JetBrains'), true);
});

test('isRealVendor accepts real open-source package ecosystems', () => {
  assert.strictEqual(isRealVendor('npm'), true);
  assert.strictEqual(isRealVendor('pip'), true);
  assert.strictEqual(isRealVendor('go'), true);
});

/* ─── slugify ─────────────────────────────────────────────────── */

test('slugify normalizes real-world vendor names', () => {
  assert.strictEqual(slugify('The Hacker News'), 'the-hacker-news');
  assert.strictEqual(slugify('D-Link'), 'd-link');
  assert.strictEqual(slugify(''), 'unknown');
});

/* ─── buildVendorIndex ───────────────────────────────────────── */

const CVES = [
  { id: 'CVE-2026-0001', title: 'Microsoft Windows RCE', vendor: 'Microsoft', cvss: 9.8, cisa_kev: true, exploited: true },
  { id: 'CVE-2026-0002', title: 'Microsoft Exchange flaw', vendor: 'Microsoft', cvss: 7.5, cisa_kev: false, exploited: false },
  { id: 'CVE-2026-0003', title: 'npm package RCE', vendor: 'npm', cvss: 8.1, cisa_kev: false, exploited: false },
  { id: 'CVE-2026-0004', title: 'Aggregator roundup', vendor: 'SecurityWeek', cvss: 5.0, cisa_kev: false, exploited: false },
  { id: 'CVE-2026-0005', title: 'No vendor known', vendor: '', cvss: 6.0, cisa_kev: false, exploited: false },
];

test('buildVendorIndex groups only real vendors, excludes source labels', () => {
  const vendors = buildVendorIndex(CVES, { minItems: 1 });
  const slugs = vendors.map((v) => v.slug);
  assert.ok(slugs.includes('microsoft'));
  assert.ok(slugs.includes('npm'));
  assert.ok(!slugs.includes('securityweek'));
});

test('buildVendorIndex computes real per-vendor stats and links to canonical CVE pages', () => {
  const vendors = buildVendorIndex(CVES, { minItems: 1 });
  const ms = vendors.find((v) => v.slug === 'microsoft');
  assert.strictEqual(ms.count, 2);
  assert.strictEqual(ms.kevCount, 1);
  assert.strictEqual(ms.exploitedCount, 1);
  assert.strictEqual(ms.criticalCount, 1);
  assert.strictEqual(ms.items[0].url, '/cve/CVE-2026-0001.html');
});

test('buildVendorIndex respects minItems threshold', () => {
  const vendors = buildVendorIndex(CVES, { minItems: 2 });
  const slugs = vendors.map((v) => v.slug);
  assert.ok(slugs.includes('microsoft'));
  assert.ok(!slugs.includes('npm')); // only 1 real CVE
});

test('buildVendorIndex returns empty array for no real vendors', () => {
  const vendors = buildVendorIndex([{ id: 'X', vendor: 'reddit_cyber' }], { minItems: 1 });
  assert.deepStrictEqual(vendors, []);
});

/* ─── buildTimeline ──────────────────────────────────────────── */

const PRODUCTS = [
  { slug: 'old-post', title: 'Old Post', generated: '2026-01-01T00:00:00Z' },
  { slug: 'new-post', title: 'New Post', generated: '2026-07-01T00:00:00Z' },
  { slug: 'no-date', title: 'Missing Date' },
  { slug: 'no-title', generated: '2026-06-01T00:00:00Z' },
];

test('buildTimeline sorts most-recent-first and skips items missing date or title', () => {
  const timeline = buildTimeline(PRODUCTS);
  assert.strictEqual(timeline.length, 2);
  assert.strictEqual(timeline[0].slug, 'new-post');
  assert.strictEqual(timeline[1].slug, 'old-post');
  assert.strictEqual(timeline[0].url, '/posts/new-post.html');
});

test('buildTimeline respects limit', () => {
  const timeline = buildTimeline(PRODUCTS, { limit: 1 });
  assert.strictEqual(timeline.length, 1);
  assert.strictEqual(timeline[0].slug, 'new-post');
});

/* ─── buildCollections ───────────────────────────────────────── */

test('buildCollections only includes collections with real matches', () => {
  const products = [{ slug: 'lb', title: 'LockBit ransomware hits hospital', generated: '2026-01-01T00:00:00Z' }];
  const collections = buildCollections(products, []);
  const slugs = collections.map((c) => c.slug);
  assert.ok(slugs.includes('ransomware-intelligence'));
  assert.ok(!slugs.includes('ai-security-intelligence'));
});

test('buildCollections returns nothing when no products match any definition', () => {
  const products = [{ slug: 'x', title: 'Completely unrelated career advice post', generated: '2026-01-01T00:00:00Z' }];
  const collections = buildCollections(products, []);
  assert.deepStrictEqual(collections, []);
});

test('buildCollections never fabricates items — count matches real matched articles', () => {
  const products = [
    { slug: 'a', title: 'CISA KEV adds critical flaw', generated: '2026-01-01T00:00:00Z', cisa_kev: true },
    { slug: 'b', title: 'Unrelated post', generated: '2026-01-02T00:00:00Z' },
  ];
  const collections = buildCollections(products, []);
  const kev = collections.find((c) => c.slug === 'kev-actively-exploited');
  assert.strictEqual(kev.count, 1);
  assert.strictEqual(kev.items[0].slug, 'a');
});

/* ─── buildDetectionLibrary ──────────────────────────────────── */

test('buildDetectionLibrary only includes products with non-empty detection content', () => {
  const products = [
    { slug: 'has-sigma', title: 'Has Sigma', generated: '2026-01-01T00:00:00Z', detections: { sigma: ['rule1'], kql: [], splunk: [], osquery: [], suricata: [] } },
    { slug: 'no-detections', title: 'No Detections', generated: '2026-01-02T00:00:00Z', detections: { sigma: [], kql: [], splunk: [], osquery: [], suricata: [] } },
    { slug: 'missing-detections-key', title: 'Missing Key', generated: '2026-01-03T00:00:00Z' },
  ];
  const lib = buildDetectionLibrary(products);
  assert.strictEqual(lib.length, 1);
  assert.strictEqual(lib[0].slug, 'has-sigma');
  assert.deepStrictEqual(lib[0].sigma, ['rule1']);
});

/* ─── articlesMatching ───────────────────────────────────────── */

test('articlesMatching returns only real title matches, most recent first', () => {
  const products = [
    { slug: 'a', title: 'LockBit strikes again', generated: '2026-01-01T00:00:00Z' },
    { slug: 'b', title: 'LockBit resurgence', generated: '2026-06-01T00:00:00Z' },
    { slug: 'c', title: 'Unrelated malware news', generated: '2026-05-01T00:00:00Z' },
  ];
  const matches = articlesMatching(products, /lockbit/i);
  assert.strictEqual(matches.length, 2);
  assert.strictEqual(matches[0].slug, 'b');
});
