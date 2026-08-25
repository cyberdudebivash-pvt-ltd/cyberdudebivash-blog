'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  SUPPORTED_TYPES, FREE_TIER_EXCLUDED_TYPES,
  buildCveDoc, buildCampaignDoc, buildActorDoc, buildIocDoc, buildReportDoc,
  buildSearchIndex, validateSearchIndex, searchDocuments,
  buildTimeline, getActorDetail, getIocDetail, getReportDetail, getCveRelated,
} = require('../api/_lib/search-index');

/* ───────────────────────── fixtures ───────────────────────── */

function makeGraph() {
  return {
    nodes: {
      'CVE-2024-0001': { id: 'CVE-2024-0001', type: 'CVE', name: 'CVE-2024-0001', attributes: {
        cvss: 9.8, threat_level: 'CRITICAL', priority_score: 95, exploited: true, cisa_kev: true, ransomware: true,
        vendor: 'Acme', product: 'Gateway', published: '2024-01-15',
      }},
      'CVE-2024-0002': { id: 'CVE-2024-0002', type: 'CVE', name: 'CVE-2024-0002', attributes: {
        cvss: 5.0, threat_level: 'MEDIUM', priority_score: 40, exploited: false, cisa_kev: false, ransomware: false,
        vendor: 'Beta', product: 'Widget', published: '2024-02-01',
      }},
      'actor:evilcorp': { id: 'actor:evilcorp', type: 'ThreatActor', name: 'EvilCorp', attributes: {
        aliases: ['EC', 'Evil Corporation'], category: 'ransomware_group', motivation: 'financial', active: true,
        first_seen: '2020-01-01', last_seen: '2024-06-01', target_sectors: ['finance'], target_regions: ['global'],
        ttps: ['T1190', 'T1486'], description: 'A fictional test-fixture actor, not a real threat group.',
      }},
      'ioc:domain:evil.test': { id: 'ioc:domain:evil.test', type: 'IOC', name: 'evil.test', attributes: {
        ioc_type: 'domain', confidence: 0.8, first_seen: '2024-01-16',
      }},
      'intel:item1': { id: 'intel:item1', type: 'Intel', name: 'Some article', attributes: {} },
    },
    edges: [
      { source: 'actor:evilcorp', target: 'CVE-2024-0001', relationship: 'exploits', confidence: 0.9,
        sources: ['https://example.test/advisory'], first_seen: '2024-01-16' },
      { source: 'ioc:domain:evil.test', target: 'intel:item1', relationship: 'linked_to', confidence: 0.7 },
    ],
  };
}

function makeCampaignsData() {
  return {
    campaigns: [
      {
        campaign_id: 'campaign:test-1', name: 'Test Campaign One', severity: 'HIGH', confidence: 0.75,
        first_seen: '2024-01-10', last_seen: '2024-01-20', has_kev: true, has_ransomware: false, has_exploited: true,
        reasoning: ['Clustered on shared CVE-2024-0001'], item_count: 3, clustering_model: 'weighted_v2',
      },
    ],
  };
}

function makeReportsIndexData() {
  return {
    reports: [
      {
        report_id: 'SA-2024-0001', title: 'Test Report Title', slug: 'sa-2024-0001-cve-2024-0001',
        url: '/intelligence/sa-2024-0001-cve-2024-0001.html', date: '2024-01-18', last_updated: '2024-01-19',
        severity: 'CRITICAL', overall_confidence: 'HIGH', tlp: 'TLP:CLEAR', cves: ['CVE-2024-0001'],
        threat_actors: ['EvilCorp'], malware_families: [], sectors: ['finance'], attack_ids: ['T1190'],
      },
    ],
  };
}

/* ───────────────────────── per-type document builders ───────────────────────── */

test('buildCveDoc: real fields, honest nulls for what is not known', () => {
  const doc = buildCveDoc(makeGraph().nodes['CVE-2024-0001'], makeReportsIndexData().reports);
  assert.equal(doc.id, 'CVE-2024-0001');
  assert.equal(doc.type, 'cve');
  assert.equal(doc.severity, 'CRITICAL');
  assert.equal(doc.confidence, null); // no confidence concept for a raw CVE node — never invented
  assert.deepEqual(doc.tags.sort(), ['cisa_kev', 'exploited', 'ransomware']);
  assert.equal(doc.vendor, 'Acme');
  assert.deepEqual(doc.report_refs, ['SA-2024-0001']); // reverse-linked via reports-index cves[]
});

test('buildCveDoc: no tags when no signal flags set', () => {
  const doc = buildCveDoc(makeGraph().nodes['CVE-2024-0002'], []);
  assert.deepEqual(doc.tags, []);
  assert.deepEqual(doc.report_refs, []);
});

test('buildCampaignDoc: pulls real fields, never fabricates missing ones', () => {
  const doc = buildCampaignDoc(makeCampaignsData().campaigns[0]);
  assert.equal(doc.id, 'campaign:test-1');
  assert.equal(doc.type, 'campaign');
  assert.equal(doc.confidence, 0.75);
  assert.deepEqual(doc.tags.sort(), ['cisa_kev', 'exploited']);
  assert.equal(doc.clustering_model, 'weighted_v2');
});

test('buildCveDoc/buildCampaignDoc: carry a dossier_url pivot to the dossier page (Intelligence Dossiers v1)', () => {
  const cveDoc = buildCveDoc(makeGraph().nodes['CVE-2024-0001'], []);
  assert.equal(cveDoc.dossier_url, '/dossier.html?type=cve&id=CVE-2024-0001');

  const campaignDoc = buildCampaignDoc(makeCampaignsData().campaigns[0]);
  assert.equal(campaignDoc.dossier_url, `/dossier.html?type=campaign&id=${encodeURIComponent(campaignDoc.id)}`);
});

test('buildActorDoc/buildIocDoc/buildReportDoc: no dossier_url — no dossier type covers them yet', () => {
  const actorDoc = buildActorDoc(makeGraph().nodes['actor:evilcorp'], []);
  assert.equal(actorDoc.dossier_url, undefined);

  const iocDoc = buildIocDoc(makeGraph().nodes['ioc:domain:evil.test']);
  assert.equal(iocDoc.dossier_url, undefined);

  const reportDoc = buildReportDoc(makeReportsIndexData().reports[0]);
  assert.equal(reportDoc.dossier_url, undefined);
});

test('buildActorDoc: aliases/ttps/sectors carried through unmodified', () => {
  const doc = buildActorDoc(makeGraph().nodes['actor:evilcorp'], makeReportsIndexData().reports);
  assert.deepEqual(doc.aliases, ['EC', 'Evil Corporation']);
  assert.deepEqual(doc.techniques, ['T1190', 'T1486']);
  assert.deepEqual(doc.sectors, ['finance']);
  assert.deepEqual(doc.report_refs, ['SA-2024-0001']); // matched by actor name in report front matter
});

test('buildIocDoc: never claims maliciousness beyond stored attributes', () => {
  const doc = buildIocDoc(makeGraph().nodes['ioc:domain:evil.test']);
  assert.equal(doc.ioc_type, 'domain');
  assert.equal(doc.confidence, 0.8);
  assert.ok(!('malicious' in doc)); // no such claim is ever added
});

test('buildReportDoc: real front-matter fields only', () => {
  const doc = buildReportDoc(makeReportsIndexData().reports[0]);
  assert.equal(doc.id, 'SA-2024-0001');
  assert.deepEqual(doc.cves, ['CVE-2024-0001']);
  assert.deepEqual(doc.techniques, ['T1190']);
});

/* ───────────────────────── index assembly + integrity ───────────────────────── */

test('buildSearchIndex: counts exactly match input cardinality', () => {
  const index = buildSearchIndex({ graph: makeGraph(), campaignsData: makeCampaignsData(), reportsIndexData: makeReportsIndexData() });
  assert.equal(index.counts.cve, 2);
  assert.equal(index.counts.actor, 1);
  assert.equal(index.counts.ioc, 1);
  assert.equal(index.counts.campaign, 1);
  assert.equal(index.counts.report, 1);
  assert.equal(index.counts.total, 6);
  assert.equal(index.documents.length, 6);
});

test('buildSearchIndex: unsupported/Intel node type never leaks into the index', () => {
  const index = buildSearchIndex({ graph: makeGraph(), campaignsData: makeCampaignsData(), reportsIndexData: makeReportsIndexData() });
  assert.ok(!index.documents.some(d => d.type === 'Intel' || d.type === 'intel'));
  for (const d of index.documents) assert.ok(SUPPORTED_TYPES.includes(d.type));
});

test('buildSearchIndex: deterministic — rebuilding from the same inputs produces the same document set', () => {
  const graph = makeGraph(), campaignsData = makeCampaignsData(), reportsIndexData = makeReportsIndexData();
  const a = buildSearchIndex({ graph, campaignsData, reportsIndexData });
  const b = buildSearchIndex({ graph, campaignsData, reportsIndexData });
  assert.deepEqual(a.documents.map(d => d.id).sort(), b.documents.map(d => d.id).sort());
  assert.deepEqual(a.counts, b.counts);
});

test('buildSearchIndex: empty inputs produce a valid, empty (not crashed) index', () => {
  const index = buildSearchIndex({ graph: { nodes: {}, edges: [] }, campaignsData: { campaigns: [] }, reportsIndexData: { reports: [] } });
  assert.equal(index.counts.total, 0);
  assert.deepEqual(index.documents, []);
});

test('buildSearchIndex: missing/null inputs handled without throwing', () => {
  const index = buildSearchIndex({ graph: null, campaignsData: null, reportsIndexData: null });
  assert.equal(index.counts.total, 0);
});

test('validateSearchIndex: passes for a correctly-built index', () => {
  const graph = makeGraph(), campaignsData = makeCampaignsData(), reportsIndexData = makeReportsIndexData();
  const index = buildSearchIndex({ graph, campaignsData, reportsIndexData });
  const check = validateSearchIndex(index, { graph, campaignsData, reportsIndexData });
  assert.equal(check.valid, true);
  assert.deepEqual(check.problems, []);
});

test('validateSearchIndex: catches a catastrophic drop (the campaign-delivery lesson, applied here)', () => {
  const graph = makeGraph(), campaignsData = makeCampaignsData(), reportsIndexData = makeReportsIndexData();
  const goodIndex = buildSearchIndex({ graph, campaignsData, reportsIndexData });
  const brokenIndex = { ...goodIndex, counts: { ...goodIndex.counts, campaign: 0 }, documents: goodIndex.documents.filter(d => d.type !== 'campaign') };
  const check = validateSearchIndex(brokenIndex, { graph, campaignsData, reportsIndexData });
  assert.equal(check.valid, false);
  assert.ok(check.problems.some(p => p.includes('campaign')));
});

test('validateSearchIndex: catches duplicate IDs', () => {
  const graph = makeGraph(), campaignsData = makeCampaignsData(), reportsIndexData = makeReportsIndexData();
  const index = buildSearchIndex({ graph, campaignsData, reportsIndexData });
  const dupIndex = { ...index, documents: [...index.documents, index.documents[0]] };
  const check = validateSearchIndex(dupIndex, { graph, campaignsData, reportsIndexData });
  assert.equal(check.valid, false);
  assert.ok(check.problems.some(p => p.includes('duplicate')));
});

/* ───────────────────────── search / ranking ───────────────────────── */

function buildIndex() {
  return buildSearchIndex({ graph: makeGraph(), campaignsData: makeCampaignsData(), reportsIndexData: makeReportsIndexData() });
}

test('searchDocuments: exact ID match ranks highest', () => {
  const r = searchDocuments(buildIndex(), 'CVE-2024-0001', { tier: 'enterprise' });
  assert.equal(r.ok, true);
  assert.equal(r.results[0].id, 'CVE-2024-0001');
  assert.equal(r.results[0].score, 100);
  assert.equal(r.results[0].matched_field, 'id');
});

test('searchDocuments: exact alias match ranks above substring match', () => {
  const r = searchDocuments(buildIndex(), 'Evil Corporation', { tier: 'enterprise' });
  assert.equal(r.results[0].id, 'actor:evilcorp');
  assert.equal(r.results[0].score, 90);
  assert.equal(r.results[0].matched_field, 'alias');
});

test('searchDocuments: substring match on vendor surfaces the CVE', () => {
  const r = searchDocuments(buildIndex(), 'acme', { tier: 'enterprise' });
  assert.ok(r.results.some(x => x.id === 'CVE-2024-0001'));
});

test('searchDocuments: query below minimum length is rejected, not silently empty', () => {
  const r = searchDocuments(buildIndex(), 'a', { tier: 'enterprise' });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'QUERY_TOO_SHORT');
});

test('searchDocuments: empty query is rejected', () => {
  const r = searchDocuments(buildIndex(), '', { tier: 'enterprise' });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'QUERY_TOO_SHORT');
});

test('searchDocuments: oversized query (10,000 chars) is rejected, not scanned', () => {
  const r = searchDocuments(buildIndex(), 'x'.repeat(10000), { tier: 'enterprise' });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'QUERY_TOO_LONG');
});

test('searchDocuments: free tier excludes IOC results entirely', () => {
  const r = searchDocuments(buildIndex(), 'evil.test', { tier: 'free' });
  assert.equal(r.results.length, 0);
});

test('searchDocuments: pro tier includes IOC results', () => {
  const r = searchDocuments(buildIndex(), 'evil.test', { tier: 'pro' });
  assert.ok(r.results.some(x => x.type === 'ioc'));
});

test('searchDocuments: type filter narrows correctly', () => {
  const r = searchDocuments(buildIndex(), 'evilcorp', { tier: 'enterprise', type: 'actor' });
  assert.ok(r.results.every(x => x.type === 'actor'));
});

test('searchDocuments: unknown type filter value is ignored, not an error', () => {
  const r1 = searchDocuments(buildIndex(), 'evilcorp', { tier: 'enterprise', type: 'not-a-real-type' });
  const r2 = searchDocuments(buildIndex(), 'evilcorp', { tier: 'enterprise' });
  assert.equal(r1.results.length, r2.results.length);
});

test('searchDocuments: severity filter applies', () => {
  const r = searchDocuments(buildIndex(), 'cve-2024', { tier: 'enterprise', severity: 'critical' });
  assert.ok(r.results.every(x => x.severity === 'CRITICAL'));
});

test('searchDocuments: reversed date range fails safe (empty, not an error, not a crash)', () => {
  const r = searchDocuments(buildIndex(), 'CVE-2024-0001', { tier: 'enterprise', from: '2030-01-01', to: '2020-01-01' });
  assert.equal(r.ok, true);
  assert.equal(r.results.length, 0);
});

test('searchDocuments: malformed date strings are ignored rather than crashing', () => {
  const r = searchDocuments(buildIndex(), 'CVE-2024-0001', { tier: 'enterprise', from: 'not-a-date', to: 'also-not-a-date' });
  assert.equal(r.ok, true);
  assert.ok(r.results.length > 0);
});

test('searchDocuments: limit and offset are clamped, never trust raw input', () => {
  const rNeg = searchDocuments(buildIndex(), 'cve', { tier: 'enterprise', limit: -5 });
  assert.ok(rNeg.pagination.limit >= 1);
  const rHuge = searchDocuments(buildIndex(), 'cve', { tier: 'enterprise', limit: 999999 });
  assert.ok(rHuge.pagination.limit <= 100);
  const rNaN = searchDocuments(buildIndex(), 'cve', { tier: 'enterprise', limit: 'not-a-number' });
  assert.ok(Number.isFinite(rNaN.pagination.limit));
});

test('searchDocuments: huge type-filter list does not error or blow up', () => {
  const hugeType = Array(1000).fill('cve').join(',');
  const r = searchDocuments(buildIndex(), 'cve-2024-0001', { tier: 'enterprise', type: hugeType });
  assert.equal(r.ok, true);
  assert.ok(r.results.every(x => x.type === 'cve'));
});

test('searchDocuments: __proto__ as a type filter value cannot pollute Object.prototype', () => {
  const before = ({}).polluted;
  searchDocuments(buildIndex(), 'evilcorp', { tier: 'enterprise', type: '__proto__' });
  assert.equal(({}).polluted, before);
  assert.equal(({}).polluted, undefined);
});

test('searchDocuments: SQL-looking and script-looking payloads degrade to zero results, never throw', () => {
  assert.doesNotThrow(() => searchDocuments(buildIndex(), "' OR 1=1 --", { tier: 'enterprise' }));
  assert.doesNotThrow(() => searchDocuments(buildIndex(), '<script>alert(1)</script>', { tier: 'enterprise' }));
  const r = searchDocuments(buildIndex(), "' OR 1=1 --", { tier: 'enterprise' });
  assert.equal(r.results.length, 0);
});

test('searchDocuments: fake CVE-shaped ID that does not exist returns zero results, not an error', () => {
  const r = searchDocuments(buildIndex(), 'CVE-0000-00000', { tier: 'enterprise' });
  assert.equal(r.ok, true);
  assert.equal(r.results.length, 0);
});

test('searchDocuments: Unicode input does not crash the matcher', () => {
  assert.doesNotThrow(() => searchDocuments(buildIndex(), ' ​🔥évil', { tier: 'enterprise' }));
});

test('searchDocuments: ranking is a strict function of score, no hidden randomness — repeated identical queries return identical order', () => {
  const index = buildIndex();
  const r1 = searchDocuments(index, 'cve', { tier: 'enterprise' });
  const r2 = searchDocuments(index, 'cve', { tier: 'enterprise' });
  assert.deepEqual(r1.results.map(x => x.id), r2.results.map(x => x.id));
});

test('searchDocuments: negated/irrelevant relationship text never upgrades a match — only indexed fields are searched', () => {
  // A campaign whose reasoning happens to mention an unrelated CVE-looking string
  // must not spuriously match on it if that string never appears in the
  // campaign's own name/summary text.
  const r = searchDocuments(buildIndex(), 'CVE-9999-99999', { tier: 'enterprise' });
  assert.equal(r.results.length, 0);
});

/* ───────────────────────── timeline ───────────────────────── */

test('buildTimeline: omits events with no known date rather than inventing one', () => {
  const t = buildTimeline([{ date: null, label: 'unknown date event' }, { date: '2024-01-01', label: 'real event' }]);
  assert.equal(t.length, 1);
  assert.equal(t[0].label, 'real event');
});

test('buildTimeline: sorts chronologically ascending', () => {
  const t = buildTimeline([{ date: '2024-06-01', label: 'later' }, { date: '2024-01-01', label: 'earlier' }]);
  assert.deepEqual(t.map(e => e.label), ['earlier', 'later']);
});

test('buildTimeline: deduplicates identical (date, label) pairs', () => {
  const t = buildTimeline([{ date: '2024-01-01', label: 'x' }, { date: '2024-01-01', label: 'x' }]);
  assert.equal(t.length, 1);
});

test('buildTimeline: rejects a non-ISO-shaped date string rather than mis-sorting it', () => {
  const t = buildTimeline([{ date: 'not-a-date', label: 'bad' }, { date: '2024-01-01', label: 'good' }]);
  assert.equal(t.length, 1);
  assert.equal(t[0].label, 'good');
});

/* ───────────────────────── entity detail ───────────────────────── */

test('getActorDetail: found actor includes real graph relationships', () => {
  const { found, actor } = getActorDetail(makeGraph(), 'actor:evilcorp');
  assert.equal(found, true);
  assert.equal(actor.related_cves.length, 1);
  assert.equal(actor.related_cves[0].id, 'CVE-2024-0001');
  assert.equal(actor.related_cves[0].confidence, 0.9);
});

test('getActorDetail: relationships carry real evidence (sources/first_seen), not just a confidence number', () => {
  const { actor } = getActorDetail(makeGraph(), 'actor:evilcorp');
  assert.deepEqual(actor.related_cves[0].evidence.sources, ['https://example.test/advisory']);
  assert.equal(actor.related_cves[0].evidence.first_seen, '2024-01-16');
});

test('getIocDetail: a relationship with no recorded sources gets an honest empty array, not a crash', () => {
  const { ioc } = getIocDetail(makeGraph(), 'ioc:domain:evil.test');
  assert.deepEqual(ioc.linked_intel[0].evidence.sources, []);
  assert.equal(ioc.linked_intel[0].evidence.first_seen, null);
});

test('getActorDetail: unknown actor ID returns found:false, not a crash or fabricated record', () => {
  const { found, actor } = getActorDetail(makeGraph(), 'actor:does-not-exist');
  assert.equal(found, false);
  assert.equal(actor, null);
});

test('getActorDetail: a CVE ID passed as an actor ID is correctly rejected (type mismatch), not silently coerced', () => {
  const { found } = getActorDetail(makeGraph(), 'CVE-2024-0001');
  assert.equal(found, false);
});

test('getIocDetail: found IOC includes linked intel via real edges', () => {
  const { found, ioc } = getIocDetail(makeGraph(), 'ioc:domain:evil.test');
  assert.equal(found, true);
  assert.equal(ioc.linked_intel.length, 1);
  assert.equal(ioc.linked_intel[0].id, 'intel:item1');
});

test('getReportDetail: found report, case-insensitive ID match', () => {
  const { found, report } = getReportDetail(makeReportsIndexData(), 'sa-2024-0001');
  assert.equal(found, true);
  assert.equal(report.report_id, 'SA-2024-0001');
});

test('getReportDetail: unknown report ID returns found:false', () => {
  const { found } = getReportDetail(makeReportsIndexData(), 'SA-9999-9999');
  assert.equal(found, false);
});

test('getReportDetail: empty reports index handled without throwing', () => {
  const { found } = getReportDetail({ reports: [] }, 'SA-2024-0001');
  assert.equal(found, false);
});

test('getCveRelated: surfaces real campaigns and actors via graph edges', () => {
  const related = getCveRelated(makeGraph(), 'CVE-2024-0001');
  assert.equal(related.related_campaigns.length, 0); // fixture graph has no Campaign nodes
  assert.equal(related.related_actors.length, 1);
  assert.equal(related.related_actors[0].id, 'actor:evilcorp');
  assert.equal(related.related_actors[0].relationship, 'exploits');
  assert.equal(related.related_actors[0].confidence, 0.9);
});

test('getCveRelated: a CVE with no linked entities returns empty arrays, not an error', () => {
  const related = getCveRelated(makeGraph(), 'CVE-2024-0002');
  assert.deepEqual(related, { related_campaigns: [], related_actors: [], related_cves: [] });
});

test('getCveRelated: unknown CVE id returns empty arrays rather than throwing', () => {
  assert.doesNotThrow(() => getCveRelated(makeGraph(), 'CVE-9999-99999'));
  const related = getCveRelated(makeGraph(), 'CVE-9999-99999');
  assert.deepEqual(related, { related_campaigns: [], related_actors: [], related_cves: [] });
});
