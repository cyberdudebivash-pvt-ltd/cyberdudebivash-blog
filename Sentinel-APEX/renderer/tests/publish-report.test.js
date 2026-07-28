'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { buildPage, slugify } = require('../publish-report');
const { parseReport } = require('../report-renderer');

const REPORTS_DIR = path.join(__dirname, '..', '..', 'reports', 'published');
const REAL_REPORT_PATH = path.join(REPORTS_DIR, 'SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md');
const REAL_REPORT_TEXT = fs.readFileSync(REAL_REPORT_PATH, 'utf8');

test('slugify produces a clean, readable slug', () => {
  assert.strictEqual(slugify('SA-2026-0001-CVE-2026-50522'), 'sa-2026-0001-cve-2026-50522');
  assert.strictEqual(slugify('Weird !!! Title -- With Spaces'), 'weird-title-with-spaces');
});

test('the published page has exactly one title heading, not a duplicate', () => {
  const model = parseReport(REAL_REPORT_TEXT);
  const html = buildPage(model, 'sa-2026-0001-cve-2026-50522');
  const h1Count = (html.match(/<h1[ >]/g) || []).length;
  assert.strictEqual(h1Count, 1, 'exactly one <h1> — the styled title with badges, not a second one from the renderer');
});

test('published page includes severity badge, CVE badges, and all real sections', () => {
  const model = parseReport(REAL_REPORT_TEXT);
  const html = buildPage(model, 'sa-2026-0001-cve-2026-50522');
  assert.ok(html.includes('CRITICAL'));
  assert.ok(html.includes('CVE-2026-50522'));
  assert.ok(html.includes('CVE-2026-45659'));
  assert.ok(html.includes('Executive Summary'));
  assert.ok(html.includes('MITRE ATT&amp;CK Mapping')); // section names are HTML-escaped
  const sectionCount = (html.match(/<section class="report-section">/g) || []).length;
  assert.strictEqual(sectionCount, 24);
});

test('published page has correct SEO metadata: canonical, OG, JSON-LD', () => {
  const model = parseReport(REAL_REPORT_TEXT);
  const html = buildPage(model, 'sa-2026-0001-cve-2026-50522');
  assert.ok(html.includes('<link rel="canonical" href="https://blog.cyberdudebivash.in/intelligence/sa-2026-0001-cve-2026-50522.html">'));
  assert.ok(html.includes('property="og:image"'));
  assert.ok(html.includes('property="og:type" content="article"'));
  assert.ok(html.includes('"@type":"Article"'));
  assert.ok(html.includes('name="robots" content="index, follow'));
});

test('dynamic OG image URL uses the real severity and primary CVE', () => {
  const model = parseReport(REAL_REPORT_TEXT);
  const html = buildPage(model, 'sa-2026-0001-cve-2026-50522');
  const ogImageMatch = html.match(/property="og:image" content="([^"]*)"/);
  assert.ok(ogImageMatch, 'og:image meta tag must be present');
  const url = ogImageMatch[1].replace(/&amp;/g, '&');
  assert.ok(url.startsWith('https://blog.cyberdudebivash.in/api/og?'));
  assert.ok(url.includes('severity=CRITICAL'));
  assert.ok(url.includes('cve=CVE-2026-50522'));
});

test('embedded HTML anywhere in the report body is neutralized, not executed', () => {
  const text = REAL_REPORT_TEXT.replace(
    'A critical, unauthenticated remote code execution',
    '<script>alert(1)</script> A critical, unauthenticated remote code execution'
  );
  const model = parseReport(text);
  const html = buildPage(model, 'sa-2026-0001-cve-2026-50522');
  assert.ok(!html.includes('<script>alert(1)</script>'));
});

test('a report missing report_id is rejected by the CLI entry point rather than silently publishing', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'publish-test-'));
  const badReportPath = path.join(tmpDir, 'no-id.md');
  fs.writeFileSync(badReportPath, '---\ntitle: "No report_id"\n---\n\n## Section\n\nBody.\n');
  const result = require('node:child_process').spawnSync(
    process.execPath, [path.join(__dirname, '..', 'publish-report.js'), badReportPath],
    { encoding: 'utf8' }
  );
  assert.notStrictEqual(result.status, 0);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('publishing the same report twice is idempotent (same slug, same output shape)', () => {
  const model = parseReport(REAL_REPORT_TEXT);
  const html1 = buildPage(model, 'sa-2026-0001-cve-2026-50522');
  const html2 = buildPage(model, 'sa-2026-0001-cve-2026-50522');
  assert.strictEqual(html1, html2);
});
