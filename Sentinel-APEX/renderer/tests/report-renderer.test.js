'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { parseReport, toHTMLDocument, section, renderMarkdown } = require('../report-renderer');

const REPORTS_ROOT = path.join(__dirname, '..', '..', 'reports');
// The full report was published (EIPP v1) and moved drafts/ -> published/;
// the executive-brief variant hasn't gone through its own publish action
// yet, so it's still in drafts/ — each read from its own current location.
const FULL_REPORT = fs.readFileSync(
  path.join(REPORTS_ROOT, 'published', 'SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md'), 'utf8');
const EXEC_BRIEF = fs.readFileSync(
  path.join(REPORTS_ROOT, 'drafts', 'SA-2026-0001-EXEC-sharepoint-cve-2026-50522.md'), 'utf8');

// ── real report: full technical report (24 sections, front matter with
// nested arrays, one embedded code fence, six tables) ──────────────────────
test('parses front matter metadata from the real full report', () => {
  const model = parseReport(FULL_REPORT);
  assert.strictEqual(model.metadata.report_id, 'SA-2026-0001');
  assert.ok(model.metadata.title.includes('SharePoint'));
  assert.deepStrictEqual(model.metadata.cves, [
    'CVE-2026-50522', 'CVE-2026-45659', 'CVE-2026-56164', 'CVE-2026-58644',
  ]);
});

test('finds all 24 sections in the real full report, in order', () => {
  const model = parseReport(FULL_REPORT);
  assert.strictEqual(model.sections.length, 24);
  assert.strictEqual(model.sections[0].name, 'Executive Summary');
  assert.strictEqual(model.sections.at(-1).name, 'Sentinel APEX Analyst Conclusion');
});

test('section() does fragment-based case-insensitive lookup', () => {
  const model = parseReport(FULL_REPORT);
  assert.ok(section(model, 'mitre att&ck'));
  assert.ok(section(model, 'IOC'));
  assert.strictEqual(section(model, 'does-not-exist'), null);
});

test('real tables render as actual <table> markup, not flattened text', () => {
  const model = parseReport(FULL_REPORT);
  const html = toHTMLDocument(model);
  const tableCount = (html.match(/<table class="tbl">/g) || []).length;
  assert.strictEqual(tableCount, 6);
  assert.ok(!html.includes('|---|'), 'raw pipe-table syntax must not leak through unconverted');
});

test('the Sigma YAML fenced code block survives completely intact', () => {
  const model = parseReport(FULL_REPORT);
  const behavioral = section(model, 'Behavioral Indicators');
  assert.ok(behavioral, 'Behavioral Indicators section must be found');
  assert.ok(behavioral.html.includes('class="code-block-lang">YAML<'));
  assert.ok(behavioral.html.includes('title: IIS Worker Process Spawning Command Interpreter'));
  assert.ok(behavioral.html.includes('condition: selection_parent and selection_child'));
  // The specific cascading-corruption failure mode found in Issue 5: inline
  // <code> tags in sections AFTER the fence must stay correctly bounded.
  const hunting = section(model, 'Threat Hunting Guidance');
  assert.ok(hunting.html.includes('<code>w3wp.exe</code>'), 'inline code after the fence must not be corrupted');
});

test('no raw ## heading markers leak into the rendered output', () => {
  const model = parseReport(FULL_REPORT);
  const html = toHTMLDocument(model);
  assert.ok(!/^##[ \t]/m.test(html));
});

// ── real report: executive brief (different front matter shape, a `#`
// heading before the first `##` section, only 8 sections, 2 tables) ────────
test('parses the structurally different executive brief correctly', () => {
  const model = parseReport(EXEC_BRIEF);
  assert.strictEqual(model.metadata.audience, 'executive');
  assert.strictEqual(model.sections.length, 8);
});

test('a level-1 heading before the first section becomes preamble content, not a section', () => {
  const model = parseReport(EXEC_BRIEF);
  assert.ok(model.preamble.html.includes('<h1>Executive Threat Brief</h1>'));
  assert.ok(!model.sections.some(s => s.name === 'Executive Threat Brief'));
});

test('executive brief tables render correctly', () => {
  const model = parseReport(EXEC_BRIEF);
  const html = toHTMLDocument(model);
  assert.strictEqual((html.match(/<table class="tbl">/g) || []).length, 2);
});

// ── security ────────────────────────────────────────────────────────────────
test('embedded raw HTML is neutralized (escaped), not executed', () => {
  const html = renderMarkdown('Note: <script>alert(1)</script> mid-paragraph.');
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('an HTML-shaped string inside a table cell is neutralized too', () => {
  const html = renderMarkdown('| A | B |\n|---|---|\n| <img src=x onerror=alert(1)> | ok |');
  assert.ok(!html.includes('<img src=x'));
});

// ── malformed / edge-case input never throws ────────────────────────────────
test('missing front matter still parses the body', () => {
  const model = parseReport('## Only Section\n\nSome content.');
  assert.deepStrictEqual(model.metadata, {});
  assert.strictEqual(model.sections.length, 1);
  assert.strictEqual(model.sections[0].name, 'Only Section');
});

test('malformed YAML front matter does not throw — metadata just stays empty', () => {
  const text = '---\ntitle: "unterminated\n---\n\n## Section\n\nBody.';
  assert.doesNotThrow(() => parseReport(text));
});

test('empty input does not throw', () => {
  assert.doesNotThrow(() => parseReport(''));
  const model = parseReport('');
  assert.deepStrictEqual(model.sections, []);
});

test('a document with no ## headings at all is entirely preamble, zero sections', () => {
  const model = parseReport('---\ntitle: "No sections"\n---\n\nJust one paragraph, no headings.');
  assert.strictEqual(model.sections.length, 0);
  assert.ok(model.preamble.html.includes('Just one paragraph'));
});
