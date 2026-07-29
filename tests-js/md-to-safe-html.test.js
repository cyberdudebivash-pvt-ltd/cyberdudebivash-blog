'use strict';
// Regression tests for mdToSafeHtml() (generate-cve-pages.js) -- platform/
// open-issues.md Issue 5. Confirmed by actually rendering SA-2026-0001's
// real markdown through this function: every pipe-table flattened into one
// unreadable line, and the fenced Sigma YAML block's triple backticks
// desynced the single-backtick inline-code regex for everything after it.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const { mdToSafeHtml, esc } = require(path.join(__dirname, '..', 'generate-cve-pages.js'));

/* ─── Synthetic fixtures — precise, maintainable assertions ───────────── */

test('a GFM pipe table renders as a real <table>, not flattened prose', () => {
  const md = [
    '| Technique | Tactic | Confidence |',
    '|---|---|---|',
    '| T1190 | Initial Access | HIGH |',
    '| T1105 | Command and Control | MEDIUM |',
  ].join('\n');

  const html = mdToSafeHtml(esc(md));

  assert.ok(html.includes('<table'), 'expected a <table> element');
  assert.ok(!html.includes('|---|'), 'the literal separator row must not leak into output');
  assert.ok(html.includes('<th'), 'expected header cells');
  assert.match(html, /<th[^>]*>Technique<\/th>/);
  assert.match(html, /<td[^>]*>T1190<\/td>/);
  assert.match(html, /<td[^>]*>Command and Control<\/td>/);
  // 2 data rows -> 2 <tr> inside <tbody>, plus 1 header <tr>.
  assert.strictEqual((html.match(/<tr>/g) || []).length, 3);
});

test('a fenced code block renders as one clean <pre><code>, and does not desync later inline code', () => {
  const md = [
    'Before text with `inline1` code.',
    '',
    '```yaml',
    'title: Test Rule',
    'detection:',
    '  selection: foo',
    '```',
    '',
    'After text with `inline2` code.',
  ].join('\n');

  const html = mdToSafeHtml(esc(md));

  assert.ok(html.includes('<pre'), 'expected a <pre> block for the fenced code');
  assert.ok(html.includes('detection:'), 'fenced content must survive intact');
  assert.ok(html.includes('data-lang="yaml"'), 'expected the fence language to be captured');
  // Both inline spans must render as their own, correctly-bounded <code>
  // elements -- the original bug scrambled everything after the fence into
  // one <code> span with the wrong boundaries.
  assert.match(html, /<code[^>]*>inline1<\/code>/);
  assert.match(html, /<code[^>]*>inline2<\/code>/);
  // The fenced body's own colons/dashes must not have been misread as an
  // inline code span themselves.
  assert.ok(!html.includes('```'), 'raw fence markers must not leak into output');
});

test('a table cell can itself contain inline formatting', () => {
  const md = [
    '| Field | Value |',
    '|---|---|',
    '| Process | `w3wp.exe` spawning `cmd.exe` |',
  ].join('\n');

  const html = mdToSafeHtml(esc(md));
  assert.match(html, /<td[^>]*><code[^>]*>w3wp\.exe<\/code> spawning <code[^>]*>cmd\.exe<\/code><\/td>/);
});

test('existing non-table, non-fence rendering is unchanged (headings, bold, lists, paragraphs)', () => {
  const md = [
    '## A Heading',
    '',
    'A paragraph with **bold** text.',
    '',
    '- bullet one',
    '- bullet two',
  ].join('\n');

  const html = mdToSafeHtml(esc(md));
  assert.ok(html.includes('<h4'));
  assert.ok(html.includes('A Heading'));
  assert.ok(html.includes('<strong>bold</strong>'));
  assert.ok((html.match(/•/g) || []).length === 2);
});

/* ─── Real-data validation — the actual defect was found this way, not by ─
   inspecting the code, so verify against the actual published report ──── */

const REAL_REPORT = path.join(
  __dirname, '..', 'Sentinel-APEX', 'reports', 'published',
  'SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md'
);

test('renders SA-2026-0001\'s real embedded Sigma rule and MITRE table correctly', () => {
  const raw = fs.readFileSync(REAL_REPORT, 'utf8');
  const html = mdToSafeHtml(esc(raw));

  // The real Sigma fence: must survive as one clean block, not scrambled.
  assert.ok(html.includes('<pre'), 'expected the real Sigma fence to render as <pre>');
  assert.ok(html.includes('selection_parent:'), 'real Sigma content must survive intact');
  assert.ok(html.includes('falsepositives:'), 'real Sigma content must survive to its closing fence');
  assert.ok(!html.includes('```'), 'no raw fence markers should leak into real output');

  // Inline code after the fence must still be correctly bounded -- this is
  // exactly the desync Issue 5 documented (20 open/20 close tags, but
  // wrapping the wrong words from the Sigma section onward).
  assert.match(html, /<code[^>]*>w3wp\.exe<\/code>/);
  assert.match(html, /<code[^>]*>cmd\.exe<\/code>/);
});
