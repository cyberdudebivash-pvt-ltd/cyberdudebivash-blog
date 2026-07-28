'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { checkRendering, countMarkdownTables, countFencedCodeBlocks } = require('../report-renderer');

const REPORTS_ROOT = path.join(__dirname, '..', '..', 'reports');
const FULL_REPORT = fs.readFileSync(
  path.join(REPORTS_ROOT, 'published', 'SA-2026-0001-sharepoint-cve-2026-50522-active-exploitation.md'), 'utf8');
const EXEC_BRIEF = fs.readFileSync(
  path.join(REPORTS_ROOT, 'drafts', 'SA-2026-0001-EXEC-sharepoint-cve-2026-50522.md'), 'utf8');

test('real full report certifies cleanly: ok, 24 sections, table/fence counts match', () => {
  const result = checkRendering(FULL_REPORT);
  assert.strictEqual(result.ok, true, JSON.stringify(result.issues));
  assert.deepStrictEqual(result.issues, []);
  assert.strictEqual(result.sectionCount, 24);
  assert.strictEqual(result.tableCount.markdown, result.tableCount.rendered);
  assert.ok(result.tableCount.rendered > 0);
  assert.strictEqual(result.codeBlockCount.markdown, result.codeBlockCount.rendered);
  assert.ok(result.codeBlockCount.rendered > 0);
});

test('real executive brief certifies cleanly: ok, 8 sections', () => {
  const result = checkRendering(EXEC_BRIEF);
  assert.strictEqual(result.ok, true, JSON.stringify(result.issues));
  assert.strictEqual(result.sectionCount, 8);
});

test('countMarkdownTables recognizes GFM separator rows, ignores plain prose', () => {
  assert.strictEqual(countMarkdownTables('| A | B |\n|---|---|\n| 1 | 2 |\n'), 1);
  assert.strictEqual(countMarkdownTables('a | b is not a table, just a sentence with a pipe.'), 0);
  assert.strictEqual(
    countMarkdownTables('| A | B |\n|---|---|\n| 1 | 2 |\n\ntext\n\n| C | D |\n|:--|--:|\n| x | y |\n'),
    2,
  );
});

test('countFencedCodeBlocks pairs opening/closing triple-backtick fences', () => {
  assert.strictEqual(countFencedCodeBlocks('no fences here'), 0);
  assert.strictEqual(countFencedCodeBlocks('```yaml\nkey: value\n```\n'), 1);
  assert.strictEqual(countFencedCodeBlocks('```yaml\na: 1\n```\ntext\n```json\n{}\n```\n'), 2);
});

test('a report with no sections and no preamble content is flagged, not silently certified', () => {
  const result = checkRendering('---\ntitle: "Empty"\n---\n\n');
  assert.strictEqual(result.ok, false);
  assert.ok(result.issues.some(i => i.includes('no sections and no preamble')));
});

test('an embedded script tag in the source is confirmed neutralized, not flagged as a failure', () => {
  const text = '## Section\n\n<script>alert(1)</script> some text.\n';
  const result = checkRendering(text);
  assert.strictEqual(result.ok, true);
});

test('malformed or empty input never throws', () => {
  assert.doesNotThrow(() => checkRendering(''));
  assert.doesNotThrow(() => checkRendering(null));
  assert.doesNotThrow(() => checkRendering(undefined));
});
