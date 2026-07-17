'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseApiFile } = require('../scripts/generate-docs');

function writeFixture(content) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-docs-'));
  const file = path.join(tmp, 'fixture.js');
  fs.writeFileSync(file, content);
  return { tmp, file };
}

test('parseApiFile extracts title, routing, and action table from an LF header', () => {
  const { tmp, file } = writeFixture(
    "/**\n * SENTINEL APEX — Fixture Router\n *\n * Routing: /api/v1/fixture?action={action}\n *\n *  action=one   GET   Does the first thing\n *  action=two   POST  Does the second thing\n */\n'use strict';\n"
  );
  const result = parseApiFile(file);
  assert.strictEqual(result.title, 'SENTINEL APEX — Fixture Router');
  assert.strictEqual(result.routing, '/api/v1/fixture?action={action}');
  assert.deepStrictEqual(result.actions, [
    { action: 'one', method: 'GET', description: 'Does the first thing' },
    { action: 'two', method: 'POST', description: 'Does the second thing' },
  ]);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('parseApiFile handles CRLF line endings identically to LF', () => {
  const lfContent = "/**\n * Fixture\n *\n *  action=x   GET   desc\n */\n";
  const crlfContent = lfContent.replace(/\n/g, '\r\n');
  const { tmp: tmpLf, file: fileLf } = writeFixture(lfContent);
  const { tmp: tmpCrlf, file: fileCrlf } = writeFixture(crlfContent);
  const lfResult = parseApiFile(fileLf);
  const crlfResult = parseApiFile(fileCrlf);
  assert.deepStrictEqual(crlfResult.actions, lfResult.actions);
  assert.strictEqual(crlfResult.actions.length, 1);
  fs.rmSync(tmpLf, { recursive: true, force: true });
  fs.rmSync(tmpCrlf, { recursive: true, force: true });
});

test('parseApiFile falls back to a direct route line for single-endpoint files', () => {
  const { tmp, file } = writeFixture("/**\n * Fixture Endpoint\n * POST /api/v1/fixture\n */\n");
  const result = parseApiFile(file);
  assert.strictEqual(result.routing, 'POST /api/v1/fixture');
  assert.deepStrictEqual(result.actions, []);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('parseApiFile returns null when the file has no header comment block', () => {
  const { tmp, file } = writeFixture("'use strict';\nmodule.exports = {};\n");
  assert.strictEqual(parseApiFile(file), null);
  fs.rmSync(tmp, { recursive: true, force: true });
});
