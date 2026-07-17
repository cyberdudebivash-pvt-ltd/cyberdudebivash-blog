'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { defineGenerator, execGenerator } = require('../orchestrator/generator-sdk');
const { topoSort, newestMtime, shouldSkipIncremental } = require('../orchestrator/build-orchestrator');

/* ─── defineGenerator ────────────────────────────────────────── */

test('defineGenerator requires id, description, outputs', () => {
  assert.throws(() => defineGenerator({ description: 'x', outputs: ['y'], command: ['echo'] }), /id/);
  assert.throws(() => defineGenerator({ id: 'x', outputs: ['y'], command: ['echo'] }), /description/);
  assert.throws(() => defineGenerator({ id: 'x', description: 'y', command: ['echo'] }), /outputs/);
});

test('defineGenerator requires run() or command', () => {
  assert.throws(() => defineGenerator({ id: 'x', description: 'y', outputs: ['z'] }), /run\(\) or command/);
});

test('defineGenerator fills defaults', () => {
  const gen = defineGenerator({ id: 'x', description: 'y', outputs: ['z'], command: ['echo', 'hi'] });
  assert.deepStrictEqual(gen.inputs, []);
  assert.deepStrictEqual(gen.dependsOn, []);
  assert.strictEqual(gen.freshnessCheck, null);
});

/* ─── execGenerator ──────────────────────────────────────────── */

test('execGenerator runs a native run() function successfully', async () => {
  let called = false;
  const gen = defineGenerator({ id: 'native-ok', description: 'x', outputs: ['y'], run: async () => { called = true; } });
  const result = await execGenerator(gen);
  assert.strictEqual(called, true);
  assert.strictEqual(result.status, 'success');
  assert.strictEqual(result.error, null);
});

test('execGenerator captures a thrown error from run()', async () => {
  const gen = defineGenerator({ id: 'native-fail', description: 'x', outputs: ['y'], run: async () => { throw new Error('boom'); } });
  const result = await execGenerator(gen);
  assert.strictEqual(result.status, 'failed');
  assert.match(result.error, /boom/);
});

test('execGenerator runs a shelled-out command successfully', async () => {
  const gen = defineGenerator({ id: 'cmd-ok', description: 'x', outputs: ['y'], command: ['node', '-e', 'process.exit(0)'] });
  const result = await execGenerator(gen);
  assert.strictEqual(result.status, 'success');
});

test('execGenerator captures a non-zero exit code with stderr tail', async () => {
  const gen = defineGenerator({ id: 'cmd-fail', description: 'x', outputs: ['y'], command: ['node', '-e', 'console.error("bad thing"); process.exit(1)'] });
  const result = await execGenerator(gen);
  assert.strictEqual(result.status, 'failed');
  assert.match(result.error, /exited with code 1/);
  assert.match(result.stderrTail, /bad thing/);
});

/* ─── topoSort ───────────────────────────────────────────────── */

test('topoSort orders dependencies before dependents', () => {
  const a = defineGenerator({ id: 'a', description: 'x', outputs: ['o'], command: ['true'] });
  const b = defineGenerator({ id: 'b', description: 'x', outputs: ['o'], command: ['true'], dependsOn: ['a'] });
  const c = defineGenerator({ id: 'c', description: 'x', outputs: ['o'], command: ['true'], dependsOn: ['b'] });
  const order = topoSort([c, b, a]).map((g) => g.id);
  assert.deepStrictEqual(order, ['a', 'b', 'c']);
});

test('topoSort detects circular dependencies', () => {
  const a = defineGenerator({ id: 'a', description: 'x', outputs: ['o'], command: ['true'], dependsOn: ['b'] });
  const b = defineGenerator({ id: 'b', description: 'x', outputs: ['o'], command: ['true'], dependsOn: ['a'] });
  assert.throws(() => topoSort([a, b]), /Circular/);
});

test('topoSort rejects an unknown dependency', () => {
  const a = defineGenerator({ id: 'a', description: 'x', outputs: ['o'], command: ['true'], dependsOn: ['ghost'] });
  assert.throws(() => topoSort([a]), /Unknown generator dependency/);
});

/* ─── newestMtime ────────────────────────────────────────────── */

test('newestMtime returns 0 for a nonexistent path', () => {
  assert.strictEqual(newestMtime('this-path-does-not-exist-xyz'), 0);
});

test('newestMtime returns a positive mtime for a real file', () => {
  assert.ok(newestMtime('package.json') > 0);
});

test('newestMtime scans a directory subtree for a real directory', () => {
  assert.ok(newestMtime('orchestrator') > 0);
});

/* ─── shouldSkipIncremental ──────────────────────────────────── */

test('shouldSkipIncremental never skips a generator with no declared inputs', () => {
  const gen = defineGenerator({ id: 'x', description: 'y', outputs: ['z'], command: ['true'], inputs: [] });
  assert.strictEqual(shouldSkipIncremental(gen, { x: { lastSuccessAt: Date.now() + 1e9 } }), false);
});

test('shouldSkipIncremental does not skip when there is no recorded prior success', () => {
  const gen = defineGenerator({ id: 'x', description: 'y', outputs: ['z'], command: ['true'], inputs: ['package.json'] });
  assert.strictEqual(shouldSkipIncremental(gen, {}), false);
});

test('shouldSkipIncremental skips when inputs are older than the last successful run', () => {
  const gen = defineGenerator({ id: 'x', description: 'y', outputs: ['z'], command: ['true'], inputs: ['package.json'] });
  const farFuture = Date.now() + 1e9;
  assert.strictEqual(shouldSkipIncremental(gen, { x: { lastSuccessAt: farFuture } }), true);
});

test('shouldSkipIncremental does not skip when inputs are newer than the last successful run', () => {
  const gen = defineGenerator({ id: 'x', description: 'y', outputs: ['z'], command: ['true'], inputs: ['package.json'] });
  assert.strictEqual(shouldSkipIncremental(gen, { x: { lastSuccessAt: 1 } }), false);
});
