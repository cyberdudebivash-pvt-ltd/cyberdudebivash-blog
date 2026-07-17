'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { defineGenerator, execGenerator } = require('../orchestrator/generator-sdk');
const {
  topoSort, newestMtime, shouldSkipIncremental, runGenerators, compareManifests, buildDependencyGraph,
} = require('../orchestrator/build-orchestrator');

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

/* ─── dry-run mode ───────────────────────────────────────────── */

test('runGenerators with dryRun never executes and reports would_run', async () => {
  let executed = false;
  const gen = defineGenerator({ id: 'x', description: 'y', outputs: ['z'], run: async () => { executed = true; } });
  const results = await runGenerators([gen], { dryRun: true, incremental: false, full: false });
  assert.strictEqual(executed, false);
  assert.deepStrictEqual(results, [{ id: 'x', status: 'would_run', durationMs: 0, error: null }]);
});

test('runGenerators with dryRun and incremental combined still never executes', async () => {
  let executed = false;
  const gen = defineGenerator({
    id: 'x', description: 'y', outputs: ['z'], inputs: ['package.json'],
    run: async () => { executed = true; },
  });
  const results = await runGenerators([gen], { dryRun: true, incremental: true, full: false });
  assert.strictEqual(executed, false);
  assert.strictEqual(results[0].status, 'would_run');
});

/* ─── compareManifests ───────────────────────────────────────── */

test('compareManifests detects newly failing and newly passing generators', () => {
  const before = { generated: 't1', results: [{ id: 'a', status: 'success', durationMs: 100 }, { id: 'b', status: 'failed', durationMs: 50 }] };
  const after = { generated: 't2', results: [{ id: 'a', status: 'failed', durationMs: 100 }, { id: 'b', status: 'success', durationMs: 50 }] };
  const diff = compareManifests(before, after);
  const byId = Object.fromEntries(diff.changes.map((c) => [c.id, c.change]));
  assert.strictEqual(byId.a, 'newly_failing');
  assert.strictEqual(byId.b, 'newly_passing');
});

test('compareManifests detects a meaningful duration regression', () => {
  const before = { generated: 't1', results: [{ id: 'a', status: 'success', durationMs: 200 }] };
  const after = { generated: 't2', results: [{ id: 'a', status: 'success', durationMs: 5000 }] };
  const diff = compareManifests(before, after);
  assert.strictEqual(diff.changes[0].change, 'slower');
});

test('compareManifests ignores small duration noise', () => {
  const before = { generated: 't1', results: [{ id: 'a', status: 'success', durationMs: 200 }] };
  const after = { generated: 't2', results: [{ id: 'a', status: 'success', durationMs: 250 }] };
  const diff = compareManifests(before, after);
  assert.strictEqual(diff.changes.length, 0);
  assert.strictEqual(diff.unchanged, 1);
});

test('compareManifests flags a generator present in only one manifest', () => {
  const before = { generated: 't1', results: [{ id: 'a', status: 'success', durationMs: 100 }] };
  const after = { generated: 't2', results: [{ id: 'a', status: 'success', durationMs: 100 }, { id: 'b', status: 'success', durationMs: 100 }] };
  const diff = compareManifests(before, after);
  assert.strictEqual(diff.changes.length, 1);
  assert.strictEqual(diff.changes[0].change, 'added');
  assert.strictEqual(diff.changes[0].id, 'b');
});

/* ─── buildDependencyGraph ───────────────────────────────────── */

test('buildDependencyGraph produces nodes and dependency-ordered edges', () => {
  const a = defineGenerator({ id: 'a', description: 'A', outputs: ['o'], command: ['true'] });
  const b = defineGenerator({ id: 'b', description: 'B', outputs: ['o'], command: ['true'], dependsOn: ['a'] });
  const graph = buildDependencyGraph([a, b]);
  assert.strictEqual(graph.nodes.length, 2);
  assert.deepStrictEqual(graph.edges, [{ from: 'a', to: 'b' }]);
});
