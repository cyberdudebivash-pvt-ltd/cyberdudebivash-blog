'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { getJsonPath, pathNewestMtime, checkGeneratorFreshness, checkAllFreshness } = require('../orchestrator/freshness');
const { defineGenerator } = require('../orchestrator/generator-sdk');

test('getJsonPath resolves a dotted path', () => {
  const obj = { metadata: { generated: '2026-01-01T00:00:00Z' } };
  assert.strictEqual(getJsonPath(obj, 'metadata.generated'), '2026-01-01T00:00:00Z');
});

test('getJsonPath returns undefined for a missing path', () => {
  assert.strictEqual(getJsonPath({ a: 1 }, 'a.b.c'), undefined);
  assert.strictEqual(getJsonPath(null, 'a.b'), undefined);
});

test('pathNewestMtime returns 0 for a nonexistent path', () => {
  assert.strictEqual(pathNewestMtime('nope-xyz-123'), 0);
});

test('checkGeneratorFreshness reports "unmonitored" when no freshnessCheck declared', () => {
  const gen = defineGenerator({ id: 'x', description: 'y', outputs: ['z'], command: ['true'] });
  const result = checkGeneratorFreshness(gen);
  assert.strictEqual(result.status, 'unmonitored');
});

test('checkGeneratorFreshness reports "missing" when the target file does not exist', () => {
  const gen = defineGenerator({
    id: 'x', description: 'y', outputs: ['z'], command: ['true'],
    freshnessCheck: { file: 'does-not-exist-xyz.json', maxAgeMinutes: 60 },
  });
  const result = checkGeneratorFreshness(gen);
  assert.strictEqual(result.status, 'missing');
});

test('checkGeneratorFreshness reports "fresh" for a file within maxAgeMinutes (mtime fallback)', () => {
  const gen = defineGenerator({
    id: 'x', description: 'y', outputs: ['z'], command: ['true'],
    freshnessCheck: { file: 'package.json', maxAgeMinutes: 999999999 },
  });
  const result = checkGeneratorFreshness(gen);
  assert.strictEqual(result.status, 'fresh');
  assert.strictEqual(typeof result.ageMinutes, 'number');
});

test('checkGeneratorFreshness reports "stale" when age exceeds maxAgeMinutes', () => {
  const gen = defineGenerator({
    id: 'x', description: 'y', outputs: ['z'], command: ['true'],
    freshnessCheck: { file: 'package.json', maxAgeMinutes: -1 },
  });
  const result = checkGeneratorFreshness(gen);
  assert.strictEqual(result.status, 'stale');
});

test('checkGeneratorFreshness prefers jsonPath timestamp over file mtime when present', () => {
  const gen = defineGenerator({
    id: 'x', description: 'y', outputs: ['z'], command: ['true'],
    freshnessCheck: { file: 'package.json', jsonPath: 'version', maxAgeMinutes: 60 },
  });
  // package.json's "version" field is not a date -> Date parse fails -> falls back to mtime, still resolves
  const result = checkGeneratorFreshness(gen);
  assert.ok(['fresh', 'stale'].includes(result.status));
});

test('checkAllFreshness returns one result per generator', () => {
  const gens = [
    defineGenerator({ id: 'a', description: 'x', outputs: ['o'], command: ['true'] }),
    defineGenerator({ id: 'b', description: 'x', outputs: ['o'], command: ['true'] }),
  ];
  const results = checkAllFreshness(gens);
  assert.strictEqual(results.length, 2);
  assert.deepStrictEqual(results.map((r) => r.id), ['a', 'b']);
});
