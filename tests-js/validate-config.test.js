'use strict';
const test = require('node:test');
const assert = require('node:assert');
const {
  validateGeneratorRegistry, validateFeatureFlags, validateSubscriptionCatalog, validateServicesCatalog, validateAll,
} = require('../scripts/validate-config');
const { defineGenerator } = require('../orchestrator/generator-sdk');

/* ─── validateGeneratorRegistry ──────────────────────────────── */

test('validateGeneratorRegistry passes a clean registry', () => {
  const gens = [
    defineGenerator({ id: 'a', description: 'A', outputs: ['o'], command: ['true'] }),
    defineGenerator({ id: 'b', description: 'B', outputs: ['o'], command: ['true'], dependsOn: ['a'] }),
  ];
  assert.deepStrictEqual(validateGeneratorRegistry(gens), []);
});

test('validateGeneratorRegistry flags a duplicate id', () => {
  const gens = [
    defineGenerator({ id: 'a', description: 'A', outputs: ['o'], command: ['true'] }),
    defineGenerator({ id: 'a', description: 'A2', outputs: ['o'], command: ['true'] }),
  ];
  const issues = validateGeneratorRegistry(gens);
  assert.ok(issues.some((i) => i.includes('Duplicate generator id')));
});

test('validateGeneratorRegistry flags a dependency on an unregistered generator', () => {
  const gens = [defineGenerator({ id: 'a', description: 'A', outputs: ['o'], command: ['true'], dependsOn: ['ghost'] })];
  const issues = validateGeneratorRegistry(gens);
  assert.ok(issues.some((i) => i.includes('unknown generator "ghost"')));
});

test('validateGeneratorRegistry flags an incomplete freshnessCheck', () => {
  const gens = [defineGenerator({
    id: 'a', description: 'A', outputs: ['o'], command: ['true'],
    freshnessCheck: { file: 'x.json' }, // missing maxAgeMinutes
  })];
  const issues = validateGeneratorRegistry(gens);
  assert.ok(issues.some((i) => i.includes('incomplete freshnessCheck')));
});

/* ─── validateFeatureFlags ───────────────────────────────────── */

test('validateFeatureFlags passes a well-formed registry', () => {
  assert.deepStrictEqual(validateFeatureFlags({ x: { enabled: true, description: 'desc' } }), []);
});

test('validateFeatureFlags flags a missing enabled boolean', () => {
  const issues = validateFeatureFlags({ x: { description: 'desc' } });
  assert.ok(issues.some((i) => i.includes('missing boolean "enabled"')));
});

test('validateFeatureFlags flags a missing description', () => {
  const issues = validateFeatureFlags({ x: { enabled: true } });
  assert.ok(issues.some((i) => i.includes('missing a description')));
});

/* ─── validateSubscriptionCatalog ────────────────────────────── */

test('validateSubscriptionCatalog flags a tier with no plan definition', () => {
  const issues = validateSubscriptionCatalog({}, ['free', 'pro']);
  assert.ok(issues.some((i) => i.includes('Tier "free"')));
  assert.ok(issues.some((i) => i.includes('Tier "pro"')));
});

test('validateSubscriptionCatalog flags an invalid apiRequestsPerDay', () => {
  const plans = { free: { apiRequestsPerDay: 0, features: ['x'] } };
  const issues = validateSubscriptionCatalog(plans, ['free']);
  assert.ok(issues.some((i) => i.includes('invalid apiRequestsPerDay')));
});

test('validateSubscriptionCatalog flags a plan with no features', () => {
  const plans = { free: { apiRequestsPerDay: 100, features: [] } };
  const issues = validateSubscriptionCatalog(plans, ['free']);
  assert.ok(issues.some((i) => i.includes('no features listed')));
});

/* ─── validateServicesCatalog ────────────────────────────────── */

test('validateServicesCatalog flags an industry referencing an unknown service', () => {
  const issues = validateServicesCatalog({ real_service: {} }, { healthcare: { services: ['real_service', 'fake_service'] } });
  assert.ok(issues.some((i) => i.includes('unknown service "fake_service"')));
});

/* ─── validateAll (integration against the real repo config) ─── */

test('validateAll returns zero issues across every real configuration surface', () => {
  const results = validateAll();
  for (const [surface, issues] of Object.entries(results)) {
    assert.deepStrictEqual(issues, [], `${surface} has unexpected issues: ${JSON.stringify(issues)}`);
  }
});
