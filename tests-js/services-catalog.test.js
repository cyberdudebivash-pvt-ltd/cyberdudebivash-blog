'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { SERVICES, INDUSTRIES, getService, getIndustry } = require('../api/_lib/services-catalog');

test('getService returns the service with its key attached', () => {
  const svc = getService('threat_hunting');
  assert.strictEqual(svc.key, 'threat_hunting');
  assert.strictEqual(svc.name, 'Threat Hunting');
});

test('getService returns null for an unknown key', () => {
  assert.strictEqual(getService('does-not-exist'), null);
});

test('getIndustry returns the industry with its key attached', () => {
  const industry = getIndustry('healthcare');
  assert.strictEqual(industry.key, 'healthcare');
  assert.strictEqual(industry.name, 'Healthcare');
});

test('getIndustry returns null for an unknown key', () => {
  assert.strictEqual(getIndustry('does-not-exist'), null);
});

test('every industry references only real service keys', () => {
  for (const [key, industry] of Object.entries(INDUSTRIES)) {
    for (const svcKey of industry.services) {
      assert.ok(SERVICES[svcKey], `industry "${key}" references unknown service "${svcKey}"`);
    }
  }
});

test('every service and industry entry has a name', () => {
  for (const [key, svc] of Object.entries(SERVICES)) {
    assert.ok(svc.name, `service "${key}" missing a name`);
  }
  for (const [key, ind] of Object.entries(INDUSTRIES)) {
    assert.ok(ind.name, `industry "${key}" missing a name`);
  }
});
