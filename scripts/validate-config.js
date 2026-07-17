#!/usr/bin/env node
/**
 * SENTINEL APEX — Config Validation Layer
 *
 * Sanity-checks the existing JS-side configuration surfaces (the
 * orchestrator generator registry, feature flags, subscription plans,
 * services/industry catalog) without centralizing them into one system —
 * each stays where it already lives, this just validates shape/references
 * across all of them from one entry point. Returns issues; never mutates.
 */
'use strict';
const { generators } = require('../orchestrator/generators');
const { FLAGS } = require('../api/_lib/feature-flags');
const { PLANS, TIERS } = require('../api/_lib/subscription-catalog');
const { SERVICES, INDUSTRIES } = require('../api/_lib/services-catalog');

function validateGeneratorRegistry(gens) {
  const issues = [];
  const ids = new Set();
  for (const g of gens) {
    if (ids.has(g.id)) issues.push(`Duplicate generator id "${g.id}"`);
    ids.add(g.id);
  }
  for (const g of gens) {
    for (const dep of g.dependsOn) {
      if (!ids.has(dep)) issues.push(`Generator "${g.id}" depends on unknown generator "${dep}"`);
    }
    if (g.freshnessCheck && (!g.freshnessCheck.file || !g.freshnessCheck.maxAgeMinutes)) {
      issues.push(`Generator "${g.id}" has an incomplete freshnessCheck (needs file + maxAgeMinutes)`);
    }
  }
  return issues;
}

function validateFeatureFlags(flags) {
  const issues = [];
  for (const [key, flag] of Object.entries(flags)) {
    if (typeof flag.enabled !== 'boolean') issues.push(`Feature flag "${key}" missing boolean "enabled"`);
    if (!flag.description) issues.push(`Feature flag "${key}" missing a description`);
  }
  return issues;
}

function validateSubscriptionCatalog(plans, tiers) {
  const issues = [];
  for (const tier of tiers) {
    if (!plans[tier]) { issues.push(`Tier "${tier}" (from middleware.js TIERS) has no matching plan definition`); continue; }
    const plan = plans[tier];
    if (typeof plan.apiRequestsPerDay !== 'number' || plan.apiRequestsPerDay <= 0) {
      issues.push(`Plan "${tier}" has an invalid apiRequestsPerDay: ${plan.apiRequestsPerDay}`);
    }
    if (!Array.isArray(plan.features) || plan.features.length === 0) {
      issues.push(`Plan "${tier}" has no features listed`);
    }
  }
  return issues;
}

function validateServicesCatalog(services, industries) {
  const issues = [];
  for (const [key, industry] of Object.entries(industries)) {
    for (const svcKey of industry.services) {
      if (!services[svcKey]) issues.push(`Industry "${key}" references unknown service "${svcKey}"`);
    }
  }
  return issues;
}

function validateAll() {
  return {
    generators: validateGeneratorRegistry(generators),
    featureFlags: validateFeatureFlags(FLAGS),
    subscriptionCatalog: validateSubscriptionCatalog(PLANS, TIERS),
    servicesCatalog: validateServicesCatalog(SERVICES, INDUSTRIES),
  };
}

function main() {
  const results = validateAll();
  let totalIssues = 0;
  for (const [surface, issues] of Object.entries(results)) {
    if (issues.length) {
      console.log(`❌ ${surface}: ${issues.length} issue(s)`);
      issues.forEach((i) => console.log(`   - ${i}`));
      totalIssues += issues.length;
    } else {
      console.log(`✅ ${surface}: OK`);
    }
  }
  if (totalIssues > 0) {
    console.error(`\n::error title=Config Validation Failed::${totalIssues} issue(s) found across configuration surfaces`);
    process.exitCode = 1;
  } else {
    console.log('\n✅ All configuration surfaces valid');
  }
}

if (require.main === module) {
  main();
}

module.exports = { validateGeneratorRegistry, validateFeatureFlags, validateSubscriptionCatalog, validateServicesCatalog, validateAll };
