#!/usr/bin/env node
/**
 * SENTINEL APEX — Unified Build Orchestrator
 *
 * A safe sequencing/reporting layer over the six generators already
 * running in production (see orchestrator/generators.js) — it discovers
 * them, resolves dependency order, executes them, and produces a build
 * manifest. It does not replace any of the six existing GitHub Actions
 * workflows or modify the generator scripts themselves; each generator's
 * own cron schedule keeps running exactly as before. This tool is for
 * on-demand full/incremental rebuilds (local or workflow_dispatch) and
 * for producing the manifest the health dashboard reads.
 *
 * Usage:
 *   node orchestrator/build-orchestrator.js --discover
 *   node orchestrator/build-orchestrator.js --run <id> [--full]
 *   node orchestrator/build-orchestrator.js --run-all [--incremental|--full]
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { generators } = require('./generators');
const { execGenerator, ROOT } = require('./generator-sdk');

const STATE_FILE = path.join(ROOT, 'data', 'orchestrator-state.json');

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch (_) {
    return {};
  }
}

function saveState(state) {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf8');
}

/** Newest mtime under a declared input path (file or directory subtree). Missing paths are ignored (0). */
function newestMtime(relPath) {
  const base = path.join(ROOT, relPath);
  let newest = 0;
  (function walk(p) {
    let st;
    try {
      st = fs.statSync(p);
    } catch (_) {
      return;
    }
    if (st.isDirectory()) {
      for (const entry of fs.readdirSync(p)) walk(path.join(p, entry));
    } else if (st.isFile() && st.mtimeMs > newest) {
      newest = st.mtimeMs;
    }
  })(base);
  return newest;
}

function topoSort(gens) {
  const byId = new Map(gens.map((g) => [g.id, g]));
  const visited = new Set();
  const visiting = new Set();
  const order = [];
  function visit(id) {
    if (visited.has(id)) return;
    if (visiting.has(id)) throw new Error(`Circular generator dependency detected at "${id}"`);
    const gen = byId.get(id);
    if (!gen) throw new Error(`Unknown generator dependency "${id}"`);
    visiting.add(id);
    for (const dep of gen.dependsOn) visit(dep);
    visiting.delete(id);
    visited.add(id);
    order.push(gen);
  }
  for (const g of gens) visit(g.id);
  return order;
}

/** No declared local inputs (e.g. external feed pulls) => never skipped by --incremental. */
function shouldSkipIncremental(gen, state) {
  if (!gen.inputs.length) return false;
  const last = state[gen.id] && state[gen.id].lastSuccessAt;
  if (!last) return false;
  const newest = Math.max(0, ...gen.inputs.map(newestMtime));
  return newest > 0 && newest <= last;
}

async function runGenerators(targets, opts) {
  const state = loadState();
  const blocked = new Set();
  const results = [];

  for (const gen of targets) {
    const blockedDeps = gen.dependsOn.filter((d) => blocked.has(d));
    if (blockedDeps.length) {
      results.push({ id: gen.id, status: 'skipped_blocked', durationMs: 0, error: `Upstream dependency failed: ${blockedDeps.join(', ')}` });
      blocked.add(gen.id);
      continue;
    }
    if (!opts.full && opts.incremental && shouldSkipIncremental(gen, state)) {
      console.log(`⏭  ${gen.id} — skipped (inputs unchanged since last successful run)`);
      results.push({ id: gen.id, status: 'skipped_unchanged', durationMs: 0, error: null });
      continue;
    }
    console.log(`\n▶ Running "${gen.id}" — ${gen.description}`);
    const result = await execGenerator(gen);
    console.log(`  ${result.status === 'success' ? '✅' : '❌'} ${gen.id} (${result.durationMs}ms)${result.error ? ' — ' + result.error : ''}`);
    if (result.stderrTail) {
      console.log(`  stderr tail:\n${result.stderrTail.split('\n').map((l) => '    ' + l).join('\n')}`);
    }
    results.push(result);
    if (result.status === 'success') {
      state[gen.id] = { lastSuccessAt: Date.now() };
    } else {
      blocked.add(gen.id);
    }
  }

  saveState(state);
  return results;
}

function writeManifest(results) {
  const manifest = {
    generated: new Date().toISOString(),
    platform: 'CYBERDUDEBIVASH SENTINEL APEX',
    results,
    summary: {
      total: results.length,
      success: results.filter((r) => r.status === 'success').length,
      failed: results.filter((r) => r.status === 'failed').length,
      skipped: results.filter((r) => String(r.status).startsWith('skipped')).length,
    },
  };
  const logsDir = path.join(ROOT, 'logs');
  fs.mkdirSync(logsDir, { recursive: true });
  const ts = manifest.generated.replace(/[:.]/g, '-');
  fs.writeFileSync(path.join(logsDir, `build-manifest-${ts}.json`), JSON.stringify(manifest, null, 2), 'utf8');
  fs.writeFileSync(path.join(logsDir, 'build-manifest-latest.json'), JSON.stringify(manifest, null, 2), 'utf8');
  console.log(`\n📋 Build manifest: logs/build-manifest-${ts}.json`);
  return manifest;
}

function printDiscovery() {
  console.log('Registered generators (dependency order):');
  for (const g of topoSort(generators)) {
    console.log(`  ${g.id.padEnd(20)} deps=[${g.dependsOn.join(',')}]  schedule=${g.schedule || 'none'}`);
    console.log(`    ${g.description}`);
  }
}

function printUsage() {
  console.log('Usage: node orchestrator/build-orchestrator.js [--discover|--run <id>|--run-all] [--incremental|--full]');
}

async function cli() {
  const args = process.argv.slice(2);
  if (args.includes('--discover') || args.length === 0) {
    printDiscovery();
    return;
  }

  const runIdx = args.indexOf('--run');
  const opts = {
    runAll: args.includes('--run-all'),
    runId: runIdx >= 0 ? args[runIdx + 1] : null,
    incremental: args.includes('--incremental'),
    full: args.includes('--full'),
  };

  let targets;
  if (opts.runAll) {
    targets = topoSort(generators);
  } else if (opts.runId) {
    const gen = generators.find((g) => g.id === opts.runId);
    if (!gen) {
      console.error(`::error title=Unknown Generator::"${opts.runId}" is not registered. Run --discover to list valid ids.`);
      process.exitCode = 1;
      return;
    }
    targets = [gen];
  } else {
    printUsage();
    process.exitCode = 1;
    return;
  }

  const results = await runGenerators(targets, opts);
  const manifest = writeManifest(results);
  console.log(`\n${manifest.summary.success}/${manifest.summary.total} succeeded, ${manifest.summary.failed} failed, ${manifest.summary.skipped} skipped`);
  if (manifest.summary.failed > 0) process.exitCode = 1;
}

if (require.main === module) {
  cli().catch((e) => {
    console.error('::error title=Orchestrator Fatal Error::' + (e.stack || e));
    process.exitCode = 1;
  });
}

module.exports = { topoSort, runGenerators, writeManifest, newestMtime, shouldSkipIncremental };
