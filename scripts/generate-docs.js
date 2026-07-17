#!/usr/bin/env node
/**
 * SENTINEL APEX — Documentation Generator
 *
 * Read-only introspection, not hand-authored prose: API reference is
 * parsed from the header comment blocks every api/v1/*.js router already
 * maintains (they're the source of truth for routing; this just extracts
 * them into one page instead of requiring six file opens). Build-system
 * docs are generated directly from orchestrator/generators.js. Data-schema
 * docs sample one real file per known JSON shape and list its actual keys
 * — field descriptions are hand-maintained annotations layered on top of
 * introspected (not guessed) key lists.
 *
 * Usage: node scripts/generate-docs.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const DOCS_DIR = path.join(ROOT, 'docs');

function esc(s) {
  return String(s == null ? '' : s);
}

/* ═══════════════════════════════════════════════════════════════════
   API REFERENCE — parsed from api/v1/*.js header comment blocks
═══════════════════════════════════════════════════════════════════ */

function parseApiFile(filePath) {
  const src = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
  const headerMatch = src.match(/^\/\*\*([\s\S]*?)\*\//);
  if (!headerMatch) return null;
  const header = headerMatch[1].split('\n').map((l) => l.replace(/^\s*\*\s?/, ''));

  const title = header.find((l) => l.trim() && !l.startsWith(' ')) || path.basename(filePath);
  const routingLine = header.find((l) => /^Routing:/.test(l.trim()));
  const routingText = routingLine ? routingLine.trim().replace(/^Routing:\s*/, '') : null;
  const actionLines = header
    .map((l) => l.match(/^\s*action=(\S+)\s+(GET|POST|PUT|DELETE)\s+(.*)$/))
    .filter(Boolean)
    .map((m) => ({ action: m[1], method: m[2], description: m[3].trim() }));

  // Single-purpose endpoints (e.g. newsletter.js) declare "POST /api/v1/x" directly instead of action= lines.
  const directRouteLine = header.find((l) => /^(GET|POST|PUT|DELETE)\s+\/api\/v1\//.test(l.trim()));

  return {
    file: path.relative(ROOT, filePath),
    title: title.trim(),
    routing: routingText || (directRouteLine ? directRouteLine.trim() : null),
    actions: actionLines,
  };
}

function generateApiReference() {
  const v1Dir = path.join(ROOT, 'api', 'v1');
  const files = fs.readdirSync(v1Dir)
    .filter((f) => f.endsWith('.js') && fs.statSync(path.join(v1Dir, f)).isFile())
    .sort();

  let md = `# API Reference\n\n_Auto-generated from the header comment block each \`api/v1/*.js\` router already maintains — regenerate with \`node scripts/generate-docs.js\` after changing a route. Do not hand-edit._\n\n`;

  for (const f of files) {
    const parsed = parseApiFile(path.join(v1Dir, f));
    if (!parsed) continue;
    md += `## ${esc(parsed.title)}\n\n`;
    md += `**File:** \`${esc(parsed.file)}\`\n\n`;
    if (parsed.routing) md += `**Routing:** ${esc(parsed.routing)}\n\n`;
    if (parsed.actions.length) {
      md += `| Action | Method | Description |\n|---|---|---|\n`;
      for (const a of parsed.actions) {
        md += `| \`${esc(a.action)}\` | ${esc(a.method)} | ${esc(a.description)} |\n`;
      }
      md += '\n';
    }
  }

  md += `## Content Graph Lookup\n\nAll five entity types exposed via \`api/v1/intel.js?action=entity&type={type}&id={id}\` are backed by \`api/_lib/content-graph.js\`, itself a facade over the intel-graph subsystem (threat-graph.js/campaign-engine.js) and the intelligence-hub subsystem (vendor/timeline/collections/detections). Valid types: \`cve\`, \`vendor\`, \`actor\`, \`campaign\`, \`collection\`.\n`;

  return md;
}

/* ═══════════════════════════════════════════════════════════════════
   BUILD SYSTEM — generated from orchestrator/generators.js
═══════════════════════════════════════════════════════════════════ */

function generateBuildSystemDocs() {
  const { generators } = require(path.join(ROOT, 'orchestrator', 'generators.js'));
  const { topoSort } = require(path.join(ROOT, 'orchestrator', 'build-orchestrator.js'));

  let md = `# Build System\n\n_Auto-generated from \`orchestrator/generators.js\` — the single source of truth for every generator's metadata. Regenerate with \`node scripts/generate-docs.js\`._\n\n`;
  md += `## Generator SDK\n\nEvery generator is described via \`orchestrator/generator-sdk.js\`'s \`defineGenerator()\` contract: \`{ id, description, inputs, outputs, dependsOn, freshnessCheck, schedule, run | command }\`. Generators with a \`run()\` execute in-process (only \`generate-intelligence-hub.js\` today, the SDK's reference implementation — it already exported \`main()\`). Every pre-existing, already-CI-scheduled generator is wrapped via \`command\` instead, shelled out exactly as its own GitHub Actions workflow already invokes it, so registering it here never requires modifying its working code.\n\n`;
  md += `## Registered Generators (dependency order)\n\n`;
  md += `| ID | Schedule | Depends On | Description |\n|---|---|---|---|\n`;
  for (const g of topoSort(generators)) {
    md += `| \`${esc(g.id)}\` | ${esc(g.schedule || 'n/a')} | ${g.dependsOn.length ? g.dependsOn.map((d) => `\`${d}\``).join(', ') : '—'} | ${esc(g.description)} |\n`;
  }
  md += `\n## Orchestrator CLI\n\n\`\`\`\nnode orchestrator/build-orchestrator.js --discover              # list generators\nnode orchestrator/build-orchestrator.js --run <id>               # run one generator\nnode orchestrator/build-orchestrator.js --run-all [--incremental] # run all, in dependency order\n\`\`\`\n\n`;
  md += `Every invocation writes \`logs/build-manifest-<timestamp>.json\` and \`logs/build-manifest-latest.json\`. \`--incremental\` skips a generator whose declared \`inputs\` haven't changed since its last recorded success (generators with no local inputs — e.g. external feed pulls — always run).\n\n`;
  md += `This orchestrator is available on-demand via the \`workflow_dispatch\`-only \`build-orchestrator.yml\` workflow. It does **not** replace or schedule over any of the six generators' own independent GitHub Actions workflows.\n`;

  return md;
}

/* ═══════════════════════════════════════════════════════════════════
   DATA SCHEMAS — introspected keys from real sampled files + hand-
   maintained field annotations
═══════════════════════════════════════════════════════════════════ */

const FIELD_NOTES = {
  'data/published_posts.json': {
    description: 'Blogger syndication state — single source of truth for what has already been re-published to cyberbivash.blogspot.com. Written by automation/content_discovery.py\'s PublicationState.',
    fields: {
      posts: 'Map of content_hash -> { source_url, source_title, blogger_post_id, blogger_url, published_at, labels[], cves[], content_hash }',
    },
  },
  'api/intel/cve/{id}.json': {
    description: 'Per-CVE intelligence record. Backs the static /cve/{id}.html page and the Vendor Intelligence Centers (api/_lib/intelligence-hub.js filters this file\'s `vendor` field for genuine technology vendors vs. news-source labels).',
    fields: {},
  },
  'api/intel/products/{slug}.json': {
    description: 'Per-article intelligence package, one per successfully published on-site post (posts/{slug}.html). Schema `sentinel-apex.intelligence/1.0`. `vendor` is frequently the ingestion SOURCE label (e.g. "BleepingComputer"), not a real affected vendor — see api/_lib/intelligence-hub.js\'s isRealVendor() filter.',
    fields: {},
  },
  'api/intel/vendors.json': {
    description: 'Generated by generate-intelligence-hub.js — real vendor/ecosystem index (technology vendors + open-source package ecosystems only, news sources excluded).',
    fields: {},
  },
  'api/intel/timeline.json': {
    description: 'Generated by generate-intelligence-hub.js — chronological feed of real published intelligence, newest first.',
    fields: {},
  },
  'api/intel/collections.json': {
    description: 'Generated by generate-intelligence-hub.js — curated topic collections (Ransomware, AI Security, Supply Chain, APT, KEV, Cloud/DevSecOps), keyword-matched against real content. Empty collections are omitted entirely.',
    fields: {},
  },
  'api/intel/campaigns.json': {
    description: 'Generated by api/_lib/campaign-engine.js — weighted-similarity campaign clustering (IOC overlap, CVE match, time decay, actor-overlap bonus) over live intel items. Legitimately empty when nothing currently clusters above the 0.60 threshold.',
    fields: {},
  },
  'api/intel/threat-graph.json': {
    description: 'Node/edge threat-actor relationship graph (ThreatActor | CVE | Campaign | Malware | IOC nodes; exploits|executes|uses|targets|... edges). Served tier-filtered via api/v1/intel.js?action=graph.',
    fields: {},
  },
};

function sampleFile(relPathOrDir) {
  const isTemplate = relPathOrDir.includes('{');
  if (!isTemplate) {
    const full = path.join(ROOT, relPathOrDir);
    if (!fs.existsSync(full)) return null;
    return JSON.parse(fs.readFileSync(full, 'utf8'));
  }
  const dir = path.join(ROOT, relPathOrDir.split('{')[0]);
  if (!fs.existsSync(dir)) return null;
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  if (!files.length) return null;
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), 'utf8'));
}

function describeShape(value) {
  if (Array.isArray(value)) return `array (${value.length} sampled item${value.length === 1 ? '' : 's'})`;
  if (value === null) return 'null';
  return typeof value;
}

function generateDataSchemas() {
  let md = `# Data Schemas\n\n_Auto-generated: top-level keys are introspected from a real sampled file per shape (never invented); descriptions are hand-maintained annotations. Regenerate with \`node scripts/generate-docs.js\`._\n\n`;

  for (const [relPath, meta] of Object.entries(FIELD_NOTES)) {
    md += `## \`${esc(relPath)}\`\n\n${esc(meta.description)}\n\n`;
    const sample = sampleFile(relPath);
    if (!sample) {
      md += `_No sample file currently present on disk to introspect._\n\n`;
      continue;
    }
    md += `| Key | Type (from sample) | Notes |\n|---|---|---|\n`;
    for (const key of Object.keys(sample)) {
      const note = meta.fields[key] || '';
      md += `| \`${esc(key)}\` | ${esc(describeShape(sample[key]))} | ${esc(note)} |\n`;
    }
    md += '\n';
  }

  return md;
}

/* ═══════════════════════════════════════════════════════════════════
   MAIN
═══════════════════════════════════════════════════════════════════ */

function main() {
  fs.mkdirSync(DOCS_DIR, { recursive: true });
  fs.writeFileSync(path.join(DOCS_DIR, 'api-reference.md'), generateApiReference(), 'utf8');
  fs.writeFileSync(path.join(DOCS_DIR, 'build-system.md'), generateBuildSystemDocs(), 'utf8');
  fs.writeFileSync(path.join(DOCS_DIR, 'data-schemas.md'), generateDataSchemas(), 'utf8');
  console.log('📚 Documentation generated: docs/api-reference.md, docs/build-system.md, docs/data-schemas.md');
}

if (require.main === module) {
  main();
}

module.exports = { main, parseApiFile, generateApiReference, generateBuildSystemDocs, generateDataSchemas };
