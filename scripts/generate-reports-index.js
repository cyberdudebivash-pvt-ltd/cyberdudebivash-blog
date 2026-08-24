#!/usr/bin/env node
/**
 * SENTINEL APEX — Reports Index Generator
 *
 * Derives api/intel/reports-index.json from the real published report
 * front matter in Sentinel-APEX/reports/published/*.md — the only
 * canonical source of "which reports are published" (there is no other
 * machine-readable manifest; intelligence/index.html is hand-maintained
 * HTML, not data — see platform/open-issues.md Issue 5's own account of
 * that page silently drifting from reality once already).
 *
 * Rebuildable, deterministic: re-running this script against the same
 * published/ directory always produces the same output (sorted by
 * report_id). Nothing here is fabricated — every field is read directly
 * from a report's own YAML front matter, or is the exact slugify()
 * formula publish-report.js itself already uses to name the rendered
 * HTML file, imported and reused unchanged (not reimplemented).
 *
 * Run manually whenever a report is published/updated:
 *   node scripts/generate-reports-index.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { slugify } = require('../Sentinel-APEX/renderer/publish-report');

const PUBLISHED_DIR = path.resolve(__dirname, '../Sentinel-APEX/reports/published');
const OUTPUT_PATH = path.resolve(__dirname, '../api/intel/reports-index.json');

function parseFrontMatter(raw) {
  const match = raw.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return null;
  return yaml.load(match[1]);
}

function buildReportsIndex() {
  const files = fs.existsSync(PUBLISHED_DIR)
    ? fs.readdirSync(PUBLISHED_DIR).filter(f => f.endsWith('.md'))
    : [];

  const reports = [];
  for (const file of files) {
    const raw = fs.readFileSync(path.join(PUBLISHED_DIR, file), 'utf8');
    const meta = parseFrontMatter(raw);
    if (!meta || !meta.report_id) {
      console.error(`[REPORTS-INDEX] Skipping ${file}: no parseable report_id in front matter`);
      continue;
    }
    if (String(meta.review_status || '').toLowerCase() !== 'published') {
      console.error(`[REPORTS-INDEX] Skipping ${file}: review_status is "${meta.review_status}", not "published"`);
      continue;
    }
    const cves = Array.isArray(meta.cves) ? meta.cves : [];
    const slug = slugify(`${meta.report_id}-${cves[0] || meta.title}`);
    reports.push({
      report_id:         meta.report_id,
      title:             meta.title || null,
      slug,
      url:               `/intelligence/${slug}.html`,
      date:              meta.date || null,
      last_updated:      meta.last_updated || meta.date || null,
      severity:          meta.severity || null,
      overall_confidence: meta.overall_confidence || null,
      tlp:               meta.tlp || null,
      cves,
      threat_actors:     Array.isArray(meta.threat_actors) ? meta.threat_actors : [],
      malware_families:  Array.isArray(meta.malware_families) ? meta.malware_families : [],
      sectors:           Array.isArray(meta.sectors) ? meta.sectors : [],
      attack_ids:        Array.isArray(meta.attack_ids) ? meta.attack_ids : [],
      source_file:       file,
    });
  }

  reports.sort((a, b) => a.report_id.localeCompare(b.report_id));

  return {
    schema_version: '1.0',
    generated:      new Date().toISOString(),
    count:          reports.length,
    reports,
  };
}

function main() {
  const index = buildReportsIndex();
  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(index, null, 2), 'utf8');
  console.log(`[REPORTS-INDEX] Wrote ${index.count} published report(s) to ${OUTPUT_PATH}`);
  for (const r of index.reports) {
    console.log(`  ${r.report_id}  ${r.slug}  cves=${r.cves.join(',')}`);
  }
}

if (require.main === module) {
  main();
} else {
  module.exports = { parseFrontMatter, buildReportsIndex };
}
