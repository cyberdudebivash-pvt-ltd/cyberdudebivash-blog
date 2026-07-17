/**
 * SENTINEL APEX — Generator Registry
 *
 * The single source of truth for every build/publishing generator that
 * runs against this repository. This is a description layer only — the
 * five pre-existing, already-CI-scheduled generators are wrapped via
 * `command` (shelled out exactly as their own GitHub Actions workflow
 * already invokes them) and are NOT modified. Only generate-intelligence-hub.js,
 * which already exports `main()`, is registered natively via `run()`.
 *
 * Consumed by orchestrator/build-orchestrator.js (build sequencing +
 * manifest) and ops/generate-health-dashboard.js (freshness monitoring) —
 * both read this one list rather than each maintaining their own.
 */
'use strict';
const { defineGenerator, ROOT } = require('./generator-sdk');

const generators = [
  defineGenerator({
    id: 'live-intel',
    description: 'Live threat intel ingestion — posts, CVE/product JSON, search index, sitemap',
    command: ['node', 'fetch-live-intel.js'],
    cwd: ROOT,
    inputs: [],
    outputs: ['posts', 'api/intel/products', 'api/intel/cve', 'live-intel.json', 'search-index.json', 'sitemap.xml'],
    dependsOn: [],
    schedule: '0,30 * * * * (sentinel-apex.yml)',
    freshnessCheck: { file: 'live-intel.json', jsonPath: 'metadata.generated', maxAgeMinutes: 90 },
  }),
  defineGenerator({
    id: 'ai-security-intel',
    description: 'AI security & LLM threat intelligence ingestion',
    command: ['node', 'ai-security-intel-engine.js'],
    cwd: ROOT,
    inputs: [],
    outputs: ['api/intel/ai-security.json', 'ai-security/intel/index.html', 'ai-security/reports', 'ai-security-intel-state.json'],
    dependsOn: [],
    schedule: '0 */2 * * * (ai-security-intel.yml)',
    freshnessCheck: { file: 'ai-security-intel-state.json', maxAgeMinutes: 180 },
  }),
  defineGenerator({
    id: 'blogger-syndication',
    description: 'Re-syndicates published reports to Blogger (cyberbivash.blogspot.com)',
    command: ['python3', '-m', 'automation.main'],
    cwd: ROOT,
    // Reads the site's own live RSS over HTTP (source_rss_url), not a local
    // file — a soft/remote dependency on rss.xml being fresh, deliberately
    // not modeled as a hard local dependsOn since the orchestrator can only
    // sequence local file relationships meaningfully.
    inputs: [],
    outputs: ['data/published_posts.json'],
    dependsOn: [],
    schedule: '15 */2 * * * (blogger-syndication.yml)',
    freshnessCheck: { file: 'data/published_posts.json', maxAgeMinutes: 240 },
  }),
  defineGenerator({
    id: 'cve-pages',
    description: 'Renders static /cve/{id}.html pages from ingested CVE JSON',
    command: ['node', 'generate-cve-pages.js'],
    cwd: ROOT,
    inputs: ['api/intel/cve'],
    outputs: ['cve', 'sitemap.xml'],
    dependsOn: ['live-intel'],
    schedule: '0 */6 * * * (cve-pages.yml)',
    freshnessCheck: { file: 'cve', maxAgeMinutes: 6 * 60 + 30 },
  }),
  defineGenerator({
    id: 'intelligence-hub',
    description: 'Vendor/ecosystem centers, timeline, collections, live detection feed',
    run: async () => { require('../generate-intelligence-hub.js').main(); },
    cwd: ROOT,
    inputs: ['api/intel/products', 'api/intel/cve', 'api/intel/campaigns.json'],
    outputs: ['vendor', 'timeline', 'collections', 'detections/live-feed.html', 'threat/index.html',
      'api/intel/vendors.json', 'api/intel/timeline.json', 'api/intel/collections.json', 'api/intel/detections-library.json'],
    dependsOn: ['live-intel'],
    schedule: '20 */6 * * * (intelligence-hub.yml)',
    freshnessCheck: { file: 'api/intel/timeline.json', jsonPath: 'generated', maxAgeMinutes: 6 * 60 + 30 },
  }),
  defineGenerator({
    id: 'rss-feed',
    description: 'Rebuilds rss.xml from published posts',
    command: ['node', 'generate-rss.js'],
    cwd: ROOT,
    inputs: ['posts'],
    outputs: ['rss.xml'],
    dependsOn: ['live-intel'],
    schedule: '0 */6 * * * (generate-rss.yml)',
    freshnessCheck: { file: 'rss.xml', maxAgeMinutes: 6 * 60 + 30 },
  }),
];

module.exports = { generators };
