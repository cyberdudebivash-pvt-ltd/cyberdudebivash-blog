'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { build, countFiles, OUT } = require('./build-cloudflare-assets');

// Path-segment-aware, not substring-aware: an earlier version of this
// test matched "data"/"platform"/"automation"/"tests"/"lib"/etc. as plain
// substrings anywhere in the path, which flags hundreds of entirely
// legitimate posts/**.html and api/intel/products/**.json paths whose
// slugs are real article titles ("...data-breach...",
// "...automation...", "north-korean-hackers-posing-as-fake-it-workers...")
// — a false-positive rate that makes the check worthless. Directory names
// must match a full path SEGMENT exactly; files must match a full
// BASENAME exactly (or a narrow suffix for .env*/.patch/.bundle). Both
// are case-insensitive.

const PROHIBITED_DIR_SEGMENTS = new Set([
  'sentinel-apex', 'eito', 'platform', 'prompts', 'scripts', 'docs',
  'marketing', 'backups', 'node_modules', '.git', '.wrangler', 'workers',
  'tests', 'tests-js', 'lib', 'types', 'automation', 'blogger-theme',
  'logs', 'data', 'coverage',
]);

const PROHIBITED_EXACT_FILENAMES = new Set([
  'claude.md', 'business-transformation-roadmap-2026.md',
  'audit-report-2026-05-28.md', 'operations.md', 'runbooks.md',
  'package.json', 'package-lock.json', 'jest.config.js', 'jest.setup.ts',
  'tsconfig.json',
  'intel-memory.json', 'intel-state.json', 'ai-security-intel-memory.json',
  'ai-security-intel-state.json', 'pipeline-health-history.json',
  'fetch-live-intel.js', 'ai-security-intel-engine.js',
  'generate-cve-pages.js', 'generate-intelligence-hub.js',
  'generate-rss.js', 'generate-search-index.py',
  'build-detections-page.js', 'build-detections.js',
  'build-evi-page.js', 'build-evi.js', 'build-research.js',
]);

function isProhibited(relPath) {
  const lower = relPath.toLowerCase();
  const segments = lower.split('/');
  const basename = segments[segments.length - 1];

  if (segments.some(seg => PROHIBITED_DIR_SEGMENTS.has(seg))) return true;
  if (PROHIBITED_EXACT_FILENAMES.has(basename)) return true;
  if (basename.startsWith('.env')) return true;
  if (basename.endsWith('.patch') || basename.endsWith('.bundle')) return true;
  return false;
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

describe('build-cloudflare-assets', () => {
  let outputFiles;

  test('build() runs and produces a non-trivial dist-public/', () => {
    const outDir = build();
    assert.equal(outDir, OUT);
    assert.ok(fs.existsSync(outDir));
    const count = countFiles(outDir);
    assert.ok(count > 100, `expected a substantial file count, got ${count}`);
    outputFiles = walk(outDir).map(f => path.relative(outDir, f).replace(/\\/g, '/'));
  });

  test('no output path matches a prohibited directory segment or filename', () => {
    const offenders = outputFiles.filter(isProhibited);
    assert.deepEqual(offenders, [], `prohibited paths leaked into dist-public/:\n${offenders.join('\n')}`);
  });

  // Regression guard for the false-positive bug this test previously had:
  // real content whose slug/filename merely contains one of the prohibited
  // words as a substring must NOT be flagged.
  test('legitimate content containing prohibited words as substrings is not flagged', () => {
    const legitimateExamples = [
      'posts/nissan-employee-data-breached-in-oracle-peoplesoft-hack.html',
      'posts/rockwell-automation-patches-vulnerabilities-in-ics-controlle.html',
      'posts/north-korean-hackers-posing-as-fake-it-workers-behind-nearly.html',
      'api/intel/cve/CVE-2026-13760-npm-aws-cdk-lib.json',
      'api/intel/products/mokn-raises-15-million-for-phish-back-platform.json',
    ];
    for (const p of legitimateExamples) {
      assert.equal(isProhibited(p), false, `${p} should not be flagged`);
    }
  });

  test('no .js file exists anywhere under the output api/ tree', () => {
    const jsUnderApi = outputFiles.filter(f => f.startsWith('api/') && f.endsWith('.js'));
    assert.deepEqual(jsUnderApi, [], `handler source leaked as a static asset:\n${jsUnderApi.join('\n')}`);
  });

  test('expected public artifacts are present', () => {
    const mustExist = [
      'index.html', 'robots.txt', 'rss.xml', 'sitemap.xml',
      'search-index.json', 'live-intel.json',
      'apex-v13.css', 'analytics-engine.js', 'banner-orchestrator.js',
    ];
    for (const f of mustExist) {
      assert.ok(outputFiles.includes(f), `expected ${f} in dist-public/ but it was missing`);
    }
    assert.ok(outputFiles.some(f => f.startsWith('posts/') && f.endsWith('.html')), 'expected at least one posts/*.html');
    assert.ok(outputFiles.some(f => f.startsWith('api/intel/') && f.endsWith('.json')), 'expected at least one api/intel/*.json');
  });

  after(() => {
    // dist-public/ is a generated build artifact (gitignored) — leaving it
    // populated on disk after the test run is fine and mirrors what a real
    // deploy step would produce; nothing to clean up for correctness.
  });
});
