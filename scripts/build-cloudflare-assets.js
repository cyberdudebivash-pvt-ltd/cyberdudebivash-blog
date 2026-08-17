'use strict';

/**
 * Builds dist-public/ — the ONLY directory wrangler.jsonc's assets.
 * directory points at. Allowlist-first, deliberately not the same model
 * as .assetsignore's denylist: only paths explicitly listed below are
 * copied, so nothing can leak into the deployed bundle by omission. A
 * missed exclusion in a denylist means exposure; a missed inclusion in an
 * allowlist just means something is briefly missing and visibly broken —
 * the safe failure direction for a repo that has already had one real
 * accidental-exposure incident (see VERCEL_MIGRATION_INVENTORY.md Sec3).
 *
 * Every entry below was verified against actual usage before inclusion,
 * not assumed from a directory/file name:
 *  - Root .js/.css files were checked for real <script src=>/<link href=>
 *    references, including from posts/**.html — that's where
 *    banner-orchestrator.js, conversion-engine.js, ux-controller.js and
 *    mobile-first.css turned out to be loaded from (a plain root-HTML-only
 *    grep misses them entirely).
 *  - Root JSON files were checked for any client-side fetcher.
 *    search-index.json (fetched by search.html/archive.html) and
 *    live-intel.json (fetched by live-feed-widget.js, itself confirmed
 *    client-loaded) qualified; intel-memory.json, intel-state.json,
 *    ai-security-intel-{memory,state}.json and data/** did not — no HTML
 *    or client-JS reference exists for any of them, only build-script
 *    (fetch-live-intel.js etc.) reads/writes — same category as the
 *    already-gitignored pipeline-health-history.json, just not yet
 *    gitignored itself. Treated as internal pipeline state, excluded.
 *  - blogger-theme/ (Blogger.com theme XML, a separate platform's
 *    publishing config, not this site's own content) and logs/
 *    (pipeline run logs, zero client/HTML reference found) are excluded
 *    here even though .vercelignore never excluded them — a deliberate,
 *    evidence-based tightening the allowlist model enables, not an
 *    oversight. See VERCEL-CLOUDFLARE-PARITY-MATRIX.md.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'dist-public');

const PUBLIC_DIRS = [
  'posts', 'cve', 'intel', 'intelligence', 'threat', 'malware',
  'detections', 'attack', 'breaking', 'collections', 'timeline',
  'research', 'ai-security', 'vendor', '.well-known',
];

const PUBLIC_ROOT_FILES = [
  // HTML pages (verified: every root-level .html file, none excluded by
  // .vercelignore today)
  'about.html', 'api-dashboard.html', 'api.html', 'archive.html',
  'contact.html', 'enterprise.html', 'faq.html', 'index.html',
  'intelligence.html', 'mitre-attack-detection.html', 'newsletter.html',
  'order-confirmation.html', 'owasp-llm-top10.html', 'pricing.html',
  'privacy.html', 'products.html', 'search.html',
  'security-disclosure.html', 'terms.html', 'threat-intelligence.html',
  // CSS — confirmed via <link href=>
  'apex-v12.css', 'apex-v13.css', 'mobile-first.css',
  // Client-side JS — confirmed via <script src=> (including from posts/**)
  'ai-monetization-engine.js', 'analytics-engine.js', 'auto-intel-engine.js',
  'banner-orchestrator.js', 'conversion-engine.js', 'email-engine.js',
  'live-feed-widget.js', 'monetization.js', 'payment-engine.js',
  'payment-flow.js', 'revenue-cta-block.js', 'security-engine.js',
  'seo-engine.js', 'ux-controller.js',
  // Icons / manifest / OG image — standard public web-app conventions
  'apple-touch-icon.png', 'brand-logo.svg', 'favicon.ico', 'favicon.svg',
  'icon-192.png', 'icon-512.png', 'og-image.png', 'site.webmanifest',
  // Feeds / crawler files
  'robots.txt', 'rss.xml', 'sitemap.xml',
  // Client-fetched JSON — confirmed via reference from search.html/
  // archive.html and live-feed-widget.js respectively
  'search-index.json', 'live-intel.json',
];

function copyDir(src, dest, filter) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(s, d, filter);
    } else if (!filter || filter(entry.name)) {
      fs.mkdirSync(path.dirname(d), { recursive: true });
      fs.copyFileSync(s, d);
    }
  }
}

function countFiles(dir) {
  let n = 0;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) n += countFiles(path.join(dir, entry.name));
    else n++;
  }
  return n;
}

/** @returns {string} the built directory's absolute path */
function build() {
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });

  for (const dir of PUBLIC_DIRS) {
    const src = path.join(ROOT, dir);
    if (fs.existsSync(src)) copyDir(src, path.join(OUT, dir));
  }
  for (const file of PUBLIC_ROOT_FILES) {
    const src = path.join(ROOT, file);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(OUT, file));
  }

  // api/intel/**/*.json only — never api/**/*.js (server-side handler
  // code, see .assetsignore's reasoning; this allowlist independently
  // enforces the same boundary via the .json-only filter, not by trusting
  // .assetsignore alone).
  const apiIntelSrc = path.join(ROOT, 'api', 'intel');
  if (fs.existsSync(apiIntelSrc)) {
    copyDir(apiIntelSrc, path.join(OUT, 'api', 'intel'), name => name.endsWith('.json'));
  }

  return OUT;
}

if (require.main === module) {
  const out = build();
  console.log(`dist-public/ built: ${countFiles(out)} files`);
}

module.exports = { build, countFiles, PUBLIC_DIRS, PUBLIC_ROOT_FILES, ROOT, OUT };
