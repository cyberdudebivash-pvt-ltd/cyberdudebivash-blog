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

// Cloudflare Workers Static Assets _headers file — transcribed from
// vercel.json's `headers` array (Stage 4 Sec3), not invented fresh. Only
// applies to responses env.ASSETS.fetch() serves; workers/lib/security-
// headers.js is the separate dynamic-response half for everything
// router.js itself returns (handler dispatch/redirects/blocked-404) — see
// that file's header comment for why the two can't be merged into one
// mechanism.
//
// Decomposed so no two rules that can BOTH match the same request set the
// same header name: Cloudflare concatenates duplicate header names across
// ALL matching rules with a comma separator rather than letting the more
// specific rule win ("An incoming request which matches multiple rules'
// URL patterns will inherit all rules' headers" / duplicates "joined with
// a comma separator" — confirmed against Cloudflare's own _headers docs,
// not assumed). Repeating the same value at two matching scopes would
// still corrupt a single-value header like X-Frame-Options into
// "DENY, DENY" on the wire. Vercel's header rules are also cumulative
// across every matching `source` pattern ("Modify actions from all
// matching rules still apply" — confirmed against Vercel's own routing
// docs), so hoisting the headers vercel.json repeats identically across
// its html/api/catch-all blocks (X-Content-Type-Options, X-Frame-Options,
// Referrer-Policy) into the single global /* rule here reproduces the
// same effective per-path header set Vercel produces today, not a
// divergent policy — just without Cloudflare's comma-join hazard.
// Permissions-Policy and Content-Security-Policy are correspondingly kept
// out of the global rule, matching vercel.json's catch-all `/(.*)` block,
// which does not set either.
//
// Deliberately has NO dedicated rule for:
//  - search-index.json / live-intel.json (root-level) — vercel.json's
//    `/api/(.*).json` pattern only matches paths starting with /api/, so
//    on Vercel these two already only ever hit its generic catch-all;
//    matching that is parity, inventing a new JSON rule for them
//    would not be.
//  - detections/rules/*.yml — served exclusively via `<a download>`
//    links in detections/index.html, so response Content-Type is moot;
//    the browser saves the file regardless of what MIME type is served.
//  - .well-known/security.txt — vercel.json has no dedicated rule for
//    it either; falls through to the catch-all on both platforms.
const HEADERS_FILE_CONTENT = `# Auto-generated by scripts/build-cloudflare-assets.js — do not hand-edit.
# See that script's HEADERS_FILE_CONTENT comment for the parity reasoning
# behind every rule (and every deliberate omission) below.

/*
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-DNS-Prefetch-Control: on
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin

/*.html
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://www.googletagmanager.com https://www.google-analytics.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://blog.cyberdudebivash.in https://www.google-analytics.com https://region1.google-analytics.com https://analytics.google.com https://stats.g.doubleclick.net https://api.rss2json.com https://api.allorigins.win https://corsproxy.io https://thingproxy.freeboard.io https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com; frame-src 'self' https://api.razorpay.com https://checkout.razorpay.com; frame-ancestors 'none'

/
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://www.googletagmanager.com https://www.google-analytics.com https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://blog.cyberdudebivash.in https://www.google-analytics.com https://region1.google-analytics.com https://analytics.google.com https://stats.g.doubleclick.net https://api.rss2json.com https://api.allorigins.win https://corsproxy.io https://thingproxy.freeboard.io https://api.razorpay.com https://checkout.razorpay.com https://lumberjack.razorpay.com; frame-src 'self' https://api.razorpay.com https://checkout.razorpay.com; frame-ancestors 'none'

/*.css
  Cache-Control: public, max-age=600, stale-while-revalidate=86400

/*.js
  Cache-Control: public, max-age=600, stale-while-revalidate=86400
  Content-Type: application/javascript; charset=UTF-8

/rss.xml
  Content-Type: application/rss+xml; charset=UTF-8
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400
  Access-Control-Allow-Origin: *

/sitemap.xml
  Content-Type: application/xml; charset=UTF-8
  Cache-Control: public, max-age=3600
  Access-Control-Allow-Origin: *

/robots.txt
  Content-Type: text/plain; charset=UTF-8
  Cache-Control: public, max-age=86400

/api/intel/*
  Content-Type: application/json; charset=UTF-8
  Cache-Control: public, max-age=600, stale-while-revalidate=3600
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Methods: GET, OPTIONS
  X-Powered-By: CYBERDUDEBIVASH SENTINEL APEX v4.0
`;

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

  // Static security headers — see HEADERS_FILE_CONTENT's own header
  // comment above for the full parity reasoning. Written last so it
  // can't be clobbered by any of the copy steps above (none of them
  // write a root-level file literally named _headers, but this ordering
  // makes that guarantee explicit rather than incidental).
  fs.writeFileSync(path.join(OUT, '_headers'), HEADERS_FILE_CONTENT);

  return OUT;
}

if (require.main === module) {
  const out = build();
  console.log(`dist-public/ built: ${countFiles(out)} files`);
}

module.exports = { build, countFiles, PUBLIC_DIRS, PUBLIC_ROOT_FILES, ROOT, OUT, HEADERS_FILE_CONTENT };
