#!/usr/bin/env node
'use strict';
/**
 * SENTINEL APEX — Analyst Report Publisher (EIPP v1)
 *
 * The one supported path from a reviewed Markdown report in
 * Sentinel-APEX/reports/ to a real, customer-facing page. Deliberately a
 * manual/CLI action, not part of the 5-minute automated feed — hand-authored
 * analyst reports go through deliberate review (see Sentinel-APEX/docs/
 * CONVENTIONS.md's drafts -> final -> published lifecycle), unlike the
 * continuous automated post pipeline in fetch-live-intel.js.
 *
 * Usage: node Sentinel-APEX/renderer/publish-report.js <path-to-report.md>
 *
 * What this does NOT do (see Sentinel-APEX/docs/report-experience-audit.md
 * and platform/open-issues.md for why these are deliberately out of scope
 * for a first publication): full faceted navigation/search across a report
 * corpus that doesn't exist yet beyond this one document, PDF/email/API
 * output, a design system beyond reusing what generatePostHTML() already
 * established.
 */

const fs = require('fs');
const path = require('path');
const { parseReport } = require('./report-renderer');

// Composes from the model's preamble/sections directly rather than
// toHTMLDocument() — that helper also renders metadata.title as its own
// <h1>, but this page already renders a styled title with badges above it
// in buildPage() below. Exactly the flexibility parseReport()/toHTMLDocument()
// being separate functions was meant to give a second consumer.
function bodyOnlyHTML(model) {
  const parts = [];
  if (model.preamble.rawMarkdown) parts.push(model.preamble.html);
  for (const s of model.sections) {
    parts.push(`<section class="report-section">\n<h2 class="sh"><span>${
      String(s.name).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    }</span></h2>\n${s.html}\n</section>`);
  }
  return parts.join('\n\n');
}

const REPO_ROOT = path.join(__dirname, '..', '..');
const OUTPUT_DIR = path.join(REPO_ROOT, 'intelligence');
const BASE_URL = 'https://blog.cyberdudebivash.in';

function escHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function slugify(str) {
  return String(str).toLowerCase().replace(/[^a-z0-9\s-]/g, ' ')
    .replace(/\s+/g, '-').replace(/-{2,}/g, '-').replace(/^-|-$/g, '').slice(0, 90);
}

function truncAtWord(s, n) {
  return s.length <= n ? s : s.slice(0, n + 1).replace(/\s+\S*$/, '').slice(0, n);
}

const SEVERITY_COLOR = { CRITICAL: '#ff3b3b', HIGH: '#ff8c00', MEDIUM: '#ffe000', LOW: '#00ff88' };

function buildPage(model, slug) {
  const meta = model.metadata;
  const severity = String(meta.severity || '').toUpperCase();
  const sevColor = SEVERITY_COLOR[severity] || SEVERITY_COLOR.HIGH;
  const title = meta.title || 'Sentinel APEX Intelligence Report';
  const metaTitle = `${title} | CYBERDUDEBIVASH SENTINEL APEX`;
  const cveList = Array.isArray(meta.cves) ? meta.cves : [];
  const primaryCve = cveList[0] || '';
  const metaDesc = truncAtWord(
    (primaryCve ? `${primaryCve} — ` : '') + title.replace(/^Critical |^Executive Threat Brief.*?— /, ''),
    155
  ) + '. Analyst intelligence report by CYBERDUDEBIVASH SENTINEL APEX.';
  const canonicalUrl = `${BASE_URL}/intelligence/${slug}.html`;
  const ogImageUrl = `${BASE_URL}/api/og?title=${encodeURIComponent(title)}&severity=${encodeURIComponent(severity || 'HIGH')}&cve=${encodeURIComponent(primaryCve)}&type=${encodeURIComponent('INTELLIGENCE REPORT')}`;
  const pubDate = meta.date || new Date().toISOString().slice(0, 10);
  const today = new Date().toISOString();

  const bodyHtml = bodyOnlyHTML(model);

  const cveBadges = cveList.map(c =>
    `<span class="badge bdg-cyan" style="font-family:var(--mono)">${escHtml(c)}</span>`).join(' ');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="${escHtml(metaDesc)}">
<meta property="og:title" content="${escHtml(metaTitle)}"><meta property="og:type" content="article">
<meta property="og:url" content="${canonicalUrl}">
<meta property="og:description" content="${escHtml(metaDesc)}">
<meta property="og:site_name" content="CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:locale" content="en_US">
<meta property="og:image" content="${escHtml(ogImageUrl)}">
<meta property="og:image:secure_url" content="${escHtml(ogImageUrl)}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${escHtml(metaTitle)}">
<meta property="article:published_time" content="${escHtml(pubDate)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escHtml(metaTitle)}">
<meta name="twitter:description" content="${escHtml(metaDesc)}">
<meta name="twitter:image" content="${escHtml(ogImageUrl)}">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#00ffe0">
<link rel="canonical" href="${canonicalUrl}">
<title>${escHtml(metaTitle)}</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","headline":"${escHtml(title)}","description":"${escHtml(metaDesc)}","image":"${ogImageUrl}","datePublished":"${escHtml(pubDate)}","dateModified":"${escHtml(meta.last_updated || pubDate)}","author":{"@type":"Organization","name":"CYBERDUDEBIVASH SENTINEL APEX","url":"${BASE_URL}"},"publisher":{"@type":"Organization","name":"CYBERDUDEBIVASH"}}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-yellow:#ffe000;--apex-green:#00ff88;--apex-purple:#a855f7;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;line-height:1.7}
header.top{padding:20px 24px;border-bottom:1px solid var(--apex-border);display:flex;align-items:center;justify-content:space-between}
header.top a.home{color:var(--apex-cyan);font-weight:800;text-decoration:none;font-size:15px;letter-spacing:.02em}
main{max-width:900px;margin:0 auto;padding:40px 24px 80px}
.report-badges{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
.badge{display:inline-block;padding:4px 12px;border-radius:5px;font-size:11px;font-weight:700;letter-spacing:.04em}
.bdg-sev{background:${sevColor};color:#07090f}
.bdg-cyan{background:rgba(0,255,224,.12);color:var(--apex-cyan);border:1px solid rgba(0,255,224,.3)}
h1.report-h1{font-size:clamp(24px,4vw,38px);font-weight:800;line-height:1.25;margin-bottom:8px;letter-spacing:-.01em}
.report-meta-line{color:var(--apex-muted);font-size:13px;margin-bottom:32px}
.report-section{margin:32px 0}
h2.sh{font-size:19px;font-weight:800;color:var(--apex-cyan);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}
.report-section p{margin-bottom:14px;font-size:15px}
.report-section ul,.report-section ol{margin:0 0 14px 22px}
.report-section li{margin-bottom:8px;font-size:15px}
.report-section strong{color:#fff}
.tbl{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px}
.tbl th{background:#1a2234;color:var(--apex-cyan);font-weight:700;padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--apex-border)}
.tbl td{padding:10px 14px;border:1px solid var(--apex-border);color:var(--apex-text);vertical-align:top}
.code-block-wrap{margin:16px 0}
.code-block-lang{display:inline-block;background:var(--apex-card);color:var(--apex-muted);font-family:var(--mono);font-size:10px;padding:4px 10px;border-radius:4px 4px 0 0;letter-spacing:.08em}
.code-block{background:#0a0e18;border:1px solid var(--apex-border);border-radius:0 8px 8px 8px;padding:16px 20px;font-family:var(--mono);font-size:12px;color:#a6e22e;overflow-x:auto;white-space:pre;max-height:420px;overflow-y:auto}
.report-section code{background:rgba(0,255,224,.08);padding:.1rem .4rem;border-radius:4px;font-size:.9em;font-family:var(--mono)}
footer.report-footer{border-top:1px solid var(--apex-border);margin-top:48px;padding-top:24px;color:var(--apex-muted);font-size:12px}
@media print{header.top,footer.report-footer{display:none}body{background:#fff;color:#000}.code-block{color:#000;background:#f5f5f5}}
</style>
</head>
<body>
<header class="top">
  <a href="/" class="home">← CYBERDUDEBIVASH SENTINEL APEX</a>
  <span style="color:var(--apex-muted);font-size:12px;font-family:var(--mono)">${escHtml(meta.report_id || '')}</span>
</header>
<main>
  <div class="report-badges">
    ${severity ? `<span class="badge bdg-sev">${escHtml(severity)}</span>` : ''}
    ${meta.tlp ? `<span class="badge bdg-cyan">${escHtml(meta.tlp)}</span>` : ''}
    ${meta.overall_confidence ? `<span class="badge bdg-cyan">${escHtml(meta.overall_confidence)} CONFIDENCE</span>` : ''}
    ${cveBadges}
  </div>
  <h1 class="report-h1">${escHtml(title)}</h1>
  <div class="report-meta-line">Published ${escHtml(pubDate)}${meta.analyst ? ` · ${escHtml(meta.analyst)}` : ''}${meta.version ? ` · v${escHtml(meta.version)}` : ''}</div>
  ${bodyHtml}
  <footer class="report-footer">
    CyberDudeBivash® Sentinel APEX Intelligence Report ${escHtml(meta.report_id || '')} · Generated ${escHtml(today.slice(0,10))}
  </footer>
</main>
</body>
</html>`;
}

function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.error('Usage: node publish-report.js <path-to-report.md>');
    process.exit(1);
  }
  const text = fs.readFileSync(inputPath, 'utf8');
  const model = parseReport(text);
  if (!model.metadata.report_id) {
    console.error('Refusing to publish: no report_id in front matter.');
    process.exit(1);
  }
  const slug = slugify(`${model.metadata.report_id}-${(model.metadata.cves || [])[0] || model.metadata.title}`);
  if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  const outPath = path.join(OUTPUT_DIR, `${slug}.html`);
  fs.writeFileSync(outPath, buildPage(model, slug));
  console.log(`Published: ${outPath}`);
  console.log(`URL: ${BASE_URL}/intelligence/${slug}.html`);
  return { slug, outPath };
}

if (require.main === module) {
  main();
} else {
  module.exports = { buildPage, slugify, main };
}
