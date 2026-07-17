#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH® SENTINEL APEX — Internal Health Dashboard
 *
 * Read-only: never executes a generator, only inspects what they've
 * already produced (freshness of declared outputs, the latest build
 * manifest if one exists, and a real publish-success trend derived from
 * automation/main.py's previously write-only run logs). Intentionally
 * kept out of the public nav/sitemap — this is an operator page, not an
 * SEO/content surface.
 *
 * Usage: node ops/generate-health-dashboard.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { ROOT } = require('../orchestrator/generator-sdk');
const { generators } = require('../orchestrator/generators');
const { checkAllFreshness } = require('../orchestrator/freshness');
const { summarizeRuns } = require('../orchestrator/run-log-stats');
const { computeStorageStats } = require('../orchestrator/storage-stats');

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function loadLatestManifest() {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, 'logs', 'build-manifest-latest.json'), 'utf8'));
  } catch (_) {
    return null;
  }
}

function statusColor(status) {
  if (status === 'fresh' || status === 'success' || status === 'healthy') return '#22c55e';
  if (status === 'stale' || status === 'failed') return '#ff3b5c';
  if (status === 'missing') return '#ff8c42';
  return '#6b7280';
}

function renderFreshnessCards(freshnessResults) {
  return freshnessResults.map((f) => {
    const gen = generators.find((g) => g.id === f.id);
    return `
      <div class="card">
        <div class="card-head">
          <span class="dot" style="background:${statusColor(f.status)}"></span>
          <strong>${esc(f.id)}</strong>
          <span class="status-pill" style="color:${statusColor(f.status)};border-color:${statusColor(f.status)}44">${esc(f.status.toUpperCase())}</span>
        </div>
        <p class="card-desc">${esc(gen ? gen.description : '')}</p>
        <div class="card-meta">
          ${f.ageMinutes != null ? `<span>Age: ${f.ageMinutes} min</span>` : ''}
          ${f.lastSeen ? `<span>Last seen: ${esc(f.lastSeen)}</span>` : ''}
          <span>Schedule: ${esc(gen && gen.schedule || 'n/a')}</span>
        </div>
      </div>`;
  }).join('\n');
}

function renderManifestSection(manifest) {
  if (!manifest) {
    return '<p class="empty">No build-manifest yet — run the orchestrator (workflow_dispatch: "Build Orchestrator") to produce one.</p>';
  }
  const rows = manifest.results.map((r) => `
      <tr>
        <td>${esc(r.id)}</td>
        <td style="color:${statusColor(r.status)}">${esc(r.status)}</td>
        <td>${r.durationMs}ms</td>
        <td>${esc(r.error || '')}</td>
      </tr>`).join('');
  return `
    <p class="card-meta">Generated ${esc(manifest.generated)} · ${manifest.summary.success}/${manifest.summary.total} succeeded, ${manifest.summary.failed} failed, ${manifest.summary.skipped} skipped</p>
    <table class="manifest-table">
      <thead><tr><th>Generator</th><th>Status</th><th>Duration</th><th>Error</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderRunTrend(runStats) {
  if (!runStats.sampledRuns) {
    return '<p class="empty">No Blogger syndication run logs found.</p>';
  }
  const alert = !runStats.mostRecent.healthy ? `
    <div class="alert">
      ⚠ Most recent Blogger syndication run (${esc(runStats.mostRecent.runStart)}) published 0 posts with ${runStats.mostRecent.failed} failure(s).
      ${runStats.mostRecent.circuitBreakerTripped ? 'Rate-limit circuit breaker tripped — remaining articles were requeued rather than retried.' : 'Check the blogger-syndication.yml workflow logs.'}
      This matches the failure signature of the OAuth/rate-limit incident this platform has hit before.
    </div>` : '';

  const bars = runStats.runs.slice(0, 20).reverse().map((r) => {
    const height = Math.max(4, Math.min(60, (r.published + r.failed) * 4));
    const color = r.healthy ? '#22c55e' : '#ff3b5c';
    return `<div class="bar" style="height:${height}px;background:${color}" title="${esc(r.runStart)} — published:${r.published} failed:${r.failed}"></div>`;
  }).join('');

  const categoryEntries = Object.entries(runStats.failureCategoryTotals || {}).sort((a, b) => b[1] - a[1]);
  const categoryBreakdown = categoryEntries.length ? `
    <div class="stat-row" style="margin-top:10px">
      ${categoryEntries.map(([cat, count]) => `<span class="stat">${esc(cat)}: <b>${count}</b></span>`).join('')}
    </div>` : '';

  return `
    ${alert}
    <p class="card-meta">Last ${runStats.sampledRuns} runs · ${runStats.successRate}% healthy · ${runStats.totalPublished} published · ${runStats.totalFailed} failed · ${runStats.circuitBreakerTrips} circuit-breaker trip(s)</p>
    <div class="bar-chart">${bars}</div>
    ${categoryBreakdown}`;
}

function renderStorageStats(storageStats) {
  const rows = storageStats.map((s) => `
      <div class="card">
        <div class="card-head"><strong>${esc(s.dir)}</strong></div>
        <div class="card-meta"><span>${s.fileCount.toLocaleString()} files</span><span>${s.totalMB} MB</span></div>
      </div>`).join('\n');
  return `<div class="grid">${rows}</div>`;
}

function render(data) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Platform Health | CYBERDUDEBIVASH SENTINEL APEX (internal)</title>
<style>
:root{--bg:#07090f;--card:#111827;--border:#1f2937;--text:#e2e8f0;--muted:#6b7280;--cyan:#00ffe0}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,'Inter',sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:32px 24px 80px}
main{max-width:1000px;margin:0 auto}
h1{font-size:28px;font-weight:900;margin-bottom:6px;color:#fff}
.subtitle{color:var(--muted);margin-bottom:28px;font-size:14px}
h2{font-size:16px;font-weight:800;margin:32px 0 14px;color:var(--cyan);text-transform:uppercase;letter-spacing:.05em}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card-head{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.status-pill{margin-left:auto;font-size:10px;font-weight:800;padding:2px 8px;border:1px solid;border-radius:10px;font-family:monospace}
.card-desc{font-size:12.5px;color:#c9d1d9;margin-bottom:8px}
.card-meta{font-size:11.5px;color:var(--muted);display:flex;gap:14px;flex-wrap:wrap;font-family:monospace}
.empty{color:var(--muted);font-size:13px;padding:12px 0}
.manifest-table{width:100%;border-collapse:collapse;margin-top:10px;font-size:12.5px}
.manifest-table th{text-align:left;color:var(--muted);font-weight:700;padding:6px 10px;border-bottom:1px solid var(--border)}
.manifest-table td{padding:6px 10px;border-bottom:1px solid var(--border)}
.alert{background:#ff3b5c15;border:1px solid #ff3b5c55;border-radius:10px;padding:12px 16px;margin-bottom:14px;font-size:13px;color:#ffb4c0}
.bar-chart{display:flex;align-items:flex-end;gap:4px;height:64px;margin-top:8px}
.bar{width:14px;border-radius:2px 2px 0 0}
footer{margin-top:40px;font-size:11.5px;color:var(--muted)}
</style>
</head>
<body>
<main>
  <h1>Platform Health</h1>
  <p class="subtitle">Internal operations view — generated ${esc(data.generated)}. Not linked from public navigation.</p>

  <h2>Generator Freshness</h2>
  <div class="grid">${renderFreshnessCards(data.freshness)}</div>

  <h2>Latest Build Manifest</h2>
  ${renderManifestSection(data.manifest)}

  <h2>Blogger Syndication — Publish Trend</h2>
  ${renderRunTrend(data.runStats)}

  <h2>Storage Growth</h2>
  ${renderStorageStats(data.storageStats)}

  <footer>CYBERDUDEBIVASH SENTINEL APEX &middot; internal tooling &middot; not for public distribution</footer>
</main>
</body>
</html>
`;
}

function main() {
  const freshness = checkAllFreshness(generators);
  const manifest = loadLatestManifest();
  const runStats = summarizeRuns(30);
  const storageStats = computeStorageStats();

  const data = { generated: new Date().toISOString(), freshness, manifest, runStats, storageStats };

  const outDir = path.join(ROOT, 'ops', 'health');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'index.html'), render(data), 'utf8');

  fs.mkdirSync(path.join(ROOT, 'data'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'data', 'health-status.json'), JSON.stringify(data, null, 2), 'utf8');

  const staleCount = freshness.filter((f) => f.status === 'stale' || f.status === 'missing').length;
  console.log(`🩺 Health dashboard generated — ${freshness.length - staleCount}/${freshness.length} generators fresh, ${runStats.successRate ?? 'n/a'}% of last ${runStats.sampledRuns} Blogger runs healthy`);
  if (!runStats.mostRecent || !runStats.mostRecent.healthy) {
    console.log('⚠ Most recent Blogger syndication run was not healthy — see ops/health/index.html');
  }
}

if (require.main === module) {
  main();
}

module.exports = { main, render };
