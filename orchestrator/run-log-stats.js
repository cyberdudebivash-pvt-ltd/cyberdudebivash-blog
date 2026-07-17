/**
 * SENTINEL APEX — Blogger Syndication Run-Log Aggregator
 *
 * automation/main.py writes one logs/run-*.json per pipeline execution
 * (via _write_run_report) but nothing has ever aggregated them — they are
 * write-only today. This reads the most recent N run reports and derives
 * a real publish-success trend and the most recent run's outcome, so the
 * health dashboard can surface silent-looking failures (a run can commit
 * state and exit 0 while still publishing zero new posts).
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { ROOT } = require('./generator-sdk');

const LOGS_DIR = path.join(ROOT, 'logs');

function listRunLogFiles(limit = 30, logsDir = LOGS_DIR) {
  let files;
  try {
    files = fs.readdirSync(logsDir).filter((f) => /^run-\d{8}-\d{6}\.json$/.test(f));
  } catch (_) {
    return [];
  }
  files.sort().reverse(); // filename timestamp sorts chronologically
  return files.slice(0, limit).map((f) => path.join(logsDir, f));
}

function loadRunReport(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return null;
  }
}

/**
 * Summarizes the last `limit` Blogger syndication runs: per-run outcome
 * plus an aggregate success rate. A run counts as "healthy" if it either
 * published something or had zero failures (matches automation/main.py's
 * own exit-code logic: `failed > 0 and published == 0` is the only
 * hard-failure case).
 */
function summarizeRuns(limit = 30, logsDir = LOGS_DIR) {
  const files = listRunLogFiles(limit, logsDir);
  const runs = files
    .map((f) => loadRunReport(f))
    .filter(Boolean)
    .map((r) => ({
      runStart: r.run_start || null,
      runEnd: r.run_end || null,
      discovered: r.discovered || 0,
      published: r.published || 0,
      failed: r.failed || 0,
      skipped: r.skipped || 0,
      healthy: !(r.failed > 0 && r.published === 0),
    }));

  const healthyCount = runs.filter((r) => r.healthy).length;
  return {
    sampledRuns: runs.length,
    healthyRuns: healthyCount,
    successRate: runs.length ? Math.round((healthyCount / runs.length) * 100) : null,
    totalPublished: runs.reduce((sum, r) => sum + r.published, 0),
    totalFailed: runs.reduce((sum, r) => sum + r.failed, 0),
    mostRecent: runs[0] || null,
    runs,
  };
}

module.exports = { listRunLogFiles, loadRunReport, summarizeRuns, LOGS_DIR };
