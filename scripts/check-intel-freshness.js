'use strict';

/**
 * SENTINEL APEX production freshness classifier.
 *
 * Runtime liveness and intelligence freshness are intentionally independent:
 * - state.lastRun proves the generator executed;
 * - state.lastReportGeneratedAt proves a report was actually emitted.
 *
 * A healthy generator is allowed to produce no new report when sources are
 * duplicates, no material event exists, or quality/evidence gates reject all
 * candidates. Only proven runtime staleness authorizes automatic recovery.
 */

const fs = require('fs');

const WARN_RUNTIME_MINUTES = 90;
const DOWN_RUNTIME_MINUTES = 180;
const STALE_CONTENT_MINUTES = 180;
const FUTURE_TOLERANCE_MINUTES = 5;

function parseTimestamp(value) {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function ageMinutes(nowMs, timestampMs) {
  return Math.floor((nowMs - timestampMs) / 60000);
}

function latestAddedAt(items) {
  let latest = null;
  for (const item of items || []) {
    const parsed = parseTimestamp(item && item._addedAt);
    if (parsed !== null && (latest === null || parsed > latest)) latest = parsed;
  }
  return latest;
}

function evaluateFreshness({ feed, state = {}, nowMs = Date.now(), feedBytes = null }) {
  const defects = [];
  const items = Array.isArray(feed && feed.items)
    ? feed.items
    : (Array.isArray(feed) ? feed : []);

  if (feedBytes !== null && feedBytes < 10000) {
    defects.push(`feed_too_small:${feedBytes}`);
  }
  if (items.length < 10) {
    defects.push(`feed_item_count:${items.length}`);
  }

  const runtimePrimary = parseTimestamp(state.lastRun);
  const runtimeFallback = parseTimestamp(
    feed && !Array.isArray(feed)
      ? ((feed.metadata || {}).generated || feed.lastUpdated)
      : null
  );
  const runtimeMs = runtimePrimary !== null ? runtimePrimary : runtimeFallback;
  const runtimeSource = runtimePrimary !== null
    ? 'intel-state.json lastRun'
    : (runtimeFallback !== null ? 'feed metadata.generated/lastUpdated fallback' : null);

  const contentPrimary = parseTimestamp(state.lastReportGeneratedAt);
  const contentFallback = latestAddedAt(items);
  const contentMs = contentPrimary !== null ? contentPrimary : contentFallback;
  const contentSource = contentPrimary !== null
    ? 'intel-state.json lastReportGeneratedAt'
    : (contentFallback !== null ? 'latest feed item _addedAt fallback' : null);

  if (runtimeMs === null) defects.push('runtime_timestamp_missing_or_invalid');
  if (runtimeMs !== null && runtimeMs - nowMs > FUTURE_TOLERANCE_MINUTES * 60000) {
    defects.push('runtime_timestamp_in_future');
  }
  if (contentMs !== null && contentMs - nowMs > FUTURE_TOLERANCE_MINUTES * 60000) {
    defects.push('content_timestamp_in_future');
  }

  const runtimeAgeMinutes = runtimeMs === null ? null : ageMinutes(nowMs, runtimeMs);
  const contentAgeMinutes = contentMs === null ? null : ageMinutes(nowMs, contentMs);

  // Structural corruption is a monitor/feed incident, not evidence that the
  // generator failed. It must fail the check without dispatching recovery.
  if (defects.length > 0) {
    return {
      status: 'MONITOR_ERROR',
      exitCode: 1,
      recoveryRequired: false,
      runtimeAgeMinutes,
      contentAgeMinutes,
      runtimeSource,
      contentSource,
      defects,
    };
  }

  if (runtimeAgeMinutes > DOWN_RUNTIME_MINUTES) {
    return {
      status: 'PIPELINE_DOWN',
      exitCode: 2,
      recoveryRequired: true,
      runtimeAgeMinutes,
      contentAgeMinutes,
      runtimeSource,
      contentSource,
      defects: [],
    };
  }

  if (runtimeAgeMinutes > WARN_RUNTIME_MINUTES) {
    return {
      status: 'RUNTIME_DEGRADED',
      exitCode: 0,
      recoveryRequired: false,
      runtimeAgeMinutes,
      contentAgeMinutes,
      runtimeSource,
      contentSource,
      defects: [],
    };
  }

  if (contentAgeMinutes === null || contentAgeMinutes > STALE_CONTENT_MINUTES) {
    return {
      status: 'CONTENT_STALE',
      exitCode: 0,
      recoveryRequired: false,
      runtimeAgeMinutes,
      contentAgeMinutes,
      runtimeSource,
      contentSource,
      defects: contentAgeMinutes === null ? ['content_timestamp_unavailable'] : [],
    };
  }

  return {
    status: 'HEALTHY',
    exitCode: 0,
    recoveryRequired: false,
    runtimeAgeMinutes,
    contentAgeMinutes,
    runtimeSource,
    contentSource,
    defects: [],
  };
}

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function main(argv = process.argv.slice(2)) {
  const feedPath = argv[0] || 'live-intel.json';
  const statePath = argv[1] || 'intel-state.json';

  let feed;
  let state = {};
  let feedBytes = null;
  try {
    const raw = fs.readFileSync(feedPath, 'utf8');
    feedBytes = Buffer.byteLength(raw, 'utf8');
    feed = JSON.parse(raw);
  } catch (error) {
    console.error(`::error title=Freshness Monitor Error::Cannot read/parse ${feedPath}: ${error.message}`);
    console.log('STATUS=MONITOR_ERROR');
    console.log('RECOVERY_REQUIRED=false');
    return 1;
  }

  try {
    state = readJson(statePath);
  } catch (error) {
    // State loss is a monitoring defect. evaluateFreshness can still use feed
    // metadata as a liveness fallback, but we surface the fallback explicitly.
    console.warn(`::warning title=Freshness State Fallback::Cannot read/parse ${statePath}: ${error.message}`);
    state = {};
  }

  const result = evaluateFreshness({ feed, state, feedBytes });
  console.log(`STATUS=${result.status}`);
  console.log(`RECOVERY_REQUIRED=${result.recoveryRequired ? 'true' : 'false'}`);
  console.log(`Runtime source: ${result.runtimeSource || 'unavailable'}`);
  console.log(`Runtime age (minutes): ${result.runtimeAgeMinutes === null ? 'unknown' : result.runtimeAgeMinutes}`);
  console.log(`Content source: ${result.contentSource || 'unavailable'}`);
  console.log(`Content age (minutes): ${result.contentAgeMinutes === null ? 'unknown' : result.contentAgeMinutes}`);

  if (result.status === 'PIPELINE_DOWN') {
    console.error(`::error title=Pipeline Down::Generator runtime is ${result.runtimeAgeMinutes} minutes stale; automatic recovery is authorized.`);
  } else if (result.status === 'RUNTIME_DEGRADED') {
    console.warn(`::warning title=Pipeline Runtime Degraded::Generator runtime is ${result.runtimeAgeMinutes} minutes old; monitoring without recovery.`);
  } else if (result.status === 'CONTENT_STALE') {
    console.warn(`::warning title=Intel Content Stale::Generator is live, but no qualifying report has been emitted for ${result.contentAgeMinutes === null ? 'an unknown duration' : `${result.contentAgeMinutes} minutes`}. No recovery dispatch will be issued.`);
  } else if (result.status === 'MONITOR_ERROR') {
    console.error(`::error title=Freshness Monitor Error::${result.defects.join(', ')}`);
  } else {
    console.log('✅ Pipeline runtime and report freshness are healthy');
  }

  return result.exitCode;
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = {
  WARN_RUNTIME_MINUTES,
  DOWN_RUNTIME_MINUTES,
  STALE_CONTENT_MINUTES,
  evaluateFreshness,
  main,
};
