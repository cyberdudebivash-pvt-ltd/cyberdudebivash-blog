'use strict';
// Regression test for the SENTINEL APEX v5.0 pipeline-staleness incident
// (freshness-check.yml CRITICAL: "Pipeline Down (CRITICAL - AUTO-RECOVERY)
// — Latest items N minutes old"). Root cause, confirmed against real
// production job logs and a real live-fetched BleepingComputer RSS feed:
//
// setSourceLastFetch() ratchets a source's incremental-poll watermark
// forward to Date.now() on every SUCCESSFUL fetch, regardless of whether
// any items were actually found. Seven call sites (fetchCISAKev,
// fetchCISAAlerts, fetchGitHubAdvisories, the shared fetchRSS() used by 20+
// blog/news sources, fetchExploitDB, fetchPacketStorm, fetchFullDisclosure)
// computed their next poll's lookback start as bare
// `lastFetch ? new Date(lastFetch) : <fallback>` with no minimum floor.
// A source with a real multi-hour quiet period (confirmed live: a genuine
// ~5h43m gap in BleepingComputer's own feed) then has its watermark
// perpetually chasing "now" with zero overlap — every poll's window starts
// exactly where the last one finished, so there is no self-healing margin
// once a run is even slightly late or a source pauses. Across ~26
// independently-operated sources doing this simultaneously, the production
// job logs showed "Sources active: 1/28" for 14+ consecutive runs spanning
// 6+ hours, with live-intel.json's newest item frozen (writeLiveIntel()
// only stamps _addedAt for items not already in the rolling window).
//
// fetchNVD() already had this exact defect fixed once (nvdMinLookbackHours,
// v5.1, "prevents 5-min window starvation") but the fix was never
// generalized to its siblings, which shared the identical unprotected
// pattern. watermarkStart() extracts that proven shape into one reusable
// helper and applies it at all seven other call sites.
//
// Widening the lookback window on every poll is safe, not merely
// convenient: isPublished()/writeLiveIntel() dedup purely by item id (TTL
// window for the former, "already in the existing live-intel.json array"
// for the latter) — re-fetching an item already seen is a no-op, not a
// duplicate publish or a reset freshness timestamp.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const { watermarkStart } = require(path.join(__dirname, '..', 'fetch-live-intel.js'));

const HOUR_MS = 3600000;
const DAY_MS = 86400000;
// Matches production's CFG.rssMinLookbackHours (fetch-live-intel.js) —
// duplicated as a literal here so this test exercises watermarkStart()
// exactly the way every real call site does, without reaching into CFG
// (which the module deliberately does not export).
const RSS_MIN_LOOKBACK_HOURS = 4;

test('a recent lastFetch (well inside the floor) is widened to the floor, not honored verbatim', () => {
  const lastFetch = Date.now() - 30 * 60000; // 30 minutes ago — the pre-fix starvation case
  const start = watermarkStart(lastFetch, RSS_MIN_LOOKBACK_HOURS, 7 * DAY_MS);
  const ageMs = Date.now() - start.getTime();
  // Must be at least the floor (allow a few ms of test-execution slack, never less).
  assert.ok(ageMs >= RSS_MIN_LOOKBACK_HOURS * HOUR_MS - 1000,
    `expected watermark >= ${RSS_MIN_LOOKBACK_HOURS}h old, got ${ageMs / 60000} min old`);
});

test('an old lastFetch (already wider than the floor) is honored, not narrowed', () => {
  const lastFetch = Date.now() - 2 * DAY_MS; // a long-broken source, 2 days since last success
  const start = watermarkStart(lastFetch, RSS_MIN_LOOKBACK_HOURS, 7 * DAY_MS);
  const ageMs = Date.now() - start.getTime();
  assert.ok(ageMs >= 2 * DAY_MS - 1000,
    `expected the floor to never narrow an already-wide window, got ${ageMs / DAY_MS} days old`);
});

test('a cold start (no lastFetch) with a fallback wider than the floor uses the fallback', () => {
  const start = watermarkStart(null, RSS_MIN_LOOKBACK_HOURS, 7 * DAY_MS);
  const ageMs = Date.now() - start.getTime();
  assert.ok(ageMs >= 7 * DAY_MS - 1000,
    `expected the 7-day cold-start fallback to win over the 4h floor, got ${ageMs / DAY_MS} days old`);
});

test('a cold start with a fallback narrower than the floor is still widened to the floor', () => {
  const start = watermarkStart(null, RSS_MIN_LOOKBACK_HOURS, 30 * 60000); // 30-minute fallback
  const ageMs = Date.now() - start.getTime();
  assert.ok(ageMs >= RSS_MIN_LOOKBACK_HOURS * HOUR_MS - 1000,
    `expected the floor to win over a narrow fallback, got ${ageMs / 60000} min old`);
});

test('the exact production incident scenario: a real item published during a quiet period is now included', () => {
  // Reproduces the confirmed-live shape: a source's watermark last advanced
  // 30 minutes ago (a routine, healthy poll), then the source had a genuine
  // multi-hour quiet period, and an item was actually published 2 hours ago
  // — inside that quiet period, but well before "30 minutes ago".
  const lastFetch = Date.now() - 30 * 60000;
  const itemPubDate = new Date(Date.now() - 2 * HOUR_MS);

  const beforeFix = lastFetch ? new Date(lastFetch) : new Date(Date.now() - 7 * DAY_MS);
  assert.ok(itemPubDate < beforeFix,
    'sanity check: the pre-fix bare watermark must exclude this item (that was the bug)');

  const afterFix = watermarkStart(lastFetch, RSS_MIN_LOOKBACK_HOURS, 7 * DAY_MS);
  assert.ok(itemPubDate >= afterFix,
    'the floor must widen the window enough to include an item from a real quiet period');
});
