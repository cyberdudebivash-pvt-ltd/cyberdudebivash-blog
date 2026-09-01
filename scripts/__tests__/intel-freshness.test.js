'use strict';

const { evaluateFreshness } = require('../check-intel-freshness');

const NOW = Date.parse('2026-09-01T10:00:00.000Z');

function isoMinutesAgo(minutes) {
  return new Date(NOW - minutes * 60000).toISOString();
}

function feed({ generatedMinutesAgo = 10, itemMinutesAgo = 10, count = 20 } = {}) {
  return {
    metadata: { generated: isoMinutesAgo(generatedMinutesAgo) },
    items: Array.from({ length: count }, (_, idx) => ({
      id: `item-${idx}`,
      _addedAt: isoMinutesAgo(itemMinutesAgo + idx),
    })),
  };
}

function evaluate({ lastRunAgo = 10, lastReportAgo = 10, generatedMinutesAgo = 10, itemMinutesAgo = 10, count = 20, feedBytes = 20000 } = {}) {
  return evaluateFreshness({
    feed: feed({ generatedMinutesAgo, itemMinutesAgo, count }),
    state: {
      lastRun: lastRunAgo === null ? null : isoMinutesAgo(lastRunAgo),
      lastReportGeneratedAt: lastReportAgo === null ? null : isoMinutesAgo(lastReportAgo),
    },
    nowMs: NOW,
    feedBytes,
  });
}

test('healthy runtime and fresh report is HEALTHY', () => {
  const result = evaluate();
  expect(result.status).toBe('HEALTHY');
  expect(result.exitCode).toBe(0);
  expect(result.recoveryRequired).toBe(false);
});

test('fresh runtime with old content is CONTENT_STALE and never auto-recovers', () => {
  const result = evaluate({ lastRunAgo: 10, lastReportAgo: 400 });
  expect(result.status).toBe('CONTENT_STALE');
  expect(result.exitCode).toBe(0);
  expect(result.recoveryRequired).toBe(false);
});

test('runtime over critical threshold authorizes recovery', () => {
  const result = evaluate({ lastRunAgo: 181, lastReportAgo: 181 });
  expect(result.status).toBe('PIPELINE_DOWN');
  expect(result.exitCode).toBe(2);
  expect(result.recoveryRequired).toBe(true);
});

test('runtime warning threshold degrades without recovery', () => {
  const result = evaluate({ lastRunAgo: 120, lastReportAgo: 120 });
  expect(result.status).toBe('RUNTIME_DEGRADED');
  expect(result.exitCode).toBe(0);
  expect(result.recoveryRequired).toBe(false);
});

test('metadata.generated is a valid runtime fallback when state lastRun is absent', () => {
  const result = evaluate({ lastRunAgo: null, generatedMinutesAgo: 20 });
  expect(result.status).toBe('HEALTHY');
  expect(result.runtimeSource).toMatch(/fallback/);
  expect(result.recoveryRequired).toBe(false);
});

test('feed structural corruption fails monitor but does not authorize recovery', () => {
  const result = evaluate({ count: 2, feedBytes: 500 });
  expect(result.status).toBe('MONITOR_ERROR');
  expect(result.exitCode).toBe(1);
  expect(result.recoveryRequired).toBe(false);
  expect(result.defects).toContain('feed_too_small:500');
  expect(result.defects).toContain('feed_item_count:2');
});

test('future runtime timestamp is monitor error, not pipeline recovery evidence', () => {
  const result = evaluateFreshness({
    feed: feed(),
    state: {
      lastRun: new Date(NOW + 10 * 60000).toISOString(),
      lastReportGeneratedAt: isoMinutesAgo(5),
    },
    nowMs: NOW,
    feedBytes: 20000,
  });
  expect(result.status).toBe('MONITOR_ERROR');
  expect(result.recoveryRequired).toBe(false);
  expect(result.defects).toContain('runtime_timestamp_in_future');
});
