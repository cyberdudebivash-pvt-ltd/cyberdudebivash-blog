'use strict';

// Regression coverage for a real syntax error found while bundling this
// module for Cloudflare Workers (esbuild parses the whole file up front,
// unlike Node's lazy per-call-site behavior, so it surfaced a hard parse
// failure Jest had never hit because nothing here was ever tested):
// api/_lib/publishing-pipeline.js:366 had `submittedFor Review:` (a
// literal space in an object key) instead of `submittedForReview:`. That
// SyntaxError also broke plain `require('./publishing-pipeline')` under
// Node — confirmed directly, not assumed — meaning
// api/v1/intelligence/publish.js was already fully broken on production
// Vercel before this fix, independent of any Cloudflare migration work.
const { PublishingPipeline } = require('../publishing-pipeline');

// Minimal fake matching api/_lib/redis.js's real return shape: Upstash's
// REST API returns HGETALL as a flat [field, value, field, value, ...]
// array (confirmed by reading redisCmd()'s implementation), not a plain
// object -- IntelligenceManager#getIntelligence() reduces it into one.
function fakeRedis(intelligenceRecord) {
  const flat = [];
  for (const [k, v] of Object.entries(intelligenceRecord)) flat.push(k, v);
  return {
    hgetall: async key => (key.startsWith('intelligence:review:') ? [] : flat),
    zrange: async () => [],
  };
}

describe('PublishingPipeline#getPipelineStatus', () => {
  test('module loads without a syntax error (the actual regression)', () => {
    expect(typeof PublishingPipeline).toBe('function');
  });

  test('returns null for an intelligence object that does not exist', async () => {
    const pipeline = new PublishingPipeline({ hgetall: async () => [], zrange: async () => [] });
    const status = await pipeline.getPipelineStatus('missing-id');
    expect(status).toBeNull();
  });

  test('timeline uses the correct submittedForReview key', async () => {
    const redis = fakeRedis({
      status: 'REVIEW',
      title: 'Test Intelligence',
      type: 'threat-actor',
      confidence: 'high',
      createdAt: '2026-08-01T00:00:00Z',
      createdBy: 'analyst1',
      reviewedAt: '2026-08-02T00:00:00Z',
      reviewedBy: 'reviewer1',
    });
    const pipeline = new PublishingPipeline(redis);
    const status = await pipeline.getPipelineStatus('test-id');

    expect(status).not.toBeNull();
    expect(status.timeline).toHaveProperty('submittedForReview');
    expect(status.timeline.submittedForReview).toEqual({ at: '2026-08-02T00:00:00Z', by: 'reviewer1' });
    expect(status.timeline).not.toHaveProperty('submittedFor');
  });
});
