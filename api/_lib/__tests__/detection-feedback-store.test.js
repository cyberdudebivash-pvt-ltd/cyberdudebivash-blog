'use strict';
/**
 * SENTINEL APEX — Threat Hunting Workspace v1: detection-feedback-store.js
 *
 * Pure persistence layer, exercised against the real fake-d1 fixture.
 * computeFeedbackSignal() is the one deliberate cross-tenant read in this
 * whole tranche -- these tests specifically prove its safety contract
 * (aggregate-only, never a raw row/owner_id/summary) alongside its
 * trigger-threshold correctness.
 */

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const feedbackStore = require('../detection-feedback-store');

const OWNER_A = 'usr_a';
const OWNER_B = 'usr_b';
const OWNER_C = 'usr_c';

beforeEach(() => {
  global.__fakeD1ForTest._reset();
});

describe('submitFeedback / listFeedbackForOwner — tenant scoping', () => {
  test('a caller only ever sees their own submitted feedback', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', summary: 'Confirmed.', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_B, { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'FALSE_POSITIVE', summary: 'Noise.', createdBy: OWNER_B });
    const aFeedback = await feedbackStore.listFeedbackForOwner(OWNER_A);
    expect(aFeedback.length).toBe(1);
    expect(aFeedback[0].classification).toBe('TRUE_POSITIVE');
  });

  test('listFeedbackForOwner can filter to one detection_id', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_1', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_2', detectionVersion: '1.0.0', classification: 'NO_SIGNAL', createdBy: OWNER_A });
    const filtered = await feedbackStore.listFeedbackForOwner(OWNER_A, { detectionId: 'det_1' });
    expect(filtered.length).toBe(1);
    expect(filtered[0].detection_id).toBe('det_1');
  });

  test('feedback can optionally carry a hunt_id or deployment_id reference', async () => {
    const id = await feedbackStore.submitFeedback(OWNER_A, {
      detectionId: 'det_1', detectionVersion: '1.0.0', huntId: 'hunt_abc', deploymentId: 'dep_xyz',
      classification: 'TOO_BROAD', summary: 'Too much noise', createdBy: OWNER_A,
    });
    const feedback = await feedbackStore.listFeedbackForOwner(OWNER_A);
    expect(feedback[0].feedback_id).toBe(id);
    expect(feedback[0].hunt_id).toBe('hunt_abc');
    expect(feedback[0].deployment_id).toBe('dep_xyz');
  });
});

describe('computeFeedbackSignal — the one deliberate cross-tenant aggregate read', () => {
  test('a single QUERY_ERROR report from one owner alone triggers REVIEW_REQUIRED immediately', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_x', detectionVersion: '2.0.0', classification: 'QUERY_ERROR', summary: 'Field name is wrong', createdBy: OWNER_A });
    const signal = await feedbackStore.computeFeedbackSignal('det_x', '2.0.0');
    expect(signal.signal).toBe('REVIEW_REQUIRED');
    expect(signal.reason_codes).toContain('QUERY_ERROR');
  });

  test('a single TELEMETRY_MISMATCH report from one owner alone triggers REVIEW_REQUIRED immediately', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_y', detectionVersion: '1.0.0', classification: 'TELEMETRY_MISMATCH', createdBy: OWNER_A });
    const signal = await feedbackStore.computeFeedbackSignal('det_y', '1.0.0');
    expect(signal.signal).toBe('REVIEW_REQUIRED');
    expect(signal.reason_codes).toContain('TELEMETRY_MISMATCH');
  });

  test('one customer\'s FALSE_POSITIVE never globalizes the detection as invalid -- no signal from a single FALSE_POSITIVE', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_z', detectionVersion: '1.0.0', classification: 'FALSE_POSITIVE', createdBy: OWNER_A });
    const signal = await feedbackStore.computeFeedbackSignal('det_z', '1.0.0');
    expect(signal.signal).toBeNull();
  });

  test('TOO_BROAD/TOO_NARROW require REPEATED reports from DISTINCT owners, not just repeated rows from one owner', async () => {
    // Same owner submits 5 times -- still only 1 distinct owner, must NOT trigger.
    for (let i = 0; i < 5; i++) {
      await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_w', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_A });
    }
    const singleOwnerSignal = await feedbackStore.computeFeedbackSignal('det_w', '1.0.0');
    expect(singleOwnerSignal.signal).toBeNull();

    // Two more DISTINCT owners each submit once -- now 3 distinct owners, must trigger.
    await feedbackStore.submitFeedback(OWNER_B, { detectionId: 'det_w', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_B });
    await feedbackStore.submitFeedback(OWNER_C, { detectionId: 'det_w', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_C });
    const threeOwnerSignal = await feedbackStore.computeFeedbackSignal('det_w', '1.0.0');
    expect(threeOwnerSignal.signal).toBe('REVIEW_REQUIRED');
    expect(threeOwnerSignal.reason_codes).toEqual(['REPEATED_TOO_BROAD']);
  });

  test('feedback is pinned to (detection_id, detection_version) -- a different version never contaminates the signal', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_v', detectionVersion: '1.0.0', classification: 'QUERY_ERROR', createdBy: OWNER_A });
    const oldVersionSignal = await feedbackStore.computeFeedbackSignal('det_v', '1.0.0');
    const newVersionSignal = await feedbackStore.computeFeedbackSignal('det_v', '2.0.0');
    expect(oldVersionSignal.signal).toBe('REVIEW_REQUIRED');
    expect(newVersionSignal.signal).toBeNull();
    expect(newVersionSignal.sample_size).toBe(0);
  });

  test('SAFETY CONTRACT: the returned signal never contains owner_id, created_by, or free-text summary -- only enum/count fields', async () => {
    await feedbackStore.submitFeedback(OWNER_A, {
      detectionId: 'det_secret', detectionVersion: '1.0.0', classification: 'QUERY_ERROR',
      summary: 'my internal SIEM hostname is soc-prod-01.internal.corp', createdBy: OWNER_A,
    });
    const signal = await feedbackStore.computeFeedbackSignal('det_secret', '1.0.0');
    const serialized = JSON.stringify(signal);
    expect(serialized).not.toContain(OWNER_A);
    expect(serialized).not.toContain('soc-prod-01');
    expect(Object.keys(signal).sort()).toEqual(['reason_codes', 'sample_size', 'signal']);
  });
});

describe('computeTenantPerformance — owner-scoped, additive (Detection Performance Intelligence v1)', () => {
  test('returns only the calling owner\'s own counts, isolated from other owners', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_p', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_p', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_B, { detectionId: 'det_p', detectionVersion: '1.0.0', classification: 'FALSE_POSITIVE', createdBy: OWNER_B });

    const perfA = await feedbackStore.computeTenantPerformance(OWNER_A, 'det_p', '1.0.0');
    expect(perfA.total_feedback).toBe(2);
    expect(perfA.classification_counts).toEqual({ TRUE_POSITIVE: 2 });

    const perfB = await feedbackStore.computeTenantPerformance(OWNER_B, 'det_p', '1.0.0');
    expect(perfB.total_feedback).toBe(1);
    expect(perfB.classification_counts).toEqual({ FALSE_POSITIVE: 1 });
  });

  test('a version this owner never gave feedback on returns zero counts, not an error', async () => {
    const perf = await feedbackStore.computeTenantPerformance(OWNER_A, 'det_untouched', '1.0.0');
    expect(perf).toEqual({ total_feedback: 0, classification_counts: {}, last_feedback_at: null });
  });

  test('tracks the most recent feedback timestamp for this owner/detection/version', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_q', detectionVersion: '1.0.0', classification: 'USEFUL_SIGNAL', createdBy: OWNER_A });
    const perf = await feedbackStore.computeTenantPerformance(OWNER_A, 'det_q', '1.0.0');
    expect(perf.last_feedback_at).toEqual(expect.any(String));
  });
});

describe('computeGlobalReviewMetrics — extends computeFeedbackSignal additively, same cross-tenant safety contract', () => {
  test('composes the exact same signal/reason_codes/sample_size computeFeedbackSignal produces, plus distinct_owners_total and last_feedback_at', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_r', detectionVersion: '1.0.0', classification: 'QUERY_ERROR', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_B, { detectionId: 'det_r', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_B });

    const baseline = await feedbackStore.computeFeedbackSignal('det_r', '1.0.0');
    const extended = await feedbackStore.computeGlobalReviewMetrics('det_r', '1.0.0');

    expect(extended.signal).toBe(baseline.signal);
    expect(extended.reason_codes).toEqual(baseline.reason_codes);
    expect(extended.sample_size).toBe(baseline.sample_size);
    expect(extended.distinct_owners_total).toBe(2);
    expect(extended.last_feedback_at).toEqual(expect.any(String));
  });

  test('zero feedback -- zero distinct owners, null timestamp, no error', async () => {
    const extended = await feedbackStore.computeGlobalReviewMetrics('det_never_seen', '1.0.0');
    expect(extended.distinct_owners_total).toBe(0);
    expect(extended.last_feedback_at).toBeNull();
  });

  test('SAFETY CONTRACT: still never exposes owner_id, created_by, or free-text summary', async () => {
    await feedbackStore.submitFeedback(OWNER_A, {
      detectionId: 'det_secret2', detectionVersion: '1.0.0', classification: 'QUERY_ERROR',
      summary: 'my internal SIEM hostname is soc-prod-02.internal.corp', createdBy: OWNER_A,
    });
    const extended = await feedbackStore.computeGlobalReviewMetrics('det_secret2', '1.0.0');
    const serialized = JSON.stringify(extended);
    expect(serialized).not.toContain(OWNER_A);
    expect(serialized).not.toContain('soc-prod-02');
  });
});

describe('Aggregation replay-safety and revision handling (on-demand computation, no materialized counters)', () => {
  test('rebuilding the same aggregate twice in a row (no writes in between) produces byte-identical results -- proves recomputation is deterministic, never drifts', async () => {
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_stable', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_B, { detectionId: 'det_stable', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_B });
    await feedbackStore.submitFeedback(OWNER_C, { detectionId: 'det_stable', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_C });

    const first = await feedbackStore.computeGlobalReviewMetrics('det_stable', '1.0.0');
    const second = await feedbackStore.computeGlobalReviewMetrics('det_stable', '1.0.0');
    expect(second).toEqual(first);

    const perfFirst = await feedbackStore.computeTenantPerformance(OWNER_A, 'det_stable', '1.0.0');
    const perfSecond = await feedbackStore.computeTenantPerformance(OWNER_A, 'det_stable', '1.0.0');
    expect(perfSecond).toEqual(perfFirst);
  });

  test('a revision (a NEW feedback row correcting an earlier one) is audit-preserving, never a destructive overwrite -- both the original and the correction are counted', async () => {
    // Analyst initially reports FALSE_POSITIVE, then later -- after further
    // investigation -- submits a NEW TRUE_POSITIVE report for the same
    // detection/version. There is no update/delete path for feedback rows
    // (raw feedback is append-only and remains canonical, per the mandate) --
    // the aggregate must reflect BOTH observations, never silently drop or
    // replace the first.
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_revised', detectionVersion: '1.0.0', classification: 'FALSE_POSITIVE', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_revised', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_A });

    const perf = await feedbackStore.computeTenantPerformance(OWNER_A, 'det_revised', '1.0.0');
    expect(perf.total_feedback).toBe(2);
    expect(perf.classification_counts).toEqual({ FALSE_POSITIVE: 1, TRUE_POSITIVE: 1 });

    const raw = await feedbackStore.listFeedbackForOwner(OWNER_A, { detectionId: 'det_revised' });
    expect(raw.length).toBe(2); // the original observation is preserved, not overwritten
  });
});
