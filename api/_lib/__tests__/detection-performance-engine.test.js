'use strict';
/**
 * SENTINEL APEX — Detection Performance Intelligence v1: detection-
 * performance-engine.js
 *
 * Two layers of coverage:
 *  1. deriveQualityState() as a pure function -- every priority tier,
 *     with zero mocking, since it only ever consumes plain objects.
 *  2. The composition layer (computeDetectionQuality/getVersionHistory/
 *     computeReviewQueue) against the REAL detection-feedback-store and
 *     detection-version-store (backed by the real fake-d1 fixture,
 *     proving the actual aggregate SQL is correct), with hunt-engine/
 *     detection-rules/deployment-store mocked to supply controlled
 *     canonical-detection/deployment fixtures without touching real fs.
 */

jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});
jest.mock('../hunt-engine', () => ({ resolveCanonicalDetection: jest.fn() }));
jest.mock('../detection-rules', () => ({ loadCanonical: jest.fn(), getRule: jest.fn() }));
jest.mock('../deployment-store', () => ({ countDeploymentsByDetection: jest.fn() }));

const feedbackStore = require('../detection-feedback-store');
const versionStore = require('../detection-version-store');
const huntEngine = require('../hunt-engine');
const detectionRules = require('../detection-rules');
const deploymentStore = require('../deployment-store');
const engine = require('../detection-performance-engine');

const OWNER_A = 'usr_a', OWNER_B = 'usr_b', OWNER_C = 'usr_c';

beforeEach(() => {
  global.__fakeD1ForTest._reset();
  jest.clearAllMocks();
  deploymentStore.countDeploymentsByDetection.mockResolvedValue({ total: 0, distinct_owners: 0 });
});

/* ─────────────────────── deriveQualityState (pure) ─────────────────────── */

describe('deriveQualityState — deterministic priority ordering', () => {
  const emptySignal = { reason_codes: [], sample_size: 0 };

  test('REVOKED always wins, regardless of feedback', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: 'REVOKED', gateStatus: null, feedbackSignal: { reason_codes: ['QUERY_ERROR'], sample_size: 10 } });
    expect(result.quality_state).toBe('REVOKED');
    expect(result.reason).toMatch(/revoked/i);
  });

  test('DEPRECATED always wins, regardless of feedback', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: 'DEPRECATED', gateStatus: null, feedbackSignal: emptySignal });
    expect(result.quality_state).toBe('DEPRECATED');
  });

  test('a BLOCKED gate status alone is TECHNICAL_FAILURE', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'BLOCKED', feedbackSignal: emptySignal });
    expect(result.quality_state).toBe('TECHNICAL_FAILURE');
    expect(result.reason).toMatch(/BLOCKED/);
  });

  test('QUERY_ERROR feedback alone (gate status RELEASED) is still TECHNICAL_FAILURE -- technical correctness overrides everything below it', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: { reason_codes: ['QUERY_ERROR'], sample_size: 5 } });
    expect(result.quality_state).toBe('TECHNICAL_FAILURE');
  });

  test('the mandate\'s own example: query invalid + 5 prior TRUE_POSITIVE-only counts is still TECHNICAL_FAILURE, not HEALTHY', () => {
    // 5 prior true positives don't appear as a reason_code trigger (TRUE_POSITIVE
    // is not a review trigger), but sample_size reflects real prior signal --
    // QUERY_ERROR must still win outright regardless of how positive-looking
    // the rest of the history is.
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'BLOCKED', feedbackSignal: { reason_codes: ['QUERY_ERROR'], sample_size: 5 } });
    expect(result.quality_state).toBe('TECHNICAL_FAILURE');
  });

  test('a REVIEW_REQUIRED gate status ALONE (no feedback trigger) is NOT, by itself, a quality-state signal -- it falls through to the evidence floor', () => {
    // gateStatus REVIEW_REQUIRED at this global level is near-universally
    // true purely because attackEvidenceState is always UNKNOWN without a
    // specific customer entity context -- it must never alone drag every
    // real detection into a REVIEW_REQUIRED quality state. Confirmed via a
    // real live-server check against the actual canonical detection store
    // before this was corrected (see the certification doc).
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'REVIEW_REQUIRED', feedbackSignal: emptySignal });
    expect(result.quality_state).toBe('INSUFFICIENT_EVIDENCE');
  });

  test('TELEMETRY_MISMATCH feedback alone is REVIEW_REQUIRED', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: { reason_codes: ['TELEMETRY_MISMATCH'], sample_size: 3 } });
    expect(result.quality_state).toBe('REVIEW_REQUIRED');
  });

  test('REPEATED_TOO_BROAD is TUNING_RECOMMENDED (below technical/review tiers)', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: { reason_codes: ['REPEATED_TOO_BROAD'], sample_size: 6 } });
    expect(result.quality_state).toBe('TUNING_RECOMMENDED');
  });

  test('REPEATED_TOO_NARROW is TUNING_RECOMMENDED', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: { reason_codes: ['REPEATED_TOO_NARROW'], sample_size: 6 } });
    expect(result.quality_state).toBe('TUNING_RECOMMENDED');
  });

  test('zero feedback and no technical/review trigger is INSUFFICIENT_EVIDENCE, never HEALTHY', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: emptySignal });
    expect(result.quality_state).toBe('INSUFFICIENT_EVIDENCE');
  });

  test('feedback exists, no trigger fired -- HEALTHY', () => {
    const result = engine.deriveQualityState({ manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: { reason_codes: [], sample_size: 4 } });
    expect(result.quality_state).toBe('HEALTHY');
  });

  test('every branch returns a non-empty, human-readable reason -- never "AI detected poor quality"', () => {
    const cases = [
      { manualOverrideStatus: 'REVOKED', gateStatus: null, feedbackSignal: emptySignal },
      { manualOverrideStatus: null, gateStatus: 'BLOCKED', feedbackSignal: emptySignal },
      { manualOverrideStatus: null, gateStatus: 'REVIEW_REQUIRED', feedbackSignal: emptySignal },
      { manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: { reason_codes: ['REPEATED_TOO_BROAD'], sample_size: 3 } },
      { manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: emptySignal },
      { manualOverrideStatus: null, gateStatus: 'RELEASED', feedbackSignal: { reason_codes: [], sample_size: 1 } },
    ];
    for (const c of cases) {
      const result = engine.deriveQualityState(c);
      expect(typeof result.reason).toBe('string');
      expect(result.reason.length).toBeGreaterThan(10);
      expect(result.reason.toLowerCase()).not.toContain('ai detected');
    }
  });
});

/* ─────────────────── computeDetectionQuality (integration) ─────────────────── */

describe('computeDetectionQuality — composition with real feedback aggregation', () => {
  test('a detection with zero feedback anywhere is INSUFFICIENT_EVIDENCE', async () => {
    huntEngine.resolveCanonicalDetection.mockReturnValue({ status: 'RELEASED', version: '1.0.0' });
    const quality = await engine.computeDetectionQuality('det_x', undefined);
    expect(quality.quality_state).toBe('INSUFFICIENT_EVIDENCE');
    expect(quality.evidence_sufficiency).toBe('NO_OPERATIONAL_EVIDENCE');
  });

  test('returns null when the detection does not exist', async () => {
    huntEngine.resolveCanonicalDetection.mockReturnValue(null);
    const quality = await engine.computeDetectionQuality('det_missing', undefined);
    expect(quality).toBeNull();
  });

  test('a single QUERY_ERROR from one customer drives TECHNICAL_FAILURE for the CURRENT version', async () => {
    huntEngine.resolveCanonicalDetection.mockReturnValue({ status: 'RELEASED', version: '1.0.0' });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_y', detectionVersion: '1.0.0', classification: 'QUERY_ERROR', createdBy: OWNER_A });
    const quality = await engine.computeDetectionQuality('det_y', undefined);
    expect(quality.quality_state).toBe('TECHNICAL_FAILURE');
    expect(quality.evidence_sufficiency).toBe('OPERATIONAL_EVIDENCE_PRESENT');
  });

  test('requirement D: a PAST version\'s quality state remains immutable even after the canonical detection moves on to a new current version', async () => {
    // v3 accumulated a QUERY_ERROR review signal; the canonical detection is
    // now at v4 with a clean RELEASED gate. v3's own quality state must
    // still reflect ITS OWN feedback, not v4's clean current state.
    huntEngine.resolveCanonicalDetection.mockReturnValue({ status: 'RELEASED', version: '4.0.0' });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_z', detectionVersion: '3.0.0', classification: 'QUERY_ERROR', createdBy: OWNER_A });

    const v3Quality = await engine.computeDetectionQuality('det_z', '3.0.0');
    const v4Quality = await engine.computeDetectionQuality('det_z', '4.0.0');

    expect(v3Quality.is_current_version).toBe(false);
    expect(v3Quality.quality_state).toBe('TECHNICAL_FAILURE');
    expect(v3Quality.validation_evaluated_for_this_version).toBe(false);
    expect(v4Quality.is_current_version).toBe(true);
    expect(v4Quality.quality_state).toBe('INSUFFICIENT_EVIDENCE'); // v4 has no feedback of its own yet
  });

  test('a REVOKED detection reports REVOKED for every version, including old ones', async () => {
    huntEngine.resolveCanonicalDetection.mockReturnValue({ status: 'REVOKED', version: '2.0.0' });
    const oldVersionQuality = await engine.computeDetectionQuality('det_r', '1.0.0');
    expect(oldVersionQuality.quality_state).toBe('REVOKED');
  });

  test('3 distinct customers reporting TOO_BROAD trigger TUNING_RECOMMENDED; 2 do not', async () => {
    huntEngine.resolveCanonicalDetection.mockReturnValue({ status: 'RELEASED', version: '1.0.0' });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_w', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_B, { detectionId: 'det_w', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_B });
    let quality = await engine.computeDetectionQuality('det_w', undefined);
    expect(quality.quality_state).toBe('HEALTHY'); // only 2 distinct owners so far -- feedback exists, no trigger fired yet

    await feedbackStore.submitFeedback(OWNER_C, { detectionId: 'det_w', detectionVersion: '1.0.0', classification: 'TOO_BROAD', createdBy: OWNER_C });
    quality = await engine.computeDetectionQuality('det_w', undefined);
    expect(quality.quality_state).toBe('TUNING_RECOMMENDED');
    expect(quality.tuning_recommendations.length).toBe(1);
    expect(quality.tuning_recommendations[0]).toMatch(/benign negative fixtures/);
  });

  test('never exposes owner_id or free-text summary anywhere in the response', async () => {
    huntEngine.resolveCanonicalDetection.mockReturnValue({ status: 'RELEASED', version: '1.0.0' });
    await feedbackStore.submitFeedback(OWNER_A, {
      detectionId: 'det_secret', detectionVersion: '1.0.0', classification: 'QUERY_ERROR',
      summary: 'my internal SIEM hostname is soc-prod-01.internal.corp', createdBy: OWNER_A,
    });
    const quality = await engine.computeDetectionQuality('det_secret', undefined);
    const serialized = JSON.stringify(quality);
    expect(serialized).not.toContain(OWNER_A);
    expect(serialized).not.toContain('soc-prod-01');
  });
});

/* ─────────────────────────── getVersionHistory ─────────────────────────── */

describe('getVersionHistory — honest content availability, never fabricated', () => {
  test('a version with a real snapshot row is marked content_available: true', async () => {
    detectionRules.getRule.mockReturnValue({
      id: 'det_h', governance: { version: '1.0.1' },
      history: [
        { version: '1.0.0', timestamp: 't0', change: 'Rule generated', author: 'detection-engine' },
        { version: '1.0.1', timestamp: 't1', change: 'Rule updated', author: 'detection-engine' },
      ],
    });
    await versionStore.snapshotVersion(
      { id: 'det_h', technique_id: 'T1', title: 'X', governance: { version: '1.0.1', status: 'GENERATED' }, platforms: { sigma: 'x' }, suricata: [] },
      { source: 'LIVE_CAPTURE' }
    );

    const history = await engine.getVersionHistory('det_h');
    const v100 = history.versions.find(v => v.version === '1.0.0');
    const v101 = history.versions.find(v => v.version === '1.0.1');
    expect(v100.content_available).toBe(false); // predates the hook/backfill -- never invented
    expect(v101.content_available).toBe(true);
    expect(v101.formats).toEqual(['sigma']);
  });

  test('returns null for an unknown detection', async () => {
    detectionRules.getRule.mockReturnValue(null);
    const history = await engine.getVersionHistory('det_missing');
    expect(history).toBeNull();
  });
});

/* ─────────────────────────── computeReviewQueue ─────────────────────────── */

describe('computeReviewQueue — internal, no customer-private content, sorted worst-first', () => {
  test('sorts CRITICAL/HIGH above HEALTHY, and every entry is free of owner-identifying fields', async () => {
    detectionRules.loadCanonical.mockReturnValue({
      rules: [
        { id: 'det_broken', title: 'Broken Rule', technique_id: 'T1', level: 'high' },
        { id: 'det_fine', title: 'Fine Rule', technique_id: 'T2', level: 'medium' },
      ],
    });
    huntEngine.resolveCanonicalDetection.mockImplementation((id) => {
      if (id === 'det_broken') return { status: 'RELEASED', version: '1.0.0' };
      return { status: 'RELEASED', version: '1.0.0' };
    });
    deploymentStore.countDeploymentsByDetection.mockImplementation((id) =>
      Promise.resolve(id === 'det_broken' ? { total: 2, distinct_owners: 2 } : { total: 0, distinct_owners: 0 })
    );
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_broken', detectionVersion: '1.0.0', classification: 'QUERY_ERROR', createdBy: OWNER_A });
    await feedbackStore.submitFeedback(OWNER_A, { detectionId: 'det_fine', detectionVersion: '1.0.0', classification: 'TRUE_POSITIVE', createdBy: OWNER_A });

    const queue = await engine.computeReviewQueue();
    expect(queue[0].detection_id).toBe('det_broken');
    expect(queue[0].priority_tier).toBe('CRITICAL');
    expect(queue[0].factors.affected_deployments).toBe(2);
    expect(queue[1].detection_id).toBe('det_fine');
    expect(queue[1].priority_tier).toBe('NONE');

    const serialized = JSON.stringify(queue);
    expect(serialized).not.toContain(OWNER_A);
  });
});
