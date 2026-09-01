'use strict';

const { sha256Text, evaluatePremiumCertification } = require('../premium-report-certification');

function fixture(overrides = {}) {
  const rendered = '# Premium Intelligence\n\nEvidence-backed artifact.\n';
  const base = {
    bundle: {
      report_id: 'CDB-RPT-001',
      is_premium_tier: true,
      rendered_text: rendered,
      review: {
        report_id: 'CDB-RPT-001',
        artifact_sha256: sha256Text(rendered),
        reviewer_identity: 'operator-1',
        reviewer_role: 'senior-analyst',
        review_timestamp: '2026-09-01T12:00:00Z',
        decision: 'APPROVE',
        review_version: 1,
        notes: '',
        is_test_only_fixture: false,
      },
    },
    commercial_readiness: { verdict: 'COMMERCIAL-READY', pass_count: 23, total_count: 23, controls: [] },
  };
  return { ...base, ...overrides, bundle: { ...base.bundle, ...(overrides.bundle || {}) }, commercial_readiness: { ...base.commercial_readiness, ...(overrides.commercial_readiness || {}) } };
}

describe('premium report certification boundary', () => {
  test('accepts only a real APPROVE bound to the exact rendered artifact hash', () => {
    const result = evaluatePremiumCertification(fixture());
    expect(result.certified).toBe(true);
    expect(result.state).toBe('PREMIUM_CERTIFIED');
    expect(result.artifactSha256).toHaveLength(64);
  });

  test('automated 23/23 readiness without a human review is not sellable', () => {
    const result = evaluatePremiumCertification(fixture({ bundle: { review: null } }));
    expect(result.certified).toBe(false);
    expect(result.reasons).toContain('MISSING_HUMAN_REVIEW');
  });

  test('any post-review artifact mutation invalidates certification', () => {
    const f = fixture();
    f.bundle.rendered_text += 'changed';
    const result = evaluatePremiumCertification(f);
    expect(result.certified).toBe(false);
    expect(result.reasons).toContain('ARTIFACT_HASH_MISMATCH');
  });

  test('test-only reviewer fixtures are forbidden in production commerce', () => {
    const f = fixture();
    f.bundle.review.is_test_only_fixture = true;
    const result = evaluatePremiumCertification(f);
    expect(result.certified).toBe(false);
    expect(result.reasons).toContain('TEST_ONLY_REVIEW_FORBIDDEN');
  });

  test('REJECT and non-commercial automated verdicts never certify', () => {
    const rejected = fixture();
    rejected.bundle.review.decision = 'REJECT';
    expect(evaluatePremiumCertification(rejected).reasons).toContain('REVIEW_NOT_APPROVED');
    expect(evaluatePremiumCertification(fixture({ commercial_readiness: { verdict: 'NO-GO' } })).reasons)
      .toContain('AUTOMATED_GATES_NOT_COMMERCIAL_READY');
  });
});
