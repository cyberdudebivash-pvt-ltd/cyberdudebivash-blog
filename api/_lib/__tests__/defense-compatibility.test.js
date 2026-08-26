'use strict';

// Runs against REAL committed production data (detection-rules-canonical.json
// + api/intel/cve/*.json), same discipline as intel-detections.test.js and
// intel-dossier.test.js -- no fixture detection objects are hand-authored
// for the truth-table tests below; only the rollup unit tests and the
// synthetic isolated-technique tests use minimal, clearly-labeled
// synthetic canonical-detection-shaped objects.

const dc = require('../defense-compatibility');
const detectionRules = require('../detection-rules');
const detectionIntelligence = require('../detection-intelligence');
const { getDossierAPI } = require('../intel');

/* ───────────────────────── rollupTelemetryStatus ───────────────────────── */

describe('rollupTelemetryStatus', () => {
  test.each([
    [['AVAILABLE'], 'FULLY_AVAILABLE'],
    [['AVAILABLE', 'AVAILABLE'], 'FULLY_AVAILABLE'],
    [['AVAILABLE', 'UNKNOWN'], 'PARTIALLY_AVAILABLE'], // mandate Phase 21's own worked example
    [['AVAILABLE', 'PARTIALLY_AVAILABLE'], 'PARTIALLY_AVAILABLE'],
    [['UNKNOWN'], 'UNKNOWN'],
    [['UNKNOWN', 'UNKNOWN'], 'UNKNOWN'],
    [['NOT_AVAILABLE'], 'GAP'], // mandate Phase 22's own worked example
    [['NOT_AVAILABLE', 'UNKNOWN'], 'GAP'],
    [[], 'UNKNOWN'],
  ])('%j -> %s', (statuses, expected) => {
    expect(dc.rollupTelemetryStatus(statuses)).toBe(expected);
  });
});

/* ───────────────────────── evaluateDetectionCompatibility (synthetic) ──── */

function fakeReleasedDetection({ attack = [{ id: 'T1490', evidence_state: 'SOURCE_ATTRIBUTED' }], formats = { sigma: {}, kql: {}, splunk: {}, osquery: {} } } = {}) {
  return { status: 'RELEASED', attack, formats };
}

describe('evaluateDetectionCompatibility — synthetic isolated cases', () => {
  test('a non-RELEASED detection is never evaluated as compatible', () => {
    const result = dc.evaluateDetectionCompatibility({ status: 'REVIEW_REQUIRED' }, { technologies: [], telemetry: {} });
    expect(result.status).toBe('NO_VALIDATED_DETECTION');
  });

  test('no SIEM declared at all -> UNKNOWN, not UNSUPPORTED_PLATFORM (mandate: absence of declaration is never treated as a known incompatibility)', () => {
    const det = fakeReleasedDetection();
    const result = dc.evaluateDetectionCompatibility(det, { technologies: [], telemetry: { process_creation: 'AVAILABLE' } });
    expect(result.status).toBe('UNKNOWN');
  });

  test('a SIEM with no validated format (QRadar) and Sigma available -> UNSUPPORTED_PLATFORM, sigma_portable true, never silently claims Sigma = ready', () => {
    const det = fakeReleasedDetection();
    const profile = { technologies: [{ category: 'siem', technology_id: 'qradar' }], telemetry: { process_creation: 'AVAILABLE' } };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.status).toBe('UNSUPPORTED_PLATFORM');
    expect(result.sigma_portable).toBe(true);
    expect(result.format_used).toBeNull();
  });

  test('declaring only "Other / Not listed" as SIEM never grants a format match (no arbitrary query dialect execution)', () => {
    const det = fakeReleasedDetection();
    const profile = { technologies: [{ category: 'siem', technology_id: 'other', custom_label: 'HomegrownSIEM' }], telemetry: { process_creation: 'AVAILABLE' } };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.status).toBe('UNKNOWN'); // "other" is excluded from siemTechnologiesOf -- same as declaring none
  });

  test('a detection missing the Sigma format entirely reports sigma_portable:false honestly', () => {
    const det = fakeReleasedDetection({ formats: { kql: {} } });
    const profile = { technologies: [{ category: 'siem', technology_id: 'qradar' }], telemetry: {} };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.sigma_portable).toBe(false);
  });

  test('matched format + AVAILABLE telemetry -> READY', () => {
    const det = fakeReleasedDetection();
    const profile = { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.status).toBe('READY');
    expect(result.format_used).toBe('kql');
  });

  test('matched format + NOT_AVAILABLE telemetry -> TELEMETRY_GAP with the exact missing data source named', () => {
    const det = fakeReleasedDetection();
    const profile = { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'NOT_AVAILABLE' } };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.status).toBe('TELEMETRY_GAP');
    expect(result.missing_telemetry[0].data_source).toBe('process_creation');
    expect(result.missing_telemetry[0].suggested_sources.length).toBeGreaterThan(0);
  });

  test('matched format + undeclared telemetry -> UNKNOWN, never silently a gap (mandate Phase 16/23)', () => {
    const det = fakeReleasedDetection();
    const profile = { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: {} };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.status).toBe('UNKNOWN');
  });

  test('matched format + PARTIALLY_AVAILABLE telemetry -> PARTIALLY_READY', () => {
    const det = fakeReleasedDetection();
    const profile = { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'PARTIALLY_AVAILABLE' } };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.status).toBe('PARTIALLY_READY');
  });

  test('Splunk technology prefers the splunk format over kql when both are present', () => {
    const det = fakeReleasedDetection();
    const profile = { technologies: [{ category: 'siem', technology_id: 'splunk-enterprise-security' }], telemetry: { process_creation: 'AVAILABLE' } };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    expect(result.format_used).toBe('splunk');
  });

  test('suggested_sources are scoped to the customer\'s declared EDR/telemetry technology, never a vendor they never mentioned', () => {
    const det = fakeReleasedDetection();
    const profile = {
      technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }, { category: 'edr_xdr', technology_id: 'crowdstrike-falcon' }],
      telemetry: { process_creation: 'NOT_AVAILABLE' },
    };
    const result = dc.evaluateDetectionCompatibility(det, profile);
    const suggestedIds = result.missing_telemetry[0].suggested_sources.map(s => s.technology_id);
    expect(suggestedIds).toEqual(['crowdstrike-falcon']);
  });
});

/* ───────────────────────── real-data truth table (mandate Phase 89-94) ─── */

describe('real-data truth table against CVE-2023-27351 / T1490 (a genuinely RELEASED detection)', () => {
  const { found, dossier } = getDossierAPI('cve', 'CVE-2023-27351', 'enterprise');
  test('sanity: the fixture CVE and its T1490 technique are really present', () => {
    expect(found).toBe(true);
    expect(dossier.attack_context.techniques.map(t => t.id)).toContain('T1490');
  });

  function coverageFor(profile) {
    return dc.computeCustomerCoverage({ attackContext: dossier.attack_context, entityType: 'cve', entityId: 'CVE-2023-27351', profile });
  }
  function t1490(cov) { return cov.techniques.find(t => t.id === 'T1490'); }

  test('READY: Sentinel + process_creation AVAILABLE', () => {
    const cov = coverageFor({ technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } });
    expect(t1490(cov).customer_status).toBe('READY');
  });

  test('TELEMETRY_GAP: Sentinel + process_creation NOT_AVAILABLE (never READY)', () => {
    const cov = coverageFor({ technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'NOT_AVAILABLE' } });
    expect(t1490(cov).customer_status).toBe('TELEMETRY_GAP');
  });

  test('UNKNOWN: Sentinel + process_creation never declared (never TELEMETRY_GAP)', () => {
    const cov = coverageFor({ technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: {} });
    expect(t1490(cov).customer_status).toBe('UNKNOWN');
  });

  test('UNSUPPORTED_PLATFORM: QRadar-only, unless a compatible representation exists (it does not for QRadar today)', () => {
    const cov = coverageFor({ technologies: [{ category: 'siem', technology_id: 'qradar' }], telemetry: { process_creation: 'AVAILABLE' } });
    expect(t1490(cov).customer_status).toBe('UNSUPPORTED_PLATFORM');
  });

  test('NO_VALIDATED_DETECTION: a technique with zero eligible rules is never conflated with a customer telemetry gap (mandate Phase 94)', () => {
    const cov = coverageFor({ technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } });
    const uncoveredTechnique = cov.techniques.find(t => t.status === 'UNSUPPORTED_TELEMETRY' || t.status === 'NO_VALIDATED_DETECTION');
    expect(uncoveredTechnique).toBeDefined();
    expect(uncoveredTechnique.customer_status).toBe('NO_VALIDATED_DETECTION');
    expect(uncoveredTechnique.customer_missing_telemetry).toEqual([]);
  });

  test('UNKNOWN_PROFILE: no profile configured at all -- global coverage is still fully present, customer dimension degrades honestly', () => {
    const cov = coverageFor(null);
    expect(cov.profile_configured).toBe(false);
    expect(t1490(cov).customer_status).toBe('UNKNOWN_PROFILE');
    // Global truth is untouched by the absence of a profile.
    expect(t1490(cov).status).toBe('COVERED');
  });

  test('customer coverage NEVER modifies global coverage truth (Phase 88)', () => {
    const withProfile = coverageFor({ technologies: [{ category: 'siem', technology_id: 'qradar' }], telemetry: {} });
    const withoutProfile = coverageFor(null);
    expect(withProfile.validated).toBe(withoutProfile.validated);
    expect(withProfile.uncovered).toBe(withoutProfile.uncovered);
    expect(t1490(withProfile).status).toBe(t1490(withoutProfile).status);
  });

  test('negative customer-inference test: a profile object is never derived from anything but its own declared fields -- an empty profile with no technologies/telemetry is UNKNOWN everywhere, never a guessed READY/GAP', () => {
    const cov = coverageFor({ technologies: [], telemetry: {} });
    expect(t1490(cov).customer_status).toBe('UNKNOWN');
  });
});

describe('CVE-2026-19598 / T1204.002 -- the documented no-corroborating-ATT&CK-linkage case', () => {
  test('a rule\'s own CVE claim is never trusted without independent dossier corroboration -- this CVE\'s dossier has zero established techniques, so customer coverage is empty too, not a fabricated match', () => {
    const { found, dossier } = getDossierAPI('cve', 'CVE-2026-19598', 'enterprise');
    expect(found).toBe(true);
    const cov = dc.computeCustomerCoverage({
      attackContext: dossier.attack_context, entityType: 'cve', entityId: 'CVE-2026-19598',
      profile: { technologies: [{ category: 'siem', technology_id: 'microsoft-sentinel' }], telemetry: { process_creation: 'AVAILABLE' } },
    });
    expect(cov.observed_techniques).toBe(0);
  });
});

describe('a technique with no ATT&CK techniques at all', () => {
  test('computeCustomerCoverage on an empty/not-established attack_context returns zero techniques, no crash', () => {
    const cov = dc.computeCustomerCoverage({ attackContext: { status: 'not_established', techniques: [] }, entityType: 'cve', entityId: 'CVE-0000-00000', profile: null });
    expect(cov.observed_techniques).toBe(0);
    expect(cov.techniques).toEqual([]);
  });
});
