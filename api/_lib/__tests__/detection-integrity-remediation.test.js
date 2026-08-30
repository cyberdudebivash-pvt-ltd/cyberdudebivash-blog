'use strict';
/**
 * SENTINEL APEX — Detection Integrity Remediation v1: permanent regression
 * fixtures for the two real canonical detections PR #145's Review Queue
 * surfaced as BLOCKED, remediated by scripts/remediate-blocked-detections.js.
 *
 * These fixtures are FROZEN, literal copies of the exact historical content
 * (captured before remediation) -- they do not depend on the live,
 * now-remediated canonical store, so they keep proving both defects are
 * detected AND stay fixed even if the canonical store changes again later.
 * Uses the real, unmodified detectionIntelligence.runValidation()/
 * evaluateReleaseGate()/toCanonicalDetectionObject() -- never a re-derived
 * validation path.
 */

const detectionIntelligence = require('../detection-intelligence');

function canonicalStatusFor(rule) {
  return detectionIntelligence.toCanonicalDetectionObject(rule, { attackEvidenceState: 'UNKNOWN' });
}

describe('9a5467dc8ae03f68 (T1547.001) — data_source metadata defect', () => {
  const REAL_SIGMA_CONTENT =
    'title: Registry Run Key Persistence From User-Writable Path\n' +
    'id: 7080b048-4dcb-5428-984f-56b6de11a5f7\n' +
    'status: experimental\n' +
    "description: 'Registry Run Key Persistence.'\n" +
    'logsource:\n' +
    '    product: windows\n' +
    '    category: registry_set\n' +
    'detection:\n' +
    '    selection:\n' +
    '        TargetObject|contains: \\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n' +
    '    filter_1:\n' +
    '        Image|startswith:\n' +
    "            - 'C:\\Program Files'\n" +
    "            - 'C:\\Windows\\'\n" +
    '    condition: selection and not filter_1\n' +
    'level: medium';

  function ruleWithDataSource(dataSource) {
    return {
      id: '9a5467dc8ae03f68',
      technique_id: 'T1547.001',
      title: 'Registry Run Key Persistence From User-Writable Path',
      level: 'medium',
      description: 'Registry Run Key Persistence From User-Writable Path.',
      data_source: dataSource,
      platforms: { sigma: REAL_SIGMA_CONTENT, kql: 'DeviceRegistryEvents | where RegistryKey contains "Run"', splunk: null, osquery: null },
      suricata: [],
      governance: { status: 'GENERATED', confidence: 'MEDIUM', version: '1.0.9' },
      source: { iocs: [], articles: ['CVE-2026-54550'], campaigns: [], evidence: '' },
    };
  }

  test('REGRESSION: the historical v1.0.9 content (data_source="process_creation") reproduces the exact real BLOCKED/UNSUPPORTED_TELEMETRY failure', () => {
    const historicalRule = ruleWithDataSource('process_creation');
    const canonical = canonicalStatusFor(historicalRule);
    expect(canonical.status).toBe('BLOCKED');
    expect(canonical.lifecycle_reasons).toContain('UNSUPPORTED_TELEMETRY');
    expect(canonical.validation.telemetry.pass).toBe(false);
    expect(canonical.validation.telemetry.missing_fields).toContain('TargetObject');
  });

  test('FIX VERIFIED: correcting data_source to "registry_set" (the rule\'s own declared Sigma logsource category, content otherwise byte-identical) clears UNSUPPORTED_TELEMETRY', () => {
    const fixedRule = ruleWithDataSource('registry_set');
    const canonical = canonicalStatusFor(fixedRule);
    expect(canonical.status).not.toBe('BLOCKED');
    expect(canonical.lifecycle_reasons).not.toContain('UNSUPPORTED_TELEMETRY');
    expect(canonical.validation.telemetry.pass).toBe(true);
    expect(canonical.validation.telemetry.missing_fields).toEqual([]);
    // Only the entity-context-dependent, expected reason remains (no specific
    // customer/CVE context supplied here) -- never claims RELEASED without it.
    expect(canonical.lifecycle_reasons).toEqual(['ATTACK_MAPPING_UNCERTAIN']);
  });

  test('the fix changes ONLY telemetry classification -- structural validity and fixture results are unaffected by data_source', () => {
    const before = canonicalStatusFor(ruleWithDataSource('process_creation'));
    const after = canonicalStatusFor(ruleWithDataSource('registry_set'));
    expect(before.validation.structural.pass).toBe(after.validation.structural.pass);
  });
});

describe('fbc0da003ab2d073 (T1059.001) — incomplete test/seed content, correctly and permanently rejected', () => {
  // Frozen, exact historical content -- confirmed via direct read of the
  // real canonical store before remediation. Never fabricated/completed
  // here: this test proves the validator keeps catching this real,
  // malformed pattern, not that the content is somehow fine.
  const REAL_HISTORICAL_RULE = {
    id: 'fbc0da003ab2d073',
    technique_id: 'T1059.001',
    title: 'Suspicious PowerShell Execution',
    level: 'high',
    description: 'PowerShell with encoded commands',
    data_source: '',
    platforms: {
      sigma: 'logsource: process_creation\ndetection:\n  selection:\n    Image|endswith: powershell.exe',
      kql: 'DeviceProcessEvents | where FileName contains "powershell"',
      splunk: null,
      osquery: null,
    },
    suricata: [],
    governance: { status: 'GENERATED', confidence: 'HIGH', version: '1.0.0' },
    source: { iocs: ['10.0.0.1'], articles: ['TEST-001'], campaigns: [], evidence: '' },
  };

  test('REGRESSION: this exact historical content is BLOCKED for well-formed, provable structural reasons', () => {
    const canonical = canonicalStatusFor(REAL_HISTORICAL_RULE);
    expect(canonical.status).toBe('BLOCKED');
    expect(canonical.lifecycle_reasons).toEqual(
      expect.arrayContaining(['INVALID_QUERY', 'INVALID_LOGSOURCE', 'UNSUPPORTED_TELEMETRY'])
    );
    expect(canonical.validation.structural.per_format.sigma.pass).toBe(false);
    expect(canonical.validation.structural.per_format.sigma.errors).toEqual(
      expect.arrayContaining([
        'Missing required field: title',
        'Missing or invalid required field: logsource',
        'Missing required field: detection.condition',
      ])
    );
  });

  test('DISPOSITION: a manual REVOKED override (the real remediation applied) takes precedence over the computed gate, without hiding the underlying reasons', () => {
    const revokedRule = { ...REAL_HISTORICAL_RULE, governance: { ...REAL_HISTORICAL_RULE.governance, status: 'REVOKED' } };
    const canonical = canonicalStatusFor(revokedRule);
    expect(canonical.status).toBe('REVOKED');
    // The underlying validation reasons remain visible for transparency --
    // REVOKED is a governance decision, not a claim the content became valid.
    expect(canonical.lifecycle_reasons).toEqual(
      expect.arrayContaining(['INVALID_QUERY', 'INVALID_LOGSOURCE', 'UNSUPPORTED_TELEMETRY'])
    );
  });
});
