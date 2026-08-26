'use strict';

const taxonomy = require('../defense-taxonomy');
const detectionEngine = require('../../../Sentinel-APEX/engine-node/detection-engine');

describe('defense-taxonomy', () => {
  test('DATA_SOURCES is imported from detection-intelligence.js, not redeclared', () => {
    const detectionIntelligence = require('../detection-intelligence');
    expect(taxonomy.DATA_SOURCES).toEqual(Object.keys(detectionIntelligence.TELEMETRY_REQUIREMENTS));
  });

  test('every TECHNOLOGIES entry has a valid category', () => {
    for (const [id, t] of Object.entries(taxonomy.TECHNOLOGIES)) {
      expect(taxonomy.TECHNOLOGY_CATEGORIES).toContain(t.category);
      expect(typeof t.label).toBe('string');
      expect(t.label.length).toBeGreaterThan(0);
    }
  });

  test('preferredFormatFor(microsoft-sentinel) is kql, matching the real generator\'s FIELD_MAP._kql_table targeting', () => {
    expect(taxonomy.preferredFormatFor('microsoft-sentinel')).toBe('kql');
  });

  test('preferredFormatFor(splunk-enterprise-security) is splunk', () => {
    expect(taxonomy.preferredFormatFor('splunk-enterprise-security')).toBe('splunk');
  });

  test('SIEMs with no validated generator (Elastic/QRadar/Google SecOps) have a null preferred format -- never fabricated', () => {
    expect(taxonomy.preferredFormatFor('elastic-security')).toBeNull();
    expect(taxonomy.preferredFormatFor('qradar')).toBeNull();
    expect(taxonomy.preferredFormatFor('google-secops')).toBeNull();
  });

  test('CUSTOM_UNMAPPED ("other") is a valid technology for every category', () => {
    for (const cat of taxonomy.TECHNOLOGY_CATEGORIES) {
      expect(taxonomy.isKnownTechnology(cat, 'other')).toBe(true);
    }
  });

  test('isKnownTechnology rejects a technology declared under the wrong category', () => {
    expect(taxonomy.isKnownTechnology('cloud', 'microsoft-sentinel')).toBe(false);
    expect(taxonomy.isKnownTechnology('siem', 'aws')).toBe(false);
  });

  test('isKnownTechnology rejects an unknown id outright', () => {
    expect(taxonomy.isKnownTechnology('siem', 'not-a-real-siem')).toBe(false);
  });

  test('microsoft-defender-xdr process_creation/registry_set source labels match the real generator\'s FIELD_MAP._kql_table values exactly (single source of truth)', () => {
    const pcSource = taxonomy.PROVIDER_TELEMETRY_SOURCES.process_creation.find(s => s.technology_id === 'microsoft-defender-xdr');
    const regSource = taxonomy.PROVIDER_TELEMETRY_SOURCES.registry_set.find(s => s.technology_id === 'microsoft-defender-xdr');
    expect(pcSource.source_label).toBe(detectionEngine.FIELD_MAP.process_creation._kql_table);
    expect(regSource.source_label).toBe(detectionEngine.FIELD_MAP.registry_set._kql_table);
    expect(pcSource.source_label).toBe('DeviceProcessEvents');
    expect(regSource.source_label).toBe('DeviceRegistryEvents');
  });

  test('every provider entry without documented fields is honestly labeled confidence:"general", never a guessed field list', () => {
    for (const sources of Object.values(taxonomy.PROVIDER_TELEMETRY_SOURCES)) {
      for (const s of sources) {
        if (s.fields === null) expect(s.confidence).toBe('general');
        if (s.confidence === 'documented') expect(Array.isArray(s.fields)).toBe(true);
      }
    }
  });

  test('suggestedSourcesFor scopes to the caller\'s declared technologies when any match exists', () => {
    const scoped = taxonomy.suggestedSourcesFor('process_creation', ['sysmon']);
    expect(scoped).toHaveLength(1);
    expect(scoped[0].technology_id).toBe('sysmon');
  });

  test('suggestedSourcesFor falls back to the full list when no declared technology matches (still explains the gap)', () => {
    const fallback = taxonomy.suggestedSourcesFor('process_creation', ['aws']); // aws is not a process_creation provider
    expect(fallback.length).toBeGreaterThan(1);
  });

  test('suggestedSourcesFor with no declared technologies returns the full list', () => {
    expect(taxonomy.suggestedSourcesFor('process_creation', [])).toEqual(taxonomy.PROVIDER_TELEMETRY_SOURCES.process_creation);
  });

  test('technologyOptionsFor always appends the "other" option last', () => {
    for (const cat of taxonomy.TECHNOLOGY_CATEGORIES) {
      const options = taxonomy.technologyOptionsFor(cat);
      expect(options[options.length - 1].id).toBe('other');
    }
  });
});
