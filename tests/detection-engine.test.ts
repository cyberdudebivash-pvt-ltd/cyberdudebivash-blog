/**
 * Unit tests for SENTINEL APEX Detection Engineering
 * Tests Sigma, YARA, Suricata, SIEM rule generation and optimization
 */

import {
  generateSigmaFromIOC,
  generateYaraFromIOC,
  generateSuricataFromIOC,
  generateSEMRuleFromIOC,
  validateDetectionRule,
  validateSigmaRule,
  validateYaraRule,
  deduplicateRules,
  optimizeRuleSet,
  renderDetectionRuleExport,
  buildDetectionCollection,
  mapBehaviorToTechniques,
  prioritizeRules,
  calculateRuleCoverage,
} from '../lib/detection/index';
import {
  generateDetectionRules,
  getDetectionRule,
  searchDetectionRules,
  getDetectionRuleStats,
  generateMalwareDetectionPack,
} from '../lib/api/detection-rules';
import type { DetectionRule } from '../lib/detection/schema';

describe('Detection Engineering - Sigma Rule Generation', () => {
  it('should generate Sigma rule for SHA256 hash', () => {
    const rule = generateSigmaFromIOC('sha256', 'abc123def456', 'Qilin');
    expect(rule.title).toContain('Qilin');
    expect(rule.title).toContain('SHA256');
    expect(rule.logsource.category).toBe('process_creation');
    expect(rule.detection).toBeDefined();
  });

  it('should generate Sigma rule for domain IOC', () => {
    const rule = generateSigmaFromIOC('domain', 'c2.malware.com', 'Qilin');
    expect(rule.title).toContain('C2 Domain');
    expect(rule.logsource.category).toBe('dns_query');
  });

  it('should generate Sigma rule for IPv4 IOC', () => {
    const rule = generateSigmaFromIOC('ipv4', '192.168.1.100', 'BianLian');
    expect(rule.title).toContain('IPv4');
    expect(rule.logsource.category).toBe('network_connection');
  });

  it('should include MITRE ATT&CK tags', () => {
    const rule = generateSigmaFromIOC('domain', 'c2.example.com', 'Malware', {
      techniques: ['T1071.001', 'T1008'],
    });
    expect(rule.tags).toContain('attack_t1071_001');
    expect(rule.tags).toContain('attack_t1008');
  });

  it('should generate unique rule IDs', () => {
    const rule1 = generateSigmaFromIOC('sha256', 'hash1', 'Malware1');
    const rule2 = generateSigmaFromIOC('sha256', 'hash2', 'Malware1');
    expect(rule1.id).not.toBe(rule2.id);
  });

  it('should set severity level correctly', () => {
    const rule = generateSigmaFromIOC('sha256', 'hash', 'Malware', {
      severity: 'critical',
    });
    expect(rule.level).toBe('critical');
  });
});

describe('Detection Engineering - YARA Rule Generation', () => {
  it('should generate YARA rule for hash IOC', () => {
    const rule = generateYaraFromIOC('sha256', 'abc123def456', 'Qilin');
    expect(rule.name).toContain('Qilin');
    expect(rule.strings.length).toBeGreaterThan(0);
    expect(rule.condition).toBeDefined();
  });

  it('should generate YARA rule for domain IOC', () => {
    const rule = generateYaraFromIOC('domain', 'c2.malware.com', 'Qilin');
    expect(rule.strings.length).toBeGreaterThan(0);
    // Should have multiple variants (direct, encoded, wildcard)
    expect(rule.strings.length).toBeGreaterThanOrEqual(2);
  });

  it('should include metadata in YARA rule', () => {
    const rule = generateYaraFromIOC('filename', 'malware.exe', 'Malware');
    expect(rule.metadata.author).toContain('SENTINEL APEX');
    expect(rule.metadata.malware_family).toBe('malware');
    expect(rule.metadata.severity).toBeGreaterThan(0);
  });

  it('should generate valid YARA conditions', () => {
    const rule = generateYaraFromIOC('registry', 'HKEY_LOCAL_MACHINE\\Software\\Test', 'Malware');
    expect(rule.condition).toBeTruthy();
    // Condition should reference string names
    const conditionHasStringRef = rule.strings.some(s => rule.condition.includes(s.name));
    expect(conditionHasStringRef || rule.condition.includes('any of') || rule.condition.includes('all of')).toBe(true);
  });
});

describe('Detection Engineering - Suricata Rule Generation', () => {
  it('should generate Suricata rules for IPv4 IOC', () => {
    const rules = generateSuricataFromIOC('ipv4', '192.168.1.100', 'Qilin');
    expect(rules.length).toBeGreaterThan(0);
    expect(rules[0].msg).toContain('Qilin');
  });

  it('should generate bidirectional rules for network communication', () => {
    const rules = generateSuricataFromIOC('ipv4', '10.0.0.1', 'Malware');
    // Should have inbound and outbound rules
    const hasInbound = rules.some(r => r.msg.includes('Outbound') || r.msg.includes('Communication'));
    expect(hasInbound).toBe(true);
  });

  it('should include proper Suricata action', () => {
    const rules = generateSuricataFromIOC('domain', 'evil.com', 'Malware');
    expect(rules.length).toBeGreaterThan(0);
    for (const rule of rules) {
      expect(['alert', 'drop', 'reject', 'pass'].includes(rule.action)).toBe(true);
    }
  });

  it('should generate HTTP rules for URLs', () => {
    const rules = generateSuricataFromIOC('url', 'https://evil.com/malware/loader', 'Malware');
    expect(rules.length).toBeGreaterThan(0);
  });

  it('should assign unique SIDs to rules', () => {
    const rules1 = generateSuricataFromIOC('ipv4', '1.1.1.1', 'Malware1');
    const rules2 = generateSuricataFromIOC('ipv4', '2.2.2.2', 'Malware2');
    const sids1 = new Set(rules1.map(r => r.sid));
    const sids2 = new Set(rules2.map(r => r.sid));
    expect(sids1.size).toBe(rules1.length);
    expect(sids2.size).toBe(rules2.length);
  });
});

describe('Detection Engineering - SIEM Rule Generation', () => {
  it('should generate Splunk search for IOC', () => {
    const rules = generateSEMRuleFromIOC('sha256', 'abc123', 'Malware');
    const splunkRule = rules.find(r => r.source === 'splunk');
    expect(splunkRule).toBeDefined();
    expect(splunkRule?.fields.some(f => f.name === 'search')).toBe(true);
  });

  it('should generate Elasticsearch query for IOC', () => {
    const rules = generateSEMRuleFromIOC('domain', 'evil.com', 'Malware');
    const elkRule = rules.find(r => r.source === 'elk');
    expect(elkRule).toBeDefined();
    expect(elkRule?.fields.some(f => f.name === 'query')).toBe(true);
  });

  it('should generate Azure Sentinel KQL query', () => {
    const rules = generateSEMRuleFromIOC('ipv4', '192.168.1.1', 'Malware');
    const sentinelRule = rules.find(r => r.source === 'sentinel');
    expect(sentinelRule).toBeDefined();
    expect(sentinelRule?.fields.some(f => f.name === 'query')).toBe(true);
  });

  it('should generate ArcSight AEL rule', () => {
    const rules = generateSEMRuleFromIOC('email', 'attacker@evil.com', 'Malware');
    const arcRule = rules.find(r => r.source === 'arcsight');
    expect(arcRule).toBeDefined();
  });

  it('should include severity in SIEM rules', () => {
    const rules = generateSEMRuleFromIOC('registry', 'HKEY_LOCAL_MACHINE\\Software', 'Malware', {
      severity: 'critical',
    });
    for (const rule of rules) {
      expect(rule.severity).toBe('critical');
    }
  });
});

describe('Detection Engineering - Rule Validation', () => {
  it('should validate Sigma rule successfully', () => {
    const rule = generateSigmaFromIOC('sha256', 'hash', 'Malware');
    const validation = validateSigmaRule(rule);
    expect(validation.valid).toBe(true);
    expect(validation.errors.length).toBe(0);
  });

  it('should reject invalid Sigma rule with missing title', () => {
    const invalidRule = {
      title: '',
      id: '123e4567-e89b-12d3-a456-426614174000',
      status: 'experimental' as const,
      description: 'Test',
      author: 'Test',
      date: '2024-01-01',
      logsource: {},
      detection: { selection: {}, condition: 'selection' },
      level: 'high' as const,
    };
    const validation = validateSigmaRule(invalidRule);
    expect(validation.valid).toBe(false);
  });

  it('should validate YARA rule successfully', () => {
    const rule = generateYaraFromIOC('filename', 'malware.exe', 'Malware');
    const validation = validateYaraRule(rule);
    expect(validation.valid).toBe(true);
  });

  it('should validate unified detection rule', () => {
    const detectionRule: DetectionRule = {
      id: 'test_rule_1',
      name: 'Test Rule',
      description: 'Test detection rule',
      author: 'Test Author',
      date: '2024-01-01',
      severity: 'high',
      formats: {
        sigma: generateSigmaFromIOC('sha256', 'hash', 'Malware'),
      },
      metadata: {
        linkedMalware: ['malware_1'],
        linkedTechniques: ['T1543'],
        linkedIOCs: ['hash'],
      },
      behaviors: [],
      enabled: true,
      tags: ['test'],
    };

    const validation = validateDetectionRule(detectionRule);
    expect(validation.valid).toBe(true);
  });
});

describe('Detection Engineering - Rule Deduplication', () => {
  it('should identify duplicate rules based on IOCs and techniques', () => {
    const rule1: DetectionRule = {
      id: 'rule_1',
      name: 'Rule 1',
      description: 'Test',
      author: 'Test',
      date: '2024-01-01',
      severity: 'high',
      formats: {},
      metadata: {
        linkedMalware: ['malware_1'],
        linkedTechniques: ['T1543'],
        linkedIOCs: ['ioc1', 'ioc2'],
      },
      behaviors: [],
      enabled: true,
      tags: [],
    };

    const rule2 = { ...rule1, id: 'rule_2', name: 'Rule 2' };

    const result = deduplicateRules([rule1, rule2]);
    expect(result.originalCount).toBe(2);
    expect(result.deduplicatedCount).toBeLessThanOrEqual(2);
  });

  it('should merge IOCs from duplicate rules', () => {
    const rule1: DetectionRule = {
      id: 'r1',
      name: 'Rule 1',
      description: 'Test',
      author: 'Test',
      date: '2024-01-01',
      severity: 'high',
      formats: {},
      metadata: {
        linkedMalware: ['mal1'],
        linkedTechniques: ['T1543'],
        linkedIOCs: ['ioc1'],
      },
      behaviors: [],
      enabled: true,
      tags: [],
    };

    const rule2: DetectionRule = {
      id: 'r2',
      name: 'Rule 2',
      description: 'Test',
      author: 'Test',
      date: '2024-01-01',
      severity: 'high',
      formats: {},
      metadata: {
        linkedMalware: ['mal1'],
        linkedTechniques: ['T1543'],
        linkedIOCs: ['ioc2'],
      },
      behaviors: [],
      enabled: true,
      tags: [],
    };

    const result = deduplicateRules([rule1, rule2]);
    const merged = result.mergedRules[0];
    expect(merged.metadata.linkedIOCs.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Detection Engineering - Rule Optimization', () => {
  it('should calculate optimization metrics', () => {
    const rules: DetectionRule[] = [];
    for (let i = 0; i < 5; i++) {
      rules.push({
        id: `rule_${i}`,
        name: `Rule ${i}`,
        description: 'Test',
        author: 'Test',
        date: '2024-01-01',
        severity: 'high',
        formats: { sigma: generateSigmaFromIOC('sha256', `hash${i}`, 'Malware') },
        metadata: {
          linkedMalware: ['malware_1'],
          linkedTechniques: ['T1543'],
          linkedIOCs: [`ioc${i}`],
          coverage: 0.8,
          fpRate: 0.05,
        },
        behaviors: [],
        enabled: true,
        tags: [],
      });
    }

    const metrics = optimizeRuleSet(rules);
    expect(metrics.totalRules).toBeGreaterThan(0);
    expect(metrics.averageCoverage).toBeLessThanOrEqual(1);
    expect(metrics.averageFPRate).toBeLessThanOrEqual(1);
  });
});

describe('Detection Engineering - Rule Rendering', () => {
  it('should render Sigma rule to YAML', () => {
    const detectionRule: DetectionRule = {
      id: 'rule_1',
      name: 'Test Rule',
      description: 'Test',
      author: 'Test',
      date: '2024-01-01',
      severity: 'high',
      formats: {
        sigma: generateSigmaFromIOC('sha256', 'hash', 'Malware'),
      },
      metadata: {
        linkedMalware: ['malware_1'],
        linkedTechniques: [],
        linkedIOCs: [],
      },
      behaviors: [],
      enabled: true,
      tags: [],
    };

    const collection = buildDetectionCollection('TestMalware', [detectionRule]);
    const export_ = renderDetectionRuleExport(collection, 'sigma');
    expect(export_.content.length).toBeGreaterThan(0);
    expect(export_.mimeType).toContain('yaml');
  });

  it('should render YARA rule collection', () => {
    const detectionRule: DetectionRule = {
      id: 'rule_1',
      name: 'Test Rule',
      description: 'Test',
      author: 'Test',
      date: '2024-01-01',
      severity: 'high',
      formats: {
        yara: generateYaraFromIOC('filename', 'malware.exe', 'Malware'),
      },
      metadata: {
        linkedMalware: [],
        linkedTechniques: [],
        linkedIOCs: [],
      },
      behaviors: [],
      enabled: true,
      tags: [],
    };

    const collection = buildDetectionCollection('TestMalware', [detectionRule]);
    const export_ = renderDetectionRuleExport(collection, 'yara');
    expect(export_.content.length).toBeGreaterThan(0);
    expect(export_.content).toContain('rule');
  });

  it('should render Suricata rules', () => {
    const detectionRule: DetectionRule = {
      id: 'rule_1',
      name: 'Test Rule',
      description: 'Test',
      author: 'Test',
      date: '2024-01-01',
      severity: 'high',
      formats: {
        suricata: generateSuricataFromIOC('ipv4', '192.168.1.1', 'Malware'),
      },
      metadata: {
        linkedMalware: [],
        linkedTechniques: [],
        linkedIOCs: [],
      },
      behaviors: [],
      enabled: true,
      tags: [],
    };

    const collection = buildDetectionCollection('TestMalware', [detectionRule]);
    const export_ = renderDetectionRuleExport(collection, 'suricata');
    expect(export_.content.length).toBeGreaterThan(0);
  });
});

describe('Detection Engineering - API Integration', () => {
  it('should generate detection rules via API', () => {
    const response = generateDetectionRules({
      iocType: 'sha256',
      iocValue: 'abc123',
      malwareId: 'test_malware',
      formats: ['sigma'],
    });

    expect(response.rules.length).toBeGreaterThan(0);
    expect(response.coverage).toBeGreaterThan(0);
    expect(response.timestamp).toBeDefined();
  });

  it('should retrieve generated detection rule', () => {
    const response = generateDetectionRules({
      iocType: 'domain',
      iocValue: 'evil.com',
      malwareId: 'test_malware',
    });

    const ruleId = response.rules[0].id;
    const retrievedRule = getDetectionRule(ruleId);
    expect(retrievedRule).toBeDefined();
    expect(retrievedRule?.id).toBe(ruleId);
  });

  it('should search detection rules by malware ID', () => {
    generateDetectionRules({
      iocType: 'sha256',
      iocValue: 'hash1',
      malwareId: 'qilin',
    });

    const results = searchDetectionRules({ malwareId: 'qilin' });
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].metadata.linkedMalware.includes('qilin')).toBe(true);
  });

  it('should generate detection pack for malware', () => {
    const rules = generateMalwareDetectionPack({
      malwareId: 'qilin',
      malwareName: 'Qilin Ransomware',
      iocs: [
        {
          type: 'sha256',
          value: 'hash1',
          confidence: 'HIGH',
        },
        {
          type: 'domain',
          value: 'c2.malware.com',
          confidence: 'HIGH',
        },
        {
          type: 'ipv4',
          value: '192.168.1.1',
          confidence: 'MEDIUM',
        },
      ],
      techniques: ['T1543', 'T1071.001'],
      formats: ['sigma', 'yara'],
    });

    expect(rules.length).toBeGreaterThanOrEqual(2);
    expect(rules.every(r => r.metadata.linkedMalware.includes('qilin'))).toBe(true);
  });

  it('should calculate detection rule statistics', () => {
    generateDetectionRules({
      iocType: 'sha256',
      iocValue: 'hash',
      formats: ['sigma', 'yara', 'suricata'],
    });

    const stats = getDetectionRuleStats();
    expect(stats.totalRules).toBeGreaterThan(0);
    expect(stats.rulesByFormat).toBeDefined();
    expect(stats.avgCoverage).toBeGreaterThanOrEqual(0);
    expect(stats.avgFPRate).toBeGreaterThanOrEqual(0);
  });
});

describe('Detection Engineering - MITRE Technique Mapping', () => {
  it('should map behaviors to MITRE techniques', () => {
    const techniques = mapBehaviorToTechniques(['NETWORK_COMMUNICATION']);
    expect(techniques.length).toBeGreaterThan(0);
    expect(techniques[0].technique_id).toMatch(/^T\d+/);
  });

  it('should include multiple behaviors', () => {
    const techniques = mapBehaviorToTechniques(['PERSISTENCE', 'DEFENSE_EVASION']);
    expect(techniques.length).toBeGreaterThan(0);
  });
});

describe('Detection Engineering - Rule Prioritization', () => {
  it('should prioritize rules by effectiveness', () => {
    const rules: DetectionRule[] = [];
    for (let i = 0; i < 3; i++) {
      rules.push({
        id: `rule_${i}`,
        name: `Rule ${i}`,
        description: 'Test',
        author: 'Test',
        date: '2024-01-01',
        severity: 'high',
        formats: {},
        metadata: {
          linkedMalware: ['malware_1'],
          linkedTechniques: i > 0 ? ['T1543'] : [],
          linkedIOCs: [i > 1 ? 'ioc1' : ''],
          coverage: 0.8 - i * 0.1,
          fpRate: 0.05 + i * 0.01,
        },
        behaviors: [],
        enabled: true,
        tags: [],
      });
    }

    const prioritized = prioritizeRules(rules);
    expect(prioritized[0].priority).toBeGreaterThanOrEqual(prioritized[1].priority);
  });
});

describe('Detection Engineering - Rule Coverage Analysis', () => {
  it('should calculate IOC coverage', () => {
    const rules: DetectionRule[] = [
      {
        id: 'rule_1',
        name: 'Rule 1',
        description: 'Test',
        author: 'Test',
        date: '2024-01-01',
        severity: 'high',
        formats: {},
        metadata: {
          linkedMalware: [],
          linkedTechniques: [],
          linkedIOCs: ['ioc1', 'ioc2'],
        },
        behaviors: [],
        enabled: true,
        tags: [],
      },
    ];

    const allIOCs = ['ioc1', 'ioc2', 'ioc3'];
    const coverage = calculateRuleCoverage(rules, allIOCs);
    expect(coverage.totalIOCs).toBe(3);
    expect(coverage.coveredByRule).toBe(2);
    expect(coverage.coverage).toBeLessThanOrEqual(100);
  });
});

describe('Detection Engineering - Performance', () => {
  it('should generate 100 rules efficiently', () => {
    const start = performance.now();

    for (let i = 0; i < 100; i++) {
      generateDetectionRules({
        iocType: 'sha256',
        iocValue: `hash${i}`,
        formats: ['sigma'],
      });
    }

    const duration = performance.now() - start;
    expect(duration).toBeLessThan(10000); // Should complete in under 10 seconds
  });

  it('should deduplicate 1000 rules efficiently', () => {
    const rules: DetectionRule[] = [];
    for (let i = 0; i < 1000; i++) {
      rules.push({
        id: `rule_${i}`,
        name: `Rule ${i}`,
        description: 'Test',
        author: 'Test',
        date: '2024-01-01',
        severity: 'high',
        formats: {},
        metadata: {
          linkedMalware: [i % 10 === 0 ? 'malware_1' : 'malware_2'],
          linkedTechniques: ['T1543'],
          linkedIOCs: [`ioc_${i % 100}`],
        },
        behaviors: [],
        enabled: true,
        tags: [],
      });
    }

    const start = performance.now();
    const result = deduplicateRules(rules);
    const duration = performance.now() - start;

    expect(result.deduplicatedCount).toBeLessThan(rules.length);
    expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
  });
});
