// Detection Factory — Dynamic detection rule test data generation

import { v4 as uuid } from 'uuid';

export interface DetectionRuleTestData {
  id: string;
  name: string;
  format: 'sigma' | 'yara' | 'suricata' | 'siem';
  content: string;
  confidence: number;
  enabled: boolean;
  createdAt: Date;
}

export class DetectionFactory {
  static createSigmaRule(overrides?: Partial<DetectionRuleTestData>): DetectionRuleTestData {
    return {
      id: uuid(),
      name: 'Sigma Test Rule',
      format: 'sigma',
      content: `
title: Malware Execution Test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'malware'
      - 'payload'
    ParentImage|endswith: 'svchost.exe'
  condition: selection
falsepositives:
  - Unlikely
level: high
      `,
      confidence: 85,
      enabled: true,
      createdAt: new Date(),
      ...overrides,
    };
  }

  static createYaraRule(overrides?: Partial<DetectionRuleTestData>): DetectionRuleTestData {
    return {
      id: uuid(),
      name: 'YARA Test Rule',
      format: 'yara',
      content: `
rule Malware_Test {
  meta:
    description = "Test YARA rule for malware detection"
    author = "Test"
    date = "2024-07-30"
  strings:
    $s1 = "malware_string" nocase
    $h1 = { 4d 5a 90 00 } // MZ header
  condition:
    any of them
}
      `,
      confidence: 90,
      enabled: true,
      createdAt: new Date(),
      ...overrides,
    };
  }

  static createSuricataRule(overrides?: Partial<DetectionRuleTestData>): DetectionRuleTestData {
    return {
      id: uuid(),
      name: 'Suricata Test Rule',
      format: 'suricata',
      content:
        'alert http any any -> any any (msg:"Malware C2 Communication"; content:"POST"; http_method; ' +
        'content:"malware.test"; http_host; classtype:trojan-activity; sid:1000001; rev:1;)',
      confidence: 75,
      enabled: true,
      createdAt: new Date(),
      ...overrides,
    };
  }

  static createSIEMRule(overrides?: Partial<DetectionRuleTestData>): DetectionRuleTestData {
    return {
      id: uuid(),
      name: 'SIEM Test Rule',
      format: 'siem',
      content: JSON.stringify({
        index: 'logs-*',
        query: {
          bool: {
            must: [
              { term: { 'event.action': 'process-create' } },
              {
                query_string: {
                  query: 'process.name:(malware* OR payload*)',
                },
              },
            ],
          },
        },
        aggregations: {
          unique_hosts: {
            cardinality: { field: 'host.name' },
          },
        },
      }),
      confidence: 80,
      enabled: true,
      createdAt: new Date(),
      ...overrides,
    };
  }

  static createRandomFormat(overrides?: Partial<DetectionRuleTestData>): DetectionRuleTestData {
    const formats = [
      () => this.createSigmaRule(),
      () => this.createYaraRule(),
      () => this.createSuricataRule(),
      () => this.createSIEMRule(),
    ];

    const creator = formats[Math.floor(Math.random() * formats.length)];
    const rule = creator();
    return { ...rule, ...overrides };
  }

  static createAllFormats(baseOverrides?: Partial<DetectionRuleTestData>): DetectionRuleTestData[] {
    return [
      this.createSigmaRule(baseOverrides),
      this.createYaraRule(baseOverrides),
      this.createSuricataRule(baseOverrides),
      this.createSIEMRule(baseOverrides),
    ];
  }

  static createBatch(count: number, format?: string): DetectionRuleTestData[] {
    if (format === 'sigma') {
      return Array.from({ length: count }, (_, i) =>
        this.createSigmaRule({
          id: uuid(),
          name: `Sigma_Rule_${i}`,
        })
      );
    } else if (format === 'yara') {
      return Array.from({ length: count }, (_, i) =>
        this.createYaraRule({
          id: uuid(),
          name: `YARA_Rule_${i}`,
        })
      );
    } else if (format === 'suricata') {
      return Array.from({ length: count }, (_, i) =>
        this.createSuricataRule({
          id: uuid(),
          name: `Suricata_Rule_${i}`,
        })
      );
    } else if (format === 'siem') {
      return Array.from({ length: count }, (_, i) =>
        this.createSIEMRule({
          id: uuid(),
          name: `SIEM_Rule_${i}`,
        })
      );
    }

    // Random format
    return Array.from({ length: count }, () => this.createRandomFormat());
  }

  static createHighFidelityRules(count: number = 10): DetectionRuleTestData[] {
    return Array.from({ length: count }, (_, i) =>
      this.createRandomFormat({
        id: uuid(),
        name: `HighFidelity_Rule_${i}`,
        confidence: 90 + Math.random() * 10, // 90-100% confidence
        enabled: true,
      })
    );
  }

  static createLowFidelityRules(count: number = 10): DetectionRuleTestData[] {
    return Array.from({ length: count }, (_, i) =>
      this.createRandomFormat({
        id: uuid(),
        name: `LowFidelity_Rule_${i}`,
        confidence: 50 + Math.random() * 30, // 50-80% confidence
        enabled: true,
      })
    );
  }
}
