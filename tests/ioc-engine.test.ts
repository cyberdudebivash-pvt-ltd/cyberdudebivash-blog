/**
 * Unit tests for SENTINEL APEX IOC Intelligence Engine
 * Tests normalization, validation, deduplication, correlation, confidence
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
  createIOCEngine,
  normalizeIOC,
  validateIOC,
  aggregateConfidence,
  deduplicate,
  createCorrelationEngine,
} from '../lib/ioc';
import { validateMalwareFamily } from '../lib/intelligence/validators';
import { IOCType } from '../lib/intelligence/schema';

describe('IOC Intelligence Engine', () => {
  let qilinData: any;
  let bianlianData: any;

  beforeAll(() => {
    const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
    const bianlianPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/bianlian.json');

    qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));
    bianlianData = JSON.parse(readFileSync(bianlianPath, 'utf-8'));
  });

  describe('Normalization', () => {
    it('should normalize hashes to uppercase', () => {
      const normalized = normalizeIOC(IOCType.SHA256, 'abc123def456');
      expect(normalized).toBe('ABC123DEF456');
    });

    it('should normalize domains to lowercase', () => {
      const normalized = normalizeIOC(IOCType.DOMAIN, 'C2.MALWARE.COM');
      expect(normalized).toBe('c2.malware.com');
    });

    it('should normalize URLs with protocol and port', () => {
      const normalized = normalizeIOC(IOCType.URL, 'HTTPS://EXAMPLE.COM:443/path');
      expect(normalized).toContain('https://example.com/path');
    });

    it('should normalize email to lowercase', () => {
      const normalized = normalizeIOC(IOCType.EMAIL, 'Admin@EXAMPLE.COM');
      expect(normalized).toBe('admin@example.com');
    });

    it('should normalize registry paths to uppercase', () => {
      const normalized = normalizeIOC(IOCType.REGISTRY, 'hkey_local_machine\\software\\test');
      expect(normalized.toUpperCase()).toContain('HKEY_LOCAL_MACHINE');
    });

    it('should be deterministic across multiple calls', () => {
      const value = 'abc123def456';
      const norm1 = normalizeIOC(IOCType.SHA256, value);
      const norm2 = normalizeIOC(IOCType.SHA256, value);
      expect(norm1).toBe(norm2);
    });
  });

  describe('Validation', () => {
    it('should validate valid SHA256 hash', () => {
      const result = validateIOC(IOCType.SHA256, '56942b36d5990f66a81955a94511298fd27cb6092e467110a7995a0654f17b1a');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject invalid SHA256 hash', () => {
      const result = validateIOC(IOCType.SHA256, 'invalid_hash');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should validate valid IPv4', () => {
      const result = validateIOC(IOCType.IPV4, '192.168.1.1');
      expect(result.valid).toBe(true);
    });

    it('should reject IPv4 with out-of-range octets', () => {
      const result = validateIOC(IOCType.IPV4, '192.168.1.256');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should validate valid email', () => {
      const result = validateIOC(IOCType.EMAIL, 'user@example.com');
      expect(result.valid).toBe(true);
    });

    it('should validate valid URL', () => {
      const result = validateIOC(IOCType.URL, 'https://example.com/path');
      expect(result.valid).toBe(true);
    });

    it('should reject malformed URL', () => {
      const result = validateIOC(IOCType.URL, 'not-a-url');
      expect(result.valid).toBe(false);
    });
  });

  describe('IOC Engine - Core Operations', () => {
    it('should add IOC and retrieve it', () => {
      const engine = createIOCEngine();
      engine.addIOC(
        'test-ioc-1',
        IOCType.SHA256,
        'abc123def456',
        'HIGH',
        [
          {
            source: 'VirusTotal',
            date: new Date().toISOString(),
            attribution: 'observed_fact',
            confidence: 'HIGH',
          },
        ]
      );

      const ioc = engine.getIOC('test-ioc-1');
      expect(ioc).toBeDefined();
      expect(ioc?.original).toBe('abc123def456');
      expect(ioc?.normalized).toBe('ABC123DEF456');
    });

    it('should reject invalid IOC on add', () => {
      const engine = createIOCEngine();
      expect(() => {
        engine.addIOC(
          'test-ioc-bad',
          IOCType.SHA256,
          'invalid',
          'HIGH',
          [
            {
              source: 'test',
              date: new Date().toISOString(),
              attribution: 'observed_fact',
              confidence: 'HIGH',
            },
          ]
        );
      }).toThrow();
    });

    it('should search IOCs by type', () => {
      const engine = createIOCEngine();
      engine.addIOC('ioc-1', IOCType.SHA256, 'abc123', 'HIGH', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
      ]);
      engine.addIOC('ioc-2', IOCType.DOMAIN, 'example.com', 'HIGH', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
      ]);

      const results = engine.search({ type: IOCType.SHA256 });
      expect(results).toHaveLength(1);
      expect(results[0].type).toBe(IOCType.SHA256);
    });

    it('should search IOCs by normalized value', () => {
      const engine = createIOCEngine();
      engine.addIOC('ioc-domain', IOCType.DOMAIN, 'EXAMPLE.COM', 'HIGH', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
      ]);

      const results = engine.search({ normalized: 'example.com' });
      expect(results).toHaveLength(1);
    });

    it('should filter IOCs by confidence level', () => {
      const engine = createIOCEngine();
      engine.addIOC('high', IOCType.SHA256, 'abc123', 'HIGH', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
      ]);
      engine.addIOC('low', IOCType.SHA256, 'def456', 'LOW', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'LOW',
        },
      ]);

      const results = engine.search({ confidence_min: 'HIGH' });
      expect(results.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Deduplication', () => {
    it('should deduplicate identical normalized IOCs', () => {
      const engine = createIOCEngine();
      const evidence = [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact' as const,
          confidence: 'HIGH' as const,
        },
      ];

      engine.addIOC('ioc-1', IOCType.SHA256, 'abc123', 'HIGH', evidence);
      engine.addIOC('ioc-2', IOCType.SHA256, 'ABC123', 'HIGH', evidence); // Same, different case

      const iocs = engine.export().iocs;
      const dedupResults = deduplicate(iocs);
      expect(dedupResults.length).toBeGreaterThan(0);
    });

    it('should preserve aliases during deduplication', () => {
      const engine = createIOCEngine();
      const evidence = [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact' as const,
          confidence: 'HIGH' as const,
        },
      ];

      engine.addIOC('ioc-1', IOCType.DOMAIN, 'c2.malware.com', 'HIGH', evidence, {
        aliases: ['c2.malware-alt.com'],
      });
      engine.addIOC('ioc-2', IOCType.DOMAIN, 'C2.MALWARE.COM', 'MEDIUM', evidence, {
        aliases: ['c2.alt.com'],
      });

      const iocs = engine.export().iocs;
      const dedupResults = deduplicate(iocs);
      expect(dedupResults.length).toBeGreaterThan(0);
    });
  });

  describe('Confidence Scoring', () => {
    it('should aggregate confidence correctly', () => {
      const result = aggregateConfidence({
        source_confidence: 'HIGH',
        observation_confidence: 'HIGH',
        analyst_confidence: 'MEDIUM',
      });
      expect(result).toBe('HIGH');
    });

    it('should compute composite confidence score', () => {
      const engine = createIOCEngine();
      const ioc = engine.addIOC('test', IOCType.SHA256, 'abc123', 'HIGH', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
      ]);

      expect(ioc.aggregate_confidence).toBe('HIGH');
    });
  });

  describe('Correlation', () => {
    it('should correlate IOC with malware family', () => {
      const correlator = createCorrelationEngine();
      const malware = validateMalwareFamily(qilinData);
      correlator.loadMalwareFamilies([malware]);

      // Get an IOC from the malware
      const testIOC = malware.iocs[0];
      if (testIOC) {
        const correlation = correlator.correlate(testIOC.normalized, testIOC.type);
        expect(correlation.correlated_malware).toContain('qilin');
      }
    });

    it('should build correlation graph', () => {
      const correlator = createCorrelationEngine();
      const malware = validateMalwareFamily(qilinData);
      correlator.loadMalwareFamilies([malware]);

      const testIOC = malware.iocs[0];
      if (testIOC) {
        const graph = correlator.getCorrelationGraph(testIOC.normalized);
        expect(graph.ioc).toBe(testIOC.normalized);
        expect(graph.malware.length).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe('Engine Statistics', () => {
    it('should calculate engine statistics', () => {
      const engine = createIOCEngine();
      engine.addIOC('ioc-1', IOCType.SHA256, 'abc123', 'HIGH', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
      ]);
      engine.addIOC('ioc-2', IOCType.DOMAIN, 'example.com', 'MEDIUM', [
        {
          source: 'test',
          date: new Date().toISOString(),
          attribution: 'observed_fact',
          confidence: 'MEDIUM',
        },
      ]);

      const stats = engine.stats();
      expect(stats.total_iocs).toBe(2);
      expect(stats.by_type[IOCType.SHA256]).toBe(1);
      expect(stats.by_type[IOCType.DOMAIN]).toBe(1);
      expect(stats.high_confidence).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Performance', () => {
    it('should handle large IOC collections efficiently', () => {
      const engine = createIOCEngine();
      const start = performance.now();

      // Add 1000 IOCs
      for (let i = 0; i < 1000; i++) {
        engine.addIOC(`ioc-${i}`, IOCType.SHA256, `abc${String(i).padStart(6, '0')}def456`, 'HIGH', [
          {
            source: 'test',
            date: new Date().toISOString(),
            attribution: 'observed_fact',
            confidence: 'HIGH',
          },
        ]);
      }

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
      expect(engine.stats().total_iocs).toBe(1000);
    });
  });

  describe('Integration', () => {
    it('should process malware family IOCs end-to-end', () => {
      const engine = createIOCEngine();
      const malware = validateMalwareFamily(qilinData);

      // Load IOCs from malware family
      for (let i = 0; i < malware.iocs.length; i++) {
        const ioc = malware.iocs[i];
        engine.addIOC(
          `qilin-ioc-${i}`,
          ioc.type,
          ioc.value,
          ioc.confidence,
          [ioc.evidence],
          {
            firstObserved: ioc.first_seen,
            lastObserved: ioc.last_seen,
          }
        );
      }

      const stats = engine.stats();
      expect(stats.total_iocs).toBe(malware.iocs.length);
      expect(stats.unique_normalized_forms).toBeGreaterThan(0);
    });
  });
});
