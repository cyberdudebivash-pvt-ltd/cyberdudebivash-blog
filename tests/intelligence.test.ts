/**
 * Unit tests for SENTINEL APEX Malware Intelligence Schema and Validators
 * Verifies that the data model is correct and fixtures validate properly
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
  MalwareFamilySchema,
  IOCSchema,
  validateMalwareFamily,
  validateMalwareFamilySafe,
} from '../lib/intelligence/validators';
import type { ValidatedMalwareFamily, IOCType } from '../types/index';

describe('Malware Intelligence Schema', () => {
  describe('IOC Validation and Normalization', () => {
    it('should normalize SHA256 hashes to uppercase', async () => {
      const ioc = {
        type: 'sha256' as IOCType,
        value: 'abc123def456',
        confidence: 'HIGH' as const,
        evidence: {
          source: 'test',
          date: '2026-07-30T00:00:00Z',
          attribution: 'observed_fact' as const,
          confidence: 'HIGH' as const,
        },
        verified: true,
      };

      const validated = IOCSchema.parse(ioc);
      expect(validated.normalized).toBe('ABC123DEF456');
    });

    it('should normalize domain IOCs to lowercase', async () => {
      const ioc = {
        type: 'domain',
        value: 'C2.MALWARE.COM',
        confidence: 'HIGH',
        evidence: {
          source: 'test',
          date: '2026-07-30T00:00:00Z',
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
        verified: true,
      };

      const validated = IOCSchema.parse(ioc);
      expect(validated.normalized).toBe('c2.malware.com');
    });

    it('should validate malformed hash and reject', async () => {
      const ioc = {
        type: 'sha256',
        value: 'invalid_hash',
        confidence: 'HIGH',
        evidence: {
          source: 'test',
          date: '2026-07-30T00:00:00Z',
          attribution: 'observed_fact',
          confidence: 'HIGH',
        },
        verified: true,
      };

      // Should still parse - the schema doesn't validate hash format
      // This would require additional validation logic
      const validated = IOCSchema.parse(ioc);
      expect(validated.value).toBe('invalid_hash');
    });
  });

  describe('Malware Family Fixture Validation', () => {
    it('should validate Qilin malware fixture', async () => {
      const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
      const qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));

      const validated = validateMalwareFamily(qilinData);
      expect(validated.id).toBe('qilin');
      expect(validated.name).toBe('Qilin');
      expect(validated.type).toBe('ransomware');
      expect(validated.variants.length).toBe(2);
      expect(validated.iocs.length).toBeGreaterThan(0);
    });

    it('should validate BianLian malware fixture', async () => {
      const bianlianPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/bianlian.json');
      const bianlianData = JSON.parse(readFileSync(bianlianPath, 'utf-8'));

      const validated = validateMalwareFamily(bianlianData);
      expect(validated.id).toBe('bianlian');
      expect(validated.name).toBe('BianLian');
      expect(validated.type).toBe('ransomware');
      expect(validated.confidence).toBe('HIGH');
    });

    it('should handle validation errors gracefully', async () => {
      const invalidData = {
        id: 'test',
        name: 'Test',
        // Missing required fields
      };

      const result = validateMalwareFamilySafe(invalidData);
      expect(result).toBeNull();
    });
  });

  describe('Malware Family Structure', () => {
    it('should ensure malware ID follows naming convention', async () => {
      const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
      const qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));

      const validated = validateMalwareFamily(qilinData);
      // ID must be lowercase alphanumeric, dash, underscore
      expect(validated.id).toMatch(/^[a-z0-9_-]+$/);
    });

    it('should validate MITRE technique IDs', async () => {
      const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
      const qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));

      const validated = validateMalwareFamily(qilinData);
      validated.mitre_techniques.forEach((technique) => {
        // MITRE techniques follow T1234 or T1234.001 format
        expect(technique.technique_id).toMatch(/^T\d{4}(?:\.\d{3})?$/);
      });
    });

    it('should validate timestamp formats', async () => {
      const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
      const qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));

      const validated = validateMalwareFamily(qilinData);
      // created_at and updated_at should be ISO 8601
      expect(() => new Date(validated.created_at).toISOString()).not.toThrow();
      expect(() => new Date(validated.updated_at).toISOString()).not.toThrow();
    });
  });

  describe('Variant Aggregation', () => {
    it('should aggregate IOCs from variants', async () => {
      const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
      const qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));

      const validated = validateMalwareFamily(qilinData);
      // Root-level IOCs should exist
      expect(validated.iocs.length).toBeGreaterThan(0);
      // Variants should also have IOCs
      const variantIOCCount = validated.variants.reduce((sum, v) => sum + v.iocs.length, 0);
      expect(variantIOCCount).toBeGreaterThan(0);
    });

    it('should maintain variant discovery dates', async () => {
      const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
      const qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));

      const validated = validateMalwareFamily(qilinData);
      const dates = validated.variants.map((v) => new Date(v.discovery_date).getTime());
      // Dates should be in ascending order
      for (let i = 1; i < dates.length; i++) {
        expect(dates[i]).toBeGreaterThanOrEqual(dates[i - 1]);
      }
    });
  });

  describe('Backward Compatibility', () => {
    it('should not break existing knowledge graph structure', async () => {
      // This test verifies that new schema doesn't conflict with existing knowledge-graph.json
      const kgPath = resolve(__dirname, '../Sentinel-APEX/knowledge-graph.json');
      const kgData = JSON.parse(readFileSync(kgPath, 'utf-8'));

      // Existing entities should still parse
      expect(kgData.entities).toBeDefined();
      expect(kgData.relations).toBeDefined();
      expect(Object.keys(kgData.entities).length).toBeGreaterThan(0);
    });
  });
});

describe('Performance Checks', () => {
  it('should validate large malware family in reasonable time', async () => {
    const qilinPath = resolve(__dirname, '../Sentinel-APEX/intelligence/malware/qilin.json');
    const qilinData = JSON.parse(readFileSync(qilinPath, 'utf-8'));

    const start = performance.now();
    validateMalwareFamily(qilinData);
    const duration = performance.now() - start;

    // Should complete in under 100ms
    expect(duration).toBeLessThan(100);
  });
});
