/**
 * IOC Validators
 * Syntax and semantic validation for all IOC types
 */

import type { IOCType } from '../intelligence/schema';
import type { ValidationRule } from './types';

const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?)$/;
const sha256Regex = /^[a-fA-F0-9]{64}$/;
const sha1Regex = /^[a-fA-F0-9]{40}$/;
const md5Regex = /^[a-fA-F0-9]{32}$/;
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const urlRegex = /^https?:\/\/.+/;
const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const validationRules: Record<IOCType, ValidationRule> = {
  ipv4: {
    type: 'ipv4',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!ipv4Regex.test(value)) {
        errors.push('Invalid IPv4 format');
        return { valid: false, errors, warnings };
      }

      const parts = value.split('.');
      for (const part of parts) {
        const num = parseInt(part, 10);
        if (num > 255) {
          errors.push(`IPv4 octet out of range: ${part}`);
        }
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'IPv4 syntax and range validation',
  },

  ipv6: {
    type: 'ipv6',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!ipv6Regex.test(value)) {
        errors.push('Invalid IPv6 format');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'IPv6 syntax validation',
  },

  domain: {
    type: 'domain',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (value.includes('/')) {
        errors.push('Domain should not contain path; use URL type instead');
      }

      if (value.length > 253) {
        errors.push('Domain exceeds maximum length of 253 characters');
      }

      if (!domainRegex.test(value)) {
        warnings.push('Domain format may be invalid');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'Domain syntax validation',
  },

  url: {
    type: 'url',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      try {
        new URL(value);
      } catch {
        errors.push('Invalid URL format');
        return { valid: false, errors, warnings };
      }

      if (!urlRegex.test(value)) {
        errors.push('URL must start with http:// or https://');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'URL syntax validation',
  },

  sha256: {
    type: 'sha256',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!sha256Regex.test(value)) {
        errors.push('SHA256 must be 64 hexadecimal characters');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'SHA256 hash format validation (64 hex chars)',
  },

  sha1: {
    type: 'sha1',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!sha1Regex.test(value)) {
        errors.push('SHA1 must be 40 hexadecimal characters');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'SHA1 hash format validation (40 hex chars)',
  },

  md5: {
    type: 'md5',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!md5Regex.test(value)) {
        errors.push('MD5 must be 32 hexadecimal characters');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'MD5 hash format validation (32 hex chars)',
  },

  email: {
    type: 'email',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!emailRegex.test(value)) {
        errors.push('Invalid email format');
      }

      if (value.length > 320) {
        errors.push('Email exceeds maximum length');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'Email address syntax validation',
  },

  mutex: {
    type: 'mutex',
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'Mutex names accepted as-is',
  },

  registry: {
    type: 'registry',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!value.includes('\\')) {
        warnings.push('Registry path should contain backslashes');
      }

      if (!value.match(/^(HKEY_|HK)/)) {
        warnings.push('Registry path should start with HKEY_ or HK');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'Windows registry path validation',
  },

  service: {
    type: 'service',
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'Service names accepted as-is',
  },

  process: {
    type: 'process',
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'Process names accepted as-is',
  },

  file_path: {
    type: 'file_path',
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'File paths accepted as-is',
  },

  certificate: {
    type: 'certificate',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!/^[a-fA-F0-9]+$/.test(value)) {
        errors.push('Certificate fingerprint must be hexadecimal');
      }

      if (value.length < 32) {
        warnings.push('Certificate fingerprint appears short');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'TLS certificate fingerprint validation',
  },

  ja3: {
    type: 'ja3',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!/^[a-fA-F0-9]{32}$/.test(value)) {
        errors.push('JA3 must be 32 hexadecimal characters');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'JA3 fingerprint validation',
  },

  ja4: {
    type: 'ja4',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!/^[a-zA-Z0-9_]{36}$/.test(value)) {
        errors.push('JA4 format appears invalid');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'JA4 fingerprint validation',
  },

  user_agent: {
    type: 'user_agent',
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'User agents accepted as-is',
  },

  tls_fingerprint: {
    type: 'tls_fingerprint',
    validate: (value: string) => {
      const errors: string[] = [];
      const warnings: string[] = [];

      if (!/^[a-fA-F0-9]+$/.test(value)) {
        errors.push('TLS fingerprint must be hexadecimal');
      }

      return { valid: errors.length === 0, errors, warnings };
    },
    description: 'TLS fingerprint validation',
  },
};

export function validateIOC(type: IOCType, value: string) {
  const rule = validationRules[type];
  if (!rule) throw new Error(`Unknown IOC type: ${type}`);
  return rule.validate(value);
}
