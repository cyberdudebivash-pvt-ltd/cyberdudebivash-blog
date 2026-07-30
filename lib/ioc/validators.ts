/**
 * IOC Validators
 * Syntax and semantic validation for all IOC types
 */

import { IOCType } from '../intelligence/schema';
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
  [IOCType.IPV4]: {
    type: IOCType.IPV4,
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

  [IOCType.IPV6]: {
    type: IOCType.IPV6,
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

  [IOCType.DOMAIN]: {
    type: IOCType.DOMAIN,
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

  [IOCType.URL]: {
    type: IOCType.URL,
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

  [IOCType.SHA256]: {
    type: IOCType.SHA256,
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

  [IOCType.SHA1]: {
    type: IOCType.SHA1,
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

  [IOCType.MD5]: {
    type: IOCType.MD5,
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

  [IOCType.EMAIL]: {
    type: IOCType.EMAIL,
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

  [IOCType.MUTEX]: {
    type: IOCType.MUTEX,
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'Mutex names accepted as-is',
  },

  [IOCType.REGISTRY]: {
    type: IOCType.REGISTRY,
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

  [IOCType.SERVICE]: {
    type: IOCType.SERVICE,
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'Service names accepted as-is',
  },

  [IOCType.PROCESS]: {
    type: IOCType.PROCESS,
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'Process names accepted as-is',
  },

  [IOCType.FILE_PATH]: {
    type: IOCType.FILE_PATH,
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'File paths accepted as-is',
  },

  [IOCType.CERTIFICATE]: {
    type: IOCType.CERTIFICATE,
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

  [IOCType.JA3]: {
    type: IOCType.JA3,
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

  [IOCType.JA4]: {
    type: IOCType.JA4,
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

  [IOCType.USER_AGENT]: {
    type: IOCType.USER_AGENT,
    validate: () => ({ valid: true, errors: [], warnings: [] }),
    description: 'User agents accepted as-is',
  },

  [IOCType.TLS_FINGERPRINT]: {
    type: IOCType.TLS_FINGERPRINT,
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
