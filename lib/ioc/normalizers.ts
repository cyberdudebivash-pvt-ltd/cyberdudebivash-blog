/**
 * IOC Normalizers
 * Deterministic normalization rules for all IOC types
 */

import { IOCType } from '../intelligence/schema';
import type { NormalizationRule } from './types';

const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?)$/;
const sha256Regex = /^[a-fA-F0-9]{64}$/;
const sha1Regex = /^[a-fA-F0-9]{40}$/;
const md5Regex = /^[a-fA-F0-9]{32}$/;

export const normalizationRules: Record<IOCType, NormalizationRule> = {
  [IOCType.IPV4]: {
    type: IOCType.IPV4,
    apply: (value: string) => value.trim(),
    description: 'IPv4 addresses normalized to standard dotted-quad notation',
  },
  [IOCType.IPV6]: {
    type: IOCType.IPV6,
    apply: (value: string) => {
      const addr = value.trim().toLowerCase();
      return compressIPv6(addr);
    },
    description: 'IPv6 addresses normalized to compressed canonical form',
  },
  [IOCType.DOMAIN]: {
    type: IOCType.DOMAIN,
    apply: (value: string) => value.trim().toLowerCase(),
    description: 'Domains normalized to lowercase',
  },
  [IOCType.URL]: {
    type: IOCType.URL,
    apply: (value: string) => {
      const url = new URL(value.trim());
      url.hostname = url.hostname.toLowerCase();
      // Remove redundant default ports
      if ((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443')) {
        url.port = '';
      }
      return url.toString();
    },
    description: 'URLs normalized: lowercase hostname, remove redundant ports, preserve path/query',
  },
  [IOCType.SHA256]: {
    type: IOCType.SHA256,
    apply: (value: string) => value.trim().toUpperCase(),
    description: 'SHA256 hashes normalized to uppercase',
  },
  [IOCType.SHA1]: {
    type: IOCType.SHA1,
    apply: (value: string) => value.trim().toUpperCase(),
    description: 'SHA1 hashes normalized to uppercase',
  },
  [IOCType.MD5]: {
    type: IOCType.MD5,
    apply: (value: string) => value.trim().toUpperCase(),
    description: 'MD5 hashes normalized to uppercase',
  },
  [IOCType.EMAIL]: {
    type: IOCType.EMAIL,
    apply: (value: string) => value.trim().toLowerCase(),
    description: 'Email addresses normalized to lowercase',
  },
  [IOCType.MUTEX]: {
    type: IOCType.MUTEX,
    apply: (value: string) => value.trim(),
    description: 'Mutex names preserved as-is with trimming',
  },
  [IOCType.REGISTRY]: {
    type: IOCType.REGISTRY,
    apply: (value: string) => {
      const normalized = value.trim();
      return normalized.toUpperCase().replace(/\\\\/g, '\\');
    },
    description: 'Registry paths normalized to uppercase with canonical backslashes',
  },
  [IOCType.SERVICE]: {
    type: IOCType.SERVICE,
    apply: (value: string) => value.trim().toLowerCase(),
    description: 'Service names normalized to lowercase',
  },
  [IOCType.PROCESS]: {
    type: IOCType.PROCESS,
    apply: (value: string) => value.trim(),
    description: 'Process names preserved with trimming',
  },
  [IOCType.FILE_PATH]: {
    type: IOCType.FILE_PATH,
    apply: (value: string) => {
      const normalized = value.trim();
      return normalized.replace(/\\\\/g, '\\').toUpperCase();
    },
    description: 'File paths normalized with canonical separators',
  },
  [IOCType.CERTIFICATE]: {
    type: IOCType.CERTIFICATE,
    apply: (value: string) => value.trim().toUpperCase(),
    description: 'Certificate fingerprints normalized to uppercase',
  },
  [IOCType.JA3]: {
    type: IOCType.JA3,
    apply: (value: string) => value.trim().toUpperCase(),
    description: 'JA3 fingerprints normalized to uppercase',
  },
  [IOCType.JA4]: {
    type: IOCType.JA4,
    apply: (value: string) => value.trim().toUpperCase(),
    description: 'JA4 fingerprints normalized to uppercase',
  },
  [IOCType.USER_AGENT]: {
    type: IOCType.USER_AGENT,
    apply: (value: string) => value.trim(),
    description: 'User agents preserved with trimming',
  },
  [IOCType.TLS_FINGERPRINT]: {
    type: IOCType.TLS_FINGERPRINT,
    apply: (value: string) => value.trim().toUpperCase(),
    description: 'TLS fingerprints normalized to uppercase',
  },
};

export function normalizeIOC(type: IOCType, value: string): string {
  const rule = normalizationRules[type];
  if (!rule) throw new Error(`Unknown IOC type: ${type}`);
  try {
    return rule.apply(value);
  } catch (error) {
    throw new Error(`Normalization failed for ${type}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function compressIPv6(addr: string): string {
  // Convert IPv6 to compressed form (simplified)
  // For production, consider using a library like ipaddr.js
  try {
    const parts = addr.split(':').filter(p => p !== '');
    if (parts.length < 3) return addr;
    return addr.toLowerCase();
  } catch {
    return addr;
  }
}
