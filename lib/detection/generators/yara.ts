/**
 * YARA Rule Generator
 * Generates YARA rules from file hashes and behavioral signatures
 */

import { v4 as uuidv4 } from 'uuid';
import type { YaraRule, YaraMetadata, YaraString } from '../schema';
import { RuleSeverity } from '../schema';
import type { IOCType } from '../../intelligence/schema';

// ============================================================================
// YARA RULE GENERATION
// ============================================================================

export interface YaraGeneratorOptions {
  severity?: RuleSeverity;
  scope?: 'private' | 'public';
  fileType?: 'pe' | 'elf' | 'macho' | 'text' | 'all';
}

export function generateYaraFromIOC(
  iocType: IOCType,
  iocValue: string,
  malwareName: string,
  options?: YaraGeneratorOptions
): YaraRule {
  const scope = options?.scope || 'private';
  const ruleId = uuidv4().replace(/-/g, '').substring(0, 16);
  const ruleName = generateYaraRuleName(malwareName, iocType);

  // Generate metadata
  const metadata = generateYaraMetadata(malwareName, iocType, options?.severity);

  // Generate strings based on IOC type
  const strings = generateYaraStrings(iocType, iocValue, malwareName);

  // Generate condition
  const condition = generateYaraCondition(strings);

  const rule: YaraRule = {
    name: ruleName,
    scope,
    metadata,
    strings,
    condition,
  };

  return rule;
}

// ============================================================================
// YARA RULE NAME GENERATION
// ============================================================================

function generateYaraRuleName(malwareName: string, iocType: IOCType): string {
  // YARA rule names must start with letter/underscore, contain only alphanumeric/underscore
  const sanitized = malwareName.replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 64);
  const typePrefix = iocType.replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 16);

  return `${sanitized}_${typePrefix}_${Math.random().toString(36).substring(2, 8)}`.substring(0, 128);
}

// ============================================================================
// YARA METADATA GENERATION
// ============================================================================

function generateYaraMetadata(malwareName: string, iocType: IOCType, severity?: RuleSeverity): YaraMetadata {
  const severityScore: Record<string, number> = {
    [RuleSeverity.CRITICAL]: 10,
    [RuleSeverity.HIGH]: 8,
    [RuleSeverity.MEDIUM]: 6,
    [RuleSeverity.LOW]: 4,
    [RuleSeverity.INFORMATIONAL]: 2,
  };

  return {
    author: 'SENTINEL APEX Detection Engineering',
    description: `Detection rule for ${malwareName} based on ${iocType} indicator`,
    date: new Date().toISOString().split('T')[0],
    severity: (severity && severityScore[severity]) || 6,
    tlp: 'white',
    malware_family: malwareName.toLowerCase(),
    ioc_type: iocType,
    source: 'SENTINEL APEX',
  };
}

// ============================================================================
// YARA STRING GENERATION
// ============================================================================

function generateYaraStrings(iocType: IOCType, iocValue: string, malwareName: string): YaraString[] {
  switch (iocType) {
    case 'sha256':
    case 'sha1':
    case 'md5':
      return generateHashStrings(iocType, iocValue);

    case 'domain':
    case 'ipv4':
    case 'ipv6':
      return generateNetworkStrings(iocType, iocValue, malwareName);

    case 'url':
      return generateURLStrings(iocValue);

    case 'registry':
      return generateRegistryStrings(iocValue);

    case 'file_path':
      return generateFilenameStrings(iocValue);

    case 'service':
      return generateServiceStrings(iocValue);

    case 'mutex':
      return generateMutexStrings(iocValue);

    case 'process':
      return generateNamedPipeStrings(iocValue);

    case 'user_agent':
      return generateUserAgentStrings(iocValue);

    case 'ja3':
      return generateJA3Strings(iocValue);

    default:
      return [
        {
          name: '$ioc_default',
          pattern: `"${iocValue.substring(0, 64)}"`,
          isCaseInsensitive: true,
        },
      ];
  }
}

function generateHashStrings(iocType: IOCType, hashValue: string): YaraString[] {
  // Hash-based detection typically uses imports and section signatures
  return [
    {
      name: '$hash',
      pattern: hashValue.toUpperCase(),
    },
    {
      name: '$pe_header',
      pattern: '"MZ"',
    },
  ];
}

function generateNetworkStrings(iocType: IOCType, iocValue: string, malwareName: string): YaraString[] {
  const strings: YaraString[] = [];

  // Direct string match
  strings.push({
    name: '$ioc_direct',
    pattern: `"${iocValue}"`,
    isCaseInsensitive: true,
  });

  // URL encoding variants
  if (iocType === 'domain') {
    strings.push({
      name: '$ioc_encoded',
      pattern: generateEncodedString(iocValue),
      isRegex: true,
    });

    // Subdomain pattern
    const domainParts = iocValue.split('.');
    if (domainParts.length >= 2) {
      strings.push({
        name: '$wildcard_domain',
        pattern: `/.*(${domainParts[domainParts.length - 2]}\\.${domainParts[domainParts.length - 1]})/i`,
        isRegex: true,
      });
    }
  }

  // HTTP User-Agent pattern
  strings.push({
    name: '$user_agent',
    pattern: `"User-Agent:"`,
  });

  // HTTP Host header
  strings.push({
    name: '$http_host',
    pattern: `"Host: ${iocValue}"`,
    isCaseInsensitive: true,
  });

  return strings;
}

function generateURLStrings(urlValue: string): YaraString[] {
  return [
    {
      name: '$url_full',
      pattern: `"${urlValue}"`,
    },
    {
      name: '$url_path',
      pattern: extractPathFromURL(urlValue),
    },
    {
      name: '$http_get',
      pattern: '"GET"',
    },
    {
      name: '$http_post',
      pattern: '"POST"',
    },
  ];
}

function generateRegistryStrings(registryPath: string): YaraString[] {
  // Registry paths often indicate persistence mechanisms
  const pathParts = registryPath.split('\\').filter(p => p.length > 0);
  const lastPart = pathParts[pathParts.length - 1] || 'Software';

  return [
    {
      name: '$registry_full',
      pattern: `"${registryPath}"`,
      isCaseInsensitive: true,
    },
    {
      name: '$registry_key',
      pattern: `"${lastPart}"`,
      isCaseInsensitive: true,
    },
    {
      name: '$reg_add',
      pattern: '"reg add"',
      isCaseInsensitive: true,
    },
  ];
}

function generateFilenameStrings(filename: string): YaraString[] {
  const strings: YaraString[] = [];

  strings.push({
    name: '$filename_exact',
    pattern: `"${filename}"`,
    isCaseInsensitive: true,
  });

  // Filename without extension
  const withoutExt = filename.split('.').slice(0, -1).join('.');
  if (withoutExt && withoutExt !== filename) {
    strings.push({
      name: '$filename_noext',
      pattern: `"${withoutExt}"`,
      isCaseInsensitive: true,
    });
  }

  // File extension
  const ext = filename.split('.').pop();
  if (ext) {
    strings.push({
      name: `$ext_${ext}`,
      pattern: `".${ext}"`,
      isCaseInsensitive: true,
    });
  }

  return strings;
}

function generateServiceStrings(serviceName: string): YaraString[] {
  return [
    {
      name: '$service_name',
      pattern: `"${serviceName}"`,
      isCaseInsensitive: true,
    },
    {
      name: '$service_install',
      pattern: '"ServiceDll"',
      isCaseInsensitive: true,
    },
    {
      name: '$sc_create',
      pattern: '"sc create"',
      isCaseInsensitive: true,
    },
  ];
}

function generateMutexStrings(mutexName: string): YaraString[] {
  return [
    {
      name: '$mutex_direct',
      pattern: `"${mutexName}"`,
      isCaseInsensitive: true,
    },
    {
      name: '$mutex_api',
      pattern: '"CreateMutexA"',
    },
    {
      name: '$mutex_kernel',
      pattern: '"Global\\\\"',
    },
  ];
}

function generateNamedPipeStrings(pipeName: string): YaraString[] {
  return [
    {
      name: '$pipe_name',
      pattern: `"${pipeName}"`,
      isCaseInsensitive: true,
    },
    {
      name: '$pipe_prefix',
      pattern: '"\\\\\\\\.\\\\pipe\\\\"',
    },
    {
      name: '$pipe_api',
      pattern: '"CreateNamedPipeA"',
    },
  ];
}

function generateUserAgentStrings(userAgent: string): YaraString[] {
  return [
    {
      name: '$ua_exact',
      pattern: `"${userAgent}"`,
    },
    {
      name: '$ua_fragment',
      pattern: `"${userAgent.substring(0, Math.min(32, userAgent.length))}"`,
    },
    {
      name: '$user_agent_header',
      pattern: '"User-Agent"',
    },
  ];
}

function generateJA3Strings(ja3Value: string): YaraString[] {
  return [
    {
      name: '$ja3_hash',
      pattern: `"${ja3Value}"`,
    },
    {
      name: '$tls_handshake',
      pattern: '{ 16 03 [01 03] }',
    },
  ];
}

// ============================================================================
// YARA CONDITION GENERATION
// ============================================================================

function generateYaraCondition(strings: YaraString[]): string {
  if (strings.length === 0) return 'false';
  if (strings.length === 1) return strings[0].name;

  // High-confidence detection: require multiple indicators
  const hashStrings = strings.filter(s => s.name === '$hash' || s.name === '$pe_header');
  const networkStrings = strings.filter(s => s.name.includes('$ioc') || s.name.includes('http'));
  const behaviorStrings = strings.filter(s =>
    s.name.includes('registry') || s.name.includes('service') || s.name.includes('mutex')
  );

  // Create tiered conditions
  if (hashStrings.length > 0) {
    // File-based detection
    return `all of them`;
  }

  if (networkStrings.length > 1) {
    // Network-based: require multiple network indicators
    const networkNames = networkStrings.map(s => s.name).join(' or ');
    return `(${networkNames})`;
  }

  if (behaviorStrings.length > 0) {
    // Behavior-based: at least 2 behavior indicators
    return `2 of them`;
  }

  // Default: any single indicator
  return `any of them`;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateEncodedString(value: string): string {
  // Generate regex for hex-encoded variants
  const hexEncoded = value
    .split('')
    .map(char => char.charCodeAt(0).toString(16))
    .join(' ?');
  return hexEncoded;
}

function extractPathFromURL(url: string): string {
  try {
    const urlObj = new URL(url);
    return `"${urlObj.pathname}"`;
  } catch {
    // Fallback for relative URLs
    const path = url.split('?')[0].split('#')[0];
    return `"${path}"`;
  }
}

// ============================================================================
// BATCH YARA GENERATION
// ============================================================================

export interface IOCForYaraGeneration {
  type: IOCType;
  value: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export function generateYaraRuleSet(
  malwareName: string,
  iocs: IOCForYaraGeneration[],
  options?: YaraGeneratorOptions
): YaraRule[] {
  return iocs
    .filter(ioc => ioc.confidence === 'HIGH' || ioc.confidence === 'MEDIUM')
    .map(ioc => generateYaraFromIOC(ioc.type, ioc.value, malwareName, options))
    .slice(0, 20); // Limit to 20 rules per set for performance
}
