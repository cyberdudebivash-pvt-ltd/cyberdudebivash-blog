/**
 * Detection Rule Validators
 * Validates Sigma, YARA, Suricata, and SIEM rules for correctness
 */

import type {
  SigmaRule,
  YaraRule,
  SuricataRule,
  SEMRule,
  DetectionRule,
  RuleValidationResult,
  RuleValidationError,
} from './schema';
import { DetectionFormat } from './schema';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function mapSourceToFormat(source: string): DetectionFormat {
  const sourceToFormat: Record<string, DetectionFormat> = {
    'splunk': DetectionFormat.SPLUNK,
    'elk': DetectionFormat.ELK,
    'sentinel': DetectionFormat.SENTINEL,
    'arcsight': DetectionFormat.ARCSIGHT,
  };
  return sourceToFormat[source] || DetectionFormat.SPLUNK;
}

// ============================================================================
// SIGMA VALIDATION
// ============================================================================

export function validateSigmaRule(rule: SigmaRule): RuleValidationResult {
  const errors: RuleValidationError[] = [];
  const warnings: RuleValidationError[] = [];

  // Required fields
  if (!rule.title || rule.title.trim().length === 0) {
    errors.push({
      rule: rule.title || 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Missing required field: title',
      field: 'title',
      severity: 'error',
    });
  }

  if (!rule.id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(rule.id)) {
    errors.push({
      rule: rule.title || 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Invalid UUID format for rule ID',
      field: 'id',
      severity: 'error',
    });
  }

  if (!rule.description || rule.description.trim().length === 0) {
    errors.push({
      rule: rule.title || 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Missing required field: description',
      field: 'description',
      severity: 'error',
    });
  }

  if (!rule.logsource) {
    errors.push({
      rule: rule.title || 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Missing required field: logsource',
      field: 'logsource',
      severity: 'error',
    });
  } else {
    if (!rule.logsource.category && !rule.logsource.product && !rule.logsource.service) {
      warnings.push({
        rule: rule.title || 'unknown',
        format: DetectionFormat.SIGMA,
        error: 'Logsource should specify at least category, product, or service',
        field: 'logsource',
        severity: 'warning',
      });
    }
  }

  // Detection validation
  if (!rule.detection) {
    errors.push({
      rule: rule.title || 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Missing required field: detection',
      field: 'detection',
      severity: 'error',
    });
  } else {
    if (!rule.detection.condition) {
      errors.push({
        rule: rule.title || 'unknown',
        format: DetectionFormat.SIGMA,
        error: 'Detection must have a condition',
        field: 'detection.condition',
        severity: 'error',
      });
    }
  }

  // Level validation
  const validLevels = ['critical', 'high', 'medium', 'low', 'informational'];
  if (!validLevels.includes(rule.level)) {
    errors.push({
      rule: rule.title || 'unknown',
      format: DetectionFormat.SIGMA,
      error: `Invalid level: ${rule.level}`,
      field: 'level',
      severity: 'error',
    });
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// ============================================================================
// YARA VALIDATION
// ============================================================================

export function validateYaraRule(rule: YaraRule): RuleValidationResult {
  const errors: RuleValidationError[] = [];
  const warnings: RuleValidationError[] = [];

  // Rule name validation
  if (!rule.name || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(rule.name)) {
    errors.push({
      rule: rule.name || 'unknown',
      format: DetectionFormat.YARA,
      error: 'Invalid YARA rule name (must start with letter or underscore)',
      field: 'name',
      severity: 'error',
    });
  }

  // Strings validation
  if (!rule.strings || rule.strings.length === 0) {
    errors.push({
      rule: rule.name || 'unknown',
      format: DetectionFormat.YARA,
      error: 'Rule must have at least one string pattern',
      field: 'strings',
      severity: 'error',
    });
  } else {
    for (const str of rule.strings) {
      if (!str.name || !/^\$[a-zA-Z_][a-zA-Z0-9_]*$/.test(str.name)) {
        errors.push({
          rule: rule.name || 'unknown',
          format: DetectionFormat.YARA,
          error: `Invalid string name: ${str.name}`,
          field: 'strings',
          severity: 'error',
        });
      }

      if (!str.pattern || str.pattern.trim().length === 0) {
        errors.push({
          rule: rule.name || 'unknown',
          format: DetectionFormat.YARA,
          error: `String ${str.name} has no pattern`,
          field: 'strings',
          severity: 'error',
        });
      }
    }
  }

  // Condition validation
  if (!rule.condition || rule.condition.trim().length === 0) {
    errors.push({
      rule: rule.name || 'unknown',
      format: DetectionFormat.YARA,
      error: 'Rule must have a condition',
      field: 'condition',
      severity: 'error',
    });
  } else {
    // Basic condition syntax check
    const validConditionKeywords = ['all', 'any', 'of', 'them', 'at', 'in', 'and', 'or', 'not', 'true', 'false'];
    const conditionLower = rule.condition.toLowerCase();
    if (
      !validConditionKeywords.some(keyword => conditionLower.includes(keyword)) &&
      !rule.strings.some(str => conditionLower.includes(str.name))
    ) {
      warnings.push({
        rule: rule.name || 'unknown',
        format: DetectionFormat.YARA,
        error: 'Condition may be invalid (no recognized keywords or string references)',
        field: 'condition',
        severity: 'warning',
      });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// ============================================================================
// SURICATA VALIDATION
// ============================================================================

export function validateSuricataRule(rule: SuricataRule): RuleValidationResult {
  const errors: RuleValidationError[] = [];
  const warnings: RuleValidationError[] = [];

  // Action validation
  const validActions = ['alert', 'drop', 'reject', 'rejectsrc', 'pass'];
  if (!validActions.includes(rule.action)) {
    errors.push({
      rule: rule.msg || 'unknown',
      format: DetectionFormat.SURICATA,
      error: `Invalid action: ${rule.action}`,
      field: 'action',
      severity: 'error',
    });
  }

  // Protocol validation
  const validProtocols = ['tcp', 'udp', 'icmp', 'ip', 'http', 'tls'];
  if (!validProtocols.includes(rule.protocol)) {
    errors.push({
      rule: rule.msg || 'unknown',
      format: DetectionFormat.SURICATA,
      error: `Invalid protocol: ${rule.protocol}`,
      field: 'protocol',
      severity: 'error',
    });
  }

  // IP/Port validation
  if (!rule.sourceIp || rule.sourceIp === '') {
    errors.push({
      rule: rule.msg || 'unknown',
      format: DetectionFormat.SURICATA,
      error: 'Missing source IP',
      field: 'sourceIp',
      severity: 'error',
    });
  }

  if (!rule.destIp || rule.destIp === '') {
    errors.push({
      rule: rule.msg || 'unknown',
      format: DetectionFormat.SURICATA,
      error: 'Missing destination IP',
      field: 'destIp',
      severity: 'error',
    });
  }

  // Message validation
  if (!rule.msg || rule.msg.trim().length === 0) {
    errors.push({
      rule: 'unknown',
      format: DetectionFormat.SURICATA,
      error: 'Rule must have a message (msg)',
      field: 'msg',
      severity: 'error',
    });
  }

  // SID validation
  if (!rule.sid) {
    errors.push({
      rule: rule.msg || 'unknown',
      format: DetectionFormat.SURICATA,
      error: 'Rule must have a SID (signature ID)',
      field: 'sid',
      severity: 'error',
    });
  }

  // Content validation
  if (!rule.content || rule.content.length === 0) {
    warnings.push({
      rule: rule.msg || 'unknown',
      format: DetectionFormat.SURICATA,
      error: 'Rule has no content patterns (may match too broadly)',
      field: 'content',
      severity: 'warning',
    });
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// ============================================================================
// SIEM VALIDATION
// ============================================================================

export function validateSEMRule(rule: SEMRule): RuleValidationResult {
  const errors: RuleValidationError[] = [];
  const warnings: RuleValidationError[] = [];

  if (!rule.name || rule.name.trim().length === 0) {
    errors.push({
      rule: 'unknown',
      format: mapSourceToFormat(rule.source),
      error: 'Rule must have a name',
      field: 'name',
      severity: 'error',
    });
  }

  if (!rule.description || rule.description.trim().length === 0) {
    errors.push({
      rule: rule.name || 'unknown',
      format: mapSourceToFormat(rule.source),
      error: 'Rule must have a description',
      field: 'description',
      severity: 'error',
    });
  }

  if (!rule.eventType || rule.eventType.trim().length === 0) {
    errors.push({
      rule: rule.name || 'unknown',
      format: mapSourceToFormat(rule.source),
      error: 'Rule must specify eventType',
      field: 'eventType',
      severity: 'error',
    });
  }

  if (!rule.fields || rule.fields.length === 0) {
    errors.push({
      rule: rule.name || 'unknown',
      format: mapSourceToFormat(rule.source),
      error: 'Rule must have at least one field',
      field: 'fields',
      severity: 'error',
    });
  }

  if (rule.threshold) {
    if (!rule.threshold.value || rule.threshold.value <= 0) {
      errors.push({
        rule: rule.name || 'unknown',
        format: mapSourceToFormat(rule.source),
        error: 'Threshold value must be greater than 0',
        field: 'threshold.value',
        severity: 'error',
      });
    }
    if (!rule.threshold.timeWindow || rule.threshold.timeWindow.trim().length === 0) {
      errors.push({
        rule: rule.name || 'unknown',
        format: mapSourceToFormat(rule.source),
        error: 'Threshold must have a time window',
        field: 'threshold.timeWindow',
        severity: 'error',
      });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// ============================================================================
// UNIFIED DETECTION RULE VALIDATION
// ============================================================================

export function validateDetectionRule(rule: DetectionRule): RuleValidationResult {
  const errors: RuleValidationError[] = [];
  const warnings: RuleValidationError[] = [];

  if (!rule.id || rule.id.trim().length === 0) {
    errors.push({
      rule: rule.name || 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Rule must have an ID',
      field: 'id',
      severity: 'error',
    });
  }

  if (!rule.name || rule.name.trim().length === 0) {
    errors.push({
      rule: 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Rule must have a name',
      field: 'name',
      severity: 'error',
    });
  }

  if (rule.formats.sigma) {
    const sigmaValidation = validateSigmaRule(rule.formats.sigma);
    errors.push(...sigmaValidation.errors);
    warnings.push(...sigmaValidation.warnings);
  }

  if (rule.formats.yara) {
    const yaraValidation = validateYaraRule(rule.formats.yara);
    errors.push(...yaraValidation.errors);
    warnings.push(...yaraValidation.warnings);
  }

  if (rule.formats.suricata && rule.formats.suricata.length > 0) {
    for (const suricataRule of rule.formats.suricata) {
      const suricataValidation = validateSuricataRule(suricataRule);
      errors.push(...suricataValidation.errors);
      warnings.push(...suricataValidation.warnings);
    }
  }

  if (rule.formats.siem && rule.formats.siem.length > 0) {
    for (const semRule of rule.formats.siem) {
      const semValidation = validateSEMRule(semRule);
      errors.push(...semValidation.errors);
      warnings.push(...semValidation.warnings);
    }
  }

  if (!rule.metadata.linkedMalware || rule.metadata.linkedMalware.length === 0) {
    warnings.push({
      rule: rule.name || 'unknown',
      format: DetectionFormat.SIGMA,
      error: 'Rule should be linked to at least one malware family',
      field: 'metadata.linkedMalware',
      severity: 'warning',
    });
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
