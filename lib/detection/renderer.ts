/**
 * Detection Rule Renderer
 * Renders detection rules in multiple export formats
 */

import YAML from 'js-yaml';
import type {
  DetectionRule,
  DetectionRuleCollection,
  SigmaRule,
  YaraRule,
  SuricataRule,
  SEMRule,
  DetectionRuleExport,
  DetectionFormat,
} from './schema';
import { formatSuricataRule } from './generators/suricata';

// ============================================================================
// SIGMA YAML RENDERING
// ============================================================================

export function renderSigmaYAML(rule: SigmaRule): string {
  // Remove undefined fields
  const cleanRule = {
    title: rule.title,
    id: rule.id,
    status: rule.status,
    description: rule.description,
    author: rule.author,
    date: rule.date,
    ...(rule.modified && { modified: rule.modified }),
    logsource: rule.logsource,
    detection: rule.detection,
    ...(rule.level && { level: rule.level }),
    ...(rule.falsepositives && { falsepositives: rule.falsepositives }),
    ...(rule.references && rule.references.length > 0 && { references: rule.references }),
    ...(rule.tags && rule.tags.length > 0 && { tags: rule.tags }),
  };

  return YAML.dump(cleanRule, {
    indent: 2,
    lineWidth: 120,
  });
}

export function renderSigmaCollection(rules: DetectionRule[]): string {
  const sigmaRules = rules
    .filter(r => r.formats.sigma)
    .map(r => r.formats.sigma!)
    .map(rule => renderSigmaYAML(rule))
    .join('\n---\n');

  return sigmaRules;
}

// ============================================================================
// YARA RULE RENDERING
// ============================================================================

export function renderYaraRule(rule: YaraRule): string {
  let output = '';

  // Rule header
  output += `rule ${rule.name}\n`;

  if (rule.scope && rule.scope !== 'public') {
    output += `${rule.scope}\n`;
  }

  output += '{\n';

  // Metadata
  if (Object.keys(rule.metadata).length > 0) {
    output += '\tmeta:\n';
    for (const [key, value] of Object.entries(rule.metadata)) {
      const quotedValue = typeof value === 'string' ? `"${value}"` : value;
      output += `\t\t${key} = ${quotedValue}\n`;
    }
  }

  // Strings
  if (rule.strings.length > 0) {
    output += '\tstrings:\n';
    for (const str of rule.strings) {
      let pattern = str.pattern;

      if (str.isRegex) {
        // Already in regex format
      } else if (str.isWide) {
        pattern = `${pattern} wide`;
      } else {
        pattern = `"${pattern}"`;
      }

      let options = '';
      if (str.isCaseInsensitive) {
        options += ' nocase';
      }

      output += `\t\t${str.name} = ${pattern}${options}\n`;
    }
  }

  // Condition
  output += '\tcondition:\n';
  output += `\t\t${rule.condition}\n`;

  output += '}\n';

  return output;
}

export function renderYaraCollection(rules: DetectionRule[]): string {
  const yaraRules = rules
    .filter(r => r.formats.yara)
    .map(r => r.formats.yara!)
    .map(rule => renderYaraRule(rule))
    .join('\n');

  return yaraRules;
}

// ============================================================================
// SURICATA RULE RENDERING
// ============================================================================

export function renderSuricataCollection(rules: DetectionRule[]): string {
  const suricataLines: string[] = [];

  for (const rule of rules) {
    if (rule.formats.suricata && rule.formats.suricata.length > 0) {
      for (const sRule of rule.formats.suricata) {
        suricataLines.push(formatSuricataRule(sRule));
      }
    }
  }

  return suricataLines.join('\n');
}

// ============================================================================
// SIEM RULE RENDERING
// ============================================================================

export function renderSplunkQueries(rules: DetectionRule[]): string {
  const queries: string[] = [];

  for (const rule of rules) {
    if (rule.formats.siem) {
      for (const semRule of rule.formats.siem) {
        if (semRule.source === 'splunk') {
          const query = semRule.fields.find(f => f.name === 'search')?.value || '';
          queries.push(`# ${rule.name}\n${query}\n`);
        }
      }
    }
  }

  return queries.join('\n---\n\n');
}

export function renderELKQueries(rules: DetectionRule[]): string {
  const queries: string[] = [];

  for (const rule of rules) {
    if (rule.formats.siem) {
      for (const semRule of rule.formats.siem) {
        if (semRule.source === 'elk') {
          const query = semRule.fields.find(f => f.name === 'query')?.value || '';
          queries.push(`// ${rule.name}\n${query}`);
        }
      }
    }
  }

  return JSON.stringify({ queries }, null, 2);
}

export function renderSentinelKQL(rules: DetectionRule[]): string {
  const queries: string[] = [];

  for (const rule of rules) {
    if (rule.formats.siem) {
      for (const semRule of rule.formats.siem) {
        if (semRule.source === 'sentinel') {
          const query = semRule.fields.find(f => f.name === 'query')?.value || '';
          queries.push(`// ${rule.name}\n${query}`);
        }
      }
    }
  }

  return queries.join('\n\n// ---\n\n');
}

// ============================================================================
// MARKDOWN RENDERING
// ============================================================================

export function renderDetectionRuleMarkdown(rules: DetectionRule[]): string {
  let markdown = '# Detection Rules\n\n';

  for (const rule of rules) {
    markdown += `## ${rule.name}\n\n`;
    markdown += `**Severity:** ${rule.severity}\n\n`;
    markdown += `**Description:** ${rule.description}\n\n`;

    if (rule.metadata.linkedIOCs.length > 0) {
      markdown += `**IOCs:**\n`;
      for (const ioc of rule.metadata.linkedIOCs) {
        markdown += `- ${ioc}\n`;
      }
      markdown += '\n';
    }

    if (rule.metadata.linkedTechniques.length > 0) {
      markdown += `**MITRE ATT&CK Techniques:**\n`;
      for (const technique of rule.metadata.linkedTechniques) {
        markdown += `- ${technique}\n`;
      }
      markdown += '\n';
    }

    markdown += '---\n\n';
  }

  return markdown;
}

// ============================================================================
// UNIFIED EXPORT FUNCTION
// ============================================================================

export function renderDetectionRuleExport(
  collection: DetectionRuleCollection,
  format: DetectionFormat
): DetectionRuleExport {
  let content = '';
  let mimeType = 'text/plain';

  switch (format) {
    case 'sigma':
      content = renderSigmaCollection(collection.rules);
      mimeType = 'application/x-yaml';
      break;

    case 'yara':
      content = renderYaraCollection(collection.rules);
      mimeType = 'text/plain';
      break;

    case 'suricata':
      content = renderSuricataCollection(collection.rules);
      mimeType = 'text/plain';
      break;

    case 'splunk':
      content = renderSplunkQueries(collection.rules);
      mimeType = 'text/plain';
      break;

    case 'elk':
      content = renderELKQueries(collection.rules);
      mimeType = 'application/json';
      break;

    case 'sentinel':
      content = renderSentinelKQL(collection.rules);
      mimeType = 'text/plain';
      break;

    default:
      content = renderDetectionRuleMarkdown(collection.rules);
      mimeType = 'text/markdown';
  }

  return {
    format,
    rules: collection.rules,
    content,
    mimeType,
  };
}

// ============================================================================
// BATCH EXPORT
// ============================================================================

export function exportDetectionRuleBundle(
  collection: DetectionRuleCollection,
  formats: DetectionFormat[]
): Map<DetectionFormat, DetectionRuleExport> {
  const exports = new Map<DetectionFormat, DetectionRuleExport>();

  for (const format of formats) {
    exports.set(format, renderDetectionRuleExport(collection, format));
  }

  return exports;
}

// ============================================================================
// HTML RENDERING FOR BLOG
// ============================================================================

export function renderDetectionRuleHTML(rules: DetectionRule[]): string {
  let html = '<div class="detection-rules-container">\n';

  for (const rule of rules) {
    html += `<div class="detection-rule" data-rule-id="${rule.id}">\n`;
    html += `<h3 class="rule-name">${escapeHTML(rule.name)}</h3>\n`;
    html += `<p class="rule-severity severity-${rule.severity}">${rule.severity.toUpperCase()}</p>\n`;
    html += `<p class="rule-description">${escapeHTML(rule.description)}</p>\n`;

    // IOCs
    if (rule.metadata.linkedIOCs.length > 0) {
      html += '<div class="rule-section">\n';
      html += '<h4>Indicators of Compromise</h4>\n';
      html += '<ul class="ioc-list">\n';
      for (const ioc of rule.metadata.linkedIOCs) {
        html += `<li><code>${escapeHTML(ioc)}</code></li>\n`;
      }
      html += '</ul>\n</div>\n';
    }

    // Techniques
    if (rule.metadata.linkedTechniques.length > 0) {
      html += '<div class="rule-section">\n';
      html += '<h4>MITRE ATT&CK Techniques</h4>\n';
      html += '<ul class="technique-list">\n';
      for (const technique of rule.metadata.linkedTechniques) {
        html += `<li><a href="https://attack.mitre.org/techniques/${technique}/" target="_blank">${escapeHTML(technique)}</a></li>\n`;
      }
      html += '</ul>\n</div>\n';
    }

    // Formats available
    if (Object.keys(rule.formats).length > 0) {
      html += '<div class="rule-formats">\n';
      html += '<strong>Available formats:</strong> ';
      html += Object.keys(rule.formats).join(', ');
      html += '\n</div>\n';
    }

    html += '</div>\n';
  }

  html += '</div>\n';

  return html;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function escapeHTML(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
