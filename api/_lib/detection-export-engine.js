'use strict';

class DetectionExportEngine {
  async exportSigmaRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    const rules = iocs.map(ioc => ({
      title: `Detection: ${ioc.type} - ${ioc.value}`,
      id: `${product.id}-${ioc.id}`.substring(0, 36),
      status: 'experimental',
      description: `Detect ${ioc.type}: ${ioc.value}`,
      logsource: {
        category: 'process_creation',
        product: 'windows',
      },
      detection: {
        selection: this.buildSigmaSelection(ioc),
        condition: 'selection',
      },
      falsepositives: ['Unknown'],
      level: this.mapConfidenceToLevel(ioc.confidence),
      references: [product.investigationId],
      author: product.metadata?.author || 'CYBERDUDEBIVASH',
      date: new Date().toISOString().split('T')[0],
    }));

    return rules.map(rule => this.formatYAML(rule)).join('\n---\n');
  }

  async exportYaraRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    let rules = '';

    iocs.forEach((ioc, idx) => {
      const ruleName = `${product.id.substring(0, 8)}_rule_${idx}`.toUpperCase();
      rules += `rule ${ruleName} {\n`;
      rules += `  meta:\n`;
      rules += `    description = "Detection rule for ${ioc.type}: ${ioc.value}"\n`;
      rules += `    author = "${product.metadata?.author || 'CYBERDUDEBIVASH'}"\n`;
      rules += `    date = "${new Date().toISOString().split('T')[0]}"\n`;
      rules += `    confidence = "${ioc.confidence || 'unknown'}"\n`;
      rules += `  strings:\n`;

      if (ioc.type === 'ip') {
        rules += `    $ip = "${ioc.value}"\n`;
      } else if (ioc.type === 'domain') {
        rules += `    $domain = "${ioc.value}"\n`;
      } else if (ioc.type === 'hash') {
        rules += `    $hash = "${ioc.value}"\n`;
      } else if (ioc.type === 'url') {
        rules += `    $url = "${ioc.value}"\n`;
      } else if (ioc.type === 'email') {
        rules += `    $email = "${ioc.value}"\n`;
      } else {
        rules += `    $indicator = "${ioc.value}"\n`;
      }

      rules += `  condition:\n`;
      rules += `    any of them\n`;
      rules += `}\n\n`;
    });

    return rules;
  }

  async exportSplunkQueries(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    const queries = [];

    iocs.forEach(ioc => {
      const query = this.buildSplunkQuery(ioc);
      queries.push({
        name: `Detect ${ioc.type}: ${ioc.value}`,
        query,
        description: `Search for ${ioc.type}: ${ioc.value}`,
        confidence: ioc.confidence || 'medium',
      });
    });

    return queries.map(q => {
      let str = `# Name: ${q.name}\n`;
      str += `# Description: ${q.description}\n`;
      str += `# Confidence: ${q.confidence}\n`;
      str += `# Product: ${product.productId}\n`;
      str += `# Investigation: ${product.investigationId}\n`;
      str += `\n${q.query}\n\n`;
      return str;
    }).join('---\n');
  }

  async exportElasticRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    const rules = iocs.map(ioc => ({
      name: `${product.id.substring(0, 8)}_${ioc.type}_${ioc.id.substring(0, 8)}`,
      title: `Detect ${ioc.type}: ${ioc.value}`,
      description: `Elastic detection rule for ${ioc.type}: ${ioc.value}`,
      type: 'query',
      enabled: true,
      risk_score: this.mapConfidenceToRiskScore(ioc.confidence),
      severity: this.mapConfidenceToSeverity(ioc.confidence),
      query: this.buildElasticQuery(ioc),
      references: [product.investigationId],
      author: product.metadata?.author || 'CYBERDUDEBIVASH',
      tags: product.metadata?.tags || ['detection'],
      from: 'now-24h',
      interval: '5m',
    }));

    return JSON.stringify(rules, null, 2);
  }

  async exportSentinelRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    const rules = iocs.map(ioc => ({
      displayName: `Detect ${ioc.type}: ${ioc.value}`,
      description: `Detection rule for ${ioc.type}: ${ioc.value}`,
      severity: this.mapConfidenceToSeverity(ioc.confidence),
      enabled: true,
      query: this.buildKQLQuery(ioc),
      tactics: this.extractTacticsFromProduct(product),
      techniques: this.extractTechniquesFromProduct(product),
      productFilter: 'SecurityEvent,WindowsEvent',
      queryPeriod: '1d',
      queryFrequency: '1h',
      triggerOperator: 'GreaterThan',
      triggerThreshold: 0,
      suppressionDuration: '1h',
      suppressionEnabled: false,
    }));

    return JSON.stringify(rules, null, 2);
  }

  async exportDefenderRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    const rules = iocs.map(ioc => ({
      name: `Detect_${ioc.type}_${ioc.id.substring(0, 8)}`,
      category: 'Detection',
      description: `Detection rule for ${ioc.type}: ${ioc.value}`,
      detection: this.buildDefenderDetection(ioc),
      enabled: true,
      severity: this.mapConfidenceToSeverity(ioc.confidence),
      author: product.metadata?.author || 'CYBERDUDEBIVASH',
      timestamp: new Date().toISOString(),
    }));

    return JSON.stringify(rules, null, 2);
  }

  async exportChronicleRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    const detections = iocs.map(ioc => ({
      name: `${product.id.substring(0, 8)}_${ioc.type}_detection`,
      description: `Detection for ${ioc.type}: ${ioc.value}`,
      yql: this.buildChronicleYQL(ioc),
      severity: this.mapConfidenceToSeverity(ioc.confidence),
      reference: product.investigationId,
    }));

    return JSON.stringify(detections, null, 2);
  }

  async exportQRadarRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    const rules = iocs.map(ioc => ({
      name: `Detect_${ioc.type}_IOC_${ioc.id.substring(0, 8)}`,
      enabled: true,
      type: 'EVENT',
      severity: this.mapConfidenceToQRadarSeverity(ioc.confidence),
      logic: this.buildQRadarLogic(ioc),
      description: `QRadar detection rule for ${ioc.type}: ${ioc.value}`,
      author: product.metadata?.author || 'CYBERDUDEBIVASH',
      created_date: new Date().toISOString(),
    }));

    return JSON.stringify(rules, null, 2);
  }

  async exportWazuhRules(product) {
    const iocs = product.modules?.indicators?.indicators || [];
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<ossec_config>\n';
    xml += '  <rules>\n';

    let ruleId = 100000 + Math.floor(Math.random() * 10000);

    iocs.forEach(ioc => {
      xml += `    <rule id="${ruleId}" level="${this.mapConfidenceToWazuhLevel(ioc.confidence)}" frequency="1">\n`;
      xml += `      <match>${ioc.value}</match>\n`;
      xml += `      <description>Detection: ${ioc.type} - ${ioc.value}</description>\n`;
      xml += `      <group>detected_ioc,${product.productId}</group>\n`;
      xml += `    </rule>\n`;
      ruleId++;
    });

    xml += '  </rules>\n';
    xml += '</ossec_config>\n';

    return xml;
  }

  buildSigmaSelection(ioc) {
    const selection = {};

    switch (ioc.type) {
      case 'ip':
        selection.CommandLine = ioc.value;
        break;
      case 'domain':
        selection.Destination = ioc.value;
        break;
      case 'hash':
        selection.Hashes = ioc.value;
        break;
      case 'url':
        selection.RequestURL = ioc.value;
        break;
      default:
        selection.keyword = ioc.value;
    }

    return selection;
  }

  buildSplunkQuery(ioc) {
    switch (ioc.type) {
      case 'ip':
        return `src_ip="${ioc.value}" OR dest_ip="${ioc.value}" | stats count by src_ip, dest_ip`;
      case 'domain':
        return `domain="${ioc.value}" OR dest_domain="${ioc.value}" | stats count by domain`;
      case 'hash':
        return `file_hash="${ioc.value}" OR md5="${ioc.value}" OR sha256="${ioc.value}" | stats count by file_hash`;
      case 'url':
        return `url="${ioc.value}" | stats count by url`;
      default:
        return `"${ioc.value}" | stats count`;
    }
  }

  buildElasticQuery(ioc) {
    switch (ioc.type) {
      case 'ip':
        return `network.transport: tcp AND (source.ip: "${ioc.value}" OR destination.ip: "${ioc.value}")`;
      case 'domain':
        return `dns.question.name: "${ioc.value}" OR url.domain: "${ioc.value}"`;
      case 'hash':
        return `file.hash.md5: "${ioc.value}" OR file.hash.sha256: "${ioc.value}"`;
      case 'url':
        return `url.full: "${ioc.value}"`;
      default:
        return `message: "${ioc.value}"`;
    }
  }

  buildKQLQuery(ioc) {
    switch (ioc.type) {
      case 'ip':
        return `(RemoteIP == "${ioc.value}") or (ComputerIP == "${ioc.value}")`;
      case 'domain':
        return `DestinationDnsDomain == "${ioc.value}" or ComputerName contains "${ioc.value}"`;
      case 'hash':
        return `FileHash == "${ioc.value}"`;
      default:
        return `Message contains "${ioc.value}"`;
    }
  }

  buildDefenderDetection(ioc) {
    return {
      operator: 'OR',
      conditions: [
        {
          field: this.getDefenderField(ioc.type),
          operator: 'Contains',
          value: ioc.value,
        },
      ],
    };
  }

  buildChronicleYQL(ioc) {
    return `SELECT * FROM events WHERE (${this.getChronicleField(ioc.type)} = "${ioc.value}")`;
  }

  buildQRadarLogic(ioc) {
    return `protocol.name = 'tcp' and (ipaddr(sourceip) = '${ioc.value}' or ipaddr(destinationip) = '${ioc.value}')`;
  }

  getDefenderField(type) {
    const fieldMap = {
      ip: 'RemoteIP',
      domain: 'ComputerName',
      hash: 'FileHash',
      url: 'InitiatingProcessCommandLine',
    };
    return fieldMap[type] || 'Message';
  }

  getChronicleField(type) {
    const fieldMap = {
      ip: 'source.ip',
      domain: 'network.dns.questions.name',
      hash: 'file.sha256',
      url: 'network.http.request_url',
    };
    return fieldMap[type] || 'raw_log';
  }

  mapConfidenceToLevel(confidence) {
    const map = {
      confirmed: 'stable',
      likely: 'testing',
      possible: 'experimental',
      unlikely: 'experimental',
      unsubstantiated: 'experimental',
    };
    return map[confidence] || 'experimental';
  }

  mapConfidenceToRiskScore(confidence) {
    const map = {
      confirmed: 90,
      likely: 70,
      possible: 50,
      unlikely: 30,
      unsubstantiated: 10,
    };
    return map[confidence] || 50;
  }

  mapConfidenceToSeverity(confidence) {
    const map = {
      confirmed: 'high',
      likely: 'medium',
      possible: 'low',
      unlikely: 'low',
      unsubstantiated: 'informational',
    };
    return map[confidence] || 'medium';
  }

  mapConfidenceToQRadarSeverity(confidence) {
    const map = {
      confirmed: 9,
      likely: 7,
      possible: 5,
      unlikely: 3,
      unsubstantiated: 1,
    };
    return map[confidence] || 5;
  }

  mapConfidenceToWazuhLevel(confidence) {
    const map = {
      confirmed: 12,
      likely: 9,
      possible: 6,
      unlikely: 3,
      unsubstantiated: 1,
    };
    return map[confidence] || 6;
  }

  extractTacticsFromProduct(product) {
    const techniques = product.modules?.techniques || [];
    const tactics = new Set();

    techniques.forEach(t => {
      if (t.tactic) tactics.add(t.tactic);
    });

    return Array.from(tactics);
  }

  extractTechniquesFromProduct(product) {
    const techniques = product.modules?.techniques || [];
    return techniques.map(t => t.id || t.name).filter(Boolean);
  }

  formatYAML(obj, indent = '') {
    let result = '';

    Object.keys(obj).forEach(key => {
      const value = obj[key];

      if (typeof value === 'string') {
        result += `${indent}${key}: "${value}"\n`;
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        result += `${indent}${key}: ${value}\n`;
      } else if (Array.isArray(value)) {
        result += `${indent}${key}:\n`;
        value.forEach(item => {
          result += `${indent}  - ${item}\n`;
        });
      } else if (typeof value === 'object') {
        result += `${indent}${key}:\n`;
        result += this.formatYAML(value, indent + '  ');
      }
    });

    return result;
  }
}

module.exports = { DetectionExportEngine };
