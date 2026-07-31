'use strict';

const fs = require('fs');
const crypto = require('crypto');

class CustomerDeliverablesEngine {
  async generateDeliverables(product, investigation, report) {
    const deliverables = {};

    deliverables.executiveBrief = this.generateExecutiveBrief(product, investigation);
    deliverables.technicalReport = this.generateTechnicalReport(product, investigation);
    deliverables.socAdvisory = this.generateSOCAdvisory(product, investigation);
    deliverables.threatHuntingGuide = this.generateThreatHuntingGuide(product, investigation);
    deliverables.detectionPack = this.generateDetectionPack(product, investigation);
    deliverables.iocPackage = this.generateIOCPackage(product, investigation);
    deliverables.mitreMapping = this.generateMITREMapping(product, investigation);
    deliverables.executiveSlides = this.generateExecutiveSlides(product, investigation);
    deliverables.json = this.generateJSON(product, investigation);
    deliverables.stix = this.generateSTIX(product, investigation);
    deliverables.markdown = this.generateMarkdown(product, investigation);
    deliverables.html = this.generateHTML(product, investigation);
    deliverables.pdfReady = this.generatePDFReady(product, investigation);

    return {
      deliverables,
      generatedAt: new Date().toISOString(),
      formats: Object.keys(deliverables),
    };
  }

  generateExecutiveBrief(product, investigation) {
    return {
      format: 'PDF',
      title: `Executive Intelligence Brief: ${investigation.title}`,
      sections: [
        {
          title: 'Threat Overview',
          content: this.buildThreatOverview(investigation),
          pages: 1,
        },
        {
          title: 'Business Impact',
          content: this.buildBusinessImpact(investigation),
          pages: 1,
        },
        {
          title: 'Key Findings',
          content: product.modules?.keyJudgements || [],
          pages: 2,
        },
        {
          title: 'Executive Actions',
          content: product.modules?.recommendations?.executive || [],
          pages: 1,
        },
        {
          title: 'Appendix: IOCs',
          content: this.formatIOCs(investigation),
          pages: 2,
        },
      ],
      pageCount: 7,
      audience: ['CISO', 'Executive Leadership', 'Board'],
      classification: investigation.classification || 'TLP:AMBER',
    };
  }

  generateTechnicalReport(product, investigation) {
    return {
      format: 'PDF / Markdown',
      title: `Technical Intelligence Report: ${investigation.title}`,
      sections: [
        {
          title: 'Executive Summary',
          content: product.modules?.executiveSummary || {},
        },
        {
          title: 'Attack Narrative',
          content: product.modules?.narratives?.attackNarrative || {},
        },
        {
          title: 'Kill Chain Analysis',
          content: product.modules?.killChain || {},
        },
        {
          title: 'Threat Actor Profile',
          content: product.modules?.threatActorProfile || {},
        },
        {
          title: 'Campaign Analysis',
          content: product.modules?.campaignAnalysis || {},
        },
        {
          title: 'Infrastructure Analysis',
          content: product.modules?.infrastructureAnalysis || {},
        },
        {
          title: 'MITRE ATT&CK Mapping',
          content: product.modules?.mitreMapping || {},
        },
        {
          title: 'Indicators of Compromise',
          content: this.formatIOCs(investigation),
        },
        {
          title: 'Recommendations',
          content: product.modules?.recommendations || {},
        },
        {
          title: 'Appendices',
          content: this.buildAppendices(investigation),
        },
      ],
      pageCount: 30,
      audience: ['Security Analysts', 'Threat Intelligence Teams', 'Incident Response'],
      classification: investigation.classification || 'TLP:GREEN',
    };
  }

  generateSOCAdvisory(product, investigation) {
    return {
      format: 'PDF / Email',
      title: `SOC Advisory: ${investigation.title}`,
      sections: [
        {
          title: 'Situation',
          content: `Active threat detected affecting ${(investigation.victims || []).length} organizations`,
        },
        {
          title: 'Immediate Actions',
          content: (product.modules?.recommendations?.soc?.immediateActions || []).slice(0, 5),
        },
        {
          title: 'Indicators to Hunt',
          content: this.formatIOCsForHunting(investigation),
        },
        {
          title: 'Detection Rules',
          content: this.formatDetectionRules(product, investigation),
        },
        {
          title: 'Escalation Path',
          content: 'Contact CIRT if indicators detected',
        },
      ],
      estimatedReadTime: '5 minutes',
      audience: ['SOC Team'],
      urgency: 'High',
    };
  }

  generateThreatHuntingGuide(product, investigation) {
    return {
      format: 'Markdown / HTML',
      title: `Threat Hunting Guide: ${investigation.title}`,
      sections: [
        {
          title: 'Objective',
          content: `Hunt for activity from ${(investigation.threatActors || [])[0]?.name || 'threat actors'}`,
        },
        {
          title: 'Priority Techniques',
          content: (investigation.mitreTechniques || []).slice(0, 8),
        },
        {
          title: 'Hunting Queries',
          content: product.modules?.recommendations?.threatHunting?.huntingQueries || [],
        },
        {
          title: 'Expected Findings',
          content: product.modules?.recommendations?.threatHunting?.expectedFindings || [],
        },
        {
          title: 'Escalation Criteria',
          content: 'Any indicator match = escalate to IR',
        },
      ],
      estimatedDuration: '24-48 hours',
      skillLevel: 'Advanced',
      audience: ['Threat Hunters'],
    };
  }

  generateDetectionPack(product, investigation) {
    return {
      format: 'ZIP Archive',
      contents: {
        sigma_rules: {
          format: 'YAML',
          count: (investigation.mitreTechniques || []).length,
          filename: 'sigma_rules.zip',
        },
        yara_rules: {
          format: 'YARA',
          count: (investigation.malwareVariants || []).length,
          filename: 'yara_rules.zip',
        },
        suricata_rules: {
          format: 'Suricata IDS',
          count: Math.ceil((investigation.infrastructure || []).length / 2),
          filename: 'suricata_rules.txt',
        },
        elastic_rules: {
          format: 'Elastic Detection Rules',
          count: (investigation.mitreTechniques || []).length,
          filename: 'elastic_rules.ndjson',
        },
        splunk_searches: {
          format: 'SPL',
          count: (investigation.mitreTechniques || []).length,
          filename: 'splunk_searches.txt',
        },
        sentinel_rules: {
          format: 'KQL',
          count: (investigation.mitreTechniques || []).length,
          filename: 'sentinel_rules.txt',
        },
        qradar_rules: {
          format: 'QRadar Custom Rules',
          count: Math.ceil((investigation.mitreTechniques || []).length / 2),
          filename: 'qradar_rules.txt',
        },
        wazuh_rules: {
          format: 'Wazuh Rules',
          count: (investigation.mitreTechniques || []).length,
          filename: 'wazuh_rules.xml',
        },
      },
      totalRuleCount: (investigation.mitreTechniques || []).length * 8,
      audience: ['Detection Engineers', 'SOC Engineers'],
      deploymentGuide: 'included',
    };
  }

  generateIOCPackage(product, investigation) {
    const iocs = investigation.iocs || [];
    return {
      format: 'Multiple Formats',
      contents: {
        csv: {
          type: 'text/csv',
          columns: ['type', 'value', 'first_seen', 'last_seen', 'confidence', 'source'],
          rowCount: iocs.length,
          filename: 'iocs.csv',
        },
        json: {
          type: 'application/json',
          structure: iocs.slice(0, 1),
          rowCount: iocs.length,
          filename: 'iocs.json',
        },
        stix: {
          type: 'application/x-stix+json',
          version: '2.1',
          filename: 'iocs.stix.json',
        },
        misp_events: {
          type: 'application/x-misp+json',
          filename: 'iocs.misp.json',
        },
        txt: {
          type: 'text/plain',
          onePerLine: true,
          filename: 'iocs.txt',
        },
      },
      iocCounts: {
        domains: iocs.filter(i => i.type === 'Domain').length,
        ips: iocs.filter(i => i.type === 'IP').length,
        hashes: iocs.filter(i => i.type === 'File Hash').length,
        urls: iocs.filter(i => i.type === 'URL').length,
        emails: iocs.filter(i => i.type === 'Email').length,
      },
      audience: ['SOC', 'TI Teams', 'External Sharing'],
    };
  }

  generateMITREMapping(product, investigation) {
    const techniques = investigation.mitreTechniques || [];
    const tactics = [...new Set(techniques.map(t => t.tactic))];

    return {
      format: 'JSON / HTML / CSV',
      title: `MITRE ATT&CK Mapping: ${investigation.title}`,
      summary: {
        techniquesCount: techniques.length,
        tacticsCount: tactics.length,
        coverage: `${Math.round((techniques.length / 200) * 100)}% of MITRE techniques`,
      },
      tactics: tactics,
      techniques: techniques,
      detectionCoverage: this.assessMITREDetectionCoverage(investigation),
      gaps: this.identifyMITREGaps(investigation),
      visualizations: [
        { type: 'Heatmap', description: 'Tactics x Techniques' },
        { type: 'Treemap', description: 'Tactic hierarchy' },
        { type: 'Graph', description: 'Technique relationships' },
      ],
      audience: ['Blue Team', 'Red Team', 'Management'],
    };
  }

  generateExecutiveSlides(product, investigation) {
    return {
      format: 'PowerPoint (.pptx)',
      title: `Executive Briefing: ${investigation.title}`,
      slides: [
        { title: 'Cover', content: 'Title, date, classification' },
        { title: 'Situation', content: 'Attack overview and scope' },
        { title: 'Key Findings', content: 'Top 3-5 findings' },
        { title: 'Business Impact', content: 'Victims, data loss, risk' },
        { title: 'Attack Timeline', content: 'When activity occurred' },
        { title: 'Threat Actor Profile', content: 'Who, why, capabilities' },
        { title: 'Immediate Actions', content: '5 priority actions' },
        { title: 'Strategic Outlook', content: 'Expected evolution' },
        { title: 'Questions', content: 'Q&A' },
      ],
      slideCount: 9,
      estimatedDuration: '15 minutes',
      audience: ['Executives', 'Board'],
    };
  }

  generateJSON(product, investigation) {
    return {
      format: 'JSON',
      schema: {
        investigation: investigation,
        product: product,
        metadata: {
          generatedAt: new Date().toISOString(),
          format: 'JSON',
          version: '1.0',
        },
      },
      audience: ['API consumers', 'Integrations'],
      filename: `intelligence-${investigation.id}.json`,
    };
  }

  generateSTIX(product, investigation) {
    const iocs = investigation.iocs || [];
    const threatActors = investigation.threatActors || [];

    return {
      format: 'STIX 2.1 Bundle',
      objects: {
        threat_report: {
          type: 'report',
          id: `report--${crypto.randomUUID()}`,
          name: investigation.title,
          published: investigation.publishedDate || new Date().toISOString(),
        },
        indicators: iocs.map(ioc => ({
          type: 'indicator',
          pattern: this.convertToSTIXPattern(ioc),
        })),
        threat_actors: threatActors.map(actor => ({
          type: 'threat-actor',
          name: actor.name,
          aliases: actor.aliases,
        })),
      },
      audience: ['STIX consumers', 'TIP platforms'],
      filename: `intelligence-${investigation.id}.stix.json`,
    };
  }

  generateMarkdown(product, investigation) {
    return {
      format: 'Markdown',
      title: investigation.title,
      sections: [
        '# ' + investigation.title,
        '## Executive Summary',
        '## Key Findings',
        '## Attack Narrative',
        '## Threat Actor Profile',
        '## Indicators of Compromise',
        '## Recommendations',
        '## References',
      ],
      audience: ['Documentation', 'Knowledge base', 'Sharing'],
      filename: `intelligence-${investigation.id}.md`,
    };
  }

  generateHTML(product, investigation) {
    return {
      format: 'HTML5',
      title: investigation.title,
      features: [
        'Responsive design',
        'Dark mode support',
        'Interactive navigation',
        'Search functionality',
        'Print-friendly',
      ],
      sections: [
        'Executive Summary',
        'Key Findings',
        'Attack Timeline',
        'Threat Actor',
        'Infrastructure',
        'Indicators',
        'Recommendations',
      ],
      audience: ['Web browsers', 'Sharing', 'Publishing'],
      filename: `intelligence-${investigation.id}.html`,
    };
  }

  generatePDFReady(product, investigation) {
    return {
      format: 'PDF (via Markdown/HTML conversion)',
      content: {
        sections: [
          'Title Page',
          'Table of Contents',
          'Executive Summary',
          'Key Findings',
          'Attack Narrative',
          'Threat Actor Profile',
          'Infrastructure Analysis',
          'Indicators of Compromise',
          'Recommendations',
          'Appendices',
        ],
        estimatedPages: 30,
        layout: 'Professional report format',
        fonts: ['Courier New for code', 'Georgia for body text'],
      },
      audience: ['Print distribution', 'Archives', 'Formal sharing'],
      filename: `intelligence-${investigation.id}.pdf`,
    };
  }

  buildThreatOverview(investigation) {
    const threatActors = investigation.threatActors || [];
    const campaigns = investigation.campaigns || [];
    const victims = investigation.victims || [];

    return {
      summary: `${threatActors[0]?.name || 'Unknown actor'} conducting ${campaigns[0]?.name || 'targeted'} activity against ${victims.length} organizations`,
      key_points: [
        `Attribution: ${threatActors[0]?.name || 'TBD'} (confidence: ${(investigation.confidence || 0.5) * 100}%)`,
        `Victims: ${victims.length} confirmed compromised`,
        `Data Exposure: ${this.estimateDataExposure(investigation)}`,
        `Status: ${investigation.status || 'Ongoing'}`,
      ],
    };
  }

  buildBusinessImpact(investigation) {
    const victims = investigation.victims || [];
    return {
      confirmed_victims: victims.length,
      affected_industries: Object.keys(investigation.industryImpact || {}),
      geographic_scope: [...new Set(victims.map(v => v.country))],
      financial_impact: investigation.estimatedLoss || 'Unknown',
      operational_impact: 'Service disruption, data loss',
      regulatory_risk: 'High',
    };
  }

  formatIOCs(investigation) {
    const iocs = investigation.iocs || [];
    return {
      count: iocs.length,
      types: {
        domains: iocs.filter(i => i.type === 'Domain').map(i => i.value),
        ips: iocs.filter(i => i.type === 'IP').map(i => i.value),
        hashes: iocs.filter(i => i.type === 'File Hash').map(i => i.value),
        urls: iocs.filter(i => i.type === 'URL').map(i => i.value),
      },
    };
  }

  formatIOCsForHunting(investigation) {
    const iocs = investigation.iocs || [];
    return iocs.slice(0, 10).map(ioc => ({
      value: ioc.value,
      type: ioc.type,
      source: ioc.source,
      confidence: ioc.confidence,
    }));
  }

  formatDetectionRules(product, investigation) {
    return {
      sigma: (product.modules?.detectionRules?.sigma || []).slice(0, 3),
      yara: (product.modules?.detectionRules?.yara || []).slice(0, 3),
      suricata: (product.modules?.detectionRules?.suricata || []).slice(0, 3),
    };
  }

  buildAppendices(investigation) {
    return {
      sources: investigation.sources || [],
      related_reports: investigation.relatedReports || [],
      glossary: this.buildGlossary(investigation),
      timeline: investigation.events || [],
    };
  }

  buildGlossary(investigation) {
    return {
      'APT': 'Advanced Persistent Threat',
      'TTPs': 'Tactics, Techniques, and Procedures',
      'C2': 'Command and Control',
      'IOC': 'Indicator of Compromise',
      'MITRE ATT&CK': 'Knowledge base of adversary tactics and techniques',
    };
  }

  estimateDataExposure(investigation) {
    const dataTypes = investigation.dataTypesAffected || [];
    return dataTypes.length > 0 ? dataTypes.join(', ') : 'Unknown';
  }

  assessMITREDetectionCoverage(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const detectionCoverage = techniques.filter(t => investigation.detectionCapabilities?.[t]).length;
    return {
      covered: detectionCoverage,
      total: techniques.length,
      percentage: parseFloat(((detectionCoverage / techniques.length) * 100).toFixed(1)),
    };
  }

  identifyMITREGaps(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const uncovered = techniques.filter(t => !investigation.detectionCapabilities?.[t]);
    return uncovered.slice(0, 5);
  }

  convertToSTIXPattern(ioc) {
    const type = ioc.type.toLowerCase();
    if (type === 'domain') return `[domain-name:value = '${ioc.value}']`;
    if (type === 'ip') return `[ipv4-addr:value = '${ioc.value}']`;
    if (type === 'file hash') return `[file:hashes.MD5 = '${ioc.value}']`;
    if (type === 'url') return `[url:value = '${ioc.value}']`;
    return null;
  }
}

module.exports = { CustomerDeliverablesEngine };
