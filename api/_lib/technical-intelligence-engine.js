'use strict';

class TechnicalIntelligenceEngine {
  constructor() {
    this.products = new Map();
  }

  async composeTechnicalThreatReport(investigation, report, qualityReview) {
    const product = {
      id: `tech-report-${report.id}`,
      productId: 'technical-threat-report',
      type: 'technical_report',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['soc', 'threat_intel', 'incident_response'],
      classification: investigation.classification || 'TLP:GREEN',
      status: 'draft',
      metadata: {
        title: `Technical Threat Report: ${investigation.title}`,
        description: 'Detailed technical analysis including IOCs, MITRE mappings, and evidence',
        createdAt: new Date().toISOString(),
      },
      modules: {
        executiveSummary: {
          threatDescription: investigation.description,
          threatActors: investigation.threatActors || [],
          campaigns: investigation.campaigns || [],
        },
        findings: investigation.findings || [],
        iocs: {
          indicators: investigation.iocs || [],
          count: (investigation.iocs || []).length,
          types: this.categorizeIOCs(investigation.iocs || []),
        },
        mitreMappings: {
          techniques: investigation.techniques || [],
          tactics: this.extractTactics(investigation.techniques || []),
        },
        attackMethodology: {
          attackMethods: investigation.attackMethods || [],
          tools: investigation.toolsUsed || [],
          malware: investigation.malware || [],
        },
        infrastructure: {
          infrastructure: investigation.infrastructure || [],
          operators: await this.identifyOperators(investigation),
        },
        timeline: investigation.timeline || [],
        references: {
          sources: investigation.sources || [],
          references: investigation.references || [],
        },
        confidence: qualityReview?.qualityScore?.overallScore || 0.5,
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-technical-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeIncidentResponseAdvisory(investigation, report) {
    const product = {
      id: `ir-advisory-${report.id}`,
      productId: 'incident-response-advisory',
      type: 'advisory',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['incident_response', 'soc'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Incident Response Advisory: ${investigation.title}`,
        description: 'Tactical guidance for incident responders and SOC teams',
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatSummary: {
          description: investigation.description,
          indicators: investigation.iocs || [],
        },
        detectionGuidance: {
          indicators: investigation.iocs || [],
          techniques: investigation.techniques || [],
          detectionStrategies: await this.buildDetectionStrategies(investigation),
        },
        responsePlaybook: await this.buildResponsePlaybook(investigation),
        forensicGuidance: await this.buildForensicGuidance(investigation),
        containmentActions: await this.buildContainmentActions(investigation),
        eradicationActions: await this.buildEradicationActions(investigation),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-technical-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeThreatHuntingGuide(investigation, report) {
    const product = {
      id: `hunting-guide-${report.id}`,
      productId: 'threat-hunting-guide',
      type: 'guide',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_hunter', 'soc'],
      classification: investigation.classification || 'TLP:GREEN',
      status: 'draft',
      metadata: {
        title: `Threat Hunting Guide: ${investigation.title}`,
        description: 'Guidance for threat hunters to proactively search for threat indicators',
        createdAt: new Date().toISOString(),
      },
      modules: {
        huntingObjectives: {
          objectives: await this.defineHuntingObjectives(investigation),
          assumptions: await this.defineHuntingAssumptions(investigation),
        },
        huntingIndicators: {
          iocs: investigation.iocs || [],
          techniques: investigation.techniques || [],
          artifacts: await this.extractHuntingArtifacts(investigation),
        },
        huntingQueries: await this.buildHuntingQueries(investigation),
        persistence: await this.identifyPersistenceMechanisms(investigation),
        timeline: investigation.timeline || [],
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-technical-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeDetectionEngineeringGuide(investigation, report) {
    const product = {
      id: `detection-guide-${report.id}`,
      productId: 'detection-engineering-guide',
      type: 'guide',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['detection_engineer', 'soc'],
      classification: investigation.classification || 'TLP:GREEN',
      status: 'draft',
      metadata: {
        title: `Detection Engineering Guide: ${investigation.title}`,
        description: 'Guidance for detection engineers to create detection rules',
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatOverview: {
          threatDescription: investigation.description,
          tactics: this.extractTactics(investigation.techniques || []),
        },
        detectionOpportunities: await this.identifyDetectionOpportunities(investigation),
        sigma: await this.buildSigmaRules(investigation),
        yara: await this.buildYaraRules(investigation),
        platformSpecific: await this.buildPlatformDetections(investigation),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-technical-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeIOCIntelligencePack(investigation, report) {
    const product = {
      id: `ioc-pack-${report.id}`,
      productId: 'ioc-intelligence-pack',
      type: 'indicator_pack',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['soc', 'automation', 'security_platform'],
      classification: 'TLP:WHITE',
      status: 'draft',
      metadata: {
        title: `IOC Intelligence Pack: ${investigation.id}`,
        description: 'Machine-readable indicators of compromise with metadata and confidence',
        createdAt: new Date().toISOString(),
      },
      modules: {
        indicators: (investigation.iocs || []).map(ioc => ({
          ...ioc,
          confidence: ioc.confidence || 0.5,
          severity: ioc.severity || 'MEDIUM',
          lastSeen: ioc.lastSeen || new Date().toISOString(),
        })),
        summary: {
          totalIndicators: (investigation.iocs || []).length,
          byType: this.categorizeIOCs(investigation.iocs || []),
          confidence: 0.65,
        },
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-technical-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeMalwareTechnicalProfile(investigation, report) {
    const product = {
      id: `malware-profile-${report.id}`,
      productId: 'malware-technical-profile',
      type: 'malware_profile',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['malware_analyst', 'soc', 'threat_intel'],
      classification: investigation.classification || 'TLP:GREEN',
      status: 'draft',
      metadata: {
        title: `Malware Technical Profile: ${investigation.title}`,
        description: 'In-depth technical analysis of malware capabilities and characteristics',
        createdAt: new Date().toISOString(),
      },
      modules: {
        malwareOverview: {
          malwareFamily: (investigation.malware || [])[0] || 'Unknown',
          aliases: await this.resolveMalwareAliases(investigation),
          type: await this.classifyMalware(investigation),
        },
        capabilities: {
          techniques: investigation.techniques || [],
          functions: await this.extractMalwareFunctions(investigation),
          capabilities: investigation.toolsUsed || [],
        },
        indicators: {
          hashes: await this.extractHashes(investigation),
          strings: await this.extractStrings(investigation),
          behaviors: await this.extractBehaviors(investigation),
        },
        infrastructure: {
          c2Servers: await this.extractC2Infrastructure(investigation),
          downloadServers: await this.extractDownloadInfrastructure(investigation),
        },
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-technical-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeInfrastructureIntelligenceReport(investigation, report) {
    const product = {
      id: `infra-report-${report.id}`,
      productId: 'infrastructure-intelligence-report',
      type: 'infrastructure_report',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel', 'infrastructure_analyst'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Infrastructure Intelligence Report: ${investigation.title}`,
        description: 'Analysis of attacker infrastructure and operational patterns',
        createdAt: new Date().toISOString(),
      },
      modules: {
        infrastructureAnalysis: {
          infrastructure: investigation.infrastructure || [],
          operators: await this.identifyOperators(investigation),
          clustering: await this.clusterInfrastructure(investigation),
        },
        operationalPatterns: {
          patterns: await this.extractOperationalPatterns(investigation),
          timeline: investigation.timeline || [],
          frequency: await this.analyzeActivityFrequency(investigation),
        },
        persistence: {
          strategies: await this.identifyPersistenceMechanisms(investigation),
          resilience: await this.assessInfrastructureResilience(investigation),
        },
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-technical-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  // Helper methods

  categorizeIOCs(iocs) {
    const types = {};
    (iocs || []).forEach(ioc => {
      types[ioc.type] = (types[ioc.type] || 0) + 1;
    });
    return types;
  }

  extractTactics(techniques) {
    const tactics = new Set();
    (techniques || []).forEach(t => {
      if (t.mitreTactic) tactics.add(t.mitreTactic);
    });
    return Array.from(tactics);
  }

  async identifyOperators(investigation) {
    return (investigation.threatActors || []).map(a => ({
      name: a.name,
      aliases: a.aliases || [],
    }));
  }

  async buildDetectionStrategies(investigation) {
    return {
      networkDetection: [
        'Monitor for C2 communications',
        'Detect data exfiltration',
        'Alert on lateral movement',
      ],
      hostDetection: [
        'Process execution patterns',
        'File system activity',
        'Registry modifications',
      ],
      userBehavior: [
        'Unusual access patterns',
        'Privilege escalation',
        'Mass file operations',
      ],
    };
  }

  async buildResponsePlaybook(investigation) {
    return {
      immediate: {
        actions: [
          'Isolate affected systems',
          'Activate incident response',
          'Begin evidence preservation',
        ],
        timeline: '0-30 minutes',
      },
      shortTerm: {
        actions: [
          'Complete forensic analysis',
          'Identify attack scope',
          'Remove malware and backdoors',
        ],
        timeline: '30 minutes - 24 hours',
      },
      longTerm: {
        actions: [
          'Harden systems',
          'Update detection rules',
          'Post-incident review',
        ],
        timeline: '24 hours+',
      },
    };
  }

  async buildForensicGuidance(investigation) {
    return {
      artifacts: await this.extractHuntingArtifacts(investigation),
      preservation: ['Capture memory', 'Preserve logs', 'Collect network traffic'],
      analysis: ['Timeline reconstruction', 'Lateral movement tracking', 'Data exfiltration analysis'],
    };
  }

  async buildContainmentActions(investigation) {
    return [
      'Network segmentation',
      'Access revocation',
      'Service shutdown',
      'Communication blocking',
    ];
  }

  async buildEradicationActions(investigation) {
    return [
      'Remove malware files',
      'Disable backdoors',
      'Reset credentials',
      'Patch vulnerabilities',
    ];
  }

  async defineHuntingObjectives(investigation) {
    return [
      `Find all evidence of ${investigation.title}`,
      'Identify lateral movement',
      'Locate data exfiltration',
    ];
  }

  async defineHuntingAssumptions(investigation) {
    return [
      'Attacker may still be present',
      'Multiple access vectors may exist',
      'Detection rules may have missed activity',
    ];
  }

  async extractHuntingArtifacts(investigation) {
    return {
      files: await this.extractFileArtifacts(investigation),
      network: await this.extractNetworkArtifacts(investigation),
      process: await this.extractProcessArtifacts(investigation),
    };
  }

  async buildHuntingQueries(investigation) {
    return {
      siem: ['Query for IOCs', 'Search for techniques', 'Lateral movement patterns'],
      endpoints: ['File hashes', 'Process names', 'Registry modifications'],
      network: ['Blocked connections', 'C2 communications', 'Data exfiltration'],
    };
  }

  async identifyPersistenceMechanisms(investigation) {
    return {
      mechanisms: investigation.persistenceMechanisms || [],
      descriptions: [],
    };
  }

  async identifyDetectionOpportunities(investigation) {
    return {
      networkDetection: [
        'Monitor for attacker C2 infrastructure',
        'Detect lateral movement',
        'Alert on data exfiltration patterns',
      ],
      endpointDetection: [
        'Malware execution',
        'Privilege escalation',
        'Persistence mechanisms',
      ],
      hunting: [
        'Historical searches for IOCs',
        'Timeline analysis',
        'Behavioral patterns',
      ],
    };
  }

  async buildSigmaRules(investigation) {
    return {
      rules: investigation.techniques?.map((t, i) => ({
        id: `sigma-rule-${i}`,
        title: `${t.name} Detection`,
        description: `Detects ${t.name} activity`,
      })) || [],
      note: 'Sigma rules can be generated from MITRE techniques',
    };
  }

  async buildYaraRules(investigation) {
    return {
      rules: (investigation.iocs || [])
        .filter(i => i.type === 'file_hash' || i.type === 'file')
        .map((i, idx) => ({
          id: `yara-rule-${idx}`,
          title: `Malware ${idx}`,
          hashes: [i.value],
        })) || [],
      note: 'YARA rules can be generated from file IOCs',
    };
  }

  async buildPlatformDetections(investigation) {
    return {
      splunk: [],
      elastic: [],
      sentinel: [],
      chronicle: [],
    };
  }

  async resolveMalwareAliases(investigation) {
    return (investigation.malware || [])[0]?.aliases || [];
  }

  async classifyMalware(investigation) {
    return 'Trojan';
  }

  async extractMalwareFunctions(investigation) {
    return investigation.techniques || [];
  }

  async extractHashes(investigation) {
    return (investigation.iocs || []).filter(i => i.type && i.type.includes('hash'));
  }

  async extractStrings(investigation) {
    return [];
  }

  async extractBehaviors(investigation) {
    return investigation.techniques || [];
  }

  async extractC2Infrastructure(investigation) {
    return investigation.infrastructure?.filter(i => i.type === 'c2') || [];
  }

  async extractDownloadInfrastructure(investigation) {
    return investigation.infrastructure?.filter(i => i.type === 'hosting') || [];
  }

  async clusterInfrastructure(investigation) {
    return {
      clusters: [],
      analysis: 'Infrastructure clustering identifies related infrastructure',
    };
  }

  async extractOperationalPatterns(investigation) {
    return {
      timezone: 'UTC',
      activityHours: '24/7',
      operatingPattern: 'Continuous',
    };
  }

  async analyzeActivityFrequency(investigation) {
    return {
      campaigns: 'Ongoing',
      deployments: 'Regular',
      updates: 'Periodic',
    };
  }

  async assessInfrastructureResilience(investigation) {
    return {
      redundancy: 'High',
      backupInfrastructure: true,
      recoverability: 'High',
    };
  }

  async extractFileArtifacts(investigation) {
    return (investigation.iocs || []).filter(i => i.type && i.type.includes('file'));
  }

  async extractNetworkArtifacts(investigation) {
    return (investigation.iocs || []).filter(i => ['ip', 'domain', 'url'].includes(i.type));
  }

  async extractProcessArtifacts(investigation) {
    return [];
  }

  getProduct(productId) {
    return this.products.get(productId);
  }

  getAllProducts() {
    return Array.from(this.products.values());
  }
}

module.exports = { TechnicalIntelligenceEngine };
