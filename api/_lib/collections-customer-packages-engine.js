'use strict';

class CollectionsCustomerPackagesEngine {
  constructor() {
    this.collections = new Map();
    this.packages = new Map();
  }

  async buildIntelligenceCollections(products) {
    const collections = [
      await this.buildRansomwareCollection(products),
      await this.buildPhishingCollection(products),
      await this.buildCloudThreatCollection(products),
      await this.buildAISecurityCollection(products),
      await this.buildSupplyChainCollection(products),
      await this.buildZeroDayCollection(products),
      await this.buildThreatActorCollection(products),
    ];

    collections.forEach(c => {
      if (c) this.collections.set(c.id, c);
    });

    return collections.filter(c => c !== null);
  }

  async buildRansomwareCollection(products) {
    return {
      id: 'ransomware-intelligence-collection',
      type: 'collection',
      title: 'Ransomware Intelligence Collection',
      description: 'Curated collection of intelligence related to ransomware threats',
      audience: ['soc', 'executive', 'threat_intel'],
      tags: ['ransomware', 'extortion', 'encryption'],
      status: 'maintained',
      productIds: products
        .filter(p => p.productId && (p.productId.includes('threat-actor') || p.productId.includes('campaign') || p.productId.includes('malware')))
        .map(p => p.id)
        .slice(0, 10),
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        productCount: 0,
      },
    };
  }

  async buildPhishingCollection(products) {
    return {
      id: 'phishing-intelligence-collection',
      type: 'collection',
      title: 'Phishing Intelligence Collection',
      description: 'Curated collection of intelligence related to phishing and social engineering',
      audience: ['soc', 'executive', 'security_awareness'],
      tags: ['phishing', 'social_engineering', 'credential_theft'],
      status: 'maintained',
      productIds: products
        .filter(p => p.productId && (p.productId.includes('threat-actor') || p.productId.includes('campaign')))
        .map(p => p.id)
        .slice(0, 10),
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        productCount: 0,
      },
    };
  }

  async buildCloudThreatCollection(products) {
    return {
      id: 'cloud-threat-intelligence-collection',
      type: 'collection',
      title: 'Cloud Threat Intelligence Collection',
      description: 'Curated collection of intelligence related to cloud security threats',
      audience: ['cloud_security', 'soc', 'threat_intel'],
      tags: ['cloud', 'aws', 'azure', 'gcp', 'misconfiguration'],
      status: 'maintained',
      productIds: products
        .filter(p => p.sector === 'technology' || (p.productId && p.productId.includes('infrastructure')))
        .map(p => p.id)
        .slice(0, 10),
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        productCount: 0,
      },
    };
  }

  async buildAISecurityCollection(products) {
    return {
      id: 'ai-security-intelligence-collection',
      type: 'collection',
      title: 'AI Security Intelligence Collection',
      description: 'Curated collection of intelligence related to AI security threats',
      audience: ['ai_security', 'threat_intel', 'research'],
      tags: ['ai', 'llm', 'ml', 'adversarial'],
      status: 'maintained',
      productIds: [],
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        productCount: 0,
      },
    };
  }

  async buildSupplyChainCollection(products) {
    return {
      id: 'supply-chain-intelligence-collection',
      type: 'collection',
      title: 'Supply Chain Intelligence Collection',
      description: 'Curated collection of intelligence related to supply chain threats',
      audience: ['supply_chain', 'executive', 'procurement'],
      tags: ['supply_chain', 'third_party', 'vendor'],
      status: 'maintained',
      productIds: products
        .filter(p => p.productId && (p.productId.includes('threat-actor') || p.productId.includes('campaign')))
        .map(p => p.id)
        .slice(0, 10),
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        productCount: 0,
      },
    };
  }

  async buildZeroDayCollection(products) {
    return {
      id: 'zero-day-intelligence-collection',
      type: 'collection',
      title: 'Zero-Day Intelligence Collection',
      description: 'Curated collection of intelligence related to zero-day vulnerabilities',
      audience: ['soc', 'threat_intel', 'security_architect'],
      tags: ['zero_day', 'vulnerability', 'exploitation'],
      status: 'maintained',
      productIds: products
        .filter(p => p.productId && p.productId.includes('vulnerability'))
        .map(p => p.id)
        .slice(0, 10),
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        productCount: 0,
      },
    };
  }

  async buildThreatActorCollection(products) {
    return {
      id: 'threat-actor-collection',
      type: 'collection',
      title: 'Threat Actor Collections',
      description: 'Curated collection of threat actor intelligence',
      audience: ['threat_intel', 'executive', 'soc'],
      tags: ['threat_actor', 'attribution', 'targeting'],
      status: 'maintained',
      productIds: products
        .filter(p => p.productId && (
          p.productId.includes('threat-actor') ||
          p.productId.includes('campaign') ||
          p.productId.includes('infrastructure')
        ))
        .map(p => p.id)
        .slice(0, 20),
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        productCount: 0,
      },
    };
  }

  async buildCustomerIntelligencePackages(investigation, report, allProducts) {
    const packages = [
      await this.buildCISOPackage(investigation, report, allProducts),
      await this.buildSOCTeamPackage(investigation, report, allProducts),
      await this.buildThreatIntelPackage(investigation, report, allProducts),
      await this.buildIncidentResponsePackage(investigation, report, allProducts),
      await this.buildExecutivePackage(investigation, report, allProducts),
      await this.buildSecurityArchitectPackage(investigation, report, allProducts),
      await this.buildMSSPPackage(investigation, report, allProducts),
    ];

    packages.forEach(p => {
      if (p) this.packages.set(p.id, p);
    });

    return packages.filter(p => p !== null);
  }

  async buildCISOPackage(investigation, report, allProducts) {
    return {
      id: `ciso-package-${report.id}`,
      productId: 'ciso-package',
      type: 'customer_package',
      role: 'ciso',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['ciso'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `CISO Package: ${investigation.title}`,
        description: 'Customized intelligence package for CISOs with business impact and strategic recommendations',
        createdAt: new Date().toISOString(),
      },
      modules: {
        executiveSummary: {
          threatDescription: investigation.description,
          businessImpact: await this.extractBusinessImpact(investigation),
          strategicRecommendations: await this.buildStrategicRecommendations(investigation),
        },
        riskAssessment: {
          risks: investigation.findings?.slice(0, 5) || [],
          riskMetrics: await this.buildRiskMetrics(investigation),
        },
        products: allProducts
          .filter(p => ['executive-brief', 'board-summary', 'threat-actor-dossier', 'capability-assessment'].includes(p.productId))
          .map(p => ({ id: p.id, productId: p.productId, title: p.metadata?.title }))
          .slice(0, 10),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-customer-packages',
      },
    };
  }

  async buildSOCTeamPackage(investigation, report, allProducts) {
    return {
      id: `soc-package-${report.id}`,
      productId: 'soc-team-package',
      type: 'customer_package',
      role: 'soc',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['soc'],
      classification: investigation.classification || 'TLP:GREEN',
      status: 'draft',
      metadata: {
        title: `SOC Team Package: ${investigation.title}`,
        description: 'Customized intelligence package for SOC teams with technical details and detection rules',
        createdAt: new Date().toISOString(),
      },
      modules: {
        technicalsummary: {
          iocs: investigation.iocs || [],
          techniques: investigation.techniques || [],
          attackMethods: investigation.attackMethods || [],
        },
        detectionGuidance: await this.buildSOCDetectionGuidance(investigation),
        responsePlaybook: await this.buildResponsePlaybook(investigation),
        products: allProducts
          .filter(p => ['technical-threat-report', 'ioc-intelligence-pack', 'threat-hunting-guide', 'detection-engineering-guide'].includes(p.productId))
          .map(p => ({ id: p.id, productId: p.productId, title: p.metadata?.title }))
          .slice(0, 10),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-customer-packages',
      },
    };
  }

  async buildThreatIntelPackage(investigation, report, allProducts) {
    return {
      id: `threat-intel-package-${report.id}`,
      productId: 'threat-intel-package',
      type: 'customer_package',
      role: 'threat_intel',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['threat_intel'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Threat Intelligence Team Package: ${investigation.title}`,
        description: 'Customized intelligence package for threat intelligence teams with deep analysis',
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatActorIntelligence: {
          actors: investigation.threatActors || [],
          campaigns: investigation.campaigns || [],
        },
        detailedAnalysis: await this.buildDetailedAnalysis(investigation),
        products: allProducts
          .filter(p => ['threat-actor-dossier', 'campaign-portfolio', 'infrastructure-map', 'capability-assessment'].includes(p.productId))
          .map(p => ({ id: p.id, productId: p.productId, title: p.metadata?.title }))
          .slice(0, 10),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-customer-packages',
      },
    };
  }

  async buildIncidentResponsePackage(investigation, report, allProducts) {
    return {
      id: `ir-package-${report.id}`,
      productId: 'incident-response-package',
      type: 'customer_package',
      role: 'incident_response',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['incident_response'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Incident Response Team Package: ${investigation.title}`,
        description: 'Customized intelligence package for incident response teams with tactical guidance',
        createdAt: new Date().toISOString(),
      },
      modules: {
        tacticalGuidance: await this.buildTacticalGuidance(investigation),
        containmentActions: await this.buildContainmentActions(investigation),
        products: allProducts
          .filter(p => ['incident-response-advisory', 'threat-hunting-guide', 'detection-engineering-guide'].includes(p.productId))
          .map(p => ({ id: p.id, productId: p.productId, title: p.metadata?.title }))
          .slice(0, 10),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-customer-packages',
      },
    };
  }

  async buildExecutivePackage(investigation, report, allProducts) {
    return {
      id: `executive-package-${report.id}`,
      productId: 'executive-package',
      type: 'customer_package',
      role: 'executive',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['executive'],
      classification: investigation.classification || 'TLP:RED',
      status: 'draft',
      metadata: {
        title: `Executive Package: ${investigation.title}`,
        description: 'Customized intelligence package for executives with business focus',
        createdAt: new Date().toISOString(),
      },
      modules: {
        executiveSummary: {
          threatDescription: investigation.description,
          businessImpact: await this.extractBusinessImpact(investigation),
          boardRecommendations: await this.buildBoardRecommendations(investigation),
        },
        products: allProducts
          .filter(p => ['executive-threat-brief', 'board-cyber-risk-brief', 'industry-executive-advisory', 'critical-threat-alert'].includes(p.productId))
          .map(p => ({ id: p.id, productId: p.productId, title: p.metadata?.title }))
          .slice(0, 10),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-customer-packages',
      },
    };
  }

  async buildSecurityArchitectPackage(investigation, report, allProducts) {
    return {
      id: `architect-package-${report.id}`,
      productId: 'security-architect-package',
      type: 'customer_package',
      role: 'security_architect',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['security_architect'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Security Architect Package: ${investigation.title}`,
        description: 'Customized intelligence package for security architects with technical depth',
        createdAt: new Date().toISOString(),
      },
      modules: {
        architecturalAnalysis: await this.buildArchitecturalAnalysis(investigation),
        defenseStrategies: await this.buildDefenseStrategies(investigation),
        products: allProducts
          .filter(p => ['technical-threat-report', 'infrastructure-intelligence-report', 'detection-engineering-guide'].includes(p.productId))
          .map(p => ({ id: p.id, productId: p.productId, title: p.metadata?.title }))
          .slice(0, 10),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-customer-packages',
      },
    };
  }

  async buildMSSPPackage(investigation, report, allProducts) {
    return {
      id: `mssp-package-${report.id}`,
      productId: 'mssp-package',
      type: 'customer_package',
      role: 'mssp',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['mssp'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `MSSP Package: ${investigation.title}`,
        description: 'Customized intelligence package for MSSPs with multi-tenant considerations',
        createdAt: new Date().toISOString(),
      },
      modules: {
        clientDeliverables: await this.buildMSSPDeliverables(investigation),
        impactAssessment: await this.buildMSSPImpactAssessment(investigation),
        products: allProducts
          .slice(0, 15)
          .map(p => ({ id: p.id, productId: p.productId, title: p.metadata?.title })),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-customer-packages',
      },
    };
  }

  // Helper methods

  async extractBusinessImpact(investigation) {
    return {
      affectedSystems: investigation.affectedSystems || [],
      exposure: investigation.affectedUserCount || 'Unknown',
      impact: investigation.businessImpact || 'Potential data breach',
    };
  }

  async buildStrategicRecommendations(investigation) {
    return [
      'Enhance threat intelligence capabilities',
      'Implement layered defense strategy',
      'Establish incident response procedures',
    ];
  }

  async buildRiskMetrics(investigation) {
    return {
      overallRisk: investigation.severity || 'MEDIUM',
      confidentiality: investigation.riskLevel?.confidentiality || 'MEDIUM',
      integrity: investigation.riskLevel?.integrity || 'MEDIUM',
      availability: investigation.riskLevel?.availability || 'MEDIUM',
    };
  }

  async buildSOCDetectionGuidance(investigation) {
    return {
      techniques: investigation.techniques || [],
      iocs: investigation.iocs?.slice(0, 20) || [],
      queries: [],
    };
  }

  async buildResponsePlaybook(investigation) {
    return {
      phases: ['Detection', 'Analysis', 'Containment', 'Eradication', 'Recovery'],
    };
  }

  async buildDetailedAnalysis(investigation) {
    return {
      threatActors: investigation.threatActors || [],
      campaigns: investigation.campaigns || [],
      relationships: [],
    };
  }

  async buildTacticalGuidance(investigation) {
    return {
      indicators: investigation.iocs?.slice(0, 20) || [],
      techniques: investigation.techniques || [],
    };
  }

  async buildContainmentActions(investigation) {
    return ['Isolate affected systems', 'Block IOCs', 'Reset credentials'];
  }

  async buildBoardRecommendations(investigation) {
    return [
      'Ensure cyber insurance coverage',
      'Establish incident response governance',
      'Allocate budget for security improvements',
    ];
  }

  async buildArchitecturalAnalysis(investigation) {
    return {
      gaps: await this.identifyArchitecturalGaps(investigation),
      recommendations: [],
    };
  }

  async buildDefenseStrategies(investigation) {
    return {
      preventionMeasures: [],
      detectionMeasures: [],
      responseStrategies: [],
    };
  }

  async identifyArchitecturalGaps(investigation) {
    return [];
  }

  async buildMSSPDeliverables(investigation) {
    return {
      clientReports: [],
      briefings: [],
      trainingSessions: [],
    };
  }

  async buildMSSPImpactAssessment(investigation) {
    return {
      affectedClients: 0,
      commonThreats: [],
      recommendations: [],
    };
  }

  getCollection(collectionId) {
    return this.collections.get(collectionId);
  }

  getPackage(packageId) {
    return this.packages.get(packageId);
  }

  getAllCollections() {
    return Array.from(this.collections.values());
  }

  getAllPackages() {
    return Array.from(this.packages.values());
  }
}

module.exports = { CollectionsCustomerPackagesEngine };
