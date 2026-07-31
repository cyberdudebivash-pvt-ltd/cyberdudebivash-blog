'use strict';

class SectorRegionalIntelligenceEngine {
  constructor() {
    this.products = new Map();
    this.sectorContext = this.initializeSectorContext();
    this.regionContext = this.initializeRegionContext();
  }

  initializeSectorContext() {
    return {
      'financial-services': {
        name: 'Financial Services',
        risks: ['Fraud', 'Data theft', 'System disruption'],
        regulations: ['PCI-DSS', 'SOX', 'GDPR'],
        priorities: ['Confidentiality', 'Availability'],
      },
      'healthcare': {
        name: 'Healthcare',
        risks: ['Patient data breach', 'System downtime', 'Ransomware'],
        regulations: ['HIPAA', 'GDPR'],
        priorities: ['Availability', 'Integrity'],
      },
      'government': {
        name: 'Government',
        risks: ['Espionage', 'Critical infrastructure', 'National security'],
        regulations: ['NIST', 'FedRAMP'],
        priorities: ['Confidentiality', 'Availability'],
      },
      'critical-infrastructure': {
        name: 'Critical Infrastructure',
        risks: ['Physical damage', 'Availability', 'Safety'],
        regulations: ['NERC', 'CISA'],
        priorities: ['Availability', 'Integrity'],
      },
      'manufacturing': {
        name: 'Manufacturing',
        risks: ['IP theft', 'Production disruption', 'Supply chain'],
        regulations: ['ITAR', 'EAR'],
        priorities: ['Confidentiality', 'Availability'],
      },
      'retail': {
        name: 'Retail',
        risks: ['Payment fraud', 'Customer data', 'Inventory'],
        regulations: ['PCI-DSS', 'GDPR'],
        priorities: ['Confidentiality', 'Integrity'],
      },
      'technology': {
        name: 'Technology',
        risks: ['Supply chain', 'IP theft', 'Customer data'],
        regulations: ['GDPR', 'Various sector-specific'],
        priorities: ['Confidentiality', 'Availability'],
      },
      'telecommunications': {
        name: 'Telecommunications',
        risks: ['Network disruption', 'Data breach', 'Espionage'],
        regulations: ['CALEA', 'GDPR'],
        priorities: ['Availability', 'Confidentiality'],
      },
      'energy': {
        name: 'Energy',
        risks: ['Grid disruption', 'Safety', 'Critical infrastructure'],
        regulations: ['NERC', 'CISA'],
        priorities: ['Availability', 'Safety'],
      },
      'education': {
        name: 'Education',
        risks: ['Student data', 'Research theft', 'System availability'],
        regulations: ['FERPA', 'GDPR'],
        priorities: ['Confidentiality', 'Availability'],
      },
    };
  }

  initializeRegionContext() {
    return {
      'north-america': {
        name: 'North America',
        countries: ['USA', 'Canada', 'Mexico'],
        regulations: ['NIST', 'GDPR', 'PIPEDA'],
      },
      'europe': {
        name: 'Europe',
        countries: ['UK', 'Germany', 'France', 'Netherlands'],
        regulations: ['GDPR', 'NIS Directive'],
      },
      'middle-east': {
        name: 'Middle East',
        countries: ['UAE', 'Saudi Arabia', 'Israel'],
        regulations: ['Local regulations'],
      },
      'africa': {
        name: 'Africa',
        countries: ['South Africa', 'Egypt', 'Kenya'],
        regulations: ['POPIA', 'Local regulations'],
      },
      'asia-pacific': {
        name: 'Asia-Pacific',
        countries: ['China', 'India', 'Australia', 'Japan'],
        regulations: ['PDPA', 'APPI', 'Cyber security law'],
      },
      'latin-america': {
        name: 'Latin America',
        countries: ['Brazil', 'Mexico', 'Argentina'],
        regulations: ['LGPD', 'GDPR', 'Local regulations'],
      },
    };
  }

  async composeSectorIntelligence(investigation, report, sector) {
    if (!investigation.targetedSectors?.includes(sector)) return null;

    const sectorInfo = this.sectorContext[sector];
    const product = {
      id: `sector-intelligence-${sector}-${report.id}`,
      productId: `sector-intelligence-${sector}`,
      type: 'sector_intelligence',
      investigationId: investigation.id,
      reportId: report.id,
      sector,
      audience: ['executive', 'ciso', 'industry_peers'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `${sectorInfo.name} Threat Intelligence`,
        description: `Threat landscape, targeting, and recommendations for the ${sectorInfo.name} sector`,
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatLandscape: {
          description: investigation.description,
          threatLevel: investigation.severity || 'MEDIUM',
          sectorContext: sectorInfo,
        },
        sectorSpecificRisks: {
          primaryRisks: sectorInfo.risks,
          applicableThreats: await this.extractSectorSpecificThreats(investigation, sector),
          targeting: investigation.targetedSectors?.includes(sector),
        },
        regulatoryCompliance: {
          regulations: sectorInfo.regulations,
          complianceImpact: await this.assessComplianceImpact(investigation, sector),
          reportingRequirements: await this.identifyReportingRequirements(sector),
        },
        recommendations: await this.buildSectorRecommendations(investigation, sector),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-sector-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeRegionalIntelligence(investigation, report, region) {
    if (!investigation.targetedRegions?.includes(region)) return null;

    const regionInfo = this.regionContext[region];
    const product = {
      id: `regional-intelligence-${region}-${report.id}`,
      productId: `regional-intelligence-${region}`,
      type: 'regional_intelligence',
      investigationId: investigation.id,
      reportId: report.id,
      region,
      audience: ['regional_teams', 'executive', 'soc'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `${regionInfo.name} Threat Intelligence`,
        description: `Regional threat landscape, infrastructure, and targeting analysis for ${regionInfo.name}`,
        createdAt: new Date().toISOString(),
      },
      modules: {
        regionalThreatLandscape: {
          region: regionInfo,
          threatLevel: investigation.severity || 'MEDIUM',
          activeThreats: await this.extractRegionalThreats(investigation, region),
        },
        targeting: {
          targetedCountries: regionInfo.countries,
          victimCount: investigation.affectedUserCount || 'Unknown',
          sectors: investigation.targetedSectors || [],
        },
        infrastructure: {
          regionalInfrastructure: await this.extractRegionalInfrastructure(investigation, region),
          operators: investigation.threatActors || [],
        },
        recommendations: await this.buildRegionalRecommendations(investigation, region),
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-regional-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  // Helper methods

  async extractSectorSpecificThreats(investigation, sector) {
    const findings = investigation.findings || [];
    const sectorContext = this.sectorContext[sector];

    return findings
      .filter(f => {
        const isRelevant = sectorContext.risks.some(risk =>
          f.statement?.toLowerCase().includes(risk.toLowerCase())
        );
        return isRelevant || f.severity === 'critical';
      })
      .slice(0, 5);
  }

  async extractRegionalThreats(investigation, region) {
    return (investigation.findings || [])
      .filter(f => f.severity === 'high' || f.severity === 'critical')
      .slice(0, 5);
  }

  async assessComplianceImpact(investigation, sector) {
    const sectorInfo = this.sectorContext[sector];
    return {
      applicableRegulations: sectorInfo.regulations,
      breachNotification: investigation.severity === 'CRITICAL',
      timeline: '72 hours',
    };
  }

  async identifyReportingRequirements(sector) {
    const requirements = {
      'financial-services': ['Regulators', 'SEC', 'Customers'],
      'healthcare': ['HHS', 'State AG', 'Patients'],
      'government': ['CISA', 'NSA', 'Congressional'],
      'critical-infrastructure': ['CISA', 'Sector coordinator'],
      'manufacturing': ['FBI', 'Customers'],
      'retail': ['State AG', 'Customers', 'PCI'],
      'technology': ['Customers', 'Regulators'],
      'telecommunications': ['FCC', 'CISA', 'Customers'],
      'energy': ['NERC', 'CISA'],
      'education': ['Authorities', 'Students', 'Parents'],
    };

    return requirements[sector] || [];
  }

  async buildSectorRecommendations(investigation, sector) {
    const sectorInfo = this.sectorContext[sector];
    return {
      immediate: [
        `Review ${sectorInfo.name} specific risks`,
        'Assess compliance requirements',
        'Alert industry peers if appropriate',
      ],
      shortTerm: [
        'Deploy sector-specific detection rules',
        'Brief sector leadership',
        'Coordinate with sector peers',
      ],
      strategic: [
        'Develop sector-specific defense strategy',
        'Establish information sharing',
        'Invest in sector-specific tools',
      ],
    };
  }

  async extractRegionalInfrastructure(investigation, region) {
    return (investigation.infrastructure || [])
      .filter(infra => {
        const regionCountries = this.regionContext[region].countries;
        return infra.location && regionCountries.some(c => infra.location.includes(c));
      });
  }

  async buildRegionalRecommendations(investigation, region) {
    const regionInfo = this.regionContext[region];
    return {
      immediate: [
        `Alert organizations in ${regionInfo.name}`,
        'Share indicators with regional ISACs',
        'Coordinate with regional authorities',
      ],
      shortTerm: [
        'Deploy regional threat indicators',
        'Brief regional security community',
      ],
      strategic: [
        'Build regional threat intelligence sharing',
        'Establish regional coordination',
      ],
    };
  }

  getProduct(productId) {
    return this.products.get(productId);
  }

  getAllProducts() {
    return Array.from(this.products.values());
  }

  getSectorProducts(sector) {
    return Array.from(this.products.values()).filter(p => p.sector === sector);
  }

  getRegionalProducts(region) {
    return Array.from(this.products.values()).filter(p => p.region === region);
  }
}

module.exports = { SectorRegionalIntelligenceEngine };
