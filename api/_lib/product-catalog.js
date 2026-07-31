'use strict';

class ProductCatalog {
  constructor() {
    this.products = this.initializeProductCatalog();
  }

  initializeProductCatalog() {
    return {
      // Executive Products
      'executive-brief': {
        id: 'executive-brief',
        name: 'Executive Intelligence Brief',
        category: 'executive',
        audience: 'EXECUTIVE',
        classification: 'TLP:AMBER',
        description: 'High-level threat summary for C-suite executives',
        requiredModules: ['executiveSummary', 'keyRisks', 'recommendations', 'timeline'],
        optionalModules: ['findings', 'assessments'],
        deliveryChannels: ['email', 'portal', 'pdf', 'html'],
        exportFormats: ['html', 'pdf', 'markdown', 'json'],
        reviewLevel: 'EXECUTIVE_APPROVAL',
        estimatedLength: '2-5 pages',
        targetAudience: ['CISO', 'CFO', 'COO', 'Board'],
      },
      'board-summary': {
        id: 'board-summary',
        name: 'Board Cyber Risk Summary',
        category: 'executive',
        audience: 'BOARD',
        classification: 'TLP:RED',
        description: 'Board-level cyber risk assessment and impact analysis',
        requiredModules: ['executiveSummary', 'businessImpact', 'riskMetrics', 'recommendations'],
        optionalModules: ['timeline', 'assessments'],
        deliveryChannels: ['email', 'portal', 'briefing'],
        exportFormats: ['html', 'pdf', 'markdown'],
        reviewLevel: 'EXECUTIVE_APPROVAL',
        estimatedLength: '1-3 pages',
        targetAudience: ['Board', 'CEO', 'CISO'],
      },
      'flash-alert': {
        id: 'flash-alert',
        name: 'Executive Flash Alert',
        category: 'executive',
        audience: 'EXECUTIVE',
        classification: 'TLP:AMBER',
        description: 'Urgent threat alert for immediate executive notification',
        requiredModules: ['threatSummary', 'immediateActions', 'timeline'],
        optionalModules: ['findings', 'confidence'],
        deliveryChannels: ['email', 'sms', 'portal', 'webhook'],
        exportFormats: ['html', 'json', 'text'],
        reviewLevel: 'EXPEDITED_REVIEW',
        estimatedLength: '< 1 page',
        targetAudience: ['CISO', 'CRO', 'SOC_Director'],
        timeToPublish: '< 30 minutes',
      },
      'ciso-advisory': {
        id: 'ciso-advisory',
        name: 'CISO Advisory',
        category: 'executive',
        audience: 'TECHNICAL_EXECUTIVE',
        classification: 'TLP:GREEN',
        description: 'Technical guidance for CISO decision-making',
        requiredModules: ['threatContext', 'recommendations', 'detectionGuidance', 'assessments'],
        optionalModules: ['findings', 'evidence', 'timeline'],
        deliveryChannels: ['email', 'portal', 'briefing'],
        exportFormats: ['html', 'pdf', 'markdown', 'json'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '3-8 pages',
        targetAudience: ['CISO', 'SOC_Director', 'Security_Manager'],
      },
      'strategic-assessment': {
        id: 'strategic-assessment',
        name: 'Strategic Threat Assessment',
        category: 'executive',
        audience: 'EXECUTIVE',
        classification: 'TLP:RED',
        description: 'Strategic analysis of threat landscape and implications',
        requiredModules: ['executiveSummary', 'threatLandscape', 'strategicImplications', 'longTermRecommendations'],
        optionalModules: ['timeline', 'actorProfiles', 'campaignAnalysis'],
        deliveryChannels: ['portal', 'briefing', 'pdf'],
        exportFormats: ['pdf', 'html', 'markdown'],
        reviewLevel: 'EXECUTIVE_APPROVAL',
        estimatedLength: '10-20 pages',
        targetAudience: ['CISO', 'Board', 'Enterprise_Security'],
      },

      // Technical Products
      'technical-report': {
        id: 'technical-report',
        name: 'Technical Intelligence Report',
        category: 'technical',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Detailed technical analysis for security professionals',
        requiredModules: ['findings', 'evidence', 'assessments', 'technicalDetails', 'references'],
        optionalModules: ['timeline', 'graphRelationships', 'confidenceBreakdown'],
        deliveryChannels: ['portal', 'api', 'pdf', 'html'],
        exportFormats: ['html', 'pdf', 'markdown', 'json'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-15 pages',
        targetAudience: ['Analyst', 'Threat_Hunter', 'SOC_Analyst'],
      },
      'threat-hunting-package': {
        id: 'threat-hunting-package',
        name: 'Threat Hunting Package',
        category: 'technical',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Operationalized threat hunting intelligence and queries',
        requiredModules: ['findings', 'huntingQueries', 'indicators', 'timeline'],
        optionalModules: ['assessments', 'technicalDetails', 'evidence'],
        deliveryChannels: ['api', 'portal', 'github'],
        exportFormats: ['json', 'yaml', 'markdown'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['Threat_Hunter', 'Analyst', 'SOC_Lead'],
      },
      'ir-advisory': {
        id: 'ir-advisory',
        name: 'Incident Response Advisory',
        category: 'technical',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Incident response guidance and playbooks',
        requiredModules: ['findings', 'timeline', 'irRecommendations', 'technicalContext'],
        optionalModules: ['evidence', 'assessments', 'graphRelationships'],
        deliveryChannels: ['portal', 'api', 'email'],
        exportFormats: ['html', 'json', 'markdown'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-10 pages',
        targetAudience: ['IR_Team', 'SOC_Analyst', 'Security_Manager'],
      },
      'detection-advisory': {
        id: 'detection-advisory',
        name: 'Detection Engineering Advisory',
        category: 'technical',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Detection engineering guidance for SIEM/EDR',
        requiredModules: ['findings', 'detectionStrategies', 'indicators', 'assessments'],
        optionalModules: ['evidence', 'timeline', 'confidence'],
        deliveryChannels: ['api', 'portal', 'github'],
        exportFormats: ['json', 'markdown', 'yaml'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-10 pages',
        targetAudience: ['Detection_Engineer', 'SOC_Lead', 'SIEM_Admin'],
      },
      'soc-daily-brief': {
        id: 'soc-daily-brief',
        name: 'SOC Daily Brief',
        category: 'technical',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Daily threat summary for SOC operations',
        requiredModules: ['threatSummary', 'newIndicators', 'recommendations'],
        optionalModules: ['findings', 'timeline'],
        deliveryChannels: ['email', 'portal', 'api'],
        exportFormats: ['html', 'json', 'markdown'],
        reviewLevel: 'ANALYST_REVIEW',
        estimatedLength: '1-3 pages',
        targetAudience: ['SOC_Analyst', 'SOC_Lead', 'Analyst'],
        frequency: 'DAILY',
      },

      // Detection Products
      'sigma-package': {
        id: 'sigma-package',
        name: 'Sigma Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:WHITE',
        description: 'Sigma detection rules for open detection sharing',
        requiredModules: ['indicators', 'technicalDetails', 'attackPatterns'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'github', 'portal'],
        exportFormats: ['yaml', 'json'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['Detection_Engineer', 'SIEM_Admin'],
      },
      'yara-package': {
        id: 'yara-package',
        name: 'YARA Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:WHITE',
        description: 'YARA malware detection rules',
        requiredModules: ['malwareIndicators', 'fileSignatures'],
        optionalModules: ['evidence', 'behavioralPatterns'],
        deliveryChannels: ['api', 'github', 'portal'],
        exportFormats: ['yara', 'json'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['Malware_Analyst', 'Detection_Engineer'],
      },
      'suricata-package': {
        id: 'suricata-package',
        name: 'Suricata Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:WHITE',
        description: 'Suricata IDS/IPS detection rules',
        requiredModules: ['networkIndicators', 'trafficPatterns'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'github', 'portal'],
        exportFormats: ['rules', 'json'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['IDS_Admin', 'Detection_Engineer'],
      },
      'splunk-package': {
        id: 'splunk-package',
        name: 'Splunk Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Splunk detection and correlation searches',
        requiredModules: ['indicators', 'searchStrategies'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'portal'],
        exportFormats: ['json', 'spl'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['SIEM_Admin', 'Detection_Engineer'],
      },
      'elastic-package': {
        id: 'elastic-package',
        name: 'Elastic Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Elastic Stack detection rules and queries',
        requiredModules: ['indicators', 'searchStrategies'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'portal'],
        exportFormats: ['json', 'ndjson'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['SIEM_Admin', 'Detection_Engineer'],
      },
      'sentinel-package': {
        id: 'sentinel-package',
        name: 'Microsoft Sentinel Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Microsoft Sentinel detection rules and analytics',
        requiredModules: ['indicators', 'detectionLogic'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'portal'],
        exportFormats: ['json', 'kql'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['SIEM_Admin', 'Detection_Engineer'],
      },
      'defender-package': {
        id: 'defender-package',
        name: 'Microsoft Defender Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Microsoft Defender detection and response rules',
        requiredModules: ['indicators', 'detectionLogic'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'portal'],
        exportFormats: ['json', 'kql'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['EDR_Admin', 'Detection_Engineer'],
      },
      'chronicle-package': {
        id: 'chronicle-package',
        name: 'Chronicle Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Google Chronicle detection and investigation content',
        requiredModules: ['indicators', 'detectionLogic'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'portal'],
        exportFormats: ['json', 'yql'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['SIEM_Admin', 'Detection_Engineer'],
      },
      'qradar-package': {
        id: 'qradar-package',
        name: 'QRadar Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'IBM QRadar detection rules and custom properties',
        requiredModules: ['indicators', 'detectionLogic'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'portal'],
        exportFormats: ['json', 'xml'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['SIEM_Admin', 'Detection_Engineer'],
      },
      'wazuh-package': {
        id: 'wazuh-package',
        name: 'Wazuh Package',
        category: 'detection',
        audience: 'TECHNICAL',
        classification: 'TLP:WHITE',
        description: 'Wazuh security monitoring and response rules',
        requiredModules: ['indicators', 'detectionLogic'],
        optionalModules: ['evidence', 'assessments'],
        deliveryChannels: ['api', 'github', 'portal'],
        exportFormats: ['json', 'xml'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: 'Variable',
        targetAudience: ['SIEM_Admin', 'Detection_Engineer'],
      },

      // Threat Intelligence Products
      'threat-actor-profile': {
        id: 'threat-actor-profile',
        name: 'Threat Actor Profile',
        category: 'threat-intelligence',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Comprehensive threat actor intelligence profile',
        requiredModules: ['actorOverview', 'capabilities', 'campaigns', 'attribution'],
        optionalModules: ['infrastructure', 'malware', 'timeline', 'targeting'],
        deliveryChannels: ['api', 'portal', 'pdf', 'html'],
        exportFormats: ['html', 'pdf', 'json', 'markdown', 'stix'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '10-20 pages',
        targetAudience: ['Analyst', 'Threat_Intel', 'CISO'],
      },
      'campaign-intelligence': {
        id: 'campaign-intelligence',
        name: 'Campaign Intelligence',
        category: 'threat-intelligence',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Cyber campaign analysis and tracking',
        requiredModules: ['campaignOverview', 'timeline', 'targets', 'techniques'],
        optionalModules: ['actors', 'infrastructure', 'malware'],
        deliveryChannels: ['api', 'portal', 'pdf'],
        exportFormats: ['html', 'pdf', 'json', 'markdown'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-15 pages',
        targetAudience: ['Analyst', 'Threat_Intel'],
      },
      'malware-profile': {
        id: 'malware-profile',
        name: 'Malware Profile',
        category: 'threat-intelligence',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Malware analysis and characterization',
        requiredModules: ['malwareOverview', 'capabilities', 'indicators', 'analysis'],
        optionalModules: ['samples', 'detections', 'relationships'],
        deliveryChannels: ['api', 'portal', 'pdf'],
        exportFormats: ['html', 'pdf', 'json', 'stix'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-15 pages',
        targetAudience: ['Malware_Analyst', 'Threat_Intel', 'Analyst'],
      },
      'infrastructure-profile': {
        id: 'infrastructure-profile',
        name: 'Infrastructure Profile',
        category: 'threat-intelligence',
        audience: 'TECHNICAL',
        classification: 'TLP:AMBER',
        description: 'Threat actor infrastructure analysis',
        requiredModules: ['infrastructureOverview', 'indicators', 'hosting', 'timeline'],
        optionalModules: ['relationships', 'threatActors', 'campaigns'],
        deliveryChannels: ['api', 'portal', 'json'],
        exportFormats: ['json', 'markdown', 'html'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-10 pages',
        targetAudience: ['Analyst', 'Threat_Intel', 'Incident_Responder'],
      },
      'ioc-feed': {
        id: 'ioc-feed',
        name: 'IOC Feed',
        category: 'threat-intelligence',
        audience: 'MACHINE',
        classification: 'TLP:WHITE',
        description: 'Machine-readable indicators of compromise feed',
        requiredModules: ['indicators', 'metadata', 'confidence'],
        optionalModules: ['relationships', 'context'],
        deliveryChannels: ['api', 'feed', 'portal'],
        exportFormats: ['json', 'csv', 'stix', 'taxii'],
        reviewLevel: 'ANALYST_REVIEW',
        estimatedLength: 'Variable',
        targetAudience: ['SIEM', 'EDR', 'Firewall', 'Proxy'],
      },
      'vulnerability-advisory': {
        id: 'vulnerability-advisory',
        name: 'Vulnerability Advisory',
        category: 'threat-intelligence',
        audience: 'TECHNICAL',
        classification: 'TLP:WHITE',
        description: 'Vulnerability exploitation and threat analysis',
        requiredModules: ['vulnerabilityDetails', 'threatContext', 'mitigation'],
        optionalModules: ['exploitCode', 'targets', 'timeline'],
        deliveryChannels: ['api', 'portal', 'email'],
        exportFormats: ['json', 'html', 'markdown'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '3-8 pages',
        targetAudience: ['Vulnerability_Manager', 'Analyst', 'Security_Team'],
      },
      'sector-threat-brief': {
        id: 'sector-threat-brief',
        name: 'Sector Threat Brief',
        category: 'threat-intelligence',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Threat intelligence for specific industry sectors',
        requiredModules: ['sectorOverview', 'threats', 'recommendations'],
        optionalModules: ['timeline', 'actors', 'campaigns'],
        deliveryChannels: ['api', 'portal', 'pdf'],
        exportFormats: ['html', 'pdf', 'json'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-15 pages',
        targetAudience: ['Sector_CISO', 'Threat_Intel', 'Analyst'],
      },
      'country-threat-brief': {
        id: 'country-threat-brief',
        name: 'Country Threat Brief',
        category: 'threat-intelligence',
        audience: 'TECHNICAL',
        classification: 'TLP:GREEN',
        description: 'Geopolitical threat intelligence by country',
        requiredModules: ['countryOverview', 'threats', 'actors', 'recommendations'],
        optionalModules: ['timeline', 'campaigns', 'targeting'],
        deliveryChannels: ['api', 'portal', 'pdf'],
        exportFormats: ['html', 'pdf', 'json'],
        reviewLevel: 'MANAGER_APPROVAL',
        estimatedLength: '5-15 pages',
        targetAudience: ['Threat_Intel', 'Government', 'Enterprise_CISO'],
      },

      // Machine Products
      'stix-bundle': {
        id: 'stix-bundle',
        name: 'STIX Bundle',
        category: 'machine',
        audience: 'MACHINE',
        classification: 'TLP:WHITE',
        description: 'STIX 2.1 threat intelligence bundle',
        requiredModules: ['indicators', 'relationships', 'context'],
        optionalModules: ['malware', 'campaigns', 'actors'],
        deliveryChannels: ['api', 'feed'],
        exportFormats: ['json'],
        reviewLevel: 'ANALYST_REVIEW',
        estimatedLength: 'Variable',
        targetAudience: ['STIX_Consumer', 'ThreatIntel_Platform'],
      },
      'taxii-package': {
        id: 'taxii-package',
        name: 'TAXII-ready Package',
        category: 'machine',
        audience: 'MACHINE',
        classification: 'TLP:WHITE',
        description: 'TAXII 2.1 threat intelligence distribution package',
        requiredModules: ['indicators', 'relationships'],
        optionalModules: ['context', 'metadata'],
        deliveryChannels: ['taxii', 'api'],
        exportFormats: ['json'],
        reviewLevel: 'ANALYST_REVIEW',
        estimatedLength: 'Variable',
        targetAudience: ['TAXII_Client', 'ThreatIntel_Platform'],
      },
      'json-object': {
        id: 'json-object',
        name: 'JSON Intelligence Object',
        category: 'machine',
        audience: 'MACHINE',
        classification: 'TLP:WHITE',
        description: 'Structured JSON threat intelligence object',
        requiredModules: ['data', 'metadata'],
        optionalModules: ['relationships', 'context'],
        deliveryChannels: ['api', 'feed', 'storage'],
        exportFormats: ['json'],
        reviewLevel: 'ANALYST_REVIEW',
        estimatedLength: 'Variable',
        targetAudience: ['API_Consumer', 'Automation', 'Integration'],
      },
      'markdown-package': {
        id: 'markdown-package',
        name: 'Markdown Package',
        category: 'machine',
        audience: 'TECHNICAL',
        classification: 'TLP:WHITE',
        description: 'Markdown-formatted intelligence documentation',
        requiredModules: ['content'],
        optionalModules: ['metadata', 'references'],
        deliveryChannels: ['github', 'portal', 'api'],
        exportFormats: ['markdown', 'html'],
        reviewLevel: 'ANALYST_REVIEW',
        estimatedLength: 'Variable',
        targetAudience: ['Developer', 'Documentation', 'GitHub'],
      },
      'html-package': {
        id: 'html-package',
        name: 'HTML Package',
        category: 'machine',
        audience: 'TECHNICAL',
        classification: 'TLP:WHITE',
        description: 'Standalone HTML intelligence document',
        requiredModules: ['content'],
        optionalModules: ['styling', 'references'],
        deliveryChannels: ['email', 'portal', 'web'],
        exportFormats: ['html', 'pdf'],
        reviewLevel: 'ANALYST_REVIEW',
        estimatedLength: 'Variable',
        targetAudience: ['End_User', 'Portal_User', 'Email'],
      },
    };
  }

  getProduct(productId) {
    return this.products[productId] || null;
  }

  getProductsByCategory(category) {
    return Object.values(this.products).filter(p => p.category === category);
  }

  getProductsByAudience(audience) {
    return Object.values(this.products).filter(p => p.audience === audience);
  }

  getProductsByClassification(classification) {
    return Object.values(this.products).filter(p => p.classification === classification);
  }

  getAllProducts() {
    return Object.values(this.products);
  }

  listProductCategories() {
    const categories = new Set();
    Object.values(this.products).forEach(p => categories.add(p.category));
    return Array.from(categories);
  }

  getProductsForInvestigation(investigation) {
    // Determine which products are applicable based on investigation data
    const applicableProducts = [];

    if (investigation.threatActors && investigation.threatActors.length > 0) {
      applicableProducts.push(this.getProduct('threat-actor-profile'));
    }

    if (investigation.campaigns && investigation.campaigns.length > 0) {
      applicableProducts.push(this.getProduct('campaign-intelligence'));
    }

    if (investigation.malware && investigation.malware.length > 0) {
      applicableProducts.push(this.getProduct('malware-profile'));
    }

    if (investigation.infrastructure && investigation.infrastructure.length > 0) {
      applicableProducts.push(this.getProduct('infrastructure-profile'));
    }

    if (investigation.iocs && investigation.iocs.length > 0) {
      applicableProducts.push(this.getProduct('ioc-feed'));
    }

    // Always generate core products
    applicableProducts.push(this.getProduct('technical-report'));
    applicableProducts.push(this.getProduct('executive-brief'));
    applicableProducts.push(this.getProduct('stix-bundle'));
    applicableProducts.push(this.getProduct('json-object'));

    return applicableProducts.filter(p => p !== null);
  }
}

module.exports = { ProductCatalog };
