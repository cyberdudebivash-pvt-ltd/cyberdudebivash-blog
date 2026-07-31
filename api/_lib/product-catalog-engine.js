'use strict';

class ProductCatalogEngine {
  constructor() {
    this.products = new Map();
    this.collections = new Map();
    this.initializeCatalog();
  }

  initializeCatalog() {
    this.registerExecutiveIntelligenceSeries();
    this.registerTechnicalIntelligenceSeries();
    this.registerThreatActorIntelligence();
    this.registerSectorIntelligence();
    this.registerRegionalIntelligence();
    this.registerVulnerabilityIntelligence();
    this.registerDetectionIntelligence();
    this.registerIntelligenceCollections();
    this.registerCustomerIntelligencePackages();
  }

  registerExecutiveIntelligenceSeries() {
    const products = [
      {
        id: 'executive-threat-brief',
        type: 'executive_brief',
        title: 'Executive Threat Brief',
        description: 'Business-focused threat summary for C-level decision-making',
        audience: ['executive', 'ciso', 'cto'],
        requiredInputs: ['investigation', 'report', 'qualityReview'],
        publicationRules: {
          minConfidence: 0.6,
          requiresApproval: true,
          classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'],
        },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, superseded: true, retired: true },
        version: '1.0',
        compositionStrategy: 'executive_summary_from_findings',
      },
      {
        id: 'board-cyber-risk-brief',
        type: 'executive_brief',
        title: 'Board Cyber Risk Brief',
        description: 'Board-level cyber risk assessment and governance implications',
        audience: ['board', 'executive', 'ciso'],
        requiredInputs: ['investigation', 'report', 'qualityReview', 'businessImpact'],
        publicationRules: {
          minConfidence: 0.7,
          requiresApproval: true,
          classificationLevels: ['TLP:RED'],
        },
        exportFormats: ['html', 'pdf'],
        lifecycle: { draft: true, review: true, approved: true, published: true, superseded: true, retired: true },
        version: '1.0',
        compositionStrategy: 'business_impact_analysis',
      },
      {
        id: 'weekly-executive-digest',
        type: 'executive_digest',
        title: 'Weekly Executive Intelligence Digest',
        description: 'Curated weekly summary of threat landscape for executives',
        audience: ['executive', 'ciso'],
        requiredInputs: ['recentIntelligence', 'metrics', 'trends'],
        publicationRules: {
          frequency: 'weekly',
          requiresApproval: false,
          classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'],
        },
        exportFormats: ['html', 'pdf', 'email'],
        lifecycle: { draft: true, review: true, published: true },
        version: '1.0',
        compositionStrategy: 'weekly_digest_aggregation',
      },
      {
        id: 'monthly-executive-outlook',
        type: 'executive_outlook',
        title: 'Monthly Executive Threat Outlook',
        description: 'Strategic threat landscape and emerging risks for executive briefing',
        audience: ['executive', 'ciso', 'board'],
        requiredInputs: ['monthlyIntelligence', 'trends', 'riskMetrics'],
        publicationRules: {
          frequency: 'monthly',
          requiresApproval: true,
          classificationLevels: ['TLP:AMBER', 'TLP:GREEN'],
        },
        exportFormats: ['html', 'pdf'],
        lifecycle: { draft: true, review: true, approved: true, published: true },
        version: '1.0',
        compositionStrategy: 'monthly_threat_outlook',
      },
      {
        id: 'industry-executive-advisory',
        type: 'advisory',
        title: 'Industry Executive Advisory',
        description: 'Industry-specific threat trends and recommended actions',
        audience: ['executive', 'industry_peers'],
        requiredInputs: ['investigation', 'targetedSectors', 'industryTrends'],
        publicationRules: {
          minConfidence: 0.65,
          requiresApproval: true,
          classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'],
        },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true, superseded: true, retired: true },
        version: '1.0',
        compositionStrategy: 'industry_advisory_composition',
      },
      {
        id: 'critical-threat-alert',
        type: 'alert',
        title: 'Critical Threat Alert',
        description: 'Urgent alert for critical, active threats requiring immediate response',
        audience: ['all'],
        requiredInputs: ['investigation', 'criticalIndicators', 'immediateActions'],
        publicationRules: {
          minConfidence: 0.8,
          requiresApproval: true,
          classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'],
          distribution: 'emergency',
        },
        exportFormats: ['html', 'pdf', 'json', 'email'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'critical_alert_extraction',
      },
    ];

    products.forEach(p => this.products.set(p.id, p));
  }

  registerTechnicalIntelligenceSeries() {
    const products = [
      {
        id: 'technical-threat-report',
        type: 'technical_report',
        title: 'Technical Threat Report',
        description: 'Detailed technical analysis including IOCs, MITRE mappings, and evidence',
        audience: ['soc', 'threat_intel', 'incident_response'],
        requiredInputs: ['investigation', 'report', 'qualityReview', 'iocs', 'mitreMappings'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json', 'stix'],
        lifecycle: { draft: true, review: true, published: true, updated: true, superseded: true, retired: true },
        version: '1.0',
        compositionStrategy: 'technical_details_from_analysis',
      },
      {
        id: 'incident-response-advisory',
        type: 'advisory',
        title: 'Incident Response Advisory',
        description: 'Tactical guidance for incident responders and SOC teams',
        audience: ['incident_response', 'soc'],
        requiredInputs: ['investigation', 'tactics', 'detectionGuidance', 'responseActions'],
        publicationRules: { minConfidence: 0.65, requiresApproval: true, classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'incident_response_guidance',
      },
      {
        id: 'threat-hunting-guide',
        type: 'guide',
        title: 'Threat Hunting Guide',
        description: 'Guidance for threat hunters to proactively search for threat indicators',
        audience: ['threat_hunter', 'soc'],
        requiredInputs: ['investigation', 'huntingIndicators', 'techniques', 'infrastructure'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'hunting_guide_composition',
      },
      {
        id: 'detection-engineering-guide',
        type: 'guide',
        title: 'Detection Engineering Guide',
        description: 'Guidance for detection engineers to create detection rules',
        audience: ['detection_engineer', 'soc'],
        requiredInputs: ['investigation', 'iocs', 'techniques', 'detectionStrategies'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'detection_guide_composition',
      },
      {
        id: 'ioc-intelligence-pack',
        type: 'indicator_pack',
        title: 'IOC Intelligence Pack',
        description: 'Machine-readable indicators of compromise with metadata and confidence',
        audience: ['soc', 'automation', 'security_platform'],
        requiredInputs: ['investigation', 'iocs', 'confidence'],
        publicationRules: { minConfidence: 0.6, requiresApproval: false, classificationLevels: ['TLP:WHITE'] },
        exportFormats: ['json', 'csv', 'stix', 'custom_formats'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'ioc_pack_assembly',
      },
      {
        id: 'malware-technical-profile',
        type: 'malware_profile',
        title: 'Malware Technical Profile',
        description: 'In-depth technical analysis of malware capabilities and characteristics',
        audience: ['malware_analyst', 'soc', 'threat_intel'],
        requiredInputs: ['investigation', 'malwareAnalysis', 'capabilities', 'infrastructure'],
        publicationRules: { minConfidence: 0.7, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true, superseded: true },
        version: '1.0',
        compositionStrategy: 'malware_profile_composition',
      },
      {
        id: 'infrastructure-intelligence-report',
        type: 'infrastructure_report',
        title: 'Infrastructure Intelligence Report',
        description: 'Analysis of attacker infrastructure and operational patterns',
        audience: ['threat_intel', 'infrastructure_analyst'],
        requiredInputs: ['investigation', 'infrastructure', 'clustering', 'operationalPatterns'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'infrastructure_report_composition',
      },
    ];

    products.forEach(p => this.products.set(p.id, p));
  }

  registerThreatActorIntelligence() {
    const products = [
      {
        id: 'threat-actor-dossier',
        type: 'threat_actor',
        title: 'Threat Actor Dossier',
        description: 'Comprehensive profile of threat actor including history, capabilities, and targeting',
        audience: ['threat_intel', 'executive', 'incident_response'],
        requiredInputs: ['threatActor', 'history', 'capabilities', 'targetingProfile'],
        publicationRules: { minConfidence: 0.65, requiresApproval: true, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true, superseded: true },
        version: '1.0',
        compositionStrategy: 'actor_dossier_composition',
      },
      {
        id: 'campaign-portfolio',
        type: 'campaign',
        title: 'Campaign Portfolio',
        description: 'Analysis of threat actor campaigns including objectives and targeting',
        audience: ['threat_intel', 'executive', 'incident_response'],
        requiredInputs: ['campaign', 'objectives', 'targeting', 'timeline'],
        publicationRules: { minConfidence: 0.65, requiresApproval: true, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true, superseded: true },
        version: '1.0',
        compositionStrategy: 'campaign_portfolio_composition',
      },
      {
        id: 'infrastructure-map',
        type: 'infrastructure',
        title: 'Infrastructure Map',
        description: 'Network and infrastructure used by threat actor for operations',
        audience: ['threat_intel', 'soc'],
        requiredInputs: ['infrastructure', 'relationships', 'operationalPatterns'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'infrastructure_map_composition',
      },
      {
        id: 'capability-assessment',
        type: 'assessment',
        title: 'Capability Assessment',
        description: 'Evaluation of threat actor technical capabilities and sophistication',
        audience: ['threat_intel', 'executive'],
        requiredInputs: ['capabilities', 'techniques', 'toolsUsed', 'malware'],
        publicationRules: { minConfidence: 0.65, requiresApproval: true, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'capability_assessment_composition',
      },
      {
        id: 'historical-activity',
        type: 'history',
        title: 'Historical Activity Profile',
        description: 'Timeline and analysis of threat actor historical operations',
        audience: ['threat_intel', 'executive', 'incident_response'],
        requiredInputs: ['timeline', 'historicalEvents', 'patterns'],
        publicationRules: { minConfidence: 0.6, requiresApproval: false, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'historical_activity_composition',
      },
      {
        id: 'targeting-analysis',
        type: 'targeting',
        title: 'Targeting Analysis',
        description: 'Analysis of threat actor targeting patterns and victim selection',
        audience: ['threat_intel', 'executive', 'industry_peers'],
        requiredInputs: ['victims', 'sectors', 'regions', 'criteria'],
        publicationRules: { minConfidence: 0.65, requiresApproval: true, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'targeting_analysis_composition',
      },
      {
        id: 'evolution-timeline',
        type: 'evolution',
        title: 'Evolution Timeline',
        description: 'Timeline of threat actor evolution, sophistication growth, and tactical changes',
        audience: ['threat_intel', 'executive'],
        requiredInputs: ['timeline', 'evolutionMarkers', 'sophisticationProgression'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'evolution_timeline_composition',
      },
    ];

    products.forEach(p => this.products.set(p.id, p));
  }

  registerSectorIntelligence() {
    const sectors = [
      'financial-services',
      'healthcare',
      'government',
      'critical-infrastructure',
      'manufacturing',
      'retail',
      'technology',
      'telecommunications',
      'energy',
      'education',
    ];

    sectors.forEach(sector => {
      const productId = `sector-intelligence-${sector}`;
      this.products.set(productId, {
        id: productId,
        type: 'sector_intelligence',
        title: `${this.sectorName(sector)} Threat Intelligence`,
        description: `Threat landscape, targeting, and recommendations for the ${this.sectorName(sector)} sector`,
        audience: ['executive', 'ciso', 'industry_peers', 'regulatory_bodies'],
        sector,
        requiredInputs: ['investigation', 'targetedSectors', 'sectorContext'],
        publicationRules: { minConfidence: 0.65, requiresApproval: true, classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true, superseded: true },
        version: '1.0',
        compositionStrategy: 'sector_intelligence_tailoring',
      });
    });
  }

  registerRegionalIntelligence() {
    const regions = ['north-america', 'europe', 'middle-east', 'africa', 'asia-pacific', 'latin-america'];

    regions.forEach(region => {
      const productId = `regional-intelligence-${region}`;
      this.products.set(productId, {
        id: productId,
        type: 'regional_intelligence',
        title: `${this.regionName(region)} Threat Intelligence`,
        description: `Regional threat landscape, infrastructure, and targeting analysis for ${this.regionName(region)}`,
        audience: ['regional_teams', 'executive', 'soc'],
        region,
        requiredInputs: ['investigation', 'targetedRegions', 'regionalContext'],
        publicationRules: { minConfidence: 0.6, requiresApproval: false, classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'regional_intelligence_tailoring',
      });
    });
  }

  registerVulnerabilityIntelligence() {
    const products = [
      {
        id: 'executive-vulnerability-brief',
        type: 'vulnerability_brief',
        title: 'Executive Vulnerability Brief',
        description: 'Business-focused summary of vulnerability impacts and risks',
        audience: ['executive', 'ciso'],
        requiredInputs: ['vulnerability', 'businessImpact', 'exploitationStatus'],
        publicationRules: { minConfidence: 0.7, requiresApproval: true, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf'],
        lifecycle: { draft: true, review: true, approved: true, published: true, updated: true, superseded: true },
        version: '1.0',
        compositionStrategy: 'vuln_executive_brief',
      },
      {
        id: 'technical-vulnerability-report',
        type: 'vulnerability_report',
        title: 'Technical Vulnerability Report',
        description: 'Technical analysis of vulnerability including affected products and exploitation',
        audience: ['soc', 'incident_response', 'security_architect'],
        requiredInputs: ['vulnerability', 'technicalAnalysis', 'affectedProducts', 'exploitation'],
        publicationRules: { minConfidence: 0.7, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true, superseded: true },
        version: '1.0',
        compositionStrategy: 'vuln_technical_report',
      },
      {
        id: 'exploitation-timeline',
        type: 'timeline',
        title: 'Exploitation Timeline',
        description: 'Timeline of vulnerability discovery, exploitation, and remediation',
        audience: ['security_architect', 'incident_response'],
        requiredInputs: ['vulnerability', 'timeline', 'exploitationData'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:AMBER', 'TLP:GREEN'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'exploitation_timeline_composition',
      },
      {
        id: 'affected-products-list',
        type: 'product_list',
        title: 'Affected Products List',
        description: 'Comprehensive list of affected products with versions',
        audience: ['all'],
        requiredInputs: ['vulnerability', 'affectedProducts'],
        publicationRules: { minConfidence: 0.8, requiresApproval: false, classificationLevels: ['TLP:WHITE'] },
        exportFormats: ['html', 'json', 'csv'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'affected_products_list',
      },
      {
        id: 'mitigation-status',
        type: 'mitigation',
        title: 'Mitigation Status',
        description: 'Current status of patches, workarounds, and mitigation options',
        audience: ['security_architect', 'soc'],
        requiredInputs: ['vulnerability', 'mitigations', 'patchStatus'],
        publicationRules: { minConfidence: 0.75, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'mitigation_status_composition',
      },
      {
        id: 'detection-guidance',
        type: 'guidance',
        title: 'Detection Guidance',
        description: 'Guidance for detecting vulnerability exploitation attempts',
        audience: ['soc', 'detection_engineer'],
        requiredInputs: ['vulnerability', 'detectionStrategies', 'indicators'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: 'detection_guidance_composition',
      },
    ];

    products.forEach(p => this.products.set(p.id, p));
  }

  registerDetectionIntelligence() {
    const formats = ['sigma', 'yara', 'suricata'];

    formats.forEach(format => {
      const productId = `detection-${format}-package`;
      this.products.set(productId, {
        id: productId,
        type: 'detection_package',
        title: `${format.toUpperCase()} Detection Package`,
        description: `${format.toUpperCase()} detection rules extracted from investigation`,
        audience: ['detection_engineer', 'soc', 'security_platform'],
        format,
        requiredInputs: ['investigation', 'iocs', 'techniques'],
        publicationRules: { minConfidence: 0.65, requiresApproval: false, classificationLevels: ['TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: [format, 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: `detection_package_${format}`,
      });
    });
  }

  registerIntelligenceCollections() {
    const collections = [
      { id: 'ransomware-intelligence', title: 'Ransomware Intelligence Collection', tags: ['ransomware'] },
      { id: 'phishing-intelligence', title: 'Phishing Intelligence Collection', tags: ['phishing', 'social_engineering'] },
      { id: 'cloud-threat-intelligence', title: 'Cloud Threat Intelligence Collection', tags: ['cloud', 'aws', 'azure', 'gcp'] },
      { id: 'ai-security-intelligence', title: 'AI Security Intelligence Collection', tags: ['ai', 'llm', 'ml'] },
      { id: 'supply-chain-intelligence', title: 'Supply Chain Intelligence Collection', tags: ['supply_chain', 'third_party'] },
      { id: 'zero-day-intelligence', title: 'Zero-Day Intelligence Collection', tags: ['zero_day', 'vulnerability'] },
      { id: 'threat-actor-collection', title: 'Threat Actor Collections', tags: ['threat_actor'] },
    ];

    collections.forEach(c => {
      this.collections.set(c.id, {
        id: c.id,
        type: 'collection',
        title: c.title,
        description: `Curated collection of intelligence related to ${c.tags.join(', ')}`,
        audience: ['threat_intel', 'soc', 'executive'],
        tags: c.tags,
        productIds: [],
        lifecycle: 'maintained',
      });
    });
  }

  registerCustomerIntelligencePackages() {
    const roles = [
      { id: 'ciso-package', title: 'CISO Package', role: 'ciso' },
      { id: 'soc-team-package', title: 'SOC Team Package', role: 'soc' },
      { id: 'threat-intel-package', title: 'Threat Intelligence Team Package', role: 'threat_intel' },
      { id: 'incident-response-package', title: 'Incident Response Team Package', role: 'incident_response' },
      { id: 'executive-package', title: 'Executive Package', role: 'executive' },
      { id: 'security-architect-package', title: 'Security Architect Package', role: 'security_architect' },
      { id: 'mssp-package', title: 'MSSP Package', role: 'mssp' },
    ];

    roles.forEach(r => {
      const productId = r.id;
      this.products.set(productId, {
        id: productId,
        type: 'customer_package',
        title: r.title,
        description: `Customized intelligence package for ${r.title} with role-specific content and emphasis`,
        audience: [r.role],
        role: r.role,
        requiredInputs: ['investigation', 'report'],
        publicationRules: { minConfidence: 0.6, requiresApproval: false, classificationLevels: ['TLP:AMBER', 'TLP:GREEN', 'TLP:WHITE'] },
        exportFormats: ['html', 'pdf', 'json'],
        lifecycle: { draft: true, review: true, published: true, updated: true },
        version: '1.0',
        compositionStrategy: `customer_package_${r.role}`,
      });
    });
  }

  getProduct(productId) {
    return this.products.get(productId);
  }

  getProductsForInvestigation(investigation) {
    const applicable = [];

    this.products.forEach((product, id) => {
      let isApplicable = false;

      // All investigations can generate executive products
      if (product.type.includes('executive') || product.type === 'alert' || product.type === 'technical_report') {
        isApplicable = true;
      }

      // If investigation has threat actors, generate threat actor products
      if (investigation.threatActors && investigation.threatActors.length > 0 && product.type === 'threat_actor') {
        isApplicable = true;
      }

      // If investigation has sectors, generate sector intelligence
      if (investigation.targetedSectors && investigation.targetedSectors.length > 0 && product.type === 'sector_intelligence') {
        isApplicable = true;
      }

      // If investigation has regions, generate regional intelligence
      if (investigation.targetedRegions && investigation.targetedRegions.length > 0 && product.type === 'regional_intelligence') {
        isApplicable = true;
      }

      // Technical products for all investigations
      if (product.type === 'technical_report' || product.type === 'detection_package') {
        isApplicable = true;
      }

      // Customer packages for all investigations
      if (product.type === 'customer_package') {
        isApplicable = true;
      }

      if (isApplicable) {
        applicable.push(product);
      }
    });

    return applicable;
  }

  getAllProducts() {
    return Array.from(this.products.values());
  }

  getProductsByType(type) {
    return Array.from(this.products.values()).filter(p => p.type === type);
  }

  getProductsByAudience(audience) {
    return Array.from(this.products.values()).filter(p => p.audience.includes(audience));
  }

  getCollection(collectionId) {
    return this.collections.get(collectionId);
  }

  getAllCollections() {
    return Array.from(this.collections.values());
  }

  addProductToCollection(collectionId, productId) {
    const collection = this.collections.get(collectionId);
    if (collection && !collection.productIds.includes(productId)) {
      collection.productIds.push(productId);
    }
  }

  sectorName(sectorId) {
    const names = {
      'financial-services': 'Financial Services',
      'healthcare': 'Healthcare',
      'government': 'Government',
      'critical-infrastructure': 'Critical Infrastructure',
      'manufacturing': 'Manufacturing',
      'retail': 'Retail',
      'technology': 'Technology',
      'telecommunications': 'Telecommunications',
      'energy': 'Energy',
      'education': 'Education',
    };
    return names[sectorId] || sectorId;
  }

  regionName(regionId) {
    const names = {
      'north-america': 'North America',
      'europe': 'Europe',
      'middle-east': 'Middle East',
      'africa': 'Africa',
      'asia-pacific': 'Asia-Pacific',
      'latin-america': 'Latin America',
    };
    return names[regionId] || regionId;
  }

  getCatalogMetrics() {
    return {
      totalProducts: this.products.size,
      totalCollections: this.collections.size,
      productsByType: this.getProductTypeDistribution(),
      productsByAudience: this.getAudienceDistribution(),
      totalExportFormats: this.getTotalExportFormats(),
    };
  }

  getProductTypeDistribution() {
    const distribution = {};
    this.products.forEach(p => {
      distribution[p.type] = (distribution[p.type] || 0) + 1;
    });
    return distribution;
  }

  getAudienceDistribution() {
    const distribution = {};
    this.products.forEach(p => {
      p.audience.forEach(a => {
        distribution[a] = (distribution[a] || 0) + 1;
      });
    });
    return distribution;
  }

  getTotalExportFormats() {
    const formats = new Set();
    this.products.forEach(p => {
      p.exportFormats.forEach(f => formats.add(f));
    });
    return Array.from(formats);
  }
}

module.exports = { ProductCatalogEngine };
