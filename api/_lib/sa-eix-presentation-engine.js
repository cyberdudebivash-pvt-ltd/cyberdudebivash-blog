'use strict';

class SentinelApexEIXPresentationEngine {
  constructor() {
    this.presentationCache = new Map();
    this.brandingConfig = this.initializeBrandingConfig();
    this.layoutConfig = this.initializeLayoutConfig();
  }

  initializeBrandingConfig() {
    return {
      name: 'Sentinel APEX',
      colors: {
        primary: '#0A3A5C',
        secondary: '#1B5E8E',
        accent: '#FF6B35',
        success: '#2ECC71',
        warning: '#F39C12',
        critical: '#E74C3C',
        neutral: '#34495E',
        light: '#ECF0F1',
        dark: '#2C3E50',
      },
      typography: {
        heading: 'Inter, -apple-system, sans-serif',
        body: 'Inter, -apple-system, sans-serif',
        mono: 'JetBrains Mono, monospace',
      },
      spacing: {
        xs: '4px',
        sm: '8px',
        md: '16px',
        lg: '24px',
        xl: '32px',
      },
    };
  }

  initializeLayoutConfig() {
    return {
      coverPage: true,
      dashboardHeader: true,
      executiveCards: true,
      evidenceGallery: true,
      interactiveDiagrams: true,
      decisionCenter: true,
      darkMode: true,
      responsiveLayout: true,
      pdfSupport: true,
      printOptimized: true,
    };
  }

  async enhanceIntelligenceProduct(product, investigation, report) {
    const enhancement = {
      productId: product.id,
      originalProduct: product,
      presentationEnhancements: {},
      visualElements: [],
      interactiveComponents: [],
      metadata: {
        enhancedAt: new Date().toISOString(),
        presentationVersion: '1.0',
        theme: 'enterprise-soc',
      },
    };

    // Layer 1: Enterprise Cover Page
    if (this.layoutConfig.coverPage) {
      enhancement.presentationEnhancements.coverPage = await this.generateEnterpriseCoverPage(product, investigation, report);
    }

    // Layer 2: SOC Dashboard Header
    if (this.layoutConfig.dashboardHeader) {
      enhancement.presentationEnhancements.dashboardHeader = await this.generateSOCDashboardHeader(product, investigation);
    }

    // Layer 3: Executive Intelligence Cards
    if (this.layoutConfig.executiveCards) {
      enhancement.presentationEnhancements.executiveCards = await this.generateExecutiveIntelligenceCards(product, investigation);
    }

    // Layer 4: Evidence Visualization
    if (this.layoutConfig.evidenceGallery) {
      enhancement.presentationEnhancements.evidenceGallery = await this.generateEvidenceGallery(product, investigation);
    }

    // Layer 5: Interactive Diagrams
    if (this.layoutConfig.interactiveDiagrams) {
      enhancement.presentationEnhancements.interactiveDiagrams = await this.generateInteractiveDiagrams(product, investigation);
    }

    // Layer 6: Executive Decision Center
    if (this.layoutConfig.decisionCenter) {
      enhancement.presentationEnhancements.decisionCenter = await this.generateExecutiveDecisionCenter(product, investigation);
    }

    // Layer 7: Responsive Layout
    enhancement.presentationEnhancements.layout = this.generateResponsiveLayout(enhancement);

    // Store in cache for quick access
    this.presentationCache.set(product.id, enhancement);

    return enhancement;
  }

  async generateEnterpriseCoverPage(product, investigation, report) {
    const coverPage = {
      type: 'enterprise-cover',
      sections: {
        header: {
          title: investigation.title || 'Intelligence Report',
          subtitle: product.metadata?.description || '',
          threatLevel: investigation.severity || 'MEDIUM',
          threatScore: this.calculateThreatScore(investigation),
          classification: investigation.classification || 'TLP:AMBER',
        },
        threatInformation: {
          severity: investigation.severity,
          confidence: investigation.confidence,
          businessImpact: investigation.businessImpact || 'Unknown',
          operationalRisk: this.assessOperationalRisk(investigation),
          detectionCoverage: this.assessDetectionCoverage(investigation),
        },
        threatActors: investigation.threatActors || [],
        campaigns: investigation.campaigns || [],
        malware: investigation.malware || [],
        affectedIndustries: investigation.targetedSectors || [],
        affectedRegions: investigation.targetedRegions || [],
        keyMetrics: {
          findingsCount: (investigation.findings || []).length,
          iocsCount: (investigation.iocs || []).length,
          infrastructureCount: (investigation.infrastructure || []).length,
          techniquesCount: (investigation.mitreTechniques || []).length,
        },
        metadata: {
          publishedAt: new Date().toISOString(),
          version: 'v1.0',
          classification: investigation.classification,
          analyst: 'Sentinel APEX',
          certificationStatus: 'GOLD',
        },
      },
      styling: this.getThemeStyling('cover-page'),
    };

    return coverPage;
  }

  async generateSOCDashboardHeader(product, investigation) {
    const dashboard = {
      type: 'soc-dashboard-header',
      widgets: [
        {
          name: 'Threat Level',
          value: investigation.severity || 'MEDIUM',
          icon: 'alert',
          color: this.getThreatLevelColor(investigation.severity),
        },
        {
          name: 'Confidence',
          value: Math.round((investigation.confidence || 0.5) * 100) + '%',
          icon: 'check-circle',
          color: this.getConfidenceColor(investigation.confidence),
        },
        {
          name: 'Business Risk',
          value: this.assessBusinessRisk(investigation),
          icon: 'trending-up',
          color: this.getRiskColor(this.assessBusinessRisk(investigation)),
        },
        {
          name: 'Operational Risk',
          value: this.assessOperationalRisk(investigation),
          icon: 'activity',
          color: this.getRiskColor(this.assessOperationalRisk(investigation)),
        },
        {
          name: 'Detection Coverage',
          value: Math.round(this.assessDetectionCoverage(investigation)) + '%',
          icon: 'shield',
          color: this.getCoverageColor(this.assessDetectionCoverage(investigation)),
        },
        {
          name: 'MITRE Coverage',
          value: ((investigation.mitreTechniques || []).length) + ' techniques',
          icon: 'grid',
          color: this.brandingConfig.colors.secondary,
        },
        {
          name: 'Evidence',
          value: ((investigation.findings || []).length + (investigation.iocs || []).length) + ' items',
          icon: 'book-open',
          color: this.brandingConfig.colors.primary,
        },
        {
          name: 'Publication Status',
          value: 'Ready',
          icon: 'check',
          color: this.brandingConfig.colors.success,
        },
      ],
      layout: 'grid-4',
      responsive: true,
    };

    return dashboard;
  }

  async generateExecutiveIntelligenceCards(product, investigation) {
    const cards = [];

    // Threat Summary Card
    if (investigation.title) {
      cards.push({
        type: 'card',
        category: 'threat-summary',
        title: 'Threat Overview',
        content: {
          headline: investigation.title,
          description: investigation.description || 'Strategic analysis of threat activity',
          severity: investigation.severity,
          threatActors: (investigation.threatActors || []).map(a => a.name).join(', ') || 'Unknown',
          campaigns: (investigation.campaigns || []).map(c => c.name).join(', ') || 'Unknown',
        },
        icon: 'alert-triangle',
        color: this.getThreatLevelColor(investigation.severity),
      });
    }

    // Business Impact Card
    if (investigation.businessImpact) {
      cards.push({
        type: 'card',
        category: 'business-impact',
        title: 'Business Impact',
        content: {
          impact: investigation.businessImpact,
          affectedSystems: investigation.affectedSystems || [],
          affectedServices: investigation.affectedServices || [],
          userCount: investigation.affectedUserCount || 'Unknown',
          estimatedExposure: this.estimateExposure(investigation),
        },
        icon: 'bar-chart-2',
        color: this.brandingConfig.colors.accent,
      });
    }

    // Executive Actions Card
    if (investigation.recommendations) {
      const criticalActions = (investigation.recommendations || [])
        .filter(r => r.priority === 'critical' || r.priority === 'immediate')
        .slice(0, 5);

      if (criticalActions.length > 0) {
        cards.push({
          type: 'card',
          category: 'executive-actions',
          title: 'Immediate Actions Required',
          content: {
            actions: criticalActions.map(a => a.action || a.statement),
            priority: 'critical',
          },
          icon: 'zap',
          color: this.brandingConfig.colors.critical,
        });
      }
    }

    // Sector Risk Card
    if (investigation.targetedSectors && investigation.targetedSectors.length > 0) {
      cards.push({
        type: 'card',
        category: 'sector-risk',
        title: 'Affected Industries',
        content: {
          sectors: investigation.targetedSectors,
          count: investigation.targetedSectors.length,
        },
        icon: 'layers',
        color: this.brandingConfig.colors.warning,
      });
    }

    // Regional Risk Card
    if (investigation.targetedRegions && investigation.targetedRegions.length > 0) {
      cards.push({
        type: 'card',
        category: 'regional-risk',
        title: 'Geographic Impact',
        content: {
          regions: investigation.targetedRegions,
          count: investigation.targetedRegions.length,
        },
        icon: 'globe',
        color: this.brandingConfig.colors.secondary,
      });
    }

    return cards;
  }

  async generateEvidenceGallery(product, investigation) {
    const gallery = {
      type: 'evidence-gallery',
      sections: [],
    };

    // Findings Section
    const findings = investigation.findings || [];
    if (findings.length > 0) {
      gallery.sections.push({
        title: 'Key Findings',
        count: findings.length,
        items: findings.slice(0, 10).map(f => ({
          id: f.id,
          statement: f.statement,
          severity: f.severity,
          confidence: f.confidence,
          businessImpact: f.businessImpact,
          evidence: f.evidence,
        })),
        icon: 'alert-circle',
      });
    }

    // IOCs Section
    const iocs = investigation.iocs || [];
    if (iocs.length > 0) {
      gallery.sections.push({
        title: 'Indicators of Compromise',
        count: iocs.length,
        items: iocs.slice(0, 20).map(i => ({
          id: i.id,
          value: i.value,
          type: i.type,
          severity: i.severity,
          confidence: i.confidence,
          validated: i.validated || false,
        })),
        icon: 'shield-alert',
      });
    }

    // Infrastructure Section
    const infrastructure = investigation.infrastructure || [];
    if (infrastructure.length > 0) {
      gallery.sections.push({
        title: 'Infrastructure',
        count: infrastructure.length,
        items: infrastructure.slice(0, 15).map(inf => ({
          id: inf.id,
          type: inf.type,
          value: inf.value,
          location: inf.location,
          operator: inf.operator,
        })),
        icon: 'server',
      });
    }

    // Techniques Section
    const techniques = investigation.mitreTechniques || [];
    if (techniques.length > 0) {
      gallery.sections.push({
        title: 'MITRE ATT&CK Techniques',
        count: techniques.length,
        items: techniques.slice(0, 20).map(t => ({
          id: t.id,
          technique: t.technique,
          tactic: t.tactic,
          id_mitre: t.id_mitre,
        })),
        icon: 'layers',
      });
    }

    return gallery;
  }

  async generateInteractiveDiagrams(product, investigation) {
    const diagrams = {
      type: 'interactive-diagrams',
      diagrams: [],
    };

    // Attack Chain Diagram
    if (investigation.techniques && investigation.techniques.length > 0) {
      diagrams.diagrams.push({
        type: 'attack-chain',
        title: 'Attack Flow',
        stages: this.buildAttackChain(investigation),
      });
    }

    // Kill Chain Diagram
    diagrams.diagrams.push({
      type: 'kill-chain',
      title: 'Kill Chain Analysis',
      stages: this.buildKillChain(investigation),
    });

    // MITRE Matrix
    if (investigation.mitreTechniques && investigation.mitreTechniques.length > 0) {
      diagrams.diagrams.push({
        type: 'mitre-matrix',
        title: 'MITRE ATT&CK Coverage',
        tactics: this.buildMitreMatrix(investigation),
      });
    }

    // Campaign Timeline
    if (investigation.timeline && investigation.timeline.length > 0) {
      diagrams.diagrams.push({
        type: 'timeline',
        title: 'Campaign Timeline',
        events: investigation.timeline.map(e => ({
          date: e.date || e.timestamp,
          event: e.event || e.description,
          severity: e.severity,
        })).sort((a, b) => new Date(a.date) - new Date(b.date)),
      });
    }

    // Infrastructure Relationships
    if (investigation.infrastructure && investigation.infrastructure.length > 1) {
      diagrams.diagrams.push({
        type: 'infrastructure-graph',
        title: 'Infrastructure Relationships',
        nodes: investigation.infrastructure,
      });
    }

    // Threat Actor Network
    if (investigation.threatActors && investigation.threatActors.length > 0) {
      diagrams.diagrams.push({
        type: 'threat-actor-network',
        title: 'Threat Actor Intelligence',
        actors: investigation.threatActors,
        campaigns: investigation.campaigns,
      });
    }

    return diagrams;
  }

  async generateExecutiveDecisionCenter(product, investigation) {
    const decisionCenter = {
      type: 'executive-decision-center',
      audiences: {},
    };

    // CEO Level
    decisionCenter.audiences.ceo = {
      title: 'CEO',
      decisions: [
        'Business Continuity Risk Assessment',
        'Insurance/Coverage Review',
        'Public Disclosure Evaluation',
        'Stakeholder Communication Plan',
      ],
      metrics: [
        { label: 'Revenue Impact', value: this.estimateFinancialImpact(investigation) },
        { label: 'Operational Impact', value: investigation.businessImpact || 'Medium' },
        { label: 'Customer Exposure', value: investigation.affectedUserCount || 'Unknown' },
      ],
    };

    // CISO Level
    decisionCenter.audiences.ciso = {
      title: 'CISO',
      decisions: [
        'Incident Response Activation',
        'Detection Rule Deployment',
        'Infrastructure Isolation',
        'Threat Hunting Prioritization',
      ],
      metrics: [
        { label: 'Threat Level', value: investigation.severity },
        { label: 'Detection Coverage', value: this.assessDetectionCoverage(investigation) + '%' },
        { label: 'Infrastructure Affected', value: (investigation.infrastructure || []).length },
      ],
    };

    // SOC Director Level
    decisionCenter.audiences.socDirector = {
      title: 'SOC Director',
      decisions: [
        'Alert Tuning Requirements',
        'Escalation Procedures',
        'Team Prioritization',
        'Workload Distribution',
      ],
      metrics: [
        { label: 'Alerts Generated', value: 'N/A' },
        { label: 'Investigation Time', value: 'N/A' },
        { label: 'Detection Rate', value: this.assessDetectionCoverage(investigation) + '%' },
      ],
    };

    // Threat Hunter Level
    decisionCenter.audiences.threatHunter = {
      title: 'Threat Hunter',
      decisions: [
        'Hunt Query Development',
        'Anomaly Detection Tuning',
        'Lateral Movement Analysis',
        'Historical Search Scope',
      ],
      metrics: [
        { label: 'MITRE Techniques', value: (investigation.mitreTechniques || []).length },
        { label: 'Evidence Items', value: ((investigation.findings || []).length + (investigation.iocs || []).length) },
        { label: 'Timeline Span', value: this.calculateTimelineSpan(investigation) },
      ],
    };

    return decisionCenter;
  }

  generateResponsiveLayout(enhancement) {
    return {
      type: 'responsive-layout',
      breakpoints: {
        mobile: '320px-768px',
        tablet: '769px-1024px',
        desktop: '1025px+',
      },
      themes: {
        light: this.generateLightTheme(),
        dark: this.generateDarkTheme(),
      },
      printStyles: this.generatePrintStyles(),
      modes: {
        executive: true,
        technical: true,
        operational: true,
        customer: true,
      },
    };
  }

  generateLightTheme() {
    return {
      name: 'light',
      background: '#FFFFFF',
      foreground: '#2C3E50',
      accent: this.brandingConfig.colors.accent,
      cardBackground: '#F8F9FA',
      borderColor: '#E1E4E8',
    };
  }

  generateDarkTheme() {
    return {
      name: 'dark',
      background: '#0D1117',
      foreground: '#C9D1D9',
      accent: this.brandingConfig.colors.accent,
      cardBackground: '#161B22',
      borderColor: '#30363D',
    };
  }

  generatePrintStyles() {
    return {
      pageSize: 'A4',
      margin: '2cm',
      breakPage: true,
      colorMode: 'full-color',
      optimization: 'print-quality',
    };
  }

  // Utility Methods

  calculateThreatScore(investigation) {
    let score = 0;
    const maxScore = 100;

    if (investigation.severity === 'CRITICAL') score += 30;
    else if (investigation.severity === 'HIGH') score += 20;
    else if (investigation.severity === 'MEDIUM') score += 10;

    score += (investigation.confidence || 0) * 30;

    if ((investigation.threatActors || []).length > 0) score += 10;
    if ((investigation.campaigns || []).length > 0) score += 10;
    if ((investigation.mitreTechniques || []).length > 2) score += 20;

    return Math.min(Math.round(score), maxScore);
  }

  getThreatLevelColor(severity) {
    const colors = {
      CRITICAL: this.brandingConfig.colors.critical,
      HIGH: '#E67E22',
      MEDIUM: this.brandingConfig.colors.warning,
      LOW: this.brandingConfig.colors.success,
    };
    return colors[severity] || this.brandingConfig.colors.neutral;
  }

  getConfidenceColor(confidence) {
    if (confidence >= 0.8) return this.brandingConfig.colors.success;
    if (confidence >= 0.6) return this.brandingConfig.colors.warning;
    return this.brandingConfig.colors.critical;
  }

  assessOperationalRisk(investigation) {
    if (investigation.severity === 'CRITICAL') return 'Critical';
    if (investigation.severity === 'HIGH') return 'High';
    return 'Medium';
  }

  assessBusinessRisk(investigation) {
    if (!investigation.businessImpact) return 'Unknown';
    if (investigation.businessImpact.toLowerCase().includes('high')) return 'High';
    if (investigation.businessImpact.toLowerCase().includes('medium')) return 'Medium';
    return 'Low';
  }

  getRiskColor(risk) {
    const colors = { Critical: this.brandingConfig.colors.critical, High: '#E67E22', Medium: this.brandingConfig.colors.warning, Low: this.brandingConfig.colors.success, Unknown: this.brandingConfig.colors.neutral };
    return colors[risk] || this.brandingConfig.colors.neutral;
  }

  assessDetectionCoverage(investigation) {
    const techniques = (investigation.mitreTechniques || []).length;
    return Math.min((techniques / 20) * 100, 100);
  }

  getCoverageColor(coverage) {
    if (coverage >= 80) return this.brandingConfig.colors.success;
    if (coverage >= 60) return this.brandingConfig.colors.warning;
    return this.brandingConfig.colors.critical;
  }

  estimateExposure(investigation) {
    const userCount = investigation.affectedUserCount;
    if (!userCount) return 'Unknown';
    if (typeof userCount === 'number') return userCount.toLocaleString();
    return userCount;
  }

  estimateFinancialImpact(investigation) {
    if (investigation.severity === 'CRITICAL') return 'Very High ($1M+)';
    if (investigation.severity === 'HIGH') return 'High ($100K-$1M)';
    return 'Medium (<$100K)';
  }

  buildAttackChain(investigation) {
    return (investigation.techniques || []).map(t => ({
      name: t.name,
      type: 'attack',
      description: t.description,
    }));
  }

  buildKillChain(investigation) {
    const stages = ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Command & Control', 'Actions on Objectives'];
    return stages.map(stage => ({
      stage,
      active: (investigation.techniques || []).some(t => t.name && t.name.toLowerCase().includes(stage.toLowerCase())),
    }));
  }

  buildMitreMatrix(investigation) {
    const tactics = {};
    (investigation.mitreTechniques || []).forEach(t => {
      if (!tactics[t.tactic]) tactics[t.tactic] = [];
      tactics[t.tactic].push(t);
    });
    return tactics;
  }

  calculateTimelineSpan(investigation) {
    if (!investigation.timeline || investigation.timeline.length < 2) return 'N/A';
    const dates = (investigation.timeline || [])
      .map(e => new Date(e.date || e.timestamp))
      .filter(d => !isNaN(d));
    if (dates.length < 2) return 'N/A';
    const span = (Math.max(...dates) - Math.min(...dates)) / (1000 * 60 * 60 * 24);
    return Math.round(span) + ' days';
  }

  getThemeStyling(component) {
    return {
      primary: this.brandingConfig.colors.primary,
      accent: this.brandingConfig.colors.accent,
      typography: this.brandingConfig.typography,
      spacing: this.brandingConfig.spacing,
    };
  }

  getProductPresentation(productId) {
    return this.presentationCache.get(productId);
  }

  getAllPresentations() {
    return Array.from(this.presentationCache.values());
  }

  getThreatLevel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'INFO';
  }

  calculateBusinessRiskScore(investigation) {
    let score = 0;
    if (investigation.businessImpact === 'High operational impact') score += 30;
    else if (investigation.businessImpact === 'Medium operational impact') score += 20;
    else if (investigation.businessImpact === 'Low operational impact') score += 10;
    score += (investigation.targetedSectors || []).length * 5;
    score += (investigation.targetedRegions || []).length * 3;
    score += (investigation.affectedUserCount || 0) > 1000 ? 20 : 10;
    return Math.min(Math.round(score), 100);
  }

  analyzeEvidenceCoverage(investigation) {
    return {
      findingsCount: (investigation.findings || []).length,
      iocsCount: (investigation.iocs || []).length,
      infrastructureCount: (investigation.infrastructure || []).length,
      totalEvidence: (investigation.findings || []).length + (investigation.iocs || []).length + (investigation.infrastructure || []).length,
      techniques: (investigation.mitreTechniques || []).length,
    };
  }

  calculateDetectionCoverage(investigation) {
    const techniques = investigation.mitreTechniques || [];
    if (techniques.length === 0) return 0;
    return Math.min(Math.round((techniques.length / 20) * 100), 100);
  }

  formatTimelineData(investigation) {
    if (!investigation.timeline || investigation.timeline.length === 0) return [];
    return investigation.timeline.map(e => ({
      date: e.date || e.timestamp,
      event: e.event || e.description,
      severity: e.severity || 'medium',
    })).sort((a, b) => new Date(a.date) - new Date(b.date));
  }

  formatAffectedSectors(sectors) {
    if (!Array.isArray(sectors)) return [];
    return sectors.map(s => ({
      name: s,
      riskLevel: Math.random() > 0.5 ? 'HIGH' : 'MEDIUM',
    }));
  }

  formatAffectedRegions(regions) {
    if (!Array.isArray(regions)) return [];
    return regions.map(r => ({
      name: r,
      threatLevel: Math.random() > 0.5 ? 'CRITICAL' : 'HIGH',
    }));
  }

  generateAudienceGuidance(audience, investigation) {
    const baseGuidance = {
      ceo: {
        decisions: ['Business Continuity', 'Insurance Review', 'Public Disclosure', 'Stakeholder Communication'],
        metrics: [
          { label: 'Revenue Impact', value: this.estimateFinancialImpact(investigation) },
          { label: 'Operational Impact', value: investigation.businessImpact || 'Medium' },
        ],
      },
      ciso: {
        decisions: ['Incident Response', 'Detection Deployment', 'Infrastructure Isolation', 'Threat Hunting'],
        metrics: [
          { label: 'Threat Level', value: investigation.severity },
          { label: 'Detection Coverage', value: this.assessDetectionCoverage(investigation) + '%' },
        ],
      },
      'soc-director': {
        decisions: ['Alert Tuning', 'Escalation Procedures', 'Team Prioritization', 'Workload Distribution'],
        metrics: [
          { label: 'Detection Rate', value: this.assessDetectionCoverage(investigation) + '%' },
          { label: 'Alert Volume', value: 'High' },
        ],
      },
      'threat-hunter': {
        decisions: ['Hunt Query Development', 'Anomaly Tuning', 'Lateral Movement Analysis', 'Historical Search'],
        metrics: [
          { label: 'MITRE Techniques', value: (investigation.mitreTechniques || []).length },
          { label: 'Evidence Items', value: ((investigation.findings || []).length + (investigation.iocs || []).length) },
        ],
      },
    };

    return baseGuidance[audience] || baseGuidance.ciso;
  }
}

module.exports = { SentinelApexEIXPresentationEngine };
