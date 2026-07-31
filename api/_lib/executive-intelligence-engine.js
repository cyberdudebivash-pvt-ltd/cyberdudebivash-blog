'use strict';

class ExecutiveIntelligenceEngine {
  constructor() {
    this.products = new Map();
  }

  async composeExecutiveThreatBrief(investigation, report, qualityReview) {
    const product = {
      id: `exec-brief-${report.id}`,
      productId: 'executive-threat-brief',
      type: 'executive_brief',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['executive', 'ciso', 'cto'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Executive Threat Brief: ${investigation.title}`,
        description: 'Business-focused threat summary for executive decision-making',
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatSummary: {
          description: investigation.description,
          threatLevel: investigation.severity || 'MEDIUM',
          businessImpact: await this.extractBusinessImpact(investigation),
        },
        keyRisks: await this.extractKeyRisks(investigation),
        immediateActions: await this.extractImmediateActions(investigation),
        recommendedResponse: await this.buildExecutiveRecommendations(investigation),
        timeline: await this.buildExecutiveTimeline(investigation),
        confidence: qualityReview?.qualityScore?.overallScore || 0.5,
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-executive-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeBoardCyberRiskBrief(investigation, report, qualityReview) {
    const product = {
      id: `board-brief-${report.id}`,
      productId: 'board-cyber-risk-brief',
      type: 'executive_brief',
      investigationId: investigation.id,
      reportId: report.id,
      audience: ['board', 'executive', 'ciso'],
      classification: 'TLP:RED',
      status: 'draft',
      metadata: {
        title: `Board Cyber Risk Summary: ${investigation.title}`,
        description: 'Board-level cyber risk assessment and governance implications',
        createdAt: new Date().toISOString(),
      },
      modules: {
        riskSummary: {
          threatLevel: investigation.severity || 'MEDIUM',
          businessImpact: await this.extractBusinessImpact(investigation),
          affectedSystems: investigation.affectedSystems || [],
          exposedCount: investigation.affectedUserCount || 'Unknown',
        },
        governanceImplications: {
          complianceImpact: await this.assessComplianceImpact(investigation),
          reportingRequirements: await this.identifyReportingRequirements(investigation),
          insuranceConsiderations: await this.identifyInsuranceConsiderations(investigation),
        },
        riskMetrics: {
          confidentiality: investigation.riskLevel?.confidentiality || 'MEDIUM',
          integrity: investigation.riskLevel?.integrity || 'MEDIUM',
          availability: investigation.riskLevel?.availability || 'MEDIUM',
        },
        boardRecommendations: await this.buildBoardRecommendations(investigation),
        confidence: qualityReview?.qualityScore?.overallScore || 0.5,
      },
      lineage: {
        investigation: investigation.id,
        report: report.id,
        source: 'phase-11-executive-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeWeeklyExecutiveDigest(recentIntelligence, metrics) {
    const product = {
      id: `weekly-digest-${Date.now()}`,
      productId: 'weekly-executive-digest',
      type: 'executive_digest',
      audience: ['executive', 'ciso'],
      classification: 'TLP:AMBER',
      status: 'published',
      metadata: {
        title: 'Weekly Executive Intelligence Digest',
        weekEnding: new Date().toISOString().split('T')[0],
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatLandscape: {
          highestRisks: recentIntelligence.slice(0, 5),
          threatTrends: await this.analyzeThreatTrends(recentIntelligence),
        },
        keyMetrics: {
          publishedReports: metrics.published || 0,
          newThreats: metrics.newThreats || 0,
          updatedIntelligence: metrics.updated || 0,
        },
        recommendations: await this.generateWeeklyRecommendations(recentIntelligence),
      },
      lineage: {
        source: 'phase-11-executive-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeMonthlyExecutiveOutlook(monthlyIntelligence, trends, riskMetrics) {
    const product = {
      id: `monthly-outlook-${Date.now()}`,
      productId: 'monthly-executive-threat-outlook',
      type: 'executive_outlook',
      audience: ['executive', 'ciso', 'board'],
      classification: 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: 'Monthly Executive Threat Outlook',
        month: new Date().toISOString().substring(0, 7),
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatLandscape: {
          overview: await this.generateMonthlyOverview(monthlyIntelligence),
          topThreats: monthlyIntelligence.slice(0, 10),
          emergingRisks: await this.identifyEmergingRisks(trends),
        },
        riskAssessment: {
          metrics: riskMetrics,
          trendAnalysis: await this.analyzeTrendAnalysis(trends),
          forecastOutlook: await this.generateOutlook(trends),
        },
        strategicRecommendations: await this.buildStrategicRecommendations(monthlyIntelligence, trends),
        confidence: 0.7,
      },
      lineage: {
        source: 'phase-11-executive-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeIndustryExecutiveAdvisory(investigation, targetedSectors, industryTrends) {
    const product = {
      id: `industry-advisory-${report.id}`,
      productId: 'industry-executive-advisory',
      type: 'advisory',
      audience: ['executive', 'industry_peers'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      metadata: {
        title: `Industry Executive Advisory: ${investigation.title}`,
        sectors: targetedSectors || [],
        createdAt: new Date().toISOString(),
      },
      modules: {
        executiveSummary: {
          threatDescription: investigation.title,
          businessImpact: await this.extractBusinessImpact(investigation),
          sectorSpecificRisks: await this.extractSectorSpecificRisks(investigation, targetedSectors),
        },
        industryContext: {
          trends: industryTrends || [],
          historicalPrecedent: await this.identifyHistoricalContext(investigation),
        },
        recommendations: await this.buildIndustryRecommendations(investigation, targetedSectors),
      },
      lineage: {
        investigation: investigation.id,
        source: 'phase-11-executive-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async composeCriticalThreatAlert(investigation) {
    const product = {
      id: `alert-${investigation.id}-${Date.now()}`,
      productId: 'critical-threat-alert',
      type: 'alert',
      investigationId: investigation.id,
      audience: ['all'],
      classification: investigation.classification || 'TLP:AMBER',
      status: 'draft',
      priority: 'critical',
      metadata: {
        title: `CRITICAL THREAT ALERT: ${investigation.title}`,
        severity: 'CRITICAL',
        publishedAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      },
      modules: {
        threatAlert: {
          threatDescription: investigation.title,
          severity: 'CRITICAL',
          isActive: true,
          immediateRisks: await this.extractCriticalRisks(investigation),
        },
        immediateActions: await this.extractUrgentActions(investigation),
        technicalDetails: {
          iocs: investigation.iocs || [],
          techniques: investigation.techniques || [],
        },
        additionalInformation: {
          sources: investigation.sources || [],
          references: investigation.references || [],
        },
      },
      lineage: {
        investigation: investigation.id,
        source: 'phase-11-executive-intelligence',
      },
    };

    this.products.set(product.id, product);
    return product;
  }

  async extractBusinessImpact(investigation) {
    return {
      affectedSystems: investigation.affectedSystems || [],
      estimatedExposure: investigation.affectedUserCount || 'Unknown',
      businessServices: investigation.affectedServices || [],
      operationalImpact: investigation.businessImpact || 'Unknown',
      confidentiality: investigation.riskLevel?.confidentiality || 'MEDIUM',
      integrity: investigation.riskLevel?.integrity || 'MEDIUM',
      availability: investigation.riskLevel?.availability || 'MEDIUM',
    };
  }

  async extractKeyRisks(investigation) {
    const findings = investigation.findings || [];
    return findings
      .filter(f => f.severity === 'critical' || f.severity === 'high')
      .slice(0, 5)
      .map(f => ({
        risk: f.statement,
        severity: f.severity,
        confidence: f.confidence,
        impact: f.businessImpact || 'Unknown',
      }));
  }

  async extractImmediateActions(investigation) {
    if (investigation.recommendations) {
      return investigation.recommendations
        .filter(r => r.priority === 'immediate' || r.priority === 'critical')
        .slice(0, 5)
        .map(r => r.action);
    }
    return [];
  }

  async buildExecutiveRecommendations(investigation) {
    return {
      immediate: [
        'Review affected systems and user access',
        'Enable enhanced logging and monitoring',
        'Activate incident response playbooks',
      ],
      shortTerm: [
        'Conduct risk assessment',
        'Deploy relevant detection rules',
        'Brief senior leadership',
      ],
      strategic: [
        'Enhance threat intelligence capabilities',
        'Improve security architecture',
        'Establish information sharing partnerships',
      ],
    };
  }

  async buildExecutiveTimeline(investigation) {
    return (investigation.timeline || []).slice(0, 10).map(event => ({
      timestamp: event.timestamp,
      event: event.event,
      severity: event.severity || 'INFO',
    }));
  }

  async assessComplianceImpact(investigation) {
    return {
      regulations: ['GDPR', 'HIPAA', 'PCI-DSS', 'SOC 2'],
      breachNotification: investigation.severity === 'CRITICAL' || investigation.severity === 'HIGH',
      reportingDeadline: '72 hours',
    };
  }

  async identifyReportingRequirements(investigation) {
    return {
      regulators: [],
      customers: investigation.severity === 'CRITICAL',
      insurance: investigation.severity === 'CRITICAL',
      publicDisclosure: investigation.severity === 'CRITICAL',
    };
  }

  async identifyInsuranceConsiderations(investigation) {
    return {
      claimability: investigation.severity === 'HIGH' || investigation.severity === 'CRITICAL',
      notification: true,
      documentation: true,
    };
  }

  async buildBoardRecommendations(investigation) {
    return {
      governance: [
        'Ensure Board awareness of active threats',
        'Review cyber insurance coverage',
        'Allocate budget for defensive measures',
      ],
      compliance: [
        'Document incident response',
        'Report to regulators as required',
        'Update breach notification procedures',
      ],
      strategy: [
        'Prioritize cyber resilience in business planning',
        'Establish cyber risk governance committee',
        'Monitor threat landscape quarterly',
      ],
    };
  }

  async analyzeThreatTrends(recentIntelligence) {
    return {
      trending: recentIntelligence.slice(0, 3),
      emerging: recentIntelligence.slice(3, 6),
      declining: [],
    };
  }

  async generateWeeklyRecommendations(recentIntelligence) {
    return [
      'Monitor for indicators of compromise',
      'Review and update detection rules',
      'Assess organizational exposure',
      'Prepare incident response teams',
    ];
  }

  async generateMonthlyOverview(monthlyIntelligence) {
    return {
      totalThreats: monthlyIntelligence.length,
      criticalCount: monthlyIntelligence.filter(t => t.severity === 'CRITICAL').length,
      highCount: monthlyIntelligence.filter(t => t.severity === 'HIGH').length,
      summary: 'Monthly threat landscape analysis',
    };
  }

  async identifyEmergingRisks(trends) {
    return [
      { risk: 'Trend 1', timeframe: 'Next 30 days', priority: 'high' },
      { risk: 'Trend 2', timeframe: 'Next 60 days', priority: 'medium' },
    ];
  }

  async analyzeTrendAnalysis(trends) {
    return {
      threatActor: 'Activity stable',
      malware: 'New variants emerging',
      vulnerabilities: 'Exploitation increasing',
    };
  }

  async generateOutlook(trends) {
    return {
      shortTerm: 'Continued threat actor activity',
      mediumTerm: 'Evolution of attack techniques',
      longTerm: 'Increased sophistication',
    };
  }

  async buildStrategicRecommendations(monthlyIntelligence, trends) {
    return {
      strategy: [
        'Implement layered defense',
        'Enhance threat intelligence sharing',
        'Invest in security capabilities',
      ],
      investments: [
        'SIEM and detection tools',
        'Threat intelligence platforms',
        'Security talent and training',
      ],
    };
  }

  async extractSectorSpecificRisks(investigation, targetedSectors) {
    const risks = {};
    (targetedSectors || []).forEach(sector => {
      risks[sector] = investigation.findings?.filter(f => f.severity === 'high' || f.severity === 'critical') || [];
    });
    return risks;
  }

  async identifyHistoricalContext(investigation) {
    return {
      previousIncidents: [],
      precedent: 'Similar to past campaigns',
    };
  }

  async buildIndustryRecommendations(investigation, targetedSectors) {
    return {
      immediate: ['Alert all industry peers', 'Implement monitoring'],
      shortTerm: ['Establish information sharing', 'Deploy detection rules'],
      strategic: ['Coordinate industry defense', 'Improve information sharing'],
    };
  }

  async extractCriticalRisks(investigation) {
    return (investigation.findings || [])
      .filter(f => f.severity === 'CRITICAL')
      .slice(0, 3);
  }

  async extractUrgentActions(investigation) {
    return [
      'Immediately isolate affected systems',
      'Activate incident response team',
      'Begin forensic investigation',
      'Notify relevant stakeholders',
      'Monitor for lateral movement',
    ];
  }

  getProduct(productId) {
    return this.products.get(productId);
  }

  getAllProducts() {
    return Array.from(this.products.values());
  }
}

module.exports = { ExecutiveIntelligenceEngine };
