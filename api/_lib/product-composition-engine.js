'use strict';

const redis = require('./redis');
const {
  ExecutiveProduct,
  TechnicalProduct,
  DetectionProduct,
  ThreatIntelligenceProduct,
  MachineProduct,
} = require('./product-models');
const { Phase8Orchestrator } = require('./phase-8-orchestrator');

class ProductCompositionEngine {
  constructor(redisClient = redis) {
    this.redis = redisClient;
    this.phase8 = new Phase8Orchestrator();
  }

  async composeExecutiveBrief(investigation, report, qualityReview) {
    const product = new ExecutiveProduct('executive-brief', investigation.id, report.id, investigation.classification || 'TLP:AMBER');

    product.setMetadata(
      `Executive Intelligence Brief: ${investigation.title}`,
      `High-level threat summary for executive decision-making`,
      'Sentinel APEX',
      ['executive', 'threat-summary', 'decision-making']
    );

    // Reuse validated outputs from Phases 1-6
    const executiveSummary = await this.buildExecutiveSummary(investigation, report, qualityReview);
    product.addModule('executiveSummary', executiveSummary);

    const keyRisks = await this.extractKeyRisks(investigation, report);
    product.addModule('keyRisks', keyRisks);

    const recommendations = await this.buildExecutiveRecommendations(investigation, report);
    product.addModule('recommendations', recommendations);

    const timeline = await this.buildTimeline(investigation);
    product.addModule('timeline', timeline);

    product.addSource(investigation.id, 'investigation');
    product.addSource(report.id, 'report');

    return product;
  }

  async composeBoardSummary(investigation, report, qualityReview) {
    const product = new ExecutiveProduct('board-summary', investigation.id, report.id, 'TLP:RED');

    product.setMetadata(
      `Board Cyber Risk Summary: ${investigation.title}`,
      `Board-level cyber risk assessment`,
      'Sentinel APEX',
      ['board', 'risk', 'governance']
    );

    const businessImpact = await this.buildBusinessImpactAnalysis(investigation, report);
    product.addModule('businessImpact', businessImpact);

    const riskMetrics = await this.buildRiskMetrics(investigation, qualityReview);
    product.addModule('riskMetrics', riskMetrics);

    const recommendations = await this.buildBoardRecommendations(investigation, report);
    product.addModule('recommendations', recommendations);

    product.addSource(investigation.id, 'investigation');
    product.addSource(report.id, 'report');

    return product;
  }

  async composeTechnicalReport(investigation, report, qualityReview) {
    const product = new TechnicalProduct('technical-report', investigation.id, report.id, investigation.classification || 'TLP:GREEN');

    product.setMetadata(
      `Technical Intelligence Report: ${investigation.title}`,
      `Detailed technical analysis for security professionals`,
      'Sentinel APEX',
      ['technical', 'analysis', 'detailed']
    );

    // Consume validated findings from Phase 3
    const findings = await this.extractFindings(investigation);
    product.addModule('findings', findings);

    // Consume evidence from Phase 2
    const evidence = await this.extractEvidence(investigation);
    product.addModule('evidence', evidence);

    // Consume assessments from Phase 3
    const assessments = await this.extractAssessments(investigation);
    product.addModule('assessments', assessments);

    const technicalDetails = await this.buildTechnicalDetails(investigation);
    product.addModule('technicalDetails', technicalDetails);

    const references = await this.buildReferences(investigation, report);
    product.addModule('references', references);

    product.addSource(investigation.id, 'investigation');
    product.addSource(report.id, 'report');

    return product;
  }

  async composeIOCFeed(investigation, report) {
    const product = new ThreatIntelligenceProduct('ioc-feed', investigation.id, report.id, 'TLP:WHITE');

    product.setMetadata(
      `IOC Feed: ${investigation.id}`,
      `Machine-readable indicators of compromise`,
      'Sentinel APEX',
      ['iocs', 'machine-readable', 'feed']
    );

    // Extract IOCs from investigation data (Phase 2)
    const iocs = await this.extractIOCs(investigation);
    product.addModule('indicators', {
      count: iocs.length,
      types: this.categorizeIOCs(iocs),
      indicators: iocs,
    });

    const metadata = await this.buildIOCMetadata(investigation, iocs);
    product.addModule('metadata', metadata);

    product.addSource(investigation.id, 'investigation');

    return product;
  }

  async composeThreatActorProfile(investigation, report) {
    const product = new ThreatIntelligenceProduct('threat-actor-profile', investigation.id, report.id, 'TLP:GREEN');

    product.setMetadata(
      `Threat Actor Profile: ${investigation.threatActors?.[0]?.name || 'Unknown'}`,
      `Comprehensive threat actor intelligence`,
      'Sentinel APEX',
      ['threat-actor', 'profile', 'intelligence']
    );

    if (investigation.threatActors && investigation.threatActors.length > 0) {
      const actorOverview = await this.buildActorOverview(investigation.threatActors[0], investigation);
      product.addModule('overview', actorOverview);

      const capabilities = await this.buildActorCapabilities(investigation.threatActors[0], investigation);
      product.addModule('capabilities', capabilities);

      const timeline = await this.buildActorTimeline(investigation);
      product.addModule('timeline', timeline);
    }

    product.addSource(investigation.id, 'investigation');

    return product;
  }

  async composeCampaignIntelligence(investigation, report) {
    const product = new ThreatIntelligenceProduct('campaign-intelligence', investigation.id, report.id, 'TLP:GREEN');

    product.setMetadata(
      `Campaign Intelligence: ${investigation.campaigns?.[0]?.name || 'Unknown'}`,
      `Cyber campaign analysis and tracking`,
      'Sentinel APEX',
      ['campaign', 'intelligence', 'tracking']
    );

    if (investigation.campaigns && investigation.campaigns.length > 0) {
      const campaignOverview = await this.buildCampaignOverview(investigation.campaigns[0], investigation);
      product.addModule('overview', campaignOverview);

      const timeline = await this.buildCampaignTimeline(investigation);
      product.addModule('timeline', timeline);

      const targets = await this.buildTargets(investigation);
      product.addModule('targets', targets);

      const techniques = await this.buildAttackTechniques(investigation);
      product.addModule('techniques', techniques);
    }

    product.addSource(investigation.id, 'investigation');

    return product;
  }

  async composeSTIXBundle(investigation, report) {
    const product = new MachineProduct('stix-bundle', investigation.id, report.id, 'stix');

    product.setMetadata(
      `STIX Bundle: ${investigation.id}`,
      `STIX 2.1 threat intelligence bundle`,
      'Sentinel APEX',
      ['stix', 'machine-readable', 'bundle']
    );

    // Extract structured data for STIX conversion (Phase 2 graph data)
    const iocs = await this.extractIOCs(investigation);
    const relationships = await this.extractGraphRelationships(investigation);

    product.addModule('structuredData', {
      indicators: iocs,
      relationships: relationships,
      metadata: {
        created: investigation.createdAt,
        modified: new Date().toISOString(),
        investigationId: investigation.id,
      },
    });

    product.addSource(investigation.id, 'investigation');

    return product;
  }

  async composeJSONIntelligenceObject(investigation, report) {
    const product = new MachineProduct('json-object', investigation.id, report.id, 'json');

    product.setMetadata(
      `JSON Intelligence Object: ${investigation.id}`,
      `Structured JSON threat intelligence object`,
      'Sentinel APEX',
      ['json', 'machine-readable', 'structured']
    );

    const structuredObject = await this.buildStructuredIntelligenceObject(investigation, report);
    product.addModule('structuredData', structuredObject);

    product.addSource(investigation.id, 'investigation');
    product.addSource(report.id, 'report');

    return product;
  }

  // Module building methods - consume Phase outputs
  async buildExecutiveSummary(investigation, report, qualityReview) {
    return {
      title: investigation.title,
      description: investigation.description,
      threatLevel: investigation.severity || 'MEDIUM',
      immediateActions: await this.extractImmediateActions(investigation),
      qualityScore: qualityReview?.qualityScore?.overallScore,
      timestamp: new Date().toISOString(),
    };
  }

  async extractKeyRisks(investigation, report) {
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

  async buildExecutiveRecommendations(investigation, report) {
    return {
      immediate: [
        'Review affected systems and user access',
        'Enable enhanced logging and monitoring',
        'Prepare incident response playbooks',
      ],
      shortTerm: [
        'Conduct risk assessment',
        'Deploy relevant detection rules',
        'Brief senior management',
      ],
      strategic: [
        'Enhance threat intelligence capabilities',
        'Improve security architecture',
        'Establish information sharing partnerships',
      ],
    };
  }

  async buildTimeline(investigation) {
    return (investigation.timeline || []).map(event => ({
      timestamp: event.timestamp,
      event: event.event,
      severity: event.severity || 'INFO',
    }));
  }

  async buildBusinessImpactAnalysis(investigation, report) {
    return {
      affectedSystems: investigation.affectedSystems || [],
      estimatedExposure: investigation.affectedUserCount || 'Unknown',
      riskAssessment: {
        confidentiality: investigation.riskLevel?.confidentiality || 'MEDIUM',
        integrity: investigation.riskLevel?.integrity || 'MEDIUM',
        availability: investigation.riskLevel?.availability || 'MEDIUM',
      },
      businessServices: investigation.affectedServices || [],
    };
  }

  async buildRiskMetrics(investigation, qualityReview) {
    return {
      threatLevel: investigation.severity || 'MEDIUM',
      confidenceScore: qualityReview?.qualityScore?.overallScore || 0.5,
      impactScore: investigation.businessImpactScore || 0.5,
      urgency: this.calculateUrgency(investigation),
    };
  }

  async buildBoardRecommendations(investigation, report) {
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

  async extractFindings(investigation) {
    return investigation.findings || [];
  }

  async extractEvidence(investigation) {
    const evidence = [];
    (investigation.findings || []).forEach(f => {
      evidence.push(...(f.evidence || []));
    });
    return evidence;
  }

  async extractAssessments(investigation) {
    return investigation.assessments || {};
  }

  async buildTechnicalDetails(investigation) {
    return {
      attackMethods: investigation.attackMethods || [],
      toolsUsed: investigation.toolsUsed || [],
      infrastructure: investigation.infrastructure || [],
      persistence: investigation.persistenceMechanisms || [],
    };
  }

  async buildReferences(investigation, report) {
    return {
      investigation: investigation.id,
      report: report.id,
      sources: investigation.sources || [],
      references: investigation.references || [],
    };
  }

  async extractIOCs(investigation) {
    return investigation.iocs || [];
  }

  categorizeIOCs(iocs) {
    const types = {};
    iocs.forEach(ioc => {
      types[ioc.type] = (types[ioc.type] || 0) + 1;
    });
    return types;
  }

  async buildIOCMetadata(investigation, iocs) {
    return {
      count: iocs.length,
      types: this.categorizeIOCs(iocs),
      lastUpdated: new Date().toISOString(),
      source: investigation.id,
      confidence: iocs.map(i => i.confidence || 'unknown'),
    };
  }

  async buildActorOverview(actor, investigation) {
    return {
      name: actor.name,
      aliases: actor.aliases || [],
      origin: actor.origin,
      firstSeen: actor.firstSeen,
      lastSeen: actor.lastSeen,
      description: actor.description,
    };
  }

  async buildActorCapabilities(actor, investigation) {
    return {
      techniques: investigation.techniques || [],
      tools: investigation.toolsUsed || [],
      malware: investigation.malware || [],
      infrastructure: investigation.infrastructure || [],
    };
  }

  async buildActorTimeline(investigation) {
    return investigation.timeline || [];
  }

  async buildCampaignOverview(campaign, investigation) {
    return {
      name: campaign.name,
      description: campaign.description,
      startDate: campaign.startDate,
      endDate: campaign.endDate,
      status: campaign.status || 'ONGOING',
    };
  }

  async buildCampaignTimeline(investigation) {
    return investigation.timeline || [];
  }

  async buildTargets(investigation) {
    return {
      sectors: investigation.targetedSectors || [],
      regions: investigation.targetedRegions || [],
      organizations: investigation.targetedOrganizations || [],
    };
  }

  async buildAttackTechniques(investigation) {
    return investigation.techniques || [];
  }

  async extractGraphRelationships(investigation) {
    return investigation.relationships || [];
  }

  async buildStructuredIntelligenceObject(investigation, report) {
    return {
      investigationId: investigation.id,
      reportId: report.id,
      title: investigation.title,
      description: investigation.description,
      severity: investigation.severity,
      threatActors: investigation.threatActors || [],
      campaigns: investigation.campaigns || [],
      malware: investigation.malware || [],
      infrastructure: investigation.infrastructure || [],
      iocs: investigation.iocs || [],
      findings: investigation.findings || [],
      timeline: investigation.timeline || [],
      relationships: investigation.relationships || [],
      metadata: {
        created: investigation.createdAt,
        modified: report.createdAt,
        classification: investigation.classification,
      },
    };
  }

  async extractImmediateActions(investigation) {
    if (investigation.recommendations) {
      return investigation.recommendations
        .filter(r => r.priority === 'immediate' || r.priority === 'critical')
        .slice(0, 3)
        .map(r => r.action);
    }
    return [];
  }

  calculateUrgency(investigation) {
    const severity = investigation.severity || 'MEDIUM';
    const severityMap = { CRITICAL: 95, HIGH: 75, MEDIUM: 50, LOW: 25 };
    return severityMap[severity] || 50;
  }

  async applyPhase8Enhancements(product, investigation, report, qualityReview) {
    try {
      const result = await this.phase8.enhanceProduct(product, investigation, report, qualityReview);
      return result.product;
    } catch (e) {
      console.warn(`[PHASE 8] Enhancement failed gracefully: ${e.message}`);
      return product;
    }
  }
}

module.exports = { ProductCompositionEngine };
