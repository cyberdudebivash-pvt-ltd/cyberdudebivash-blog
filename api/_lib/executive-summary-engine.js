'use strict';

class ExecutiveSummaryEngine {
  generateExecutiveSummary(investigation, report, qualityReview) {
    const summary = {
      id: `exec-summary-${investigation.id}`,
      threatOverview: this.generateThreatOverview(investigation, report),
      businessImpact: this.generateBusinessImpact(investigation, report),
      operationalImpact: this.generateOperationalImpact(investigation, report),
      affectedIndustries: this.extractIndustriesByRisk(investigation),
      geographicImpact: this.extractGeographicImpact(investigation),
      riskLevel: this.assessRiskLevel(investigation, qualityReview),
      executivePriorities: this.deriveExecutivePriorities(investigation, report),
      immediateActions: this.generateImmediateActions(investigation, report),
      expectedEvolution: this.projectEvolution(investigation),
      confidence: this.calculateSummaryConfidence(investigation, qualityReview),
      generatedAt: new Date().toISOString(),
    };

    return summary;
  }

  generateThreatOverview(investigation, report) {
    const threatActors = investigation.threatActors || [];
    const campaigns = investigation.campaigns || [];
    const iocs = investigation.iocs || [];

    const hasAttribution = threatActors.length > 0 && (threatActors[0].confidence || 0) >= 0.6;
    const campaignContext = campaigns.length > 0
      ? `as part of ${campaigns[0].name || 'ongoing campaign'}`
      : 'outside known campaign';

    return {
      summary: `${threatActors.length > 0 ? threatActors[0].name : 'Unknown actor'} conducting targeted activity ${campaignContext}`,
      attribution: hasAttribution ? 'Confirmed' : 'Suspected',
      threatActorCount: threatActors.length,
      campaignCount: campaigns.length,
      iocsIdentified: iocs.length,
      analysis: this.buildThreatNarrative(investigation),
    };
  }

  generateBusinessImpact(investigation, report) {
    const victims = investigation.victims || [];
    const industryImpact = investigation.industryImpact || {};

    return {
      affectedOrganizations: victims.length,
      targetedIndustries: Object.keys(industryImpact).length,
      estimatedExposure: this.estimateExposure(investigation),
      financialRisk: this.assessFinancialRisk(investigation),
      reputationalRisk: this.assessReputationalRisk(investigation),
      operationalDisruption: this.assessOperationalDisruption(investigation),
      reguatory_compliance_risk: this.assessComplianceRisk(investigation),
      statement: this.buildBusinessImpactStatement(investigation),
    };
  }

  generateOperationalImpact(investigation, report) {
    const techniques = investigation.mitreTechniques || [];
    const detection = investigation.detectionCapabilities || {};
    const toolsUsed = investigation.toolsUsed || [];

    return {
      attackTechniques: techniques.length,
      affectedSystems: this.getAffectedSystems(investigation),
      detectionCoverage: Object.values(detection).filter(d => d.detected).length,
      detectionGaps: Object.values(detection).filter(d => !d.detected).length,
      malwareVariants: (investigation.malwareVariants || []).length,
      toolsObserved: toolsUsed.length,
      infrastructureInvolved: (investigation.infrastructure || []).length,
      persistenceMechanisms: this.identifyPersistence(techniques),
      exfiltrationChannels: this.identifyExfiltration(techniques),
      statement: this.buildOperationalImpactStatement(investigation),
    };
  }

  extractIndustriesByRisk(investigation) {
    const industryImpact = investigation.industryImpact || {};

    return Object.entries(industryImpact)
      .sort((a, b) => (b[1].riskScore || 0) - (a[1].riskScore || 0))
      .slice(0, 5)
      .map(([industry, data]) => ({
        industry,
        riskScore: data.riskScore || 0,
        victimCount: data.victimCount || 0,
        criticalSystems: data.criticalSystems || [],
      }));
  }

  extractGeographicImpact(investigation) {
    const victims = investigation.victims || [];
    const geoCount = {};

    victims.forEach(v => {
      if (v.country) {
        geoCount[v.country] = (geoCount[v.country] || 0) + 1;
      }
    });

    return Object.entries(geoCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([country, count]) => ({ country, victimCount: count }));
  }

  assessRiskLevel(investigation, qualityReview) {
    const severity = investigation.severity || 'medium';
    const victimCount = (investigation.victims || []).length;
    const confidence = (investigation.confidence || 0.5);

    const riskScores = {
      critical: 0.9,
      high: 0.7,
      medium: 0.5,
      low: 0.3,
    };

    const baseScore = riskScores[severity] || 0.5;
    const victimFactor = Math.min(victimCount / 100, 0.2);
    const confidenceFactor = confidence * 0.15;

    const finalScore = Math.min(baseScore + victimFactor + confidenceFactor, 1.0);

    let level = 'Low';
    if (finalScore >= 0.8) level = 'Critical';
    else if (finalScore >= 0.6) level = 'High';
    else if (finalScore >= 0.4) level = 'Medium';

    return {
      level,
      score: parseFloat(finalScore.toFixed(2)),
      factors: {
        threatSeverity: severity,
        victimCount,
        confidenceLevel: parseFloat((confidence * 100).toFixed(0)) + '%',
      },
    };
  }

  deriveExecutivePriorities(investigation, report) {
    const priorities = [];

    if (investigation.threatActors && investigation.threatActors.length > 0) {
      const actor = investigation.threatActors[0];
      priorities.push({
        priority: 1,
        action: `Attribute threat to ${actor.name}`,
        rationale: `High-confidence attribution enables focused defense planning`,
        timeline: 'Immediate',
      });
    }

    if ((investigation.victims || []).length > 10) {
      priorities.push({
        priority: 2,
        action: 'Conduct industry coordination',
        rationale: 'Widespread impact across sector requires coordinated defense',
        timeline: '24 hours',
      });
    }

    if ((investigation.detectionCapabilities || {}).overallCoverage < 0.6) {
      priorities.push({
        priority: 3,
        action: 'Deploy additional detection content',
        rationale: 'Detection gaps enable continued undetected activity',
        timeline: '48 hours',
      });
    }

    return priorities.slice(0, 5);
  }

  generateImmediateActions(investigation, report) {
    return [
      {
        actor: 'Security Team',
        action: 'Hunt for related IOCs across infrastructure',
        expectedOutcome: 'Identify and block active intrusions',
        timeline: 'Immediate',
        effort: 'Low',
      },
      {
        actor: 'Detection Engineering',
        action: 'Deploy Sigma and YARA rules to production',
        expectedOutcome: 'Enable detection of similar activity',
        timeline: '2-4 hours',
        effort: 'Medium',
      },
      {
        actor: 'Incident Response',
        action: 'Review logs for related techniques',
        expectedOutcome: 'Identify undetected breach activity',
        timeline: '24 hours',
        effort: 'Medium',
      },
      {
        actor: 'Executive Leadership',
        action: 'Notify board of incident scope',
        expectedOutcome: 'Align leadership on response strategy',
        timeline: 'Immediate',
        effort: 'Low',
      },
    ];
  }

  projectEvolution(investigation) {
    const threatActors = investigation.threatActors || [];
    const campaigns = investigation.campaigns || [];

    if (threatActors.length === 0) {
      return {
        outlook: 'Unknown',
        reasoning: 'Insufficient attribution data for projection',
      };
    }

    const actor = threatActors[0];
    const historicalActivity = (actor.campaigns || []).length;

    return {
      outlook: historicalActivity > 3 ? 'Likely to continue' : 'Unknown',
      projectedTimeline: '30-90 days',
      expectedTargets: this.extractTargetProfile(investigation),
      potentialEscalation: this.assessEscalation(investigation),
      preventionRecommendations: this.generatePreventionStrategy(investigation),
    };
  }

  calculateSummaryConfidence(investigation, qualityReview) {
    const investigationConfidence = investigation.confidence || 0.5;
    const evidenceQuality = (investigation.evidenceQuality || 0.6);
    const analysisCompleteness = (investigation.analysisCompleteness || 0.7);

    const overall = (investigationConfidence * 0.4) + (evidenceQuality * 0.3) + (analysisCompleteness * 0.3);

    return {
      overall: parseFloat((overall * 100).toFixed(0)) + '%',
      components: {
        investigation: parseFloat((investigationConfidence * 100).toFixed(0)) + '%',
        evidence: parseFloat((evidenceQuality * 100).toFixed(0)) + '%',
        analysis: parseFloat((analysisCompleteness * 100).toFixed(0)) + '%',
      },
    };
  }

  buildThreatNarrative(investigation) {
    const threatActors = investigation.threatActors || [];
    const campaigns = investigation.campaigns || [];
    const techniques = investigation.mitreTechniques || [];

    if (threatActors.length === 0) return 'Unknown threat actor conducting targeted attack';

    const actor = threatActors[0];
    const campaign = campaigns[0];
    const motivation = actor.motivation || 'financial gain';

    return `${actor.name} (${actor.aliases ? actor.aliases.join(', ') : actor.name}) is conducting ${campaign ? 'campaign ' + campaign.name : 'targeted'} activity against ${investigation.targetIndustry || 'organizations'} with suspected motivation of ${motivation}.`;
  }

  buildBusinessImpactStatement(investigation) {
    const victimCount = (investigation.victims || []).length;
    const estimatedLoss = investigation.estimatedLoss || 0;

    if (victimCount === 0) return 'No confirmed compromises at this time.';
    if (victimCount === 1) return `1 organization confirmed compromised.`;
    return `${victimCount} organizations confirmed compromised. Estimated loss: ${estimatedLoss > 0 ? '$' + estimatedLoss.toLocaleString() : 'unknown'}.`;
  }

  buildOperationalImpactStatement(investigation) {
    const techniques = (investigation.mitreTechniques || []).length;
    const detectionGaps = this.identifyDetectionGaps(investigation);

    if (techniques === 0) return 'No techniques identified.';
    return `${techniques} distinct techniques observed. Detection coverage: ${(((techniques - detectionGaps) / techniques) * 100).toFixed(0)}%.`;
  }

  estimateExposure(investigation) {
    const victims = investigation.victims || [];
    return {
      directExposure: victims.length,
      potentialSecondaryExposure: Math.floor(victims.length * 0.3),
      supplyChainRisk: investigation.supplyChainInvolved ? 'High' : 'Low',
    };
  }

  assessFinancialRisk(investigation) {
    const attackType = investigation.type || 'unknown';
    const victims = investigation.victims || [];

    const riskMap = {
      'ransomware': 0.9,
      'data-breach': 0.7,
      'supply-chain': 0.8,
      'incident-response': 0.5,
    };

    const score = riskMap[attackType] || 0.5;
    return {
      level: score >= 0.8 ? 'High' : score >= 0.5 ? 'Medium' : 'Low',
      score: parseFloat((score * 100).toFixed(0)),
      factors: ['Data loss', 'Operational disruption', 'Compliance violations', 'Ransomware payments'],
    };
  }

  assessReputationalRisk(investigation) {
    const publicDisclosure = investigation.publicDisclosure || false;
    const mediaAttention = investigation.mediaAttention || 'low';

    return {
      level: publicDisclosure ? 'High' : mediaAttention === 'high' ? 'Medium' : 'Low',
      publicAwareness: publicDisclosure ? 'Yes' : 'No',
      mediaAttention,
      customerTrust: publicDisclosure ? 'At risk' : 'Stable',
    };
  }

  assessOperationalDisruption(investigation) {
    const techniques = investigation.mitreTechniques || [];
    const disruptiveCount = techniques.filter(t =>
      ['Defacement', 'Data Encrypted for Impact', 'Service Stop'].some(d => t.includes(d))
    ).length;

    return {
      level: disruptiveCount > 0 ? 'High' : 'Medium',
      disruptiveTechniquesCount: disruptiveCount,
      expectedDowntime: disruptiveCount > 0 ? '24-48 hours' : 'Minimal',
    };
  }

  assessComplianceRisk(investigation) {
    const dataTypes = investigation.dataTypesAffected || [];
    const hasPersonalData = dataTypes.includes('PII') || dataTypes.includes('PHI');

    return {
      level: hasPersonalData ? 'High' : 'Medium',
      affectedDataTypes: dataTypes,
      applicableRegulations: hasPersonalData ? ['GDPR', 'CCPA', 'HIPAA', 'SOC 2'] : ['SOC 2'],
      notificationRequired: hasPersonalData,
    };
  }

  getAffectedSystems(investigation) {
    return investigation.affectedSystems || [
      'Windows systems',
      'Linux systems',
      'Cloud infrastructure',
      'Email systems',
      'File storage',
    ];
  }

  identifyPersistence(techniques) {
    return techniques.filter(t =>
      ['Registry', 'Scheduled Task', 'Service', 'Startup Folder'].some(p => t.includes(p))
    ) || [];
  }

  identifyExfiltration(techniques) {
    return techniques.filter(t =>
      ['Data from Local System', 'Data from Network', 'Exfiltration Over C2'].some(e => t.includes(e))
    ) || [];
  }

  identifyDetectionGaps(investigation) {
    return ((investigation.detectionCapabilities || {}).gaps || []).length;
  }

  extractTargetProfile(investigation) {
    const industries = this.extractIndustriesByRisk(investigation);
    return industries.slice(0, 3).map(i => i.industry);
  }

  assessEscalation(investigation) {
    const previousIncidents = (investigation.previousIncidents || []).length;
    const trendingUpward = previousIncidents > 5;

    return {
      likelihood: trendingUpward ? 'Moderate to High' : 'Low to Moderate',
      escalationVectors: ['Increased attack frequency', 'Expanded target scope', 'New techniques adoption'],
    };
  }

  generatePreventionStrategy(investigation) {
    return [
      'Deploy preventive detection rules',
      'Harden access controls',
      'Implement network segmentation',
      'Enhance threat hunting',
      'Establish incident response procedures',
    ];
  }
}

module.exports = { ExecutiveSummaryEngine };
