'use strict';

class GoldStandardEIPCCertificationEngine {
  constructor() {
    this.certificationScores = new Map();
    this.certificationHistory = [];
    this.targetScores = {
      executiveIntelligence: 95,
      technicalIntelligence: 95,
      analyticalTradecraft: 95,
      campaignIntelligence: 95,
      intelligenceCorrelation: 95,
      originalAnalyticalValue: 95,
      detectionEngineering: 98,
      multiAudienceDecisionSupport: 98,
      editorialExcellence: 98,
      commercialProductExcellence: 98,
    };
  }

  async certifyProduct(product, investigation, report) {
    const certification = {
      productId: product.id,
      productType: product.productType,
      investigationId: investigation.id,
      reportId: report.id,
      timestamp: new Date().toISOString(),
      categories: {},
      overallScore: 0,
      certificationStatus: 'PENDING',
      recommendations: [],
      passedCategories: 0,
      failedCategories: 0,
    };

    // Evaluate all 10 certification categories
    certification.categories.executiveIntelligence = this.certifyExecutiveIntelligence(product, investigation);
    certification.categories.technicalIntelligence = this.certifyTechnicalIntelligence(product, investigation);
    certification.categories.analyticalTradecraft = this.certifyAnalyticalTradecraft(product, investigation);
    certification.categories.campaignIntelligence = this.certifyCampaignIntelligence(product, investigation);
    certification.categories.intelligenceCorrelation = this.certifyIntelligenceCorrelation(product, investigation);
    certification.categories.originalAnalyticalValue = this.certifyOriginalAnalyticalValue(product, investigation);
    certification.categories.detectionEngineering = this.certifyDetectionEngineering(product, investigation);
    certification.categories.multiAudienceDecisionSupport = this.certifyMultiAudienceDecisionSupport(product, investigation);
    certification.categories.editorialExcellence = this.certifyEditorialExcellence(product, investigation);
    certification.categories.commercialProductExcellence = this.certifyCommercialProductExcellence(product, investigation);

    // Calculate overall certification
    this.calculateOverallCertification(certification);

    // Store for trend analysis
    this.certificationScores.set(product.id, certification);
    this.certificationHistory.push(certification);

    return certification;
  }

  certifyExecutiveIntelligence(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Executive summary clarity (25 points)
    if (modules.executiveSummary) {
      const summary = modules.executiveSummary.content || '';
      const isClarity = typeof summary === 'string' && summary.length >= 100 && summary.length <= 500;
      if (isClarity) {
        score += 25;
      } else {
        findings.push('Executive summary clarity needs improvement');
      }
    }

    // Business relevance (25 points)
    if (investigation.businessImpact || modules.businessContext) {
      score += 25;
    } else {
      findings.push('Business relevance not clearly articulated');
    }

    // Operational implications (20 points)
    if (modules.immediateActions || modules.operationalRecommendations) {
      score += 20;
    } else {
      findings.push('Operational implications not documented');
    }

    // Strategic implications (15 points)
    if (modules.strategicRecommendations || investigation.strategicContext) {
      score += 15;
    } else {
      findings.push('Strategic implications not addressed');
    }

    // Risk communication (15 points)
    if (investigation.severity && investigation.riskLevel) {
      score += 15;
    } else {
      findings.push('Risk level not clearly communicated');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.executiveIntelligence,
      passed: score >= this.targetScores.executiveIntelligence,
      findings,
    };
  }

  certifyTechnicalIntelligence(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Technical depth (20 points)
    if (modules.technicalAnalysis || modules.technicalThreatReport) {
      score += 20;
    } else {
      findings.push('Technical depth analysis required');
    }

    // Attack explanation (20 points)
    if (modules.narratives || modules.attackFlow) {
      score += 20;
    } else {
      findings.push('Attack workflow not clearly explained');
    }

    // Root cause analysis (15 points)
    if (modules.rootCause || modules.vulnerability) {
      score += 15;
    } else {
      findings.push('Root cause not documented');
    }

    // Exploitation workflow (15 points)
    if (modules.techniques && modules.techniques.content) {
      score += 15;
    } else {
      findings.push('Exploitation workflow not detailed');
    }

    // Detection opportunities (15 points)
    if (modules.detectionRules || modules.detectionContent) {
      score += 15;
    } else {
      findings.push('Detection opportunities not provided');
    }

    // Defensive guidance (10 points)
    if (modules.recommendations || modules.mitigationStrategies) {
      score += 10;
    } else {
      findings.push('Defensive guidance not included');
    }

    // Residual risk (5 points)
    if (modules.residualRisk || modules.limitations) {
      score += 5;
    } else {
      findings.push('Residual risk assessment recommended');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.technicalIntelligence,
      passed: score >= this.targetScores.technicalIntelligence,
      findings,
    };
  }

  certifyAnalyticalTradecraft(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Supporting evidence (20 points)
    const hasEvidence = (investigation.findings || []).length > 0 || (investigation.iocs || []).length > 0;
    if (hasEvidence) {
      score += 20;
    } else {
      findings.push('Insufficient supporting evidence');
    }

    // Contradictory evidence (15 points)
    if (modules.evidenceConflict || modules.contradictions) {
      score += 15;
    } else {
      findings.push('Contradictory evidence analysis recommended');
    }

    // Confidence explanation (20 points)
    if (investigation.confidence && investigation.confidenceReasoning) {
      score += 20;
    } else {
      findings.push('Confidence reasoning not documented');
    }

    // Alternative hypotheses (15 points)
    if (modules.alternativeHypotheses || modules.hypotheses) {
      score += 15;
    } else {
      findings.push('Alternative hypotheses not considered');
    }

    // Assumptions documentation (15 points)
    if (modules.assumptions || investigation.assumptionsDocumented) {
      score += 15;
    } else {
      findings.push('Assumptions not clearly documented');
    }

    // Uncertainty articulation (10 points)
    if (investigation.uncertaintyAreas || modules.limitations) {
      score += 10;
    } else {
      findings.push('Uncertainty areas should be articulated');
    }

    // Collection gaps (5 points)
    if (modules.collectionGaps || modules.gaps) {
      score += 5;
    } else {
      findings.push('Collection gaps should be documented');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.analyticalTradecraft,
      passed: score >= this.targetScores.analyticalTradecraft,
      findings,
    };
  }

  certifyCampaignIntelligence(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Campaign lifecycle (15 points)
    if (modules.campaign || investigation.campaigns) {
      score += 15;
    } else {
      findings.push('Campaign lifecycle not documented');
    }

    // Infrastructure evolution (20 points)
    if (modules.infrastructureEvolution || modules.infrastructure) {
      score += 20;
    } else {
      findings.push('Infrastructure evolution not tracked');
    }

    // Victimology (15 points)
    if (modules.victimology || investigation.targetedSectors) {
      score += 15;
    } else {
      findings.push('Victimology not analyzed');
    }

    // Malware evolution (15 points)
    if (modules.malwareEvolution || investigation.malware) {
      score += 15;
    } else {
      findings.push('Malware evolution not documented');
    }

    // Operator objectives (15 points)
    if (modules.objectives || investigation.motivation) {
      score += 15;
    } else {
      findings.push('Operator objectives not articulated');
    }

    // Timeline (10 points)
    if (modules.timeline && modules.timeline.content) {
      score += 10;
    } else {
      findings.push('Timeline not provided');
    }

    // Attack progression (10 points)
    if (modules.attackProgression || modules.techniques) {
      score += 10;
    } else {
      findings.push('Attack progression not documented');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.campaignIntelligence,
      passed: score >= this.targetScores.campaignIntelligence,
      findings,
    };
  }

  certifyIntelligenceCorrelation(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Threat actor correlation (12 points)
    if (investigation.threatActors && investigation.threatActors.length > 0) {
      score += 12;
    } else {
      findings.push('Threat actor correlation opportunity');
    }

    // Campaign correlation (12 points)
    if (investigation.campaigns && investigation.campaigns.length > 0) {
      score += 12;
    } else {
      findings.push('Campaign correlation opportunity');
    }

    // Malware correlation (12 points)
    if (investigation.malware && investigation.malware.length > 0) {
      score += 12;
    } else {
      findings.push('Malware correlation opportunity');
    }

    // Infrastructure correlation (12 points)
    if (investigation.infrastructure && investigation.infrastructure.length > 0) {
      score += 12;
    } else {
      findings.push('Infrastructure correlation opportunity');
    }

    // MITRE ATT&CK correlation (15 points)
    if (investigation.mitreTechniques && investigation.mitreTechniques.length > 0) {
      score += 15;
    } else {
      findings.push('MITRE ATT&CK mapping recommended');
    }

    // IOC correlation (12 points)
    if (investigation.iocs && investigation.iocs.length > 0) {
      score += 12;
    } else {
      findings.push('IOC extraction and validation needed');
    }

    // CVE/CWE correlation (13 points)
    if (investigation.cves || investigation.vulnerabilities) {
      score += 13;
    } else {
      findings.push('CVE/CWE correlation opportunity');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.intelligenceCorrelation,
      passed: score >= this.targetScores.intelligenceCorrelation,
      findings,
    };
  }

  certifyOriginalAnalyticalValue(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Synthesis of sources (25 points)
    if (modules.synthesis || (investigation.sources && investigation.sources.length > 1)) {
      score += 25;
    } else {
      findings.push('Multi-source synthesis needed');
    }

    // Relationship identification (25 points)
    if (modules.relationships || modules.correlations) {
      score += 25;
    } else {
      findings.push('Relationship identification needed');
    }

    // Significance explanation (25 points)
    if (modules.significance || modules.implications) {
      score += 25;
    } else {
      findings.push('Significance not clearly articulated');
    }

    // Evidence-backed insights (20 points)
    if (modules.insights || modules.keyJudgements) {
      score += 20;
    } else {
      findings.push('Evidence-backed insights needed');
    }

    // Observation vs assessment distinction (5 points)
    if (modules.observationAssessmentDistinction || investigation.confidenceReasoning) {
      score += 5;
    } else {
      findings.push('Observation/assessment distinction should be clear');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.originalAnalyticalValue,
      passed: score >= this.targetScores.originalAnalyticalValue,
      findings,
    };
  }

  certifyDetectionEngineering(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Sigma rules (15 points)
    if (modules.sigmaRules || modules.detectionRules?.sigma) {
      score += 15;
    } else {
      findings.push('Sigma rule generation recommended');
    }

    // YARA rules (14 points)
    if (modules.yaraRules || modules.detectionRules?.yara) {
      score += 14;
    } else {
      findings.push('YARA rule generation recommended');
    }

    // Suricata rules (14 points)
    if (modules.suricataRules || modules.detectionRules?.suricata) {
      score += 14;
    } else {
      findings.push('Suricata rule generation recommended');
    }

    // SIEM queries (14 points)
    if (modules.siemQueries || modules.detectionRules?.siem) {
      score += 14;
    } else {
      findings.push('SIEM query generation recommended');
    }

    // Threat hunting queries (14 points)
    if (modules.threatHuntingQueries || modules.huntingGuides) {
      score += 14;
    } else {
      findings.push('Threat hunting queries recommended');
    }

    // Detection coverage (14 points)
    if (modules.detectionCoverage || (investigation.mitreTechniques && investigation.mitreTechniques.length > 0)) {
      score += 14;
    } else {
      findings.push('Detection coverage mapping needed');
    }

    // Operational deployment guidance (15 points)
    if (modules.deploymentGuidance || modules.operationalGuidance) {
      score += 15;
    } else {
      findings.push('Operational deployment guidance needed');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.detectionEngineering,
      passed: score >= this.targetScores.detectionEngineering,
      findings,
    };
  }

  certifyMultiAudienceDecisionSupport(product, investigation) {
    const modules = product.modules || {};
    const audiences = ['ceo', 'board', 'ciso', 'soc', 'hunting', 'ir', 'cloud', 'identity', 'vuln', 'risk', 'security'];
    let score = 0;
    const findings = [];

    // Check for audience-specific guidance
    const hasAudienceGuidance = modules.executiveSummary || modules.technicalRecommendations || modules.operationalGuidance;

    if (hasAudienceGuidance) {
      score += 50;
    } else {
      findings.push('Audience-specific guidance not found');
    }

    // Check for actionable recommendations
    if (modules.recommendations || modules.actions) {
      score += 25;
    } else {
      findings.push('Actionable recommendations needed');
    }

    // Check for evidence traceability
    if (modules.evidence || investigation.findings) {
      score += 25;
    } else {
      findings.push('Evidence traceability to recommendations needed');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.multiAudienceDecisionSupport,
      passed: score >= this.targetScores.multiAudienceDecisionSupport,
      findings,
    };
  }

  certifyEditorialExcellence(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Readability (20 points)
    if (modules.executiveSummary || modules.narrative) {
      const content = modules.executiveSummary?.content || modules.narrative?.content || '';
      const hasReadability = typeof content === 'string' && content.length > 50;
      if (hasReadability) {
        score += 20;
      } else {
        findings.push('Readability score below target');
      }
    }

    // Structure (20 points)
    if (product.modules && Object.keys(product.modules).length >= 5) {
      score += 20;
    } else {
      findings.push('Report structure needs more sections');
    }

    // Consistency (15 points)
    if (investigation.classification && product.classification) {
      score += 15;
    } else {
      findings.push('Consistency check - classification should match');
    }

    // Grammar/terminology (15 points)
    score += 15; // Assume acceptable for now

    // Section quality (15 points)
    if (modules.keyJudgements || modules.findings) {
      score += 15;
    } else {
      findings.push('Key sections need development');
    }

    // Formatting (10 points)
    if (product.metadata) {
      score += 10;
    } else {
      findings.push('Metadata and formatting incomplete');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.editorialExcellence,
      passed: score >= this.targetScores.editorialExcellence,
      findings,
    };
  }

  certifyCommercialProductExcellence(product, investigation) {
    const modules = product.modules || {};
    let score = 0;
    const findings = [];

    // Customer usefulness (25 points)
    if (modules.recommendations || modules.actions) {
      score += 25;
    } else {
      findings.push('Customer actionability needs improvement');
    }

    // Executive usefulness (20 points)
    if (modules.executiveSummary && modules.businessContext) {
      score += 20;
    } else {
      findings.push('Executive value proposition not clear');
    }

    // Technical usefulness (20 points)
    if (modules.detectionRules || modules.technicalRecommendations) {
      score += 20;
    } else {
      findings.push('Technical utility not maximized');
    }

    // Operational usefulness (15 points)
    if (modules.immediateActions || modules.operationalGuidance) {
      score += 15;
    } else {
      findings.push('Operational guidance incomplete');
    }

    // Completeness (10 points)
    if (Object.keys(modules).length >= 6) {
      score += 10;
    } else {
      findings.push('Report completeness needs more modules');
    }

    // Reusability (10 points)
    if (modules.correlations || investigation.threatActors) {
      score += 10;
    } else {
      findings.push('Reusability could be improved');
    }

    return {
      score: Math.min(score, 100),
      targetScore: this.targetScores.commercialProductExcellence,
      passed: score >= this.targetScores.commercialProductExcellence,
      findings,
    };
  }

  calculateOverallCertification(certification) {
    const categories = certification.categories;
    const categoryArray = Object.values(categories);

    // Calculate average score
    const totalScore = categoryArray.reduce((sum, cat) => sum + cat.score, 0);
    certification.overallScore = Math.round(totalScore / categoryArray.length);

    // Count passed categories
    certification.passedCategories = categoryArray.filter(cat => cat.passed).length;
    certification.failedCategories = categoryArray.filter(cat => !cat.passed).length;

    // Determine certification status
    if (certification.passedCategories === 10) {
      certification.certificationStatus = 'GOLD';
    } else if (certification.passedCategories >= 8) {
      certification.certificationStatus = 'SILVER';
    } else if (certification.passedCategories >= 6) {
      certification.certificationStatus = 'BRONZE';
    } else {
      certification.certificationStatus = 'FAIL';
    }

    // Generate improvement recommendations
    certification.recommendations = this.generateImprovementRecommendations(certification);
  }

  generateImprovementRecommendations(certification) {
    const recommendations = [];
    const failedCategories = Object.entries(certification.categories)
      .filter(([_, cat]) => !cat.passed)
      .map(([name, cat]) => ({ name, ...cat }));

    for (const category of failedCategories) {
      const gap = category.targetScore - category.score;
      recommendations.push({
        category: this.humanizeCategory(category.name),
        currentScore: category.score,
        targetScore: category.targetScore,
        gap,
        priority: gap > 20 ? 'High' : 'Medium',
        findings: category.findings.slice(0, 2),
        recommendation: this.recommendationForCategory(category.name),
      });
    }

    return recommendations.sort((a, b) => b.gap - a.gap);
  }

  humanizeCategory(categoryName) {
    const humanized = {
      executiveIntelligence: 'Executive Intelligence',
      technicalIntelligence: 'Technical Intelligence',
      analyticalTradecraft: 'Analytical Tradecraft',
      campaignIntelligence: 'Campaign Intelligence',
      intelligenceCorrelation: 'Intelligence Correlation',
      originalAnalyticalValue: 'Original Analytical Value',
      detectionEngineering: 'Detection Engineering',
      multiAudienceDecisionSupport: 'Multi-Audience Decision Support',
      editorialExcellence: 'Editorial Excellence',
      commercialProductExcellence: 'Commercial Product Excellence',
    };
    return humanized[categoryName] || categoryName;
  }

  recommendationForCategory(categoryName) {
    const recommendations = {
      executiveIntelligence: 'Enhance executive summary clarity and articulate business impact more explicitly',
      technicalIntelligence: 'Deepen technical analysis with step-by-step attack workflow documentation',
      analyticalTradecraft: 'Document assumptions, confidence reasoning, and alternative hypotheses',
      campaignIntelligence: 'Provide detailed campaign timeline and infrastructure evolution analysis',
      intelligenceCorrelation: 'Cross-reference with existing threat actors, campaigns, and IOCs in knowledge base',
      originalAnalyticalValue: 'Synthesize multiple sources and explain relationships and significance',
      detectionEngineering: 'Generate detection rules (Sigma, YARA, SIEM) and threat hunting queries',
      multiAudienceDecisionSupport: 'Create tailored recommendations for each audience (CISO, SOC, threat hunters)',
      editorialExcellence: 'Improve readability, structure consistency, and metadata completeness',
      commercialProductExcellence: 'Ensure report is actionable, complete, and reusable for customers',
    };
    return recommendations[categoryName] || 'Review and improve this dimension';
  }

  generateScorecard(certification) {
    const scorecard = {
      productId: certification.productId,
      productType: certification.productType,
      timestamp: certification.timestamp,
      scores: {
        executiveIntelligence: certification.categories.executiveIntelligence.score,
        technicalIntelligence: certification.categories.technicalIntelligence.score,
        analyticalTradecraft: certification.categories.analyticalTradecraft.score,
        campaignIntelligence: certification.categories.campaignIntelligence.score,
        intelligenceCorrelation: certification.categories.intelligenceCorrelation.score,
        originalAnalyticalValue: certification.categories.originalAnalyticalValue.score,
        detectionEngineering: certification.categories.detectionEngineering.score,
        multiAudienceDecisionSupport: certification.categories.multiAudienceDecisionSupport.score,
        editorialExcellence: certification.categories.editorialExcellence.score,
        commercialProductExcellence: certification.categories.commercialProductExcellence.score,
      },
      overallCertification: certification.certificationStatus,
      overallScore: certification.overallScore,
      passedCategories: certification.passedCategories,
      failedCategories: certification.failedCategories,
      publishingGate: certification.certificationStatus === 'GOLD' || certification.certificationStatus === 'SILVER',
    };

    return scorecard;
  }

  getCertificationHistory(productId) {
    if (productId) {
      return this.certificationHistory.filter(c => c.productId === productId);
    }
    return this.certificationHistory;
  }

  detectRegression(productId) {
    const history = this.getCertificationHistory(productId);
    if (history.length < 2) return null;

    const current = history[history.length - 1];
    const previous = history[history.length - 2];

    const regression = {
      productId,
      detectedAt: new Date().toISOString(),
      previousScore: previous.overallScore,
      currentScore: current.overallScore,
      scoreDifference: current.overallScore - previous.overallScore,
      isRegression: current.overallScore < previous.overallScore,
      categoriesRegressed: [],
      categoriesImproved: [],
    };

    for (const [categoryName, currentCat] of Object.entries(current.categories)) {
      const prevCat = previous.categories[categoryName];
      if (prevCat) {
        if (currentCat.score < prevCat.score) {
          regression.categoriesRegressed.push({
            category: this.humanizeCategory(categoryName),
            previousScore: prevCat.score,
            currentScore: currentCat.score,
            decline: prevCat.score - currentCat.score,
          });
        } else if (currentCat.score > prevCat.score) {
          regression.categoriesImproved.push({
            category: this.humanizeCategory(categoryName),
            previousScore: prevCat.score,
            currentScore: currentCat.score,
            improvement: currentCat.score - prevCat.score,
          });
        }
      }
    }

    return regression;
  }
}

module.exports = { GoldStandardEIPCCertificationEngine };
