'use strict';

const { ExecutiveSummaryEngine } = require('./executive-summary-engine');
const { KeyJudgementsEngine } = require('./key-judgements-engine');
const { NarrativeEngine } = require('./narrative-engine');
const { EvidenceTraceabilityEngine } = require('./evidence-traceability-engine');
const { QualityGatesEngine } = require('./quality-gates-engine');
const { EnterpriseRecommendationsEngine } = require('./enterprise-recommendations-engine');
const { CustomerDeliverablesEngine } = require('./customer-deliverables-engine');
const { MITREIntelligenceEngine } = require('./mitre-intelligence-engine');
const {
  IOCIntelligenceEngine,
  InfrastructureIntelligenceEngine,
  ThreatActorIntelligenceEngine,
  CampaignIntelligenceEngine,
} = require('./intelligence-synthesis-engine');

class Phase8Orchestrator {
  constructor() {
    this.executiveSummary = new ExecutiveSummaryEngine();
    this.keyJudgements = new KeyJudgementsEngine();
    this.narrative = new NarrativeEngine();
    this.traceability = new EvidenceTraceabilityEngine();
    this.qualityGates = new QualityGatesEngine();
    this.recommendations = new EnterpriseRecommendationsEngine();
    this.deliverables = new CustomerDeliverablesEngine();
    this.mitre = new MITREIntelligenceEngine();
    this.iocs = new IOCIntelligenceEngine();
    this.infrastructure = new InfrastructureIntelligenceEngine();
    this.actors = new ThreatActorIntelligenceEngine();
    this.campaigns = new CampaignIntelligenceEngine();
  }

  async enhanceProduct(product, investigation, report, qualityReview) {
    console.log(`[PHASE 8] Enhancing product ${product.id} with enterprise intelligence`);

    try {
      // Phase 8A: Executive summaries and judgements
      product.modules.executiveSummary = this.executiveSummary.generateExecutiveSummary(
        investigation,
        report,
        qualityReview
      );

      product.modules.keyJudgements = this.keyJudgements.generateKeyJudgements(
        investigation,
        report,
        qualityReview
      );

      // Phase 8B: Comprehensive narratives
      product.modules.narratives = this.narrative.generateNarratives(
        investigation,
        report,
        qualityReview
      );

      // Phase 8C: Intelligence synthesis
      product.modules.intelligence = {
        iocs: this.iocs.groupIOCs(investigation),
        infrastructure: this.infrastructure.analyzeInfrastructure(investigation),
        threatActors: this.actors.generateActorProfile(investigation),
        campaigns: this.campaigns.generateCampaignAnalysis(investigation),
        mitre: this.mitre.generateMITREIntelligence(investigation),
      };

      // Phase 8D: Enterprise recommendations
      product.modules.recommendations = this.recommendations.generateEnterpriseRecommendations(
        investigation,
        report,
        product.audience
      );

      // Phase 8E: Evidence traceability
      const traceability = this.traceability.ensureTraceability(product, investigation, report);
      product.modules.evidenceTraceability = traceability;
      product = this.traceability.addTraceMetadata(product, traceability);

      // Phase 8F: Quality validation
      const qualityResult = this.qualityGates.validateProductForPublication(
        product,
        investigation,
        report
      );
      product = this.qualityGates.addQualityMetadata(product, qualityResult);

      // Phase 8G: Customer deliverables
      product.modules.deliverables = await this.deliverables.generateDeliverables(
        product,
        investigation,
        report
      );

      product.modules.qualityReport = this.qualityGates.generateQualityReport(
        product,
        qualityResult
      );

      // Mark product as Phase 8 enhanced
      product.phase8Enhanced = true;
      product.phase8EnhancedAt = new Date().toISOString();

      console.log(
        `[PHASE 8] Product enhancement complete. Quality score: ${(qualityResult.qualityScore * 100).toFixed(1)}%`
      );

      return {
        product,
        qualityResult,
        traceability,
      };
    } catch (e) {
      console.error(`[PHASE 8] Enhancement failed: ${e.message}`);
      throw e;
    }
  }

  async validateEnhancedProduct(product, investigation) {
    const quality = this.qualityGates.validateProductForPublication(product, investigation);

    return {
      valid: quality.approvedForPublication,
      quality: quality.qualityScore,
      blockers: quality.blockers,
      publishingReady: quality.publishingReady,
      warnings: quality.warnings,
    };
  }

  getEnhancementSummary(product) {
    if (!product.phase8Enhanced) {
      return {
        status: 'Not enhanced',
        phase: 'Pre-Phase 8',
      };
    }

    return {
      status: 'Enhanced',
      phase: 'Phase 8',
      enhancedAt: product.phase8EnhancedAt,
      quality: product.qualityAssurance?.qualityScore,
      modules: Object.keys(product.modules || {}),
    };
  }
}

module.exports = { Phase8Orchestrator };
