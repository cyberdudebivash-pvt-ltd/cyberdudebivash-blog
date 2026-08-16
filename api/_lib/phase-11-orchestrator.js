'use strict';

const { ProductCatalogEngine } = require('./product-catalog-engine');
const { ExecutiveIntelligenceEngine } = require('./executive-intelligence-engine');
const { TechnicalIntelligenceEngine } = require('./technical-intelligence-engine');
const { ThreatActorIntelligenceEngine } = require('./threat-actor-intelligence-engine');
const { SectorRegionalIntelligenceEngine } = require('./sector-regional-intelligence-engine');
const { VulnerabilityDetectionIntelligenceEngine } = require('./vulnerability-detection-intelligence-engine');
const { CollectionsCustomerPackagesEngine } = require('./collections-customer-packages-engine');

class Phase11Orchestrator {
  constructor() {
    this.catalog = new ProductCatalogEngine();
    this.executive = new ExecutiveIntelligenceEngine();
    this.technical = new TechnicalIntelligenceEngine();
    this.threatActor = new ThreatActorIntelligenceEngine();
    this.sectorRegional = new SectorRegionalIntelligenceEngine();
    this.vulnerabilityDetection = new VulnerabilityDetectionIntelligenceEngine();
    this.collectionsPackages = new CollectionsCustomerPackagesEngine();
    this.compositionStats = {
      attempted: 0,
      succeeded: 0,
      failed: 0,
      skipped: 0,
    };
  }

  async generateGlobalIntelligencePortfolio(investigation, report, vulnerabilityData = {}) {
    console.log(`[PHASE 11] Generating global intelligence portfolio for investigation ${investigation.id}`);

    const portfolio = {
      investigationId: investigation.id,
      reportId: report.id,
      products: {
        executive: [],
        technical: [],
        threatActor: [],
        sectorRegional: [],
        vulnerabilityDetection: [],
        collections: [],
        customerPackages: [],
      },
      metadata: {
        generatedAt: new Date().toISOString(),
        compositionStats: { ...this.compositionStats },
      },
    };

    try {
      console.log('[PHASE 11] Composing executive intelligence products');
      portfolio.products.executive = await this.composeExecutiveProducts(investigation, report);

      console.log('[PHASE 11] Composing technical intelligence products');
      portfolio.products.technical = await this.composeTechnicalProducts(investigation, report);

      console.log('[PHASE 11] Composing threat actor intelligence products');
      portfolio.products.threatActor = await this.composeThreatActorProducts(investigation, report);

      console.log('[PHASE 11] Composing sector and regional intelligence products');
      portfolio.products.sectorRegional = await this.composeSectorRegionalProducts(investigation, report);

      if (vulnerabilityData && Object.keys(vulnerabilityData).length > 0) {
        console.log('[PHASE 11] Composing vulnerability and detection products');
        portfolio.products.vulnerabilityDetection = await this.composeVulnerabilityProducts(
          investigation,
          report,
          vulnerabilityData
        );
      }

      console.log('[PHASE 11] Building intelligence collections');
      portfolio.products.collections = await this.buildIntelligenceCollections(investigation, report);

      console.log('[PHASE 11] Building customer packages');
      const allComposedProducts = [
        ...portfolio.products.executive,
        ...portfolio.products.technical,
        ...portfolio.products.threatActor,
        ...portfolio.products.sectorRegional,
        ...portfolio.products.vulnerabilityDetection,
        ...portfolio.products.collections,
      ];
      portfolio.products.customerPackages = await this.buildCustomerPackages(investigation, report, allComposedProducts);

      portfolio.metadata.compositionStats = { ...this.compositionStats };
      portfolio.metadata.totalProducts = Object.values(portfolio.products).reduce((sum, arr) => sum + arr.length, 0);
      portfolio.metadata.status = 'complete';

      console.log(`[PHASE 11] Portfolio generation complete: ${portfolio.metadata.totalProducts} products`);

      return portfolio;
    } catch (e) {
      console.error(`[PHASE 11] Portfolio generation failed: ${e.message}`);
      portfolio.metadata.status = 'error';
      portfolio.metadata.error = e.message;
      return portfolio;
    }
  }

  async composeExecutiveProducts(investigation, report) {
    const products = [];

    try {
      const executiveBrief = await this.executive.composeExecutiveThreatBrief(investigation, report);
      if (executiveBrief) {
        products.push(executiveBrief);
        this.recordComposition(true);
      }

      const boardBrief = await this.executive.composeBoardCyberRiskBrief(investigation, report);
      if (boardBrief) {
        products.push(boardBrief);
        this.recordComposition(true);
      }

      // composeWeeklyExecutiveDigest(recentIntelligence, metrics) and
      // composeMonthlyExecutiveOutlook(monthlyIntelligence, trends, riskMetrics)
      // are cross-investigation, time-windowed aggregates -- they were being
      // called here with (investigation, report), which don't match either
      // signature. Neither call threw (defensive `Array.isArray(...) ? : []`
      // and `|| {}` fallbacks absorbed the mismatch), so they silently
      // produced a "digest"/"outlook" product with empty threat data and
      // zeroed metrics on every single investigation -- shipped to
      // customers looking complete while carrying no real content, and
      // also why their lineage.investigation/lineage.report were never
      // set (these functions don't take an investigation/report at all).
      // There's no per-investigation source for "recent intelligence this
      // week across the platform", and fabricating one here would violate
      // this platform's zero-hallucination standard, so these two are not
      // called from this per-investigation flow. The underlying methods
      // are untouched in executive-intelligence-engine.js, ready for a
      // real caller with genuine cross-investigation, time-windowed data
      // once one exists.

      const industryAdvisory = await this.executive.composeIndustryExecutiveAdvisory(
        investigation,
        report,
        investigation.targetedSectors
      );
      if (industryAdvisory) {
        products.push(industryAdvisory);
        this.recordComposition(true);
      }

      const criticalAlert = await this.executive.composeCriticalThreatAlert(investigation, report);
      if (criticalAlert) {
        products.push(criticalAlert);
        this.recordComposition(true);
      }
    } catch (e) {
      console.warn(`[PHASE 11] Executive products composition failed gracefully: ${e.message}`);
    }

    return products;
  }

  async composeTechnicalProducts(investigation, report) {
    const products = [];

    try {
      const technicalReport = await this.technical.composeTechnicalThreatReport(investigation, report);
      if (technicalReport) {
        products.push(technicalReport);
        this.recordComposition(true);
      }

      const irAdvisory = await this.technical.composeIncidentResponseAdvisory(investigation, report);
      if (irAdvisory) {
        products.push(irAdvisory);
        this.recordComposition(true);
      }

      const huntingGuide = await this.technical.composeThreatHuntingGuide(investigation, report);
      if (huntingGuide) {
        products.push(huntingGuide);
        this.recordComposition(true);
      }

      const detectionGuide = await this.technical.composeDetectionEngineeringGuide(investigation, report);
      if (detectionGuide) {
        products.push(detectionGuide);
        this.recordComposition(true);
      }

      const iocPack = await this.technical.composeIOCIntelligencePack(investigation, report);
      if (iocPack) {
        products.push(iocPack);
        this.recordComposition(true);
      }

      const malwareProfile = await this.technical.composeMalwareTechnicalProfile(investigation, report);
      if (malwareProfile) {
        products.push(malwareProfile);
        this.recordComposition(true);
      }

      const infraReport = await this.technical.composeInfrastructureIntelligenceReport(investigation, report);
      if (infraReport) {
        products.push(infraReport);
        this.recordComposition(true);
      }
    } catch (e) {
      console.warn(`[PHASE 11] Technical products composition failed gracefully: ${e.message}`);
    }

    return products;
  }

  async composeThreatActorProducts(investigation, report) {
    const products = [];

    if (!investigation.threatActors || investigation.threatActors.length === 0) {
      this.recordComposition(false, true);
      return products;
    }

    try {
      const dossier = await this.threatActor.composeThreatActorDossier(investigation, report);
      if (dossier) {
        products.push(dossier);
        this.recordComposition(true);
      }

      const campaignPortfolio = await this.threatActor.composeCampaignPortfolio(investigation, report);
      if (campaignPortfolio) {
        products.push(campaignPortfolio);
        this.recordComposition(true);
      }

      const infraMap = await this.threatActor.composeInfrastructureMap(investigation, report);
      if (infraMap) {
        products.push(infraMap);
        this.recordComposition(true);
      }

      const capabilityAssessment = await this.threatActor.composeCapabilityAssessment(investigation, report);
      if (capabilityAssessment) {
        products.push(capabilityAssessment);
        this.recordComposition(true);
      }

      const historicalActivity = await this.threatActor.composeHistoricalActivity(investigation, report);
      if (historicalActivity) {
        products.push(historicalActivity);
        this.recordComposition(true);
      }

      const targetingAnalysis = await this.threatActor.composeTargetingAnalysis(investigation, report);
      if (targetingAnalysis) {
        products.push(targetingAnalysis);
        this.recordComposition(true);
      }

      const evolutionTimeline = await this.threatActor.composeEvolutionTimeline(investigation, report);
      if (evolutionTimeline) {
        products.push(evolutionTimeline);
        this.recordComposition(true);
      }
    } catch (e) {
      console.warn(`[PHASE 11] Threat actor products composition failed gracefully: ${e.message}`);
    }

    return products;
  }

  async composeSectorRegionalProducts(investigation, report) {
    const products = [];

    try {
      // Compose sector-specific intelligence
      if (investigation.targetedSectors && investigation.targetedSectors.length > 0) {
        for (const sector of investigation.targetedSectors) {
          try {
            const sectorProduct = await this.sectorRegional.composeSectorIntelligence(investigation, report, sector);
            if (sectorProduct) {
              products.push(sectorProduct);
              this.recordComposition(true);
            }
          } catch (e) {
            console.warn(`[PHASE 11] Sector intelligence for ${sector} failed: ${e.message}`);
          }
        }
      }

      // Compose regional-specific intelligence
      if (investigation.targetedRegions && investigation.targetedRegions.length > 0) {
        for (const region of investigation.targetedRegions) {
          try {
            const regionalProduct = await this.sectorRegional.composeRegionalIntelligence(investigation, report, region);
            if (regionalProduct) {
              products.push(regionalProduct);
              this.recordComposition(true);
            }
          } catch (e) {
            console.warn(`[PHASE 11] Regional intelligence for ${region} failed: ${e.message}`);
          }
        }
      }

      if (products.length === 0) {
        this.recordComposition(false, true);
      }
    } catch (e) {
      console.warn(`[PHASE 11] Sector/regional products composition failed gracefully: ${e.message}`);
    }

    return products;
  }

  async composeVulnerabilityProducts(investigation, report, vulnerabilityData) {
    const products = [];

    try {
      const vulnProducts = await this.vulnerabilityDetection.composeVulnerabilityProducts(
        investigation,
        report,
        vulnerabilityData
      );

      if (vulnProducts && vulnProducts.length > 0) {
        products.push(...vulnProducts);
        vulnProducts.forEach(() => this.recordComposition(true));
      }

      const detectionPackages = await this.vulnerabilityDetection.composeDetectionPackages(investigation, report);

      if (detectionPackages && detectionPackages.length > 0) {
        products.push(...detectionPackages);
        detectionPackages.forEach(() => this.recordComposition(true));
      }
    } catch (e) {
      console.warn(`[PHASE 11] Vulnerability/detection products composition failed gracefully: ${e.message}`);
    }

    return products;
  }

  async buildIntelligenceCollections(investigation, report) {
    const collections = [];

    try {
      if (!this.collectionsPackages || typeof this.collectionsPackages.buildIntelligenceCollections !== 'function') {
        this.recordComposition(false, true);
        return collections;
      }

      const productsArray = Array.isArray(investigation) ? investigation : [];
      const collectionProducts = await this.collectionsPackages.buildIntelligenceCollections(productsArray);

      if (collectionProducts && Array.isArray(collectionProducts) && collectionProducts.length > 0) {
        collections.push(...collectionProducts);
        collectionProducts.forEach(() => this.recordComposition(true));
      }
    } catch (e) {
      console.warn(`[PHASE 11] Intelligence collections building failed gracefully: ${e.message}`);
      this.recordComposition(false, true);
    }

    return collections;
  }

  async buildCustomerPackages(investigation, report, allProducts) {
    const packages = [];

    try {
      if (!this.collectionsPackages || typeof this.collectionsPackages.buildCustomerIntelligencePackages !== 'function') {
        this.recordComposition(false, true);
        return packages;
      }

      const customerPackages = await this.collectionsPackages.buildCustomerIntelligencePackages(investigation, report, allProducts || []);

      if (customerPackages && Array.isArray(customerPackages) && customerPackages.length > 0) {
        packages.push(...customerPackages);
        customerPackages.forEach(() => this.recordComposition(true));
      }
    } catch (e) {
      if (e.message.includes('not a function')) {
        this.recordComposition(false, true);
      } else {
        console.warn(`[PHASE 11] Customer packages building failed gracefully: ${e.message}`);
        this.recordComposition(false, true);
      }
    }

    return packages;
  }

  recordComposition(succeeded, skipped = false) {
    this.compositionStats.attempted++;
    if (succeeded) this.compositionStats.succeeded++;
    else if (skipped) this.compositionStats.skipped++;
    else this.compositionStats.failed++;
  }

  async getCompositionStats() {
    return {
      ...this.compositionStats,
      successRate: this.compositionStats.attempted > 0
        ? ((this.compositionStats.succeeded / this.compositionStats.attempted) * 100).toFixed(2) + '%'
        : '0%',
    };
  }

  async validatePhase11Integration(investigation, report) {
    try {
      const validation = {
        catalog: !!this.catalog,
        executive: !!this.executive,
        technical: !!this.technical,
        threatActor: !!this.threatActor,
        sectorRegional: !!this.sectorRegional,
        vulnerabilityDetection: !!this.vulnerabilityDetection,
        collectionsPackages: !!this.collectionsPackages,
      };

      const allEnginesReady = Object.values(validation).every(v => v === true);

      return {
        phase11Orchestrator: 'operational',
        enginesReady: validation,
        status: allEnginesReady ? 'ready' : 'degraded',
      };
    } catch (e) {
      console.warn(`[PHASE 11] Integration validation failed gracefully: ${e.message}`);
      return { status: 'error', message: e.message };
    }
  }

  async enhanceProductWithPhase11Context(product, investigation, report, vulnerabilityData = {}) {
    try {
      const enhancements = {
        globalIntelligencePortfolio: true,
        operationalMetadata: {
          phase11Enabled: true,
          orchestratorVersion: '1.0',
          capabilities: [
            'executive_intelligence',
            'technical_intelligence',
            'threat_actor_intelligence',
            'sector_intelligence',
            'regional_intelligence',
            'vulnerability_intelligence',
            'detection_packages',
            'intelligence_collections',
            'customer_packages',
          ],
        },
      };

      if (product) {
        product.phase11Enhancements = enhancements;
      }

      return {
        product,
        enhancements,
        status: 'enhanced',
      };
    } catch (e) {
      console.warn(`[PHASE 11] Product enhancement failed gracefully: ${e.message}`);
      return { product, status: 'error', message: e.message };
    }
  }
}

module.exports = { Phase11Orchestrator };
